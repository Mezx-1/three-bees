"""Endpoint event scoring and cross-source threat correlation.

Correlation links an endpoint event to existing evidence only through concrete shared facts:
  * observed: the same indicator value (hash, domain, IP, filename) appears in both
  * inferred: the device owner is the recipient of a high-risk email (same person, no shared artefact)
Each link is recorded with its type so the UI can distinguish observed evidence from inference.
"""
from __future__ import annotations

import re

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Analysis, Device, EndpointEvent, Incident, Indicator
from .risk import Finding, combine, severity_for
from .store import add_event, audit, max_sev
from .url_analyzer import registered_domain

OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "acrord32.exe", "acrobat.exe", "msedge.exe", "chrome.exe", "explorer.exe"}
SCRIPT_HOSTS = {"wscript.exe", "cscript.exe", "powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe"}


def score_event(event_type: str, d: dict, ctx_blocked: dict) -> list[Finding]:
    f: list[Finding] = []
    if event_type == "process":
        name = (d.get("process_name") or "").lower()
        parent = (d.get("parent_process") or "").lower()
        cmd = (d.get("command_line") or "").lower()
        path = (d.get("path") or "").lower()
        if parent in OFFICE and name in SCRIPT_HOSTS:
            f.append(Finding("Document/email app spawned a script host", f"{parent} launched {name} — a typical malicious-attachment execution chain.",
                             "endpoint", "critical", 55, "verified", ["malware_delivery"], evidence=f"{parent} → {name}"))
        elif name in SCRIPT_HOSTS:
            f.append(Finding("Script interpreter executed", f"{name} ran on the endpoint.", "endpoint", "low", 10, "verified", ["malware_delivery"]))
        if re.search(r"-enc|-encodedcommand|iex|downloadstring|frombase64|bypass|hidden", cmd):
            f.append(Finding("Obfuscated / download command line", "Command line contains encoded or download-cradle patterns.", "endpoint", "high", 40, "verified",
                             ["malware_delivery"], evidence=cmd[:160]))
        if re.search(r"\\(temp|appdata\\local\\temp|downloads|content\.outlook)\\", path):
            f.append(Finding("Executed from a temporary/download folder", "Process ran from a location used for email attachments and downloads.",
                             "endpoint", "medium", 18, "verified", ["malware_delivery"], evidence=path[:160]))
        if re.search(r"\.(pdf|docx?|xlsx?|jpe?g|png|txt)\.(exe|scr|js|vbs|bat|cmd|hta)\b", cmd + " " + path):
            f.append(Finding("Double-extension file executed", "A file disguised as a document was executed.", "endpoint", "critical", 45, "verified", ["malware_delivery"]))
    elif event_type == "network_connection":
        ip = d.get("dest_ip") or ""
        dom = (d.get("dest_domain") or "").lower()
        port = d.get("dest_port")
        if ip in ctx_blocked["ip"] or (dom and registered_domain(dom) in ctx_blocked["domain"]):
            f.append(Finding("Connection to a blocklisted destination", f"Endpoint contacted {dom or ip}, which is on the WOLVE blocklist.",
                             "endpoint", "critical", 60, "verified", ["suspicious_infrastructure"], evidence=dom or ip))
        if port and int(port) in (4444, 1337, 8081, 6667, 9001, 31337):
            f.append(Finding("Connection on a port associated with C2/backdoors", f"Destination port {port}.", "endpoint", "high", 30, "heuristic",
                             ["suspicious_infrastructure"], evidence=str(port)))
        proc = (d.get("process_name") or "").lower()
        if proc in SCRIPT_HOSTS:
            f.append(Finding("Script host made an outbound connection", f"{proc} opened a network connection — possible payload download or C2.",
                             "endpoint", "high", 34, "verified", ["malware_delivery", "suspicious_infrastructure"], evidence=f"{proc} → {dom or ip}:{port}"))
    elif event_type == "file":
        name = (d.get("file_name") or "").lower()
        if re.search(r"\.(exe|scr|js|vbs|bat|cmd|hta|ps1|lnk)$", name):
            f.append(Finding("Executable file written", f"{name} was created on disk.", "endpoint", "medium", 16, "verified", ["malware_delivery"]))
    elif event_type == "login":
        if d.get("result") == "failure" and int(d.get("attempts", 1)) >= 5:
            f.append(Finding("Repeated failed logins", f"{d.get('attempts')} failed login attempts.", "endpoint", "medium", 22, "verified", ["credential_theft"]))
    return f


def event_indicators(event_type: str, d: dict, device: Device) -> list[tuple[str, str, str]]:
    out = [("device", device.hostname, "device")]
    if device.owner_email:
        out.append(("email", device.owner_email.lower(), "device_owner"))
    for key, typ in (("sha256", "hash"), ("dest_ip", "ip"), ("file_name", "filename")):
        if d.get(key):
            out.append((typ, str(d[key]).lower() if typ == "hash" else str(d[key]), key))
    if d.get("dest_domain"):
        out.append(("domain", registered_domain(d["dest_domain"]), "dest_domain"))
    cmd = d.get("command_line") or ""
    for m in re.findall(r"[\w\-. ]+\.(?:pdf|docx?|xlsx?)\.(?:js|exe|vbs|scr|bat|cmd|hta)", cmd, re.I):
        out.append(("filename", m.strip().split("\\")[-1], "process_target"))
    return out


def correlate(db: Session, ev: EndpointEvent, device: Device, inds: list[tuple[str, str, str]], actor: str) -> dict:
    """Find prior evidence sharing facts with this event; attach to / escalate an incident."""
    links: list[dict] = []
    target: Incident | None = None
    for typ, val, role in inds:
        if typ in ("device",) or role == "device_owner":
            continue
        rows = db.scalars(select(Indicator).where(Indicator.type == typ, Indicator.value.ilike(val), Indicator.analysis_id.is_not(None))).all()
        for r in rows:
            a = db.get(Analysis, r.analysis_id)
            if not a:
                continue
            links.append({"type": "observed", "indicator": f"{typ}:{val}", "analysis_id": a.id, "incident_id": a.incident_id,
                          "reason": f"Endpoint {role} matches {r.role} '{val}' from {a.kind} analysis {a.id}"})
            if a.incident_id and target is None:
                target = db.get(Incident, a.incident_id)
    if device.owner_email:
        rows = db.scalars(select(Indicator).where(Indicator.type == "email", Indicator.value == device.owner_email.lower(), Indicator.role == "recipient")).all()
        for r in rows:
            a = db.get(Analysis, r.analysis_id) if r.analysis_id else None
            if a and a.risk_score >= 60:
                links.append({"type": "inferred", "indicator": f"email:{device.owner_email}", "analysis_id": a.id, "incident_id": a.incident_id,
                              "reason": f"Device owner {device.owner_email} received high-risk email {a.id}"})
                if a.incident_id and target is None and ev.risk_score >= 30:
                    target = db.get(Incident, a.incident_id)

    result = {"links": links, "incident_id": None, "created_incident": False}
    if target is None and ev.risk_score >= 60:
        target = Incident(title=f"Endpoint threat on {device.hostname}: {ev.title}", severity=ev.severity, source="Endpoint Protection",
                          risk_score=ev.risk_score, demo=ev.simulated, summary="; ".join(x["title"] for x in ev.findings[:5]),
                          recommended_response=["Recommend isolating the endpoint from the network for investigation.",
                                                "Collect process tree and memory image before remediation.",
                                                "Reset credentials of the device owner."])
        db.add(target)
        db.flush()
        add_event(db, target, "created", f"Incident created from endpoint event #{ev.id} on {device.hostname}.", "system")
        result["created_incident"] = True
    if target is not None:
        ev.incident_id = target.id
        sim = " [SIMULATED EVENT]" if ev.simulated else ""
        add_event(db, target, "evidence", f"Endpoint {device.hostname}: {ev.title} (risk {ev.risk_score}){sim}", "system", {"endpoint_event_id": ev.id})
        observed = [l for l in links if l["type"] == "observed" and l.get("incident_id") == target.id]
        inferred = [l for l in links if l["type"] == "inferred" and l.get("incident_id") == target.id]
        if observed or inferred:
            target.correlated = True
            parts = [l["reason"] for l in (observed + inferred)[:4]]
            add_event(db, target, "correlation", "Correlated: " + " | ".join(parts), "WOLVE correlation engine",
                      {"observed": len(observed), "inferred": len(inferred)})
            # Email + endpoint execution evidence => escalate.
            old = target.severity
            bump = "critical" if (observed and ev.risk_score >= 50) else max_sev(target.severity, ev.severity)
            target.severity = max_sev(target.severity, bump)
            target.risk_score = max(target.risk_score, min(100, max(target.risk_score, ev.risk_score) + 10))
            if target.severity != old:
                add_event(db, target, "escalation", f"Severity escalated {old} → {target.severity}: attack progressed from email to endpoint.", "WOLVE correlation engine")
            for rec in ["Recommend isolating the endpoint from the network for investigation.", f"Check other recipients of the same email and devices contacting the same destinations."]:
                if rec not in target.recommended_response:
                    target.recommended_response = [*target.recommended_response, rec]
        if target.status == "resolved":
            target.status = "investigating"
        result["incident_id"] = target.id
        audit(db, actor, "correlation.link", target.id, {"endpoint_event": ev.id, "links": len(links)})
    return result


def recompute_device(db: Session, device: Device) -> None:
    events = db.scalars(select(EndpointEvent).where(EndpointEvent.device_id == device.id).order_by(EndpointEvent.created_at.desc()).limit(50)).all()
    scores = [e.risk_score for e in events]
    device.risk_score = max(scores) if scores else 0
    if device.status in ("isolation_recommended",):
        return
    device.status = "compromised" if device.risk_score >= 80 else "at_risk" if device.risk_score >= 40 else "healthy"


def ingest_event(db: Session, device: Device, event_type: str, title: str, details: dict, simulated: bool, actor: str) -> tuple[EndpointEvent, dict]:
    from ..models import BlockedIndicator

    blocked = db.scalars(select(BlockedIndicator)).all()
    ctx_blocked = {"ip": {b.value for b in blocked if b.type == "ip"}, "domain": {b.value for b in blocked if b.type == "domain"}}
    findings = score_event(event_type, details, ctx_blocked)
    score = combine(findings)
    ev = EndpointEvent(device_id=device.id, event_type=event_type, title=title[:300], details=details, simulated=simulated,
                       risk_score=score, severity=severity_for(score) if findings else "low", findings=[f.to_dict() for f in findings])
    db.add(ev)
    db.flush()
    inds = event_indicators(event_type, details, device)
    for typ, val, role in inds:
        db.add(Indicator(type=typ, value=val, endpoint_event_id=ev.id, role=role, malicious=score >= 60))
    corr = correlate(db, ev, device, inds, actor)
    recompute_device(db, device)
    audit(db, actor, "endpoint.event" + (".simulated" if simulated else ""), device.id, {"event_id": ev.id, "type": event_type, "risk": score})
    db.flush()
    return ev, corr
