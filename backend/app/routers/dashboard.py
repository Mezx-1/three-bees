from __future__ import annotations

from collections import Counter, defaultdict
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..config import settings
from ..db import get_db
from ..deps import current_user, ser_analysis, ser_event, ser_incident
from ..models import Analysis, BlockedIndicator, Device, EndpointEvent, Incident, Indicator, User, utcnow
from ..services.store import get_setting

router = APIRouter(prefix="/api", tags=["dashboard"])
ACTIVE = ("open", "investigating", "contained")


@router.get("/dashboard")
def dashboard(db: Session = Depends(get_db), user: User = Depends(current_user)):
    analyses = db.scalars(select(Analysis).order_by(Analysis.created_at.desc())).all()
    incidents = db.scalars(select(Incident).order_by(Incident.created_at.desc())).all()
    devices = db.scalars(select(Device)).all()
    events = db.scalars(select(EndpointEvent).order_by(EndpointEvent.created_at.desc()).limit(12)).all()

    emails = [a for a in analyses if a.kind == "email"]
    files = [a for a in analyses if a.kind in ("file", "image", "audio", "video")]
    active = [i for i in incidents if i.status in ACTIVE]
    sev_active = Counter(i.severity for i in active)
    if sev_active["critical"]:
        status, status_text = "critical", f"{sev_active['critical']} critical incident(s) need immediate response"
    elif sev_active["high"]:
        status, status_text = "elevated", f"{sev_active['high']} high-severity incident(s) under investigation"
    elif active:
        status, status_text = "guarded", f"{len(active)} lower-severity incident(s) open"
    else:
        status, status_text = "normal", "No active incidents"

    now = utcnow()
    days = [(now - timedelta(days=d)).date() for d in range(13, -1, -1)]
    timeline = {d.isoformat(): defaultdict(int) for d in days}
    for a in analyses:
        key = a.created_at.date().isoformat() if a.created_at else None
        if key in timeline:
            timeline[key][a.severity] += 1
    activity = [{"date": d, **{s: v.get(s, 0) for s in ("low", "medium", "high", "critical")}} for d, v in timeline.items()]

    recs: list[dict] = []
    for i in active:
        if i.severity == "critical" and not i.assigned_to:
            recs.append({"level": "critical", "text": f"Assign an analyst to critical incident {i.id}.", "link": f"/incidents/{i.id}"})
    for dv in devices:
        if dv.status == "compromised":
            recs.append({"level": "critical", "text": f"Endpoint {dv.hostname} shows compromise indicators — recommend isolation.", "link": f"/endpoints?device={dv.id}"})
    pending_q = [a for a in emails if a.status == "quarantined"]
    if pending_q:
        recs.append({"level": "medium", "text": f"{len(pending_q)} quarantined email(s) awaiting analyst review.", "link": "/email-security?status=quarantined"})
    unreviewed_sus = [a for a in emails if a.status == "suspicious"]
    if unreviewed_sus:
        recs.append({"level": "high", "text": f"{len(unreviewed_sus)} suspicious email(s) not yet quarantined or reviewed.", "link": "/email-security?status=suspicious"})
    mal_unblocked = db.scalar(select(func.count(func.distinct(Indicator.value))).where(
        Indicator.malicious.is_(True), Indicator.type.in_(["domain", "ip"]),
        Indicator.value.not_in(select(BlockedIndicator.value)))) or 0
    if mal_unblocked:
        recs.append({"level": "high", "text": f"{mal_unblocked} malicious domain/IP indicator(s) are not on the blocklist.", "link": "/prevention"})
    if not settings.anthropic_api_key:
        recs.append({"level": "info", "text": "AI analysis is offline (no ANTHROPIC_API_KEY). Deterministic engine is active.", "link": "/settings"})
    if not settings.virustotal_api_key and not settings.abuseipdb_api_key:
        recs.append({"level": "info", "text": "No threat-reputation providers configured; reputation results are not available.", "link": "/settings"})

    return {
        "security_status": status, "security_status_text": status_text,
        "totals": {
            "emails_analyzed": len(emails), "suspicious_emails": sum(1 for a in emails if a.risk_score >= 30),
            "quarantined_emails": len(pending_q), "critical_threats": sum(1 for a in analyses if a.severity == "critical"),
            "files_analyzed": len(files), "total_analyses": len(analyses), "active_incidents": len(active),
            "endpoints": len(devices), "endpoints_at_risk": sum(1 for d in devices if d.status in ("at_risk", "compromised", "isolation_recommended")),
            "blocked_indicators": db.scalar(select(func.count(BlockedIndicator.id))) or 0,
        },
        "severity_distribution": [{"severity": s, "count": sum(1 for a in analyses if a.severity == s)} for s in ("low", "medium", "high", "critical")],
        "kind_distribution": [{"kind": k, "count": v} for k, v in Counter(a.kind for a in analyses).most_common()],
        "endpoint_status": [{"status": k, "count": v} for k, v in Counter(d.status for d in devices).items()],
        "activity": activity,
        "recent_analyses": [ser_analysis(a) for a in analyses[:10]],
        "recent_incidents": [ser_incident(i) for i in incidents[:6]],
        "recent_endpoint_events": [ser_event(e) for e in events],
        "recommendations": recs[:8],
        "contains_demo_data": any(a.demo for a in analyses) or any(d.source == "simulated" for d in devices),
        "ai_enabled": bool(get_setting(db, "ai_enabled")) and bool(settings.anthropic_api_key),
        "generated_at": now.isoformat(),
    }


@router.get("/graph")
def threat_graph(incident_id: str | None = None, db: Session = Depends(get_db), user: User = Depends(current_user)):
    if incident_id:
        inc = db.get(Incident, incident_id)
        if not inc:
            raise HTTPException(404, "Incident not found")
        incidents = [inc]
    else:
        incidents = db.scalars(select(Incident).order_by(Incident.created_at.desc()).limit(8)).all()
    nodes: dict[str, dict] = {}
    edges: dict[str, dict] = {}

    def node(nid, ntype, label, **kw):
        if nid not in nodes:
            nodes[nid] = {"id": nid, "type": ntype, "label": label, **kw}
        else:
            nodes[nid].update({k: v for k, v in kw.items() if v})
        return nid

    def edge(src, dst, label, kind="observed"):
        eid = f"{src}->{dst}"
        if eid not in edges:
            edges[eid] = {"id": eid, "source": src, "target": dst, "label": label, "kind": kind}

    for inc in incidents:
        iid = node(f"incident:{inc.id}", "incident", inc.id, severity=inc.severity, title=inc.title, status=inc.status)
        analyses = db.scalars(select(Analysis).where(Analysis.incident_id == inc.id)).all()
        analysis_values: set[tuple[str, str]] = set()
        for a in analyses:
            aid = node(f"analysis:{a.id}", a.kind, a.title[:40], severity=a.severity, ref=a.id)
            edge(iid, aid, "evidence")
            for ind in db.scalars(select(Indicator).where(Indicator.analysis_id == a.id)).all():
                if ind.type == "filename" and ind.role == "attachment":
                    continue
                analysis_values.add((ind.type, ind.value.lower()))
                nid = node(f"{ind.type}:{ind.value.lower()}", ind.type, ind.value[:48], malicious=ind.malicious)
                edge(aid, nid, ind.role.replace("_", " "))
        for ev in db.scalars(select(EndpointEvent).where(EndpointEvent.incident_id == inc.id)).all():
            dv = ev.device
            did = node(f"device:{dv.hostname.lower()}", "device", dv.hostname, status=dv.status, simulated=dv.source == "simulated")
            eid = node(f"event:{ev.id}", "endpoint_event", ev.title[:40], severity=ev.severity, simulated=ev.simulated)
            edge(did, eid, "reported")
            ev_inds = db.scalars(select(Indicator).where(Indicator.endpoint_event_id == ev.id)).all()
            shares = False
            for ind in ev_inds:
                if ind.type == "device":
                    continue
                key = (ind.type, ind.value.lower())
                nid = node(f"{ind.type}:{ind.value.lower()}", ind.type, ind.value[:48], malicious=ind.malicious)
                if ind.role == "device_owner":
                    edge(did, nid, "owned by")
                    continue
                if key in analysis_values:
                    shares = True
                edge(eid, nid, ind.role.replace("_", " "))
            edge(iid, eid, "observed link" if shares else "inferred link", "observed" if shares else "inferred")
    return {"nodes": list(nodes.values()), "edges": list(edges.values()),
            "legend": {"observed": "Relationship directly present in submitted evidence or endpoint telemetry",
                       "inferred": "Relationship inferred by WOLVE (e.g. same person, no shared artefact)"}}
