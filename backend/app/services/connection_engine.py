"""Live connection monitoring: IP origin enrichment, connection risk scoring, posture checks.

Origin data (country/city/network owner) is approximate and comes from ip-api.com when external
lookups are enabled; results are cached for 24 h and always carry their source and timestamp.
"""
from __future__ import annotations

import ipaddress
import re
from datetime import timedelta

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import BlockedIndicator, Connection, Device, Indicator, IpIntel, utcnow
from .risk import Finding, combine

SCRIPT_HOSTS = {"wscript.exe", "cscript.exe", "powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe", "rundll32.exe",
                "regsvr32.exe", "certutil.exe", "bitsadmin.exe"}
C2_PORTS = {4444, 1337, 6667, 8081, 9001, 31337, 5555, 2222}
COMMON_INBOUND = {80, 443, 22, 3389, 445, 139, 135, 5040, 7680}
GEO_FIELDS = "status,message,country,countryCode,regionName,city,lat,lon,isp,org,as,asname,proxy,hosting,mobile,query"
CACHE_TTL = timedelta(hours=24)


def _ip_kind(ip: str) -> str:
    try:
        o = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return "invalid"
    if o.is_private or o.is_link_local:
        return "private"
    if not o.is_global:
        return "reserved"
    return "public"


def enrich_ips(db: Session, ips: set[str], external: bool) -> dict[str, dict]:
    """Returns ip -> origin dict. Private IPs are labelled locally; public ones via cache / ip-api batch."""
    out: dict[str, dict] = {}
    need: list[str] = []
    now = utcnow()
    for ip in ips:
        kind = _ip_kind(ip)
        if kind != "public":
            out[ip] = {"scope": kind, "label": "Local network" if kind == "private" else "Special-purpose address"}
            continue
        row = db.get(IpIntel, ip)
        fetched = row.fetched_at.replace(tzinfo=now.tzinfo) if row and row.fetched_at.tzinfo is None else (row.fetched_at if row else None)
        if row and fetched and now - fetched < CACHE_TTL:
            out[ip] = {**row.data, "scope": "public", "source": row.source, "fetched_at": fetched.isoformat()}
        else:
            need.append(ip)
    if need and external:
        for i in range(0, min(len(need), 300), 100):
            chunk = need[i:i + 100]
            try:
                r = httpx.post(f"http://ip-api.com/batch?fields={GEO_FIELDS}", json=chunk, timeout=6.0)
                results = r.json() if r.status_code == 200 else []
            except Exception:
                results = []
            for ip, res in zip(chunk, results):
                if not isinstance(res, dict) or res.get("status") != "success":
                    continue
                data = {k: res.get(k) for k in ("country", "countryCode", "regionName", "city", "lat", "lon", "isp", "org", "as", "asname", "proxy", "hosting", "mobile")}
                row = db.get(IpIntel, ip)
                if row:
                    row.data, row.fetched_at, row.source = data, now, "ip-api.com"
                else:
                    db.add(IpIntel(ip=ip, data=data, source="ip-api.com", fetched_at=now))
                out[ip] = {**data, "scope": "public", "source": "ip-api.com", "fetched_at": now.isoformat()}
    for ip in need:
        out.setdefault(ip, {"scope": "public", "label": "Origin unknown" + ("" if external else " (external lookups off)")})
    return out


def score_connection(c: dict, origin: dict, blocked_ips: set[str], malicious_ips: set[str]) -> list[Finding]:
    f: list[Finding] = []
    rip, rport = c.get("remote_ip"), c.get("remote_port")
    proc = (c.get("process_name") or "").lower()
    exe = (c.get("exe") or "").lower()
    public = origin.get("scope") == "public"
    if rip in blocked_ips:
        f.append(Finding("Connection to a blocked IP", f"{proc or 'A process'} is talking to {rip}, which is on the WOLVE blocklist.",
                         "network", "critical", 70, "verified", ["suspicious_infrastructure"], evidence=rip))
    elif rip in malicious_ips:
        f.append(Finding("Connection to an IP flagged in an investigation", f"{rip} was flagged malicious in a WOLVE analysis or incident.",
                         "network", "high", 50, "verified", ["suspicious_infrastructure"], evidence=rip))
    if proc in SCRIPT_HOSTS and public and c.get("direction") == "outbound":
        f.append(Finding("Script interpreter connecting to the internet", f"{proc} opened a connection to {rip}:{rport}. Scripts downloading code is a common malware step.",
                         "network", "high", 34, "verified", ["malware_delivery"], evidence=f"{proc} → {rip}:{rport}"))
    if re.search(r"\\(temp|appdata\\local\\temp|downloads)\\", exe) and public:
        f.append(Finding("Program from Temp/Downloads using the network", "Programs running from temporary or download folders are often freshly delivered malware.",
                         "network", "medium", 18, "verified", ["malware_delivery"], evidence=c.get("exe")))
    if rport in C2_PORTS and public:
        f.append(Finding("Port often used by backdoors", f"Remote port {rport} is commonly used by remote-access tools and malware.",
                         "network", "high", 30, "heuristic", ["suspicious_infrastructure"], evidence=str(rport)))
    if origin.get("proxy"):
        f.append(Finding("Remote side is a proxy/VPN/Tor exit", "The network owner is flagged as an anonymising service.",
                         "network", "medium", 15, "intel", ["suspicious_infrastructure"], evidence=f"{origin.get('source')} · {origin.get('isp')}"))
    if c.get("direction") == "inbound" and public and c.get("local_port") not in COMMON_INBOUND:
        f.append(Finding("Inbound connection from the internet", f"{rip} connected in to local port {c.get('local_port')} ({proc or 'unknown program'}).",
                         "network", "medium", 16, "verified", ["suspicious_infrastructure"], evidence=f"{rip} → :{c.get('local_port')}"))
    return f


def ingest_connections(db: Session, device: Device, conns: list[dict], listening: list[dict], external: bool, actor: str) -> dict:
    from .endpoint_engine import ingest_event

    now = utcnow()
    blocked_ips = {b.value for b in db.scalars(select(BlockedIndicator).where(BlockedIndicator.type == "ip")).all()}
    malicious_ips = {i.value for i in db.scalars(select(Indicator).where(Indicator.type == "ip", Indicator.malicious.is_(True))).all()}
    origins = enrich_ips(db, {c["remote_ip"] for c in conns if c.get("remote_ip")}, external)
    existing = {(r.process_name, r.remote_ip, r.remote_port, r.direction, r.local_port if r.direction == "inbound" else 0): r
                for r in db.scalars(select(Connection).where(Connection.device_id == device.id)).all()}
    seen_keys = set()
    new = flagged = 0
    events = []
    for c in conns:
        key = (c.get("process_name"), c.get("remote_ip"), c.get("remote_port"), c.get("direction"), c.get("local_port") if c.get("direction") == "inbound" else 0)
        seen_keys.add(key)
        origin = origins.get(c["remote_ip"], {})
        findings = score_connection(c, origin, blocked_ips, malicious_ips)
        score = combine(findings)
        row = existing.get(key)
        if row is None:
            row = Connection(device_id=device.id, process_name=c.get("process_name"), exe=c.get("exe"), pid=c.get("pid"),
                             protocol=c.get("protocol", "tcp"), direction=c.get("direction", "outbound"), local_port=c.get("local_port"),
                             remote_ip=c["remote_ip"], remote_port=c.get("remote_port"), first_seen=now)
            db.add(row)
            existing[key] = row
            new += 1
        else:
            row.hits += 1
        row.status, row.active, row.last_seen, row.pid = c.get("status", ""), True, now, c.get("pid")
        row.risk_score, row.flags = score, [x.to_dict() for x in findings]
        if score >= 30:
            flagged += 1
        if score >= 40 and not row.event_created:
            row.event_created = True
            events.append((row, origin))
    for key, row in existing.items():
        if key not in seen_keys and row.active:
            row.active = False
    db.flush()
    for row, origin in events[:20]:
        place = ", ".join(x for x in (origin.get("city"), origin.get("country")) if x)
        ingest_event(db, device, "network_connection",
                     f"{row.process_name or 'Unknown program'} → {row.remote_ip}:{row.remote_port}" + (f" ({place})" if place else ""),
                     {"process_name": (row.process_name or "").lower(), "dest_ip": row.remote_ip, "dest_port": row.remote_port,
                      "direction": row.direction, "remote_country": origin.get("country"), "remote_org": origin.get("org") or origin.get("isp"),
                      "source": "live agent telemetry"},
                     simulated=False, actor=actor)
    info = dict(device.system_info or {})
    info["listening_ports"] = listening[:200]
    info["connections_updated_at"] = now.isoformat()
    device.system_info = info
    return {"new": new, "flagged": flagged, "active": len(conns), "events": len(events)}


def posture_findings(p: dict) -> list[Finding]:
    f: list[Finding] = []
    for prof, state in (p.get("firewall") or {}).items():
        if state == "off":
            f.append(Finding(f"Windows Firewall is off ({prof} profile)", "The firewall is disabled for this network profile, so inbound attacks are not filtered.",
                             "endpoint", "high", 35, "verified", ["suspicious_infrastructure"], evidence=f"{prof}=off"))
    d = p.get("defender") or {}
    if d.get("realtime") is False:
        f.append(Finding("Defender real-time protection is off", "Malware will not be blocked when files are opened.", "endpoint", "high", 40, "verified", ["malware_delivery"]))
    if d.get("antivirus") is False:
        f.append(Finding("Antivirus is disabled", "Microsoft Defender antivirus reports as disabled.", "endpoint", "high", 35, "verified", ["malware_delivery"]))
    age = d.get("signature_age_days")
    if isinstance(age, int) and age > 7:
        f.append(Finding("Antivirus signatures are out of date", f"Signatures are {age} days old.", "endpoint", "medium", 18, "verified", ["malware_delivery"]))
    return f


def device_summary(db: Session, device: Device) -> dict:
    rows = db.scalars(select(Connection).where(Connection.device_id == device.id, Connection.active.is_(True))).all()
    origins = enrich_ips(db, {r.remote_ip for r in rows}, external=False)  # cache only — no new lookups here
    countries: dict[str, dict] = {}
    orgs: dict[str, int] = {}
    procs: dict[str, int] = {}
    points: dict[tuple, dict] = {}
    for r in rows:
        o = origins.get(r.remote_ip, {})
        cname = o.get("country") or (o.get("label") or "Unknown")
        cc = countries.setdefault(cname, {"country": cname, "code": o.get("countryCode"), "count": 0, "flagged": 0})
        cc["count"] += 1
        cc["flagged"] += 1 if r.risk_score >= 30 else 0
        org = o.get("org") or o.get("isp") or o.get("label") or "Unknown"
        orgs[org] = orgs.get(org, 0) + 1
        procs[r.process_name or "unknown"] = procs.get(r.process_name or "unknown", 0) + 1
        if o.get("lat") is not None:
            k = (round(o["lat"], 1), round(o["lon"], 1))
            pt = points.setdefault(k, {"lat": o["lat"], "lon": o["lon"], "city": o.get("city"), "country": o.get("country"), "count": 0, "max_risk": 0})
            pt["count"] += 1
            pt["max_risk"] = max(pt["max_risk"], r.risk_score)
    return {
        "active_connections": len(rows),
        "inbound": sum(1 for r in rows if r.direction == "inbound"), "outbound": sum(1 for r in rows if r.direction == "outbound"),
        "flagged": sum(1 for r in rows if r.risk_score >= 30),
        "countries": sorted(countries.values(), key=lambda x: -x["count"]),
        "top_orgs": [{"org": k, "count": v} for k, v in sorted(orgs.items(), key=lambda kv: -kv[1])[:8]],
        "top_processes": [{"process": k, "count": v} for k, v in sorted(procs.items(), key=lambda kv: -kv[1])[:8]],
        "points": list(points.values()),
    }
