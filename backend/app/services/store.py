"""Persistence helpers: settings, audit logging, saving analyses, incident lifecycle."""
from __future__ import annotations

import json
import re
from pathlib import PurePath

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..models import (AppSetting, Analysis, AuditLog, BlockedIndicator, Incident, IncidentEvent, Indicator, Organization, utcnow)
from .pipeline import AnalysisResult, Context
from .risk import SEVERITY_ORDER

AUTO_INCIDENT_THRESHOLD = 60

SOURCE_BY_KIND = {"email": "Email Security", "message": "Scam Analyzer", "url": "Network Intelligence", "domain": "Network Intelligence",
                  "ip": "Network Intelligence", "phone": "Scam Analyzer", "file": "File Forensics", "image": "File Forensics",
                  "audio": "Multimedia Forensics", "video": "Multimedia Forensics", "call": "Call Guard"}

DEFAULT_SETTINGS = {
    "ai_enabled": json.dumps(settings.ai_enabled_default),
    "external_lookups": json.dumps(settings.external_lookups_default),
    "auto_incident_threshold": json.dumps(AUTO_INCIDENT_THRESHOLD),
    "language": json.dumps("en"),
    "external_lookups_consent": json.dumps(None),
}


def get_setting(db: Session, key: str):
    row = db.get(AppSetting, key)
    raw = row.value if row else DEFAULT_SETTINGS.get(key, "null")
    return json.loads(raw)


def set_setting(db: Session, key: str, value) -> None:
    row = db.get(AppSetting, key)
    if row:
        row.value = json.dumps(value)
    else:
        db.add(AppSetting(key=key, value=json.dumps(value)))


def audit(db: Session, actor: str, action: str, target: str = "", details: dict | None = None, ip: str | None = None) -> None:
    db.add(AuditLog(actor=actor, action=action, target=target[:500], details=details or {}, ip=ip))


EXTERNAL_PROVIDERS = [
    {"name": "ip-api.com", "purpose": "Approximate IP origin (country, city, network owner, proxy/hosting flags)",
     "sends": "Public IP addresses only — never private/LAN addresses, file contents, emails or user names",
     "transport": "HTTP (free tier does not offer HTTPS), so the queried IPs can be observed on the network path",
     "limits": "Free tier: 45 single / 15 batch requests per minute; location is approximate (network operator, not a person)"},
    {"name": "System DNS resolver", "purpose": "Check that domains in analysed links exist (A/AAAA/MX/NS/TXT records)",
     "sends": "Domain names found in submitted links", "transport": "Your configured DNS server", "limits": "Results reflect the resolver's view"},
]


def external_lookups_enabled(db: Session) -> bool:
    """External lookups run only when switched on AND an administrator has recorded consent."""
    return bool(get_setting(db, "external_lookups")) and bool(get_setting(db, "external_lookups_consent"))


def build_context(db: Session) -> Context:
    org = db.scalars(select(Organization)).first()
    blocked = db.scalars(select(BlockedIndicator)).all()
    return Context(
        org_domain=org.domain if org else None,
        blocked_domains={b.value for b in blocked if b.type == "domain"},
        blocked_urls={b.value for b in blocked if b.type == "url"},
        blocked_ips={b.value for b in blocked if b.type == "ip"},
        blocked_phones={b.value for b in blocked if b.type == "phone"},
        known_bad_hashes={b.value: b.reason or "blocked by analyst" for b in blocked if b.type == "hash"},
        ai_enabled=bool(get_setting(db, "ai_enabled")),
        external_lookups=external_lookups_enabled(db),
    )


def safe_filename(name: str) -> str:
    base = PurePath(name or "file").name
    base = re.sub(r"[^A-Za-z0-9._-]", "_", base)[:120]
    return base or "file"


def save_result(db: Session, res: AnalysisResult, actor: str, *, demo: bool = False, auto_incident: bool = True) -> Analysis:
    rep = res.report
    a = Analysis(kind=res.kind, title=res.title[:400], classification=rep["classification"], risk_score=rep["risk_score"],
                 severity=rep["severity"], confidence=rep["confidence"], report=rep, submitted_by=actor,
                 recipient=res.recipient, sha256=res.sha256, demo=demo,
                 status="suspicious" if rep["risk_score"] >= 30 and res.kind == "email" else "new")
    db.add(a)
    db.flush()
    # Store suspicious file bytes in quarantine (never executed; name neutralised with .quarantined suffix).
    if res.file_bytes is not None and rep["risk_score"] >= 30:
        qpath = settings.upload_dir / "quarantine" / f"{a.id}_{safe_filename(res.filename or 'file')}.quarantined"
        qpath.write_bytes(res.file_bytes)
        a.stored_path = str(qpath)
    seen = set()
    for t, v, role, mal in res.indicators:
        key = (t, v.lower(), role)
        if not v or key in seen:
            continue
        seen.add(key)
        db.add(Indicator(type=t, value=v.lower() if t in ("email", "domain", "hash") else v, analysis_id=a.id, role=role, malicious=mal))
    audit(db, actor, f"analysis.{res.kind}", a.id, {"risk_score": a.risk_score, "classification": a.classification})
    threshold = int(get_setting(db, "auto_incident_threshold") or AUTO_INCIDENT_THRESHOLD)
    if auto_incident and a.risk_score >= threshold:
        create_incident_from_analysis(db, a, actor="system")
    db.flush()
    return a


def add_event(db: Session, inc: Incident, event_type: str, message: str, actor: str = "system", data: dict | None = None) -> None:
    db.add(IncidentEvent(incident_id=inc.id, event_type=event_type, message=message, actor=actor, data=data or {}))
    inc.updated_at = utcnow()


def max_sev(a: str, b: str) -> str:
    return a if SEVERITY_ORDER.index(a) >= SEVERITY_ORDER.index(b) else b


def create_incident_from_analysis(db: Session, a: Analysis, actor: str = "system") -> Incident:
    rep = a.report
    ai_text = ((rep.get("ai") or {}).get("assessment") or {}).get("summary")
    inc = Incident(
        title=f"{rep['classification']}: {a.title[:200]}", severity=a.severity, source=SOURCE_BY_KIND.get(a.kind, "WOLVE"),
        risk_score=a.risk_score, demo=a.demo,
        summary="; ".join(f["title"] for f in rep["findings"][:6]),
        ai_explanation=ai_text, recommended_response=rep.get("recommended_actions", []),
    )
    db.add(inc)
    db.flush()
    a.incident_id = inc.id
    add_event(db, inc, "created", f"Incident created automatically from {a.kind} analysis {a.id} (risk {a.risk_score}/100, {a.severity}).", actor,
              {"analysis_id": a.id})
    for f in rep["findings"][:8]:
        if f["weight"] > 0:
            add_event(db, inc, "evidence", f"[{f['source']}] {f['title']}" + (f" — {f['evidence']}" if f.get("evidence") else ""), "system")
    audit(db, actor, "incident.create", inc.id, {"from_analysis": a.id})
    return inc
