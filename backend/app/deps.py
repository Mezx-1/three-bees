"""Request dependencies: identity, role checks, rate limiting, serializers.

Identity: users sign in with a password and receive a bearer session token (services/auth.py).
The legacy `X-WOLVE-User` header works only when WOLVE_DEV_HEADER_AUTH=true (automated tests).
Endpoint agents authenticate with a per-device token (`X-Device-Token`)."""
from __future__ import annotations

import time
from datetime import datetime, timezone
from collections import defaultdict, deque

from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import settings
from .db import get_db
from .models import Analysis, Device, EndpointEvent, Incident, User

ROLE_RANK = {"employee": 0, "analyst": 1, "admin": 2}


def resolve_user(db: Session, authorization: str | None, x_wolve_user: str | None) -> User | None:
    """Bearer session token (real login). The X-WOLVE-User header is honoured only in dev/test mode."""
    from .services.auth import user_for_token

    if authorization and authorization.lower().startswith("bearer "):
        return user_for_token(db, authorization[7:].strip())
    if settings.dev_header_auth and x_wolve_user:
        return db.scalars(select(User).where(User.username == x_wolve_user)).first()
    return None


def current_user(authorization: str | None = Header(default=None), x_wolve_user: str | None = Header(default=None),
                 db: Session = Depends(get_db)) -> User:
    user = resolve_user(db, authorization, x_wolve_user)
    if not user:
        raise HTTPException(401, "Please sign in.")
    return user


def require(role: str):
    def dep(user: User = Depends(current_user)) -> User:
        if ROLE_RANK.get(user.role, -1) < ROLE_RANK[role]:
            raise HTTPException(403, f"This action requires the '{role}' role (you are '{user.role}').")
        return user

    return dep


_hits: dict[str, deque] = defaultdict(deque)


def rate_limit(request: Request) -> None:
    key = request.client.host if request.client else "unknown"
    now = time.monotonic()
    q = _hits[key]
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= settings.rate_limit_per_minute:
        raise HTTPException(429, "Rate limit exceeded — please wait a minute.")
    q.append(now)


def iso(dt):
    """ISO-8601 with an explicit UTC offset. SQLite returns naive datetimes (stored as UTC);
    without the offset browsers would read them as local time (e.g. 4h off in the UAE)."""
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def ser_analysis(a: Analysis, full: bool = False) -> dict:
    d = {"id": a.id, "kind": a.kind, "title": a.title, "classification": a.classification, "risk_score": a.risk_score,
         "severity": a.severity, "confidence": a.confidence, "status": a.status, "submitted_by": a.submitted_by,
         "recipient": a.recipient, "incident_id": a.incident_id, "demo": a.demo, "quarantined_file": bool(a.stored_path),
         "created_at": iso(a.created_at)}
    if a.kind == "email":
        em = (a.report or {}).get("email", {})
        d["from"] = em.get("from_address")
        d["from_name"] = em.get("from_name")
    if full:
        d["report"] = a.report
    return d


def ser_incident(i: Incident, full: bool = False) -> dict:
    d = {"id": i.id, "title": i.title, "severity": i.severity, "status": i.status, "source": i.source, "risk_score": i.risk_score,
         "assigned_to": i.assigned_to, "escalated": i.escalated, "correlated": i.correlated, "demo": i.demo,
         "created_at": iso(i.created_at), "updated_at": iso(i.updated_at), "summary": i.summary}
    if full:
        d.update({"ai_explanation": i.ai_explanation, "recommended_response": i.recommended_response,
                  "timeline": [{"id": e.id, "type": e.event_type, "message": e.message, "actor": e.actor, "data": e.data, "created_at": iso(e.created_at)} for e in i.events]})
    return d


def ser_device(dv: Device) -> dict:
    return {"id": dv.id, "hostname": dv.hostname, "os": dv.os, "owner_email": dv.owner_email, "ip_address": dv.ip_address,
            "agent_version": dv.agent_version, "source": dv.source, "status": dv.status, "risk_score": dv.risk_score,
            "last_seen": iso(dv.last_seen), "system_info": dv.system_info, "created_at": iso(dv.created_at),
            "online": _online(dv)}


def _online(dv: Device) -> bool:
    if dv.source != "agent" or not dv.last_seen:
        return False
    ls = dv.last_seen if dv.last_seen.tzinfo else dv.last_seen.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - ls).total_seconds() < 90


def ser_event(e: EndpointEvent) -> dict:
    return {"id": e.id, "device_id": e.device_id, "event_type": e.event_type, "severity": e.severity, "title": e.title, "details": e.details,
            "simulated": e.simulated, "risk_score": e.risk_score, "findings": e.findings, "incident_id": e.incident_id, "created_at": iso(e.created_at)}
