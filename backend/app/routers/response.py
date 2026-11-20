"""Prevention & Response Center: blocklist, indicator review, response action log, audit log."""
from __future__ import annotations

import ipaddress

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import current_user, iso, require
from ..models import AuditLog, BlockedIndicator, Indicator, ResponseAction, User
from ..services.store import audit
from ..services.url_analyzer import normalize_url, registered_domain, urlsplit

router = APIRouter(prefix="/api", tags=["response"])


class BlockIn(BaseModel):
    type: str = Field(pattern="^(domain|url|ip|hash|phone)$")
    value: str = Field(min_length=3, max_length=1000)
    reason: str = Field(default="", max_length=500)


def _normalize(t: str, v: str) -> str:
    v = v.strip()
    if t == "ip":
        try:
            return str(ipaddress.ip_address(v))
        except ValueError:
            raise HTTPException(422, "Invalid IP address")
    if t == "domain":
        host = urlsplit(normalize_url(v)).hostname or ""
        if "." not in host:
            raise HTTPException(422, "Invalid domain")
        return registered_domain(host)
    if t == "url":
        return normalize_url(v)
    if t == "phone":
        from ..services.network_intel import analyze_phone

        try:
            return analyze_phone(v)[1]["normalized"]
        except ValueError as exc:
            raise HTTPException(422, str(exc))
    if t == "hash":
        v = v.lower()
        if len(v) != 64 or any(c not in "0123456789abcdef" for c in v):
            raise HTTPException(422, "Hash must be a SHA-256 hex digest")
        return v
    return v


@router.get("/blocklist")
def list_blocklist(db: Session = Depends(get_db), user: User = Depends(current_user)):
    return [{"id": b.id, "type": b.type, "value": b.value, "reason": b.reason, "added_by": b.added_by, "created_at": iso(b.created_at)}
            for b in db.scalars(select(BlockedIndicator).order_by(BlockedIndicator.created_at.desc())).all()]


@router.post("/blocklist")
def add_block(body: BlockIn, db: Session = Depends(get_db), user: User = Depends(require("analyst"))):
    value = _normalize(body.type, body.value)
    if db.scalars(select(BlockedIndicator).where(BlockedIndicator.type == body.type, BlockedIndicator.value == value)).first():
        raise HTTPException(409, f"{body.type} '{value}' is already blocked")
    b = BlockedIndicator(type=body.type, value=value, reason=body.reason, added_by=user.username)
    db.add(b)
    for ind in db.scalars(select(Indicator).where(Indicator.type == body.type, Indicator.value == value)).all():
        ind.malicious = True
    msg = f"Blocked {body.type} {value} in the 3B demo environment. Future analyses and endpoint events matching it are flagged. Not pushed to any firewall, proxy or mail gateway."
    db.add(ResponseAction(action=f"block.{body.type}", target_type=body.type, target_id=value, actor=user.username, simulated=True, result=msg))
    audit(db, user.username, "blocklist.add", value, {"type": body.type, "reason": body.reason})
    db.commit()
    return {"ok": True, "message": msg, "id": b.id, "value": value}


@router.delete("/blocklist/{bid}")
def remove_block(bid: int, db: Session = Depends(get_db), user: User = Depends(require("analyst"))):
    b = db.get(BlockedIndicator, bid)
    if not b:
        raise HTTPException(404, "Not found")
    audit(db, user.username, "blocklist.remove", b.value, {"type": b.type})
    db.delete(b)
    db.commit()
    return {"ok": True}


@router.get("/indicators")
def list_indicators(malicious: bool | None = None, reviewed: bool | None = None, type: str | None = None,
                    db: Session = Depends(get_db), user: User = Depends(current_user)):
    stmt = select(Indicator.type, Indicator.value, func.max(Indicator.malicious), func.min(Indicator.reviewed), func.count(Indicator.id),
                  func.max(Indicator.created_at)).group_by(Indicator.type, Indicator.value)
    if type:
        stmt = stmt.where(Indicator.type == type)
    stmt = stmt.where(Indicator.type.not_in(["device", "filename"]))
    rows = db.execute(stmt.order_by(func.max(Indicator.created_at).desc()).limit(500)).all()
    blocked = {(b.type, b.value) for b in db.scalars(select(BlockedIndicator)).all()}
    out = []
    for t, v, mal, rev, cnt, last in rows:
        if malicious is not None and bool(mal) != malicious:
            continue
        if reviewed is not None and bool(rev) != reviewed:
            continue
        out.append({"type": t, "value": v, "malicious": bool(mal), "reviewed": bool(rev), "sightings": cnt, "last_seen": iso(last),
                    "blocked": (t, v) in blocked})
    return out


class ReviewIn(BaseModel):
    type: str
    value: str
    verdict: str = Field(pattern="^(malicious|benign)$")


@router.post("/indicators/review")
def review_indicator(body: ReviewIn, db: Session = Depends(get_db), user: User = Depends(require("analyst"))):
    rows = db.scalars(select(Indicator).where(Indicator.type == body.type, Indicator.value == body.value)).all()
    if not rows:
        raise HTTPException(404, "Indicator not found")
    for r in rows:
        r.reviewed = True
        r.malicious = body.verdict == "malicious"
    audit(db, user.username, "indicator.review", f"{body.type}:{body.value}", {"verdict": body.verdict})
    db.commit()
    return {"ok": True, "updated": len(rows)}


@router.get("/actions")
def list_actions(db: Session = Depends(get_db), user: User = Depends(current_user)):
    return [{"id": a.id, "action": a.action, "target_type": a.target_type, "target_id": a.target_id, "actor": a.actor, "simulated": a.simulated,
             "result": a.result, "created_at": iso(a.created_at)} for a in db.scalars(select(ResponseAction).order_by(ResponseAction.created_at.desc()).limit(300)).all()]


@router.get("/audit")
def list_audit(limit: int = 300, actor: str | None = None, db: Session = Depends(get_db), user: User = Depends(require("analyst"))):
    stmt = select(AuditLog).order_by(AuditLog.created_at.desc())
    if actor:
        stmt = stmt.where(AuditLog.actor == actor)
    return [{"id": a.id, "actor": a.actor, "action": a.action, "target": a.target, "details": a.details, "created_at": iso(a.created_at)}
            for a in db.scalars(stmt.limit(min(limit, 1000))).all()]
