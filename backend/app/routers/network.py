"""Collective protection network API: shared indicators, sync, appeals, protection settings, campaigns, stats.

Authorisation is enforced here on the server: indicator values, reasons, evidence references and appeals are
visible to analysts only. Ordinary users and devices get statuses and hashes, never other people's reports.
"""
from __future__ import annotations

from collections import Counter

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import current_user, iso, rate_limit, require, resolve_user
from ..models import (Device, IndicatorAppeal, IndicatorEvent, PhoneIntel, PhoneReport, ProtectionEvent, ProtectionPrefs, ScamReport,
                      ThreatIndicator, User, UserListEntry)
from ..services import collective, report_links
from ..services.store import audit

router = APIRouter(prefix="/api/network", tags=["network"])


def _ind(i: ThreatIndicator, full: bool = True) -> dict:
    d = {"id": i.id, "type": i.type, "value": i.value if full else collective.mask(i.type, i.value), "status": i.status, "category": i.category,
         "confidence": i.confidence, "distinct_reporters": len(set(i.reporter_keys or [])), "report_count": i.report_count,
         "data_mode": i.data_mode, "first_seen": iso(i.first_seen), "last_seen": iso(i.last_seen), "review_due": iso(i.review_due), "version": i.version}
    if full:
        d["reasons"] = i.reasons or []
        d["evidence_refs"] = (i.evidence_refs or [])[:20]
    return d


# ---------------------------------------------------------------- sync for devices / browsers

def _client(db: Session, x_device_token: str | None, authorization: str | None, x_3b_user: str | None) -> str:
    if x_device_token and db.scalars(select(Device).where(Device.token == x_device_token)).first():
        return "device"
    if resolve_user(db, authorization, x_3b_user):
        return "user"
    raise HTTPException(401, "Sign in or use a paired device token.")


@router.get("/sync", dependencies=[Depends(rate_limit)])
def sync(since: int = Query(0, ge=0), limit: int = Query(500, ge=1, le=2000), include_demo: bool = False, db: Session = Depends(get_db),
         x_device_token: str | None = Header(default=None), authorization: str | None = Header(default=None), x_3b_user: str | None = Header(default=None)):
    _client(db, x_device_token, authorization, x_3b_user)
    return collective.sync(db, since, limit, include_demo)


@router.post("/check", dependencies=[Depends(rate_limit)])
def check(body: dict = Body(...), db: Session = Depends(get_db), user: User = Depends(current_user)):
    """Is this number / email / domain / link on the shared list? Returns the status, never who reported it."""
    t, v = body.get("type"), body.get("value", "")
    try:
        nv = collective.normalize(t, v)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    trusted = db.scalars(select(UserListEntry).where(UserListEntry.user_id == user.id, UserListEntry.list == "trusted",
                                                     UserListEntry.type == t, UserListEntry.value == nv)).first()
    blocked = db.scalars(select(UserListEntry).where(UserListEntry.user_id == user.id, UserListEntry.list == "blocked",
                                                     UserListEntry.type == t, UserListEntry.value == nv)).first()
    rows = db.scalars(select(ThreatIndicator).where(ThreatIndicator.type == t, ThreatIndicator.value == nv)).all()
    best = max(rows, key=lambda i: ["allowlisted", "revoked", "reported", "suspicious", "verified"].index(i.status) if i.status != "allowlisted" else 5, default=None)
    status = best.status if best else "not_listed"
    level = {"verified": "block", "suspicious": "warn"}.get(status, "none")
    if trusted:
        level, status = "none", "trusted_by_you"
    elif blocked:
        level = "block"
    return {"type": t, "value": collective.mask(t, nv), "status": status, "level": level, "category": best.category if best else None,
            "distinct_reporters": len(set(best.reporter_keys or [])) if best else 0, "demo": bool(best and best.data_mode == "demo"),
            "note": "Not listed doesn't mean safe. A report is not proof." if status in ("not_listed", "reported") else ""}


# ---------------------------------------------------------------- analyst: indicators

@router.get("/indicators")
def indicators(status: str | None = None, type: str | None = None, mode: str = "user", q: str | None = None,
               db: Session = Depends(get_db), user: User = Depends(require("analyst"))):
    collective.expire_stale(db)
    stmt = select(ThreatIndicator).where(ThreatIndicator.data_mode == mode).order_by(ThreatIndicator.last_seen.desc())
    if status:
        stmt = stmt.where(ThreatIndicator.status.in_(status.split(",")))
    if type:
        stmt = stmt.where(ThreatIndicator.type == type)
    if q:
        stmt = stmt.where(ThreatIndicator.value.ilike(f"%{q}%"))
    return [_ind(i) for i in db.scalars(stmt.limit(500)).all()]


@router.post("/indicators")
def add_indicator(body: dict = Body(...), db: Session = Depends(get_db), user: User = Depends(require("analyst"))):
    t, v, st = body.get("type"), body.get("value", ""), body.get("status", "suspicious")
    if st not in ("reported", "suspicious", "verified", "allowlisted"):
        raise HTTPException(422, "Unknown status")
    reason = (body.get("reason") or "").strip()
    if st in ("verified", "allowlisted") and len(reason) < 10:
        raise HTTPException(422, "Explain the evidence (at least a sentence) when verifying or allow-listing.")
    try:
        ind = collective.get_or_create(db, t, v, category=body.get("category", "other"), by=user.username)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    collective.set_status(db, ind, st, user.username, reason or "Added by analyst")
    audit(db, user.username, "network.indicator_add", f"{t}:{ind.value}", {"status": st})
    db.commit()
    return _ind(ind)


@router.get("/indicators/{iid}")
def indicator(iid: int, db: Session = Depends(get_db), user: User = Depends(require("analyst"))):
    i = db.get(ThreatIndicator, iid)
    if not i:
        raise HTTPException(404, "Not found")
    ev = db.scalars(select(IndicatorEvent).where(IndicatorEvent.indicator_id == iid).order_by(IndicatorEvent.id.desc()).limit(100)).all()
    ap = db.scalars(select(IndicatorAppeal).where(IndicatorAppeal.indicator_id == iid).order_by(IndicatorAppeal.id.desc())).all()
    return {**_ind(i), "events": [{"version": e.id, "action": e.action, "from": e.from_status, "to": e.to_status, "by": e.by, "note": e.note, "at": iso(e.at)} for e in ev],
            "appeals": [{"id": a.id, "status": a.status, "reason": a.reason, "decision_note": a.decision_note, "created_at": iso(a.created_at)} for a in ap]}


@router.patch("/indicators/{iid}")
def update_indicator(iid: int, body: dict = Body(...), db: Session = Depends(get_db), user: User = Depends(require("analyst"))):
    i = db.get(ThreatIndicator, iid)
    if not i:
        raise HTTPException(404, "Not found")
    st, note = body.get("status"), (body.get("note") or "").strip()
    if st not in ("reported", "suspicious", "verified", "revoked", "allowlisted"):
        raise HTTPException(422, "Unknown status")
    if st in ("verified", "revoked", "allowlisted") and len(note) < 10:
        raise HTTPException(422, "Explain the evidence or reason (at least a sentence).")
    collective.set_status(db, i, st, user.username, note or f"Set to {st}")
    audit(db, user.username, "network.indicator_status", f"{i.type}:{i.value}", {"status": st})
    db.commit()
    return _ind(i)


# ---------------------------------------------------------------- appeals / false positives

@router.post("/appeals", dependencies=[Depends(rate_limit)])
def submit_appeal(body: dict = Body(...), db: Session = Depends(get_db), authorization: str | None = Header(default=None),
                  x_3b_user: str | None = Header(default=None)):
    user = resolve_user(db, authorization, x_3b_user)
    t, v, reason = body.get("type"), body.get("value", ""), (body.get("reason") or "").strip()
    if len(reason) < 10:
        raise HTTPException(422, "Please explain why this is a mistake (at least a sentence).")
    try:
        nv = collective.normalize(t, v)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    i = db.scalars(select(ThreatIndicator).where(ThreatIndicator.type == t, ThreatIndicator.value == nv, ThreatIndicator.data_mode == "user")).first()
    if not i or i.status in ("revoked", "allowlisted"):
        return {"ok": True, "listed": False, "message": "This is not on the shared list, so nothing is being blocked or warned about."}
    a = collective.appeal(db, i, reason, body.get("contact"), user.username if user else "anonymous")
    audit(db, user.username if user else "anonymous", "network.appeal", f"{t}:{collective.mask(t, nv)}")
    db.commit()
    return {"ok": True, "listed": True, "appeal_id": a.id,
            "message": "Thank you. An analyst will review it. While an unverified warning is under appeal it is paused for everyone."}


@router.get("/appeals")
def appeals(status: str = "open", db: Session = Depends(get_db), user: User = Depends(require("analyst"))):
    rows = db.scalars(select(IndicatorAppeal).where(IndicatorAppeal.status == status).order_by(IndicatorAppeal.id.desc()).limit(200)).all()
    out = []
    for a in rows:
        i = db.get(ThreatIndicator, a.indicator_id)
        out.append({"id": a.id, "status": a.status, "reason": a.reason, "contact": a.contact, "created_at": iso(a.created_at),
                    "indicator": _ind(i) if i else None})
    return out


@router.patch("/appeals/{aid}")
def decide(aid: int, body: dict = Body(...), db: Session = Depends(get_db), user: User = Depends(require("analyst"))):
    a = db.get(IndicatorAppeal, aid)
    if not a or a.status != "open":
        raise HTTPException(404, "Open appeal not found")
    note = (body.get("note") or "").strip()
    if len(note) < 5:
        raise HTTPException(422, "Add a short decision note.")
    collective.decide_appeal(db, a, bool(body.get("uphold")), note, user.username)
    audit(db, user.username, "network.appeal_" + a.status, str(aid))
    db.commit()
    return {"id": aid, "status": a.status}


# ---------------------------------------------------------------- personal protection settings

@router.get("/prefs")
def get_prefs(db: Session = Depends(get_db), user: User = Depends(current_user)):
    p = db.get(ProtectionPrefs, user.id)
    return {**collective.DEFAULT_PREFS, **(p.prefs if p else {})}


@router.put("/prefs")
def put_prefs(body: dict = Body(...), db: Session = Depends(get_db), user: User = Depends(current_user)):
    clean = {k: bool(v) for k, v in body.items() if k in collective.DEFAULT_PREFS}
    if clean.get("email_scanning"):
        clean["email_scanning"] = False  # needs a connected mailbox via OAuth — not available yet (see docs/COLLECTIVE_PROTECTION.md)
    p = db.get(ProtectionPrefs, user.id) or ProtectionPrefs(user_id=user.id, prefs={})
    p.prefs = {**(p.prefs or {}), **clean}
    db.merge(p)
    audit(db, user.username, "network.prefs", "", clean)
    db.commit()
    return {**collective.DEFAULT_PREFS, **p.prefs}


@router.get("/lists")
def get_lists(db: Session = Depends(get_db), user: User = Depends(current_user)):
    rows = db.scalars(select(UserListEntry).where(UserListEntry.user_id == user.id).order_by(UserListEntry.created_at.desc())).all()
    return [{"id": r.id, "list": r.list, "type": r.type, "value": r.value, "note": r.note, "created_at": iso(r.created_at)} for r in rows]


@router.post("/lists")
def add_list(body: dict = Body(...), db: Session = Depends(get_db), user: User = Depends(current_user)):
    lst, t = body.get("list"), body.get("type")
    if lst not in ("blocked", "trusted"):
        raise HTTPException(422, "list must be blocked or trusted")
    try:
        v = collective.normalize(t, body.get("value", ""))
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    db.query(UserListEntry).filter(UserListEntry.user_id == user.id, UserListEntry.type == t, UserListEntry.value == v).delete()
    e = UserListEntry(user_id=user.id, list=lst, type=t, value=v, note=(body.get("note") or "")[:200])
    db.add(e)
    db.commit()
    return {"id": e.id, "list": lst, "type": t, "value": v}


@router.delete("/lists/{eid}")
def del_list(eid: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    e = db.get(UserListEntry, eid)
    if not e or e.user_id != user.id:
        raise HTTPException(404, "Not found")
    db.delete(e)
    db.commit()
    return {"deleted": eid}


@router.get("/events")
def events(db: Session = Depends(get_db), user: User = Depends(current_user)):
    rows = db.scalars(select(ProtectionEvent).where(ProtectionEvent.user_id == user.id).order_by(ProtectionEvent.at.desc()).limit(100)).all()
    return [{"id": r.id, "kind": r.kind, "channel": r.channel, "indicator_type": r.indicator_type, "indicator": r.indicator_masked,
             "reason": r.reason, "at": iso(r.at)} for r in rows]


@router.post("/events")
def log_event(body: dict = Body(...), db: Session = Depends(get_db), user: User = Depends(current_user)):
    """A client (web check, phone app) records that it warned about or blocked something for this user."""
    t = body.get("indicator_type", "phone")
    try:
        v = collective.normalize(t, body.get("indicator", ""))
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    e = ProtectionEvent(user_id=user.id, kind=body.get("kind", "warned")[:20], channel=body.get("channel", "message")[:20], indicator_type=t,
                        indicator_masked=collective.mask(t, v), reason=(body.get("reason") or "")[:500])
    db.add(e)
    db.commit()
    return {"id": e.id}


# ---------------------------------------------------------------- investigators: campaigns + dashboard

@router.get("/campaigns")
def campaigns(mode: str = "user", db: Session = Depends(get_db), user: User = Depends(require("analyst"))):
    rs = db.scalars(select(ScamReport).where(ScamReport.data_mode == mode, ScamReport.status != "rejected")).all()
    g = report_links.graph(rs)
    for n in g["nodes"]:
        if "created_at" in n:
            n["created_at"] = iso(n["created_at"])
    for c in g["campaigns"]:
        c["first_seen"], c["last_seen"] = iso(c["first_seen"]), iso(c["last_seen"])
    g["demo"] = mode == "demo"
    return g


@router.get("/stats")
def stats(db: Session = Depends(get_db), user: User = Depends(current_user)):
    collective.expire_stale(db)

    def count(mode):
        rows = db.execute(select(ThreatIndicator.status, ThreatIndicator.type, func.count()).where(ThreatIndicator.data_mode == mode)
                          .group_by(ThreatIndicator.status, ThreatIndicator.type)).all()
        st, ty = Counter(), Counter()
        for s, t, n in rows:
            st[s] += n
            if s in ("suspicious", "verified"):
                ty[t] += n
        rs = db.scalars(select(ScamReport).where(ScamReport.data_mode == mode, ScamReport.status != "rejected")).all()
        camps = report_links.groups(rs)
        return {"verified": st["verified"], "suspicious_awaiting_review": st["suspicious"], "reported_only": st["reported"],
                "revoked": st["revoked"], "allowlisted": st["allowlisted"],
                "phones": ty["phone"], "emails": ty["email"] + ty["email_domain"], "domains": ty["domain"] + ty["url"],
                "campaigns": len(camps), "related_reports": sum(c["size"] for c in camps),
                "numbers_with_reports": db.scalar(select(func.count()).select_from(PhoneIntel).where(PhoneIntel.data_mode == mode, PhoneIntel.report_count > 0)) or 0,
                "phone_reports_pending": db.scalar(select(func.count()).select_from(PhoneReport).where(PhoneReport.data_mode == mode, PhoneReport.status == "pending")) or 0}

    return {"user": count("user"), "demo": count("demo"), "sync_version": collective.current_version(db),
            "open_appeals": db.scalar(select(func.count()).select_from(IndicatorAppeal).where(IndicatorAppeal.status == "open")) or 0,
            "my_protection_events": db.scalar(select(func.count()).select_from(ProtectionEvent).where(ProtectionEvent.user_id == user.id)) or 0,
            "note": "Counts come from the 3B database. 'user' is real submitted data; 'demo' is fictional and labelled DEMO."}


@router.post("/expire")
def expire(db: Session = Depends(get_db), user: User = Depends(require("admin"))):
    return {"expired": collective.expire_stale(db)}
