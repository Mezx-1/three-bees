"""Phone intelligence API: caller-ID lookup, community number reports, moderation.

Anyone signed in can look up a number. Reports can be anonymous (bot check + rate limits); the reporter's
identity is stored only as a hash and never shown. Moderation and verified-business records: analysts/admins.
"""
from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Query, Request
from fastapi.concurrency import run_in_threadpool
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import ROLE_RANK, current_user, iso, rate_limit, require, resolve_user
from ..models import PhoneIntel, PhoneReport, User, utcnow
from ..services import collective, phone_intel
from ..services.store import audit

router = APIRouter(prefix="/api/phone", tags=["phone"])
DAILY_LIMIT = 10


@router.get("/lookup", dependencies=[Depends(rate_limit)])
def lookup(number: str = Query(min_length=3, max_length=40), include_demo: bool = True, db: Session = Depends(get_db),
           user: User = Depends(current_user)):
    try:
        return phone_intel.lookup(db, number, investigator=ROLE_RANK.get(user.role, 0) >= ROLE_RANK["analyst"], include_demo=include_demo)
    except ValueError as exc:
        raise HTTPException(422, str(exc))


@router.get("/categories")
def categories():
    return [{"key": k, "name": v} for k, v in phone_intel.REPORT_CATEGORIES.items()]


@router.post("/report", dependencies=[Depends(rate_limit)])
async def report(request: Request, body: dict = Body(...), db: Session = Depends(get_db),
                 authorization: str | None = Header(default=None), x_3b_user: str | None = Header(default=None)):
    from ..services.cloud import turnstile_verify

    ip = request.client.host if request.client else "unknown"
    check = await run_in_threadpool(turnstile_verify, body.get("turnstile_token"), ip)
    if not check["ok"]:
        raise HTTPException(403, "The bot check did not pass. Please complete the check and submit again.")
    user = resolve_user(db, authorization, x_3b_user)
    category = body.get("category", "other")
    if category not in phone_intel.REPORT_CATEGORIES:
        raise HTTPException(422, "Unknown report category.")
    desc = (body.get("description") or "").strip()[:2000]
    try:
        num = phone_intel.e164(body.get("number", ""))
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    identity = f"user:{user.username}" if user else f"anon:{ip}"
    key = collective.reporter_hash(identity)
    since = utcnow() - timedelta(hours=24)
    if db.scalar(select(func.count()).select_from(PhoneReport).where(PhoneReport.reporter_key == key, PhoneReport.e164 == num,
                                                                    PhoneReport.created_at >= since)):
        raise HTTPException(409, "You already reported this number in the last 24 hours. Thank you — one report per person counts.")
    if db.scalar(select(func.count()).select_from(PhoneReport).where(PhoneReport.reporter_key == key, PhoneReport.created_at >= since)) >= DAILY_LIMIT:
        raise HTTPException(429, "Daily report limit reached. Please try again tomorrow.")
    row = phone_intel.intel_row(db, num, "user", create=True)
    # Every report waits for a moderator; it counts as one unverified claim until then.
    db.add(PhoneReport(e164=num, data_mode="user", category=category, description=desc, reporter_key=key, status="pending"))
    db.flush()
    phone_intel.refresh_counts(db, row)
    ind = collective.record_report(db, "phone", num, reporter=identity, category=category)
    audit(db, user.username if user else "anonymous", "phone.report", num[:-4] + "••••", {"category": category})
    db.commit()
    return {"ok": True, "number": num, "shared_status": ind.status,
            "message": "Thank you. Your report is counted once and reviewed by a moderator. A single report never blocks a number for others."}


@router.get("/reports")
def moderation_queue(status: str = "pending", db: Session = Depends(get_db), user: User = Depends(require("analyst"))):
    rows = db.scalars(select(PhoneReport).where(PhoneReport.status == status, PhoneReport.data_mode == "user")
                      .order_by(PhoneReport.created_at.desc()).limit(200)).all()
    return [{"id": r.id, "number": r.e164, "category": r.category, "description": r.description, "status": r.status,
             "created_at": iso(r.created_at), "reporter": "hidden"} for r in rows]


@router.patch("/reports/{rid}")
def moderate(rid: int, body: dict = Body(...), db: Session = Depends(get_db), user: User = Depends(require("analyst"))):
    r = db.get(PhoneReport, rid)
    if not r:
        raise HTTPException(404, "Report not found")
    st = body.get("status")
    if st not in ("accepted", "rejected"):
        raise HTTPException(422, "status must be accepted or rejected")
    r.status = st
    if st == "rejected":
        collective.withdraw_report(db, "phone", r.e164, r.reporter_key, user.username, r.data_mode)
    row = phone_intel.intel_row(db, r.e164, r.data_mode)
    if row:
        phone_intel.refresh_counts(db, row)
    audit(db, user.username, f"phone.report_{st}", str(rid))
    db.commit()
    return {"id": rid, "status": st}


@router.patch("/numbers/{number}")
def set_number(number: str, body: dict = Body(...), db: Session = Depends(get_db), user: User = Depends(require("admin"))):
    """Record an analyst review or a verified business identity (with its source)."""
    try:
        num = phone_intel.e164(number)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    row = phone_intel.intel_row(db, num, "user", create=True)
    if "review_status" in body:
        if body["review_status"] not in ("unreviewed", "confirmed_scam", "legitimate", "disputed"):
            raise HTTPException(422, "Unknown review status")
        row.review_status = body["review_status"]
        ind = collective.get_or_create(db, "phone", num, by=user.username)
        if row.review_status == "confirmed_scam":
            collective.set_status(db, ind, "verified", user.username, body.get("note") or "Analyst confirmed")
        elif row.review_status == "legitimate":
            collective.set_status(db, ind, "allowlisted", user.username, body.get("note") or "Reviewed as legitimate")
    if body.get("verified_business"):
        if not (body.get("verified_source") or "").strip():
            raise HTTPException(422, "A verified business name needs its source (e.g. the company's official website or contract).")
        row.verified_business, row.verified_source = body["verified_business"][:200], body["verified_source"][:300]
    audit(db, user.username, "phone.number_update", num, {k: body.get(k) for k in ("review_status", "verified_business")})
    db.commit()
    return phone_intel.lookup(db, num, investigator=True)
