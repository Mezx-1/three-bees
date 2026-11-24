"""Collective protection network: shared indicators, verification thresholds, sync, appeals and campaign graph.

Status ladder for an indicator (phone, email, email domain, domain, URL, handle, payment ID):

  reported    one or more user reports, not enough independent evidence      -> NOT distributed
  suspicious  >= 3 distinct reporters, or 2 reporters + a high-risk analysis  -> distributed as WARNING only
  verified    analyst decision, or a listing by a trusted reputation provider -> distributed, block-eligible
  revoked     overturned (appeal upheld / new evidence)                        -> removed from clients
  allowlisted known legitimate (verified business)                             -> never warned about

A report is not proof of guilt, and a similarity match is not proof of common ownership. Indicators are
distributed as SHA-256 hashes of the normalised value with a category and a short reason — never the
reporter, the report text or evidence. Suspicious/verified indicators get a review date and fall back to
'reported' when it passes without a fresh review.
"""
from __future__ import annotations

import hashlib
import re
from datetime import timedelta
from urllib.parse import urlsplit

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import IndicatorAppeal, IndicatorEvent, ScamReport, ThreatIndicator, utcnow
from . import phone_intel

TYPES = ("phone", "email", "email_domain", "domain", "url", "handle", "payment", "ip")
ACTIVE = ("suspicious", "verified")
REVIEW_DAYS = {"suspicious": 30, "verified": 90}
FREE_MAIL = {"gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "icloud.com", "live.com", "proton.me", "protonmail.com", "aol.com", "gmx.com", "yandex.com", "mail.com"}

DEFAULT_PREFS = {
    "shared_intel": True, "caller_warnings": True, "auto_block_calls": False, "email_scanning": False, "email_warnings": True,
    "url_protection": True, "message_similarity": True, "cross_device_sync": True,
}


def normalize(type_: str, value: str) -> str:
    v = (value or "").strip()
    if type_ == "phone":
        return phone_intel.e164(v)
    if type_ == "email":
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", v):
            raise ValueError("Not a valid email address")
        return v.lower()
    if type_ in ("domain", "email_domain"):
        v = v.lower()
        if "://" in v:
            v = urlsplit(v).hostname or ""
        v = v.split("@")[-1].strip(".")
        v = v[4:] if v.startswith("www.") else v
        if not re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", v):
            raise ValueError("Not a valid domain")
        return v
    if type_ == "url":
        u = urlsplit(v if "://" in v else "http://" + v)
        if not u.hostname:
            raise ValueError("Not a valid URL")
        host = u.hostname.lower()
        return f"{host[4:] if host.startswith('www.') else host}{u.path.rstrip('/')}"
    if type_ == "handle":
        return v.lower().lstrip("@")
    if type_ == "payment":
        return re.sub(r"\s+", "", v).upper()
    if type_ == "ip":
        return v
    raise ValueError(f"Unknown indicator type '{type_}'")


def vhash(type_: str, value: str) -> str:
    return hashlib.sha256(f"{type_}:{value}".encode()).hexdigest()


def mask(type_: str, value: str) -> str:
    if type_ == "phone":
        return value[:-4] + "••••" if len(value) > 6 else "••••"
    if type_ == "email":
        user, _, dom = value.partition("@")
        return (user[:2] + "•••@" + dom) if dom else "•••"
    return value


def _event(db: Session, ind: ThreatIndicator, action: str, by: str, note: str = "", frm: str | None = None, to: str | None = None) -> int:
    ev = IndicatorEvent(indicator_id=ind.id, action=action, from_status=frm, to_status=to, by=by, note=note[:1000])
    db.add(ev)
    db.flush()
    ind.version = ev.id
    return ev.id


def _confidence(ind: ThreatIndicator, high_risk_analysis: bool = False) -> int:
    distinct = len(set(ind.reporter_keys or []))
    c = 10 + 15 * min(distinct, 4) + (20 if high_risk_analysis else 0)
    if ind.status == "verified":
        c = max(c, 85)
    if any("provider" in (r.get("text") or "").lower() for r in ind.reasons or []):
        c = max(c, 80)
    return min(95, c)


def set_status(db: Session, ind: ThreatIndicator, to: str, by: str, note: str) -> None:
    if to == ind.status:
        return
    frm = ind.status
    ind.status = to
    ind.review_due = utcnow() + timedelta(days=REVIEW_DAYS[to]) if to in REVIEW_DAYS else None
    ind.reasons = (ind.reasons or []) + [{"at": utcnow().isoformat(), "by": by, "text": note[:300]}]
    ind.confidence = _confidence(ind)
    _event(db, ind, "status_changed", by, note, frm, to)


def get_or_create(db: Session, type_: str, value: str, *, mode: str = "user", category: str = "other", by: str = "system") -> ThreatIndicator:
    v = normalize(type_, value)
    ind = db.scalars(select(ThreatIndicator).where(ThreatIndicator.type == type_, ThreatIndicator.value == v, ThreatIndicator.data_mode == mode)).first()
    if ind is None:
        ind = ThreatIndicator(type=type_, value=v, value_hash=vhash(type_, v), data_mode=mode, category=category, status="reported", reasons=[], reporter_keys=[], evidence_refs=[])
        db.add(ind)
        db.flush()
        _event(db, ind, "created", by, f"First seen ({category})", None, "reported")
    return ind


def reporter_hash(identity: str) -> str:
    return hashlib.sha256(f"3b-reporter:{identity}".encode()).hexdigest()[:24]


def withdraw_report(db: Session, type_: str, value: str, key: str, by: str, mode: str = "user") -> None:
    """A moderator rejected a report: its reporter no longer counts; an unverified indicator may drop back."""
    try:
        v = normalize(type_, value)
    except ValueError:
        return
    ind = db.scalars(select(ThreatIndicator).where(ThreatIndicator.type == type_, ThreatIndicator.value == v, ThreatIndicator.data_mode == mode)).first()
    if not ind or key not in (ind.reporter_keys or []):
        return
    ind.reporter_keys = [k for k in ind.reporter_keys if k != key]
    _event(db, ind, "report_rejected", by, "A report was rejected by a moderator")
    if ind.status == "suspicious" and len(set(ind.reporter_keys)) < 3:
        set_status(db, ind, "reported", by, "Fewer than 3 independent reports after moderation")
    ind.confidence = _confidence(ind)


def record_report(db: Session, type_: str, value: str, *, reporter: str, category: str, ref: str | None = None,
                  analysis_score: int = 0, mode: str = "user") -> ThreatIndicator:
    """A user report about an indicator. May raise it to 'suspicious' — never to 'verified'."""
    ind = get_or_create(db, type_, value, mode=mode, category=category, by="report")
    if ind.status == "allowlisted":
        return ind
    key = reporter_hash(reporter)
    keys = list(ind.reporter_keys or [])
    if key not in keys:
        keys.append(key)
    ind.reporter_keys = keys
    ind.report_count = (ind.report_count or 0) + 1
    if ref and ref not in (ind.evidence_refs or []):
        ind.evidence_refs = (ind.evidence_refs or []) + [ref]
    ind.last_seen = utcnow()
    ind.category = category if ind.category in ("other", None) else ind.category
    distinct = len(keys)
    _event(db, ind, "report_added", "report", f"Report {ref or ''} ({distinct} distinct reporters)")
    if ind.status == "reported" and (distinct >= 3 or (distinct >= 2 and analysis_score >= 80)):
        set_status(db, ind, "suspicious", "system", f"{distinct} independent reports" + (" and a high-risk analysis" if analysis_score >= 80 else ""))
    ind.confidence = _confidence(ind, analysis_score >= 80)
    return ind


def record_provider_listing(db: Session, type_: str, value: str, provider: str, result: str) -> ThreatIndicator:
    ind = get_or_create(db, type_, value, category="phishing" if "phishing" in result else "malware", by=provider)
    if ind.status not in ("allowlisted", "revoked", "verified"):
        set_status(db, ind, "verified", provider, f"Listed by reputation provider {provider} ({result})")
    return ind


def report_indicators(r: ScamReport) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if r.phone:
        out.append(("phone", r.phone))
    if r.url:
        out.append(("url", r.url))
    if r.domain:
        out.append(("domain", r.domain))
    for e in sorted(set(re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", f"{r.message} {r.description}")))[:3]:
        out.append(("email", e))
        dom = e.split("@")[1].lower()
        if dom not in FREE_MAIL:
            out.append(("email_domain", dom))
    for iban in re.findall(r"\bAE\d{2}\s?(?:\d{4}\s?){4}\d{3}\b", f"{r.message} {r.description}", re.I)[:2]:
        out.append(("payment", iban))
    return out


def ingest_report(db: Session, r: ScamReport) -> list[ThreatIndicator]:
    res = []
    for t, v in report_indicators(r):
        try:
            res.append(record_report(db, t, v, reporter=r.reporter if r.reporter != "anonymous" else f"anon:{r.reference}", category=r.category,
                                     ref=r.reference, analysis_score=r.risk_score or 0, mode=r.data_mode))
        except ValueError:
            continue
    return res


def expire_stale(db: Session) -> int:
    """Suspicious/verified indicators past their review date fall back to 'reported' (removed from clients)."""
    now = utcnow()
    n = 0
    for ind in db.scalars(select(ThreatIndicator).where(ThreatIndicator.status.in_(ACTIVE), ThreatIndicator.review_due.is_not(None))).all():
        due = ind.review_due if ind.review_due.tzinfo else ind.review_due.replace(tzinfo=now.tzinfo)
        if due < now:
            set_status(db, ind, "reported", "system", "Review date passed without re-review; no longer distributed")
            n += 1
    if n:
        db.commit()
    return n


def current_version(db: Session) -> int:
    return db.scalar(select(func.max(IndicatorEvent.id))) or 0


def sync(db: Session, since: int = 0, limit: int = 500, include_demo: bool = False) -> dict:
    """Incremental update for clients. since=0 returns the active set; later calls return only changes."""
    expire_stale(db)
    modes = ["user", "demo"] if include_demo else ["user"]
    stmt = select(ThreatIndicator).where(ThreatIndicator.data_mode.in_(modes))
    if since:
        stmt = stmt.where(ThreatIndicator.version > since)
    else:
        stmt = stmt.where(ThreatIndicator.status.in_(ACTIVE))
    rows = db.scalars(stmt.order_by(ThreatIndicator.version).limit(limit + 1)).all()
    more = len(rows) > limit
    rows = rows[:limit]
    changes = []
    for i in rows:
        if i.status in ACTIVE:
            changes.append({"op": "upsert", "type": i.type, "hash": i.value_hash, "level": "block" if i.status == "verified" else "warn",
                            "category": i.category, "confidence": i.confidence, "demo": i.data_mode == "demo",
                            "reason": "Verified scam indicator" if i.status == "verified" else "Reported by several 3B users — not verified"})
        else:
            changes.append({"op": "remove", "type": i.type, "hash": i.value_hash})
    version = rows[-1].version if (rows and more) else max(current_version(db), since)
    return {"version": version, "since": since, "more": more, "changes": changes,
            "hashing": "sha256('<type>:<normalised value>') — phones in E.164, emails/domains lower-case, URLs host+path without query",
            "note": "Only hashes, categories and levels are distributed. Reporter identities and report texts never leave the server."}


def appeal(db: Session, ind: ThreatIndicator, reason: str, contact: str | None, by: str) -> IndicatorAppeal:
    a = IndicatorAppeal(indicator_id=ind.id, reason=reason[:5000], contact=(contact or None), submitted_by=by)
    db.add(a)
    db.flush()
    _event(db, ind, "appeal_opened", by, f"Appeal #{a.id}")
    if ind.status == "suspicious":  # warnings on an unverified indicator pause while the appeal is reviewed
        set_status(db, ind, "reported", "system", f"Paused pending appeal #{a.id}")
    return a


def decide_appeal(db: Session, a: IndicatorAppeal, uphold: bool, note: str, by: str) -> None:
    ind = db.get(ThreatIndicator, a.indicator_id)
    a.status = "upheld" if uphold else "rejected"
    a.decision_note = note[:1000]
    a.decided_at = utcnow()
    if ind:
        _event(db, ind, "appeal_" + a.status, by, note)
        if uphold:
            set_status(db, ind, "allowlisted", by, f"Appeal #{a.id} upheld: {note}")


def shared_map(db: Session) -> dict[tuple[str, str], dict]:
    """(type, value) -> status info for analysis (statuses that change what users see)."""
    out = {}
    for i in db.scalars(select(ThreatIndicator).where(ThreatIndicator.status.in_(("reported", "suspicious", "verified", "allowlisted")))).all():
        out[(i.type, i.value)] = {"status": i.status, "category": i.category, "confidence": i.confidence,
                                  "reports": len(set(i.reporter_keys or [])), "demo": i.data_mode == "demo", "id": i.id}
    return out


def stats(db: Session) -> dict:
    rows = db.execute(select(ThreatIndicator.status, ThreatIndicator.type, ThreatIndicator.data_mode, func.count()).group_by(
        ThreatIndicator.status, ThreatIndicator.type, ThreatIndicator.data_mode)).all()
    out: dict = {"user": {}, "demo": {}}
    for st, ty, mode, n in rows:
        m = out[mode]
        m.setdefault("by_status", {})[st] = m.get("by_status", {}).get(st, 0) + n
        m.setdefault("by_type", {})[ty] = m.get("by_type", {}).get(ty, 0) + n
    return out
