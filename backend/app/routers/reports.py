"""Scam reports: a person reports a scam, investigators review it and see potentially related reports.

Roles: anyone signed in can submit a report and see their own; analysts and admins (the investigators) can
list, review, change status, add notes, view evidence, print a summary and load or reset the demo data.
Submitting here is NOT an official police complaint — the app says so and points to the official channels.
"""
from __future__ import annotations

import hashlib
import html
import io
import re
import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, File, Form, Header, HTTPException, Query, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..config import settings
from ..db import get_db
from ..deps import ROLE_RANK, current_user, iso, rate_limit, require
from ..models import Analysis, ScamReport, User, utcnow
from ..services import pipeline, report_links
from ..services.store import audit, build_context, save_result

router = APIRouter(prefix="/api/reports", tags=["reports"])

CATEGORIES = ("bank_impersonation", "government_impersonation", "toll_fine", "delivery", "job", "investment", "shopping",
              "romance", "qr", "account_takeover", "phishing_email", "other")
CHANNELS = ("sms", "whatsapp", "call", "email", "website", "social", "other")
STATUSES = ("submitted", "under_review", "escalated", "resolved", "rejected")
EMIRATES = ("Abu Dhabi", "Dubai", "Sharjah", "Ajman", "Umm Al Quwain", "Ras Al Khaimah", "Fujairah", "Al Ain")
IMAGE_FORMATS = {"PNG": "image/png", "JPEG": "image/jpeg", "WEBP": "image/webp"}
MAX_EVIDENCE_MB = 5
DISCLAIMER = ("3B is a hackathon prototype. A report here is not an official police complaint. For urgent help or a formal "
              "complaint, use the Abu Dhabi Police app, call Aman on 8002626, or 999 in an emergency.")


def is_investigator(user: User) -> bool:
    return ROLE_RANK.get(user.role, 0) >= ROLE_RANK["analyst"]


def ser(r: ScamReport, *, full: bool = False, investigator: bool = False) -> dict:
    d = {"reference": r.reference, "data_mode": r.data_mode, "category": r.category, "channel": r.channel, "phone": r.phone,
         "url": r.url, "domain": r.domain, "incident_date": r.incident_date, "amount_lost": r.amount_lost, "currency": r.currency,
         "emirate": r.emirate, "status": r.status, "risk_score": r.risk_score, "severity": r.severity, "flagged": r.flagged,
         "has_evidence": bool(r.evidence_path), "created_at": iso(r.created_at), "updated_at": iso(r.updated_at)}
    if full:
        d.update({"message": r.message, "description": r.description, "analysis_id": r.analysis_id,
                  "evidence_name": r.evidence_name, "evidence_sha256": r.evidence_sha256,
                  "history": r.history or []})
        if investigator:
            d.update({"notes": r.notes or [], "contact": r.contact, "reporter": r.reporter})
    return d


def next_reference(db: Session, mode: str) -> str:
    prefix = f"3B-{'DEMO' if mode == 'demo' else 'UAE'}-{datetime.now(timezone.utc).year}-"
    last = db.scalar(select(func.max(ScamReport.reference)).where(ScamReport.reference.like(prefix + "%")))
    n = int(last.rsplit("-", 1)[1]) + 1 if last else 1
    return f"{prefix}{n:06d}"


def _domain(url: str | None) -> str | None:
    """The link's host name (without www.). The full host, not just the registered domain: scam sites on
    shared or free hosting (many-sites.example.com) must not all look like one site."""
    if not url:
        return None
    host = urlparse(url if "://" in url else "http://" + url).hostname
    return host.lower().removeprefix("www.") if host else None


def _check_image(data: bytes) -> str:
    """Return the real image format, or reject. The extension is not trusted; the bytes are."""
    from PIL import Image

    try:
        with Image.open(io.BytesIO(data)) as im:
            fmt = im.format
            im.verify()
    except Exception:
        raise HTTPException(415, "Evidence must be a PNG, JPG or WEBP image.")
    if fmt not in IMAGE_FORMATS:
        raise HTTPException(415, "Evidence must be a PNG, JPG or WEBP image.")
    return fmt


def _get(db: Session, ref: str) -> ScamReport:
    r = db.scalar(select(ScamReport).where(ScamReport.reference == ref))
    if not r:
        raise HTTPException(404, "Report not found")
    return r


def _analyse(db: Session, r: ScamReport, actor: str) -> None:
    text = "\n".join(x for x in (r.message, r.url) if x)
    if not text.strip():
        return
    channel = r.channel if r.channel in ("sms", "whatsapp", "email", "call") else "message"
    res = pipeline.run_message(text, build_context(db), channel, title=f"Scam report {r.reference}")
    a = save_result(db, res, actor, demo=r.data_mode == "demo", auto_incident=False)
    r.analysis_id, r.risk_score, r.severity = a.id, a.risk_score, a.severity
    r.flagged = a.risk_score >= 60


# ---------------------------------------------------------------- submit and read

@router.post("", dependencies=[Depends(rate_limit)])
async def submit(category: str = Form(...), channel: str = Form("sms"), phone: str | None = Form(None), url: str | None = Form(None),
                 message: str = Form(""), description: str = Form(""), incident_date: str | None = Form(None),
                 amount_lost: int | None = Form(None), currency: str = Form("AED"), emirate: str | None = Form(None),
                 contact: str | None = Form(None), privacy_ack: bool = Form(False), evidence: UploadFile | None = File(None),
                 db: Session = Depends(get_db), user: User = Depends(current_user)):
    if not privacy_ack:
        raise HTTPException(422, "Please confirm you have read how the report is stored and used.")
    if category not in CATEGORIES:
        raise HTTPException(422, "Unknown scam category.")
    if channel not in CHANNELS:
        raise HTTPException(422, "Unknown channel.")
    if emirate and emirate not in EMIRATES:
        raise HTTPException(422, "Unknown emirate.")
    if incident_date and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", incident_date):
        raise HTTPException(422, "Incident date must be YYYY-MM-DD.")
    if amount_lost is not None and not 0 <= amount_lost <= 100_000_000:
        raise HTTPException(422, "Amount lost is out of range.")
    if not re.fullmatch(r"[A-Z]{3}", currency or ""):
        raise HTTPException(422, "Currency must be a 3-letter code.")
    for name, val, mx in (("phone", phone, 40), ("url", url, 2000), ("message", message, 20_000), ("description", description, 5000), ("contact", contact, 200)):
        if val and len(val) > mx:
            raise HTTPException(422, f"{name} is too long (max {mx}).")
    if not any(x and x.strip() for x in (message, description, url, phone)) and not (evidence and evidence.filename):
        raise HTTPException(422, "Describe what happened, or add the message, link, number or a screenshot.")

    ev_path = ev_name = ev_sha = None
    ocr_text = ""
    if evidence is not None and evidence.filename:
        data = await evidence.read(MAX_EVIDENCE_MB * 1024 * 1024 + 1)
        if len(data) > MAX_EVIDENCE_MB * 1024 * 1024:
            raise HTTPException(413, f"Evidence image is larger than {MAX_EVIDENCE_MB} MB.")
        _check_image(data)
        ev_sha = hashlib.sha256(data).hexdigest()
        folder = settings.upload_dir / "reports"
        folder.mkdir(exist_ok=True)
        path = folder / f"{uuid.uuid4().hex}.evidence"  # stored inert, never served as a public file
        path.write_bytes(data)
        ev_path, ev_name = str(path), re.sub(r"[^\w.\- ]", "_", evidence.filename)[:200]
        if not message.strip():
            from ..services import ocr

            ocr_text = (await run_in_threadpool(ocr.extract_text, data)).get("text", "") or ""

    r = ScamReport(category=category, channel=channel, phone=(phone or "").strip() or None, url=(url or "").strip() or None,
                   message=(message or ocr_text).strip(), description=description.strip(), incident_date=incident_date,
                   amount_lost=amount_lost, currency=currency, emirate=emirate, contact=(contact or "").strip() or None,
                   evidence_path=ev_path, evidence_name=ev_name, evidence_sha256=ev_sha, reporter=user.username,
                   data_mode="user", history=[{"by": user.username, "at": iso(utcnow()), "status": "submitted"}])
    r.domain = _domain(r.url)
    await run_in_threadpool(_analyse, db, r, user.username)
    for _ in range(3):
        r.reference = next_reference(db, "user")
        db.add(r)
        try:
            db.commit()
            break
        except IntegrityError:
            db.rollback()
    else:
        raise HTTPException(503, "Could not allocate a reference number, please retry.")
    audit(db, user.username, "report.submit", r.reference, {"category": category})
    db.commit()
    return {**ser(r, full=True), "disclaimer": DISCLAIMER}


@router.get("/mine")
def mine(db: Session = Depends(get_db), user: User = Depends(current_user)):
    rs = db.scalars(select(ScamReport).where(ScamReport.reporter == user.username, ScamReport.data_mode == "user")
                    .order_by(ScamReport.created_at.desc())).all()
    return [ser(r) for r in rs]


@router.get("")
def list_reports(mode: str = Query("user", pattern="^(user|demo)$"), status: str | None = None, category: str | None = None,
                 q: str | None = None, min_score: int = 0, limit: int = Query(200, le=500),
                 db: Session = Depends(get_db), user: User = Depends(require("analyst"))):
    stmt = select(ScamReport).where(ScamReport.data_mode == mode).order_by(ScamReport.created_at.desc())
    if status:
        stmt = stmt.where(ScamReport.status.in_(status.split(",")))
    if category:
        stmt = stmt.where(ScamReport.category == category)
    if min_score:
        stmt = stmt.where(ScamReport.risk_score >= min_score)
    if q:
        like = f"%{q.strip()}%"
        stmt = stmt.where(ScamReport.reference.ilike(like) | ScamReport.phone.ilike(like) | ScamReport.domain.ilike(like)
                          | ScamReport.message.ilike(like) | ScamReport.description.ilike(like))
    return [ser(r) for r in db.scalars(stmt.limit(limit)).all()]


@router.get("/stats")
def stats(mode: str = Query("user", pattern="^(user|demo)$"), db: Session = Depends(get_db), user: User = Depends(require("analyst"))):
    rs = db.scalars(select(ScamReport).where(ScamReport.data_mode == mode)).all()
    now = datetime.now(timezone.utc)
    weeks = []
    for w in range(11, -1, -1):
        start = (now - timedelta(days=7 * (w + 1)))
        end = now - timedelta(days=7 * w)
        weeks.append({"week": end.date().isoformat(), "count": sum(1 for r in rs if start < _aware(r.created_at) <= end)})
    phones = Counter(r.phone for r in rs if r.phone)
    domains = Counter(r.domain for r in rs if r.domain)
    gs = report_links.groups(rs)
    return {
        "mode": mode, "total": len(rs),
        "pending": sum(1 for r in rs if r.status in ("submitted", "under_review")),
        "escalated": sum(1 for r in rs if r.status == "escalated"),
        "high_risk": sum(1 for r in rs if r.risk_score >= 60),
        "linked": sum(g["size"] for g in gs),
        "total_lost": sum(r.amount_lost or 0 for r in rs),
        "by_status": {s: sum(1 for r in rs if r.status == s) for s in STATUSES},
        "by_category": dict(Counter(r.category for r in rs).most_common()),
        "by_week": weeks,
        "top_phones": [{"value": v, "count": c} for v, c in phones.most_common(5) if c > 1],
        "top_domains": [{"value": v, "count": c} for v, c in domains.most_common(5) if c > 1],
        "groups": [{**g, "first_seen": iso(g["first_seen"]), "last_seen": iso(g["last_seen"])} for g in gs[:8]],
        "demo_label": "DEMO DATA — FICTIONAL — NOT REAL INCIDENTS" if mode == "demo" else None,
    }


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


@router.get("/{ref}")
def get_report(ref: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    r = _get(db, ref)
    inv = is_investigator(user)
    if not inv and r.reporter != user.username:
        raise HTTPException(404, "Report not found")
    out = ser(r, full=True, investigator=inv)
    if inv:
        others = db.scalars(select(ScamReport).where(ScamReport.data_mode == r.data_mode)).all()
        out["related"] = [{**x, "created_at": iso(x["created_at"])} for x in report_links.related(r, others)]
        a = db.get(Analysis, r.analysis_id) if r.analysis_id else None
        if a:
            rep = a.report or {}
            out["analysis"] = {"id": a.id, "risk_score": a.risk_score, "severity": a.severity, "classification": a.classification,
                               "reasons": [f["title"] for f in rep.get("findings", []) if f.get("weight", 0) > 0][:6],
                               "next_steps": rep.get("next_steps")}
        audit(db, user.username, "report.view", r.reference)
        db.commit()
    out["disclaimer"] = DISCLAIMER
    return out


class ReviewIn(BaseModel):
    status: str | None = Field(default=None, pattern="^(submitted|under_review|escalated|resolved|rejected)$")
    note: str | None = Field(default=None, max_length=4000)


@router.patch("/{ref}")
def review(ref: str, body: ReviewIn, db: Session = Depends(get_db), user: User = Depends(require("analyst"))):
    r = _get(db, ref)
    if not body.status and not (body.note and body.note.strip()):
        raise HTTPException(422, "Nothing to change.")
    if body.status and body.status != r.status:
        r.status = body.status
        r.history = [*(r.history or []), {"by": user.username, "at": iso(utcnow()), "status": body.status}]
        audit(db, user.username, "report.status", r.reference, {"status": body.status})
    if body.note and body.note.strip():
        r.notes = [*(r.notes or []), {"by": user.username, "at": iso(utcnow()), "text": body.note.strip()}]
        audit(db, user.username, "report.note", r.reference)
    db.commit()
    return get_report(ref, db, user)


@router.get("/{ref}/evidence")
def evidence(ref: str, db: Session = Depends(get_db), user: User = Depends(require("analyst"))):
    r = _get(db, ref)
    if not r.evidence_path:
        raise HTTPException(404, "No evidence attached")
    from pathlib import Path

    data = Path(r.evidence_path).read_bytes()
    fmt = _check_image(data)
    audit(db, user.username, "report.evidence_view", r.reference)
    db.commit()
    return Response(data, media_type=IMAGE_FORMATS[fmt], headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})


@router.get("/{ref}/print", response_class=HTMLResponse)
def print_summary(ref: str, x_3b_lang: str | None = Header(default=None), db: Session = Depends(get_db), user: User = Depends(require("analyst"))):
    """A printable incident summary; the browser's Print → Save as PDF turns it into a PDF."""
    r = _get(db, ref)
    d = get_report(ref, db, user)
    e = html.escape
    rows = [("Reference", r.reference), ("Data", "DEMO DATA — FICTIONAL — NOT REAL INCIDENTS" if r.data_mode == "demo" else "User-submitted report"),
            ("Submitted", d["created_at"][:16].replace("T", " ") + " UTC"), ("Incident date", r.incident_date or "—"),
            ("Category", r.category.replace("_", " ")), ("Channel", r.channel), ("Emirate", r.emirate or "—"),
            ("Phone number", r.phone or "—"), ("Link / domain", f"{r.url or '—'}  ({r.domain or '—'})"),
            ("Amount lost", f"{r.amount_lost:,} {r.currency}" if r.amount_lost else "—"), ("Status", r.status.replace("_", " ")),
            ("Risk", f"{r.risk_score}/100 ({r.severity})")]
    a = d.get("analysis") or {}
    reasons = "".join(f"<li>{e(x)}</li>" for x in a.get("reasons", [])) or "<li>No analysis available</li>"
    related = "".join(f"<li>{e(x['reference'])} — {e('; '.join(l['explanation'] for l in x['links']))}</li>" for x in d.get("related", [])) or "<li>None found</li>"
    notes = "".join(f"<li><b>{e(n['by'])}</b> ({e(n['at'][:16])}): {e(n['text'])}</li>" for n in d.get("notes", [])) or "<li>None</li>"
    ev = f"{e(r.evidence_name or '')} · SHA-256 {e(r.evidence_sha256 or '')}" if r.evidence_path else "None"
    demo_banner = '<div class="demo">DEMO DATA — FICTIONAL — NOT REAL INCIDENTS</div>' if r.data_mode == "demo" else ""
    audit(db, user.username, "report.print", r.reference)
    db.commit()
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{e(r.reference)} — Three Bees incident summary</title>
<style>body{{font-family:Arial,sans-serif;color:#0e1726;margin:32px;}}h1{{font-size:22px;margin:0}}.brand{{color:#a15c07;font-weight:bold}}
table{{border-collapse:collapse;width:100%;margin:16px 0}}td{{border:1px solid #e1e5ec;padding:6px 8px;font-size:13px;vertical-align:top}}
td:first-child{{width:30%;color:#444e5f}}h2{{font-size:15px;margin:18px 0 6px}}li{{font-size:13px;margin:3px 0}}.demo{{background:#fff4dc;border:2px solid #f4a62a;
padding:8px;font-weight:bold;text-align:center;margin:12px 0}}.disc{{font-size:11px;color:#636d7e;border-top:1px solid #e1e5ec;padding-top:8px;margin-top:20px}}
pre{{white-space:pre-wrap;font-size:12px;background:#f2f4f7;padding:8px}}</style></head><body onload="window.print()">
<div class="brand">THREE BEES (3B)</div><h1>Incident summary · {e(r.reference)}</h1>{demo_banner}
<table>{''.join(f'<tr><td>{e(k)}</td><td>{e(str(v))}</td></tr>' for k, v in rows)}</table>
<h2>What was received</h2><pre>{e(r.message or '—')}</pre><h2>What happened</h2><pre>{e(r.description or '—')}</pre>
<h2>Indicators found</h2><ul>{reasons}</ul><h2>Evidence</h2><p style="font-size:13px">{ev}</p>
<h2>Potentially related reports</h2><ul>{related}</ul><h2>Investigator notes</h2><ul>{notes}</ul>
<p class="disc">{e(DISCLAIMER)} Indicators are signs that need review, not proof of a crime. Potentially related reports share a number,
domain or wording; numbers and domains can be spoofed, shared or mistyped.</p></body></html>"""


# ---------------------------------------------------------------- demo data

@router.post("/demo/load")
def demo_load(db: Session = Depends(get_db), user: User = Depends(require("analyst"))):
    from ..demo.reports_demo import rows

    existing = db.scalar(select(func.count()).select_from(ScamReport).where(ScamReport.data_mode == "demo"))
    if existing:
        return {"loaded": 0, "already": existing, "message": "Demo data is already loaded."}
    from ..services import risk, text_analyzer

    year = datetime.now(timezone.utc).year
    for n, row in enumerate(rows(), start=1):
        findings, _ = text_analyzer.analyze_text(row["message"], row["channel"] if row["channel"] in ("sms", "call") else "message")
        score = risk.combine(findings)
        r = ScamReport(**row, reference=f"3B-DEMO-{year}-{n:06d}", data_mode="demo", reporter="demo",
                       domain=_domain(row["url"]), risk_score=score, severity=risk.severity_for(score), flagged=score >= 60,
                       history=[{"by": "demo", "at": iso(row["created_at"]), "status": "submitted"}]
                       + ([] if row["status"] == "submitted" else [{"by": "demo", "at": iso(row["created_at"] + timedelta(days=1)), "status": row["status"]}]))
        db.add(r)
    audit(db, user.username, "report.demo_load", "", {"count": len(rows())})
    db.commit()
    return {"loaded": len(rows()), "message": "Demo data loaded."}


@router.post("/demo/reset")
def demo_reset(db: Session = Depends(get_db), user: User = Depends(require("analyst"))):
    n = db.execute(delete(ScamReport).where(ScamReport.data_mode == "demo")).rowcount
    audit(db, user.username, "report.demo_reset", "", {"deleted": n})
    db.commit()
    return {"deleted": n, "message": "Demo data removed. User-submitted reports were not touched."}
