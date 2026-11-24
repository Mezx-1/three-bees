"""Mobile protection API — the server side for the phone apps.

iOS:     SMS Filter Extension (IdentityLookup) calls /sms/classify for messages from unknown senders and files
         them in Junk; Call Directory Extension syncs /call-directory to label/block numbers on the incoming-call screen.
Android: CallScreeningService calls /caller-check before the phone rings; SMS receiver calls /sms/classify.

Privacy: legitimate messages are NOT stored — only messages classified as scams are kept as evidence.
"""
from __future__ import annotations

import re

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import rate_limit
from ..models import Analysis, BlockedIndicator, Device, Indicator, User
from ..services import network_intel as ni
from ..services import pipeline
from ..services.risk import Finding, build_report
from ..services.store import build_context, save_result

router = APIRouter(prefix="/api/mobile", tags=["mobile"])
JUNK_THRESHOLD = 50


def mobile_caller(db: Session = Depends(get_db), x_device_token: str | None = Header(default=None),
                  authorization: str | None = Header(default=None), x_3b_user: str | None = Header(default=None)) -> str:
    """Phone apps authenticate with their device token; the web simulator uses the signed-in user's session."""
    from ..deps import resolve_user

    if x_device_token:
        d = db.scalars(select(Device).where(Device.token == x_device_token)).first()
        if d:
            return f"phone:{d.hostname}"
    u = resolve_user(db, authorization, x_3b_user)
    if u:
        return u.username
    raise HTTPException(401, "Missing device token")


class SmsIn(BaseModel):
    sender: str = Field(default="", max_length=200)
    body: str = Field(min_length=1, max_length=5000)


def _sender_findings(sender: str) -> tuple[list[Finding], dict | None]:
    s = sender.strip()
    if not s:
        return [], None
    if "@" in s:
        return [Finding("Text message sent from an email address",
                        "Banks, government services and delivery companies send SMS from short names or numbers. "
                        "Messages from email addresses (iMessage) are a common way scammers bypass SMS filters.",
                        "sender", "high", 30, "verified", ["smishing", "impersonation"], evidence=s)], None
    if re.fullmatch(r"[+\d][\d\s()-]{5,20}", s):
        try:
            pf, info, _ = ni.analyze_phone(s)
            return pf, info
        except ValueError:
            return [], None
    return [], None  # alphanumeric sender ID (e.g. "SALIK") — can be spoofed, not scored


@router.post("/sms/classify", dependencies=[Depends(rate_limit)])
def classify_sms(body: SmsIn, db: Session = Depends(get_db), who: str = Depends(mobile_caller)):
    ctx = build_context(db)
    res = pipeline.run_message(body.body, ctx, "sms", title=f"SMS from {body.sender or 'unknown'}: {body.body[:60]}")
    extra_f, sender_info = _sender_findings(body.sender)
    if extra_f or sender_info:
        rep = res.report
        findings = [Finding(**f) for f in rep["findings"]] + extra_f
        if sender_info and sender_info["normalized"] in ctx.blocked_phones:
            findings.append(Finding("Sender number is on the 3B blocklist", "This number was reported as a scam number.",
                                    "phone", "critical", 70, "verified", ["smishing"], evidence=sender_info["normalized"]))
        keep = {k: v for k, v in rep.items() if k not in ("risk_score", "severity", "classification", "threat_categories", "confidence",
                                                          "findings", "verified_findings", "heuristic_findings", "ai_findings",
                                                          "social_engineering_techniques", "recommended_actions", "limitations", "score_note")}
        res.report = build_report(findings, rep["limitations"], extra={**keep, "sender": body.sender, "sender_info": sender_info})
    rep = res.report
    action = "junk" if rep["risk_score"] >= JUNK_THRESHOLD else "allow"
    out = {"action": action, "risk_score": rep["risk_score"], "severity": rep["severity"], "classification": rep["classification"],
           "reasons": [f["title"] for f in rep["findings"] if f["weight"] > 0][:5],
           "advice": rep["recommended_actions"][:2], "stored": False}
    if action == "junk":  # only scams are kept as evidence; normal messages are never stored
        res.indicators.append(("phone" if sender_info else "email", (sender_info or {}).get("normalized") or body.sender, "sms_sender", True))
        a = save_result(db, res, who)
        db.commit()
        out.update({"stored": True, "analysis_id": a.id, "incident_id": a.incident_id})
    return out


def _caller_verdict(db: Session, number: str) -> dict:
    try:
        findings, info, limits = ni.analyze_phone(number)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    n = info["normalized"]
    if db.scalars(select(BlockedIndicator).where(BlockedIndicator.type == "phone", BlockedIndicator.value == n)).first():
        findings.append(Finding("Number is on the 3B scam blocklist", "Reported as a scam number by an analyst.", "phone", "critical", 80, "verified", ["vishing"]))
    from ..models import ThreatIndicator
    from ..services import collective

    try:
        e164 = collective.normalize("phone", n)
    except ValueError:
        e164 = n
    for s in db.scalars(select(ThreatIndicator).where(ThreatIndicator.type == "phone", ThreatIndicator.value == e164, ThreatIndicator.data_mode == "user")).all():
        if s.status == "verified":
            findings.append(Finding("On the 3B verified threat list", "Verified by an analyst or a trusted source. Opted-in devices warn about or block this number.",
                                    "phone", "critical", 80, "verified", ["vishing"]))
        elif s.status == "suspicious":
            findings.append(Finding("On the 3B suspicious list (not verified)", "Several independent signals, awaiting analyst review. Devices show a warning only.",
                                    "phone", "high", 35, "heuristic", ["vishing"]))
    seen = db.scalars(select(Indicator).where(Indicator.type == "phone", Indicator.value == n, Indicator.analysis_id.is_not(None))).all()
    bad = [a for a in (db.get(Analysis, i.analysis_id) for i in seen) if a and a.risk_score >= 60]
    if bad:
        findings.append(Finding("Number appeared in scam reports", f"Linked to {len(bad)} high-risk message(s) or call(s) analysed by 3B.",
                                "phone", "high", 50, "verified", ["vishing"], evidence=", ".join(a.id for a in bad[:3])))
    rep = build_report(findings, limits)
    score = rep["risk_score"]
    if score >= 60:
        level, label = "danger", "⚠️ 3B: likely scam"
    elif score >= 25:
        level, label = "caution", "⚠️ 3B: be careful"
    else:
        level, label = "none", ""
    return {"number": n, "registered_region": info.get("registered_region"), "warn": level != "none", "level": level, "label": label,
            "risk_score": score, "reasons": [f["title"] for f in rep["findings"] if f["weight"] > 0][:4],
            "advice": "Do not share codes, passwords or card numbers. If they claim to be a bank or the police, hang up and call the official number."
            if level != "none" else "", "note": "Based on the number only. Caller ID can be spoofed."}


@router.get("/caller-check", dependencies=[Depends(rate_limit)])
def caller_check(number: str = Query(min_length=3, max_length=40), db: Session = Depends(get_db), who: str = Depends(mobile_caller)):
    return _caller_verdict(db, number)


@router.get("/call-directory")
def call_directory(db: Session = Depends(get_db), who: str = Depends(mobile_caller)):
    """Numbers for the iOS Call Directory extension: label (shown before answering) or block."""
    entries: dict[str, dict] = {}
    for b in db.scalars(select(BlockedIndicator).where(BlockedIndicator.type == "phone")).all():
        entries[b.value] = {"number": b.value, "label": "⚠️ 3B: reported scam", "block": True}
    for i in db.scalars(select(Indicator).where(Indicator.type == "phone")).all():
        a = db.get(Analysis, i.analysis_id) if i.analysis_id else None
        if i.malicious or (a is not None and a.risk_score >= 60):  # numbers seen in high-risk calls / messages
            entries.setdefault(i.value, {"number": i.value, "label": "⚠️ 3B: likely scam", "block": False})
    from ..models import ThreatIndicator

    for s in db.scalars(select(ThreatIndicator).where(ThreatIndicator.type == "phone", ThreatIndicator.data_mode == "user",
                                                      ThreatIndicator.status.in_(("verified", "suspicious")))).all():
        if s.status == "verified":
            entries[s.value] = {"number": s.value, "label": "⚠️ 3B: verified scam number", "block": True}
        else:
            entries.setdefault(s.value, {"number": s.value, "label": "⚠️ 3B: reported by several users", "block": False})
    return {"entries": sorted(entries.values(), key=lambda e: e["number"]),
            "prefix_warnings": [{"prefix": "+882", "label": "⚠️ 3B: satellite number"}, {"prefix": "+883", "label": "⚠️ 3B: satellite number"},
                                {"prefix": "+881", "label": "⚠️ 3B: satellite number"}]}


# ---- phone pairing & on-device filter rules --------------------------------------------------

class PhoneRegisterIn(BaseModel):
    pairing_code: str = Field(min_length=6, max_length=20)
    device_name: str = Field(min_length=1, max_length=100)
    consent: bool = False


@router.post("/register")
def register_phone(body: PhoneRegisterIn, db: Session = Depends(get_db)):
    """Pair a phone using a one-time code created by an analyst in the 3B web app."""
    import secrets

    from ..models import Device, utcnow
    from ..services.auth import redeem_pairing_code
    from ..services.store import audit

    if not body.consent:
        raise HTTPException(422, "Consent is required to protect this phone.")
    pc = redeem_pairing_code(db, body.pairing_code, "phone")
    if not pc:
        raise HTTPException(401, "Pairing code is wrong, already used or expired.")
    d = Device(hostname=body.device_name, os="iOS", source="phone", agent_version="ios-0.1", last_seen=utcnow(),
               token=secrets.token_urlsafe(32),
               system_info={"collection": "Only messages from unknown senders are checked, on the phone; nothing is uploaded unless checked manually."})
    db.add(d)
    db.flush()
    audit(db, pc.created_by, "phone.register", d.id, {"name": body.device_name, "consent": True})
    db.commit()
    return {"device_id": d.id, "token": d.token}


@router.delete("/device")
def delete_phone(db: Session = Depends(get_db), x_device_token: str | None = Header(default=None)):
    """Unlink the phone and delete its data from 3B (App Store account-deletion requirement)."""
    from ..services.store import audit

    d = db.scalars(select(Device).where(Device.token == (x_device_token or "-"), Device.source == "phone")).first()
    if not d:
        raise HTTPException(401, "Missing device token")
    audit(db, f"phone:{d.hostname}", "phone.deleted", d.id)
    db.delete(d)
    db.commit()
    return {"ok": True, "message": "This phone was unlinked and its data deleted from 3B."}


@router.get("/filter-config")
def filter_config(db: Session = Depends(get_db), who: str = Depends(mobile_caller)):
    """Rules for the phone's offline SMS filter, kept in sync with the server."""
    from ..services.url_analyzer import OFFICIAL_DOMAINS, SHORTENERS, SUSPICIOUS_TLDS

    blocked = db.scalars(select(BlockedIndicator)).all()
    return {
        "version": 1,
        "blocked_domains": sorted(b.value for b in blocked if b.type == "domain"),
        "blocked_phones": sorted(b.value for b in blocked if b.type == "phone"),
        "suspicious_tlds": sorted(SUSPICIOUS_TLDS),
        "shorteners": sorted(SHORTENERS),
        "official_domains": OFFICIAL_DOMAINS,
        "junk_threshold": JUNK_THRESHOLD,
    }
