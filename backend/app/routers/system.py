from __future__ import annotations

import pathlib
import shutil

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..db import Base, engine, get_db
from ..deps import current_user, require, ser_analysis, ser_device, ser_event
from ..demo import scenario
from ..models import Device, User, utcnow
from ..services import ai, ocr, pipeline
from ..services.endpoint_engine import ingest_event
from ..services.store import EXTERNAL_PROVIDERS, audit, build_context, external_lookups_enabled, get_setting, save_result, set_setting

router = APIRouter(prefix="/api", tags=["system"])


@router.get("/health")
def health():
    return {"status": "ok", "service": "WOLVE AI"}


@router.get("/system/status")
def system_status(db: Session = Depends(get_db)):
    return {
        "ai": ai.ai_status(bool(get_setting(db, "ai_enabled"))),
        "ocr": {"engine": ocr.ocr_engine()},
        "qr": {"engine": "OpenCV QRCodeDetector"},
        "media": {"ffmpeg": bool(shutil.which("ffmpeg")), "ffprobe": bool(shutil.which("ffprobe")), "speech_to_text": False},
        "external_lookups": external_lookups_enabled(db),
        "external_lookups_consent": get_setting(db, "external_lookups_consent"),
        "external_providers": EXTERNAL_PROVIDERS,
        "providers": {
            "dns": {"configured": True, "note": "System resolver via dnspython (when external lookups are on)"},
            "geolocation": {"configured": True, "note": "ip-api.com free tier (when external lookups are on)"},
            "abuseipdb": {"configured": bool(settings.abuseipdb_api_key)},
            "virustotal": {"configured": bool(settings.virustotal_api_key), "note": "Hash lookups only; files are never uploaded"},
        },
        "integrations": {
            "microsoft_365": {"connected": False, "note": "Planned: Microsoft Graph API (Mail.Read, Mail.ReadWrite) with admin consent"},
            "google_workspace": {"connected": False, "note": "Planned: Gmail API with domain-wide delegation"},
            "edr_network_isolation": {"connected": False, "note": "Isolation is recommended, not enforced, in the MVP"},
        },
        "sandbox": {"available": False, "note": "Dynamic detonation sandbox is a planned isolated service; uploads are analysed statically."},
        "max_upload_mb": settings.max_upload_mb,
    }


@router.get("/users")
def users(db: Session = Depends(get_db), user: User = Depends(current_user)):
    return [{"username": u.username, "full_name": u.full_name, "role": u.role, "email": u.email} for u in db.scalars(select(User)).all()]


class SettingsIn(BaseModel):
    ai_enabled: bool | None = None
    external_lookups: bool | None = None
    consent_acknowledged: bool | None = None
    auto_incident_threshold: int | None = None


@router.get("/settings")
def get_settings(db: Session = Depends(get_db), user: User = Depends(current_user)):
    return _settings_view(db)


def _settings_view(db: Session) -> dict:
    out = {k: get_setting(db, k) for k in ("ai_enabled", "auto_incident_threshold", "external_lookups_consent")}
    out["external_lookups"] = external_lookups_enabled(db)
    return out


@router.put("/settings")
def put_settings(body: SettingsIn, db: Session = Depends(get_db), user: User = Depends(require("admin"))):
    changes = body.model_dump(exclude_none=True)
    ack = changes.pop("consent_acknowledged", None)
    if changes.get("external_lookups") is True:
        if not ack:
            raise HTTPException(422, "Turning on external lookups requires explicit consent: public IP addresses and domains will be sent to ip-api.com and your DNS resolver.")
        set_setting(db, "external_lookups_consent", {"by": user.username, "at": utcnow().isoformat()})
    elif changes.get("external_lookups") is False:
        set_setting(db, "external_lookups_consent", None)
    if "auto_incident_threshold" in changes and not (30 <= changes["auto_incident_threshold"] <= 95):
        raise HTTPException(422, "Threshold must be between 30 and 95")
    for k, v in changes.items():
        set_setting(db, k, v)
    audit(db, user.username, "settings.update", "settings", changes)
    db.commit()
    return _settings_view(db)


# ---------------------------------------------------------------- demo

SAMPLES = {
    "phishing-ceo-fraud.eml": ("message/rfc822", scenario.make_phishing_eml),
    "legitimate-hr.eml": ("message/rfc822", scenario.make_legit_eml),
    "mailbox-lure.png": ("image/png", scenario.make_lure_image),
    "Invoice_Q4_2026.pdf": ("application/octet-stream", scenario.make_disguised_attachment),
    "scam-call.wav": ("audio/wav", lambda: (pathlib.Path(scenario.__file__).parent / "sample_scam_call.wav").read_bytes()),
    "scam-call-claims.wav": ("audio/wav", lambda: (pathlib.Path(scenario.__file__).parent / "sample_scam_call_claims.wav").read_bytes()),
}


@router.get("/demo/samples")
def demo_samples():
    return {"files": [{"name": n, "mime": m} for n, (m, _) in SAMPLES.items()],
            "messages": [{"key": k, **v} for k, v in scenario.SAMPLE_MESSAGES.items()],
            "note": "All samples are harmless test data generated by WOLVE."}


@router.get("/demo/samples/{name}")
def demo_sample(name: str):
    if name not in SAMPLES:
        raise HTTPException(404, "Unknown sample")
    mime, fn = SAMPLES[name]
    return Response(fn(), media_type=mime, headers={"Content-Disposition": f'attachment; filename="{name}"'})


def _victim_device(db: Session) -> Device:
    d = db.scalars(select(Device).where(Device.hostname == scenario.VICTIM["device"])).first()
    if not d:
        d = Device(hostname=scenario.VICTIM["device"], os="Windows 11 Enterprise 24H2", owner_email=scenario.VICTIM["email"],
                   ip_address="10.20.4.37", source="simulated", agent_version="sim-0.1")
        db.add(d)
        db.flush()
    return d


@router.post("/demo/scenario/email")
def demo_email(db: Session = Depends(get_db), user: User = Depends(require("analyst"))):
    """Step 1: the suspicious email arrives and runs through the real email pipeline."""
    res = pipeline.run_email(scenario.make_phishing_eml(), build_context(db))
    a = save_result(db, res, "mail-gateway (demo)", demo=True)
    audit(db, user.username, "demo.email_injected", a.id)
    db.commit()
    return ser_analysis(a, full=True)


@router.post("/demo/scenario/endpoint")
def demo_endpoint(db: Session = Depends(get_db), user: User = Depends(require("analyst"))):
    """Step 2: SIMULATED endpoint telemetry from the victim's laptop after opening the attachment."""
    d = _victim_device(db)
    out = []
    for e in scenario.endpoint_events():
        ev, corr = ingest_event(db, d, e["event_type"], e["title"], e["details"], simulated=True, actor=user.username)
        out.append({"event": ser_event(ev), "correlation": corr})
    db.commit()
    return {"device": ser_device(d), "results": out, "note": "These endpoint events are SIMULATED for the demo."}


@router.post("/demo/reset")
def demo_reset(db: Session = Depends(get_db), user: User = Depends(require("admin"))):
    """Wipe all data and reseed the baseline demo organisation."""
    actor = user.username
    db.close()
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    from ..seed import seed

    seed(reset_by=actor)
    for f in (settings.upload_dir / "quarantine").glob("*.quarantined"):
        f.unlink(missing_ok=True)
    return {"ok": True, "message": "Demo environment reset."}


PRIVACY_HTML = """<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>WOLVE — سياسة الخصوصية / Privacy Policy</title>
<style>body{font-family:-apple-system,Segoe UI,Tahoma,Arial,sans-serif;max-width:760px;margin:0 auto;padding:24px 16px;line-height:1.7;color:#101828;background:#fff}
h1{color:#1d4ed8;font-size:1.6rem}h2{font-size:1.15rem;margin-top:1.6em}section[lang=en]{direction:ltr;text-align:left;border-top:1px solid #e2e7ee;margin-top:2.5em;padding-top:1em}</style></head><body>
<h1>سياسة الخصوصية — WOLVE</h1>
<p>WOLVE تطبيق لحماية المستخدمين من رسائل ومكالمات الاحتيال. نحن نجمع أقل قدر ممكن من البيانات.</p>
<h2>الرسائل النصية</h2><p>تُفحص رسائل المرسلين <b>غير الموجودين في جهات اتصالك</b> فقط، وذلك <b>على جهازك نفسه</b>، ولا تُرسل إلى أي خادم. لا يمكن للتطبيق قراءة رسائل جهات الاتصال. عند استخدام «افحص» يدوياً فقط يُرسل النص الذي تكتبه إلى خادم WOLVE لتحليله، ولا تُحفظ إلا الرسائل التي تُصنّف احتيالاً كدليل.</p>
<h2>المكالمات</h2><p>لا يستطيع التطبيق الاستماع إلى المكالمات أو تسجيلها. يعرض تحذيراً على أرقام مُبلّغ عنها بناءً على قائمة تُحمّل من خادم WOLVE إلى جهازك.</p>
<h2>بيانات الربط</h2><p>عند ربط الجوال نحفظ اسم الجهاز ورمزاً سرياً للجهاز. يمكنك حذفها في أي وقت من الإعدادات ← «فك الربط وحذف بيانات هذا الجوال».</p>
<h2>لا تتبّع ولا إعلانات</h2><p>لا نستخدم أي تتبّع أو إعلانات أو تحليلات من جهات خارجية، ولا نبيع أي بيانات.</p>
<h2>التواصل</h2><p>للاستفسارات حول الخصوصية تواصل مع فريق WOLVE عبر الجهة التي زودتك بالتطبيق.</p>
<section lang="en"><h1>Privacy Policy — WOLVE</h1>
<p>WOLVE protects people from scam messages and calls and collects as little data as possible.</p>
<h2>Text messages</h2><p>Only messages from senders <b>not in your contacts</b> are checked, <b>on your device</b>; they are not sent to any server. The app cannot read messages from your contacts. Only when you use “Check” manually is the text you enter sent to the WOLVE server for analysis; only messages classified as scams are kept as evidence.</p>
<h2>Calls</h2><p>The app cannot listen to or record calls. It shows warnings for reported numbers using a list downloaded from the WOLVE server to your device.</p>
<h2>Pairing data</h2><p>When you pair the phone we store the device name and a secret device token. Delete them at any time in Settings → “Unlink and delete this phone's data”.</p>
<h2>No tracking, no ads</h2><p>No third-party tracking, advertising or analytics. We never sell data.</p></section>
</body></html>"""


public_router = APIRouter(tags=["public"])


@public_router.get("/privacy", include_in_schema=False)
def privacy_page():
    from fastapi.responses import HTMLResponse

    return HTMLResponse(PRIVACY_HTML)
