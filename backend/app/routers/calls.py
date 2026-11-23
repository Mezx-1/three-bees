"""Call Guard: analyse a phone call from a recording, or live from the microphone in short chunks.

Audio is processed in memory and on local temp storage only; it is never stored or sent to a cloud service.
"""
from __future__ import annotations

import re
import threading
import time
import uuid

import numpy as np
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy.orm import Session

from ..config import settings
from ..db import get_db
from ..deps import current_user, rate_limit, ser_analysis
from ..models import Analysis, Indicator, User
from ..services import pipeline, voice
from ..services.store import audit, build_context, create_incident_from_analysis, get_setting, save_result

router = APIRouter(prefix="/api/calls", tags=["calls"])

MAX_SESSION_SECONDS = 20 * 60
_sessions: dict[str, dict] = {}
_lock = threading.Lock()


def _gc() -> None:
    now = time.time()
    for k in [k for k, v in _sessions.items() if now - v["touched"] > 3600]:
        _sessions.pop(k, None)


@router.get("/status")
def call_status():
    from ..services.questions import default_questions

    return {"questions": default_questions(), "speech_to_text": voice.stt_status(), "ffmpeg": bool(__import__("shutil").which("ffmpeg")),
            "stores_audio": False, "cloud_upload": False}


@router.post("/analyze", dependencies=[Depends(rate_limit)])
async def analyze_call(audio: UploadFile | None = File(default=None), caller_number: str | None = Form(default=None),
                       transcript: str | None = Form(default=None), consent: bool = Form(default=False),
                       session_id: str | None = Form(default=None), db: Session = Depends(get_db), user: User = Depends(current_user)):
    if not consent:
        raise HTTPException(422, "Consent is required: confirm you are a participant in this call and that analysing it is allowed.")
    if caller_number and len(caller_number) > 40:
        raise HTTPException(422, "Caller number is too long.")
    if transcript and len(transcript) > 100_000:
        raise HTTPException(422, "Transcript too long (max 100k characters).")

    chunk_text, stt, pcm = "", None, None
    if audio is not None and audio.filename:
        data = await audio.read(settings.max_upload_mb * 1024 * 1024 + 1)
        if len(data) > settings.max_upload_mb * 1024 * 1024:
            raise HTTPException(413, f"Audio exceeds the {settings.max_upload_mb} MB limit.")
        if data:
            suffix = "." + (audio.filename.rsplit(".", 1)[-1].lower() if "." in audio.filename else "webm")
            try:
                pcm = voice.decode_audio(data, suffix)
            except RuntimeError as exc:
                raise HTTPException(422, str(exc))
            stt = voice.transcribe(pcm)
            chunk_text = stt.get("text", "")

    ctx = build_context(db)
    with _lock:
        _gc()
        sess = _sessions.get(session_id) if session_id else None
        if session_id and sess is None:
            sess = _sessions[session_id] = {"parts": [], "pcm": [], "analysis_id": None, "touched": time.time(), "number": caller_number}
        if sess is not None:
            if chunk_text:
                sess["parts"].append(chunk_text)
            if pcm is not None and sum(len(p) for p in sess["pcm"]) / voice.SR < MAX_SESSION_SECONDS:
                sess["pcm"].append(pcm)
            sess["touched"] = time.time()
            full_text = " ".join(sess["parts"])
            full_pcm = np.concatenate(sess["pcm"]) if sess["pcm"] else None
        else:
            full_text = chunk_text
            full_pcm = pcm
    if transcript and transcript.strip():
        full_text = (full_text + "\n" + transcript.strip()).strip()
    feats = voice.acoustic_features(full_pcm, words=len(full_text.split()) or None) if full_pcm is not None else {}
    res = pipeline.run_call(full_text, caller_number, feats, stt or voice.stt_status(), ctx)

    if sess is not None and sess["analysis_id"]:
        a = db.get(Analysis, sess["analysis_id"])
        rep = res.report
        a.report, a.risk_score, a.severity, a.confidence, a.classification = rep, rep["risk_score"], rep["severity"], rep["confidence"], rep["classification"]
        threshold = int(get_setting(db, "auto_incident_threshold") or 60)
        if not a.incident_id and a.risk_score >= threshold:
            create_incident_from_analysis(db, a, actor="system")
        for t, v, role, mal in res.indicators:
            if not db.query(Indicator).filter_by(analysis_id=a.id, type=t, value=v).first():
                db.add(Indicator(type=t, value=v, analysis_id=a.id, role=role, malicious=mal))
        db.commit()
    else:
        a = save_result(db, res, user.username)
        if sess is not None:
            sess["analysis_id"] = a.id
        audit(db, user.username, "call.analyze", a.id, {"live": bool(session_id), "consent": True})
        db.commit()
    db.refresh(a)
    out = ser_analysis(a, full=True)
    # Once a code has been heard, never echo its digits back to the screen.
    out["chunk_text"] = re.sub(r"[0-9٠-٩]", "•", chunk_text) if res.report.get("call", {}).get("code_spoken") else chunk_text
    out["session_id"] = session_id
    return out


@router.post("/session")
def new_session(user: User = Depends(current_user)):
    return {"session_id": uuid.uuid4().hex}
