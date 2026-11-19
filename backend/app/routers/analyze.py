from __future__ import annotations

import html
import ipaddress
import json
import re
from pathlib import PurePath

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..db import get_db
from ..deps import current_user, rate_limit, require, ser_analysis
from ..models import Analysis, User
from ..services import pipeline
from ..services.email_analyzer import looks_like_headers
from ..services.store import audit, build_context, save_result

router = APIRouter(prefix="/api", tags=["analysis"])

ALLOWED_EXTS = {
    # documents & archives
    "pdf", "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx", "pptm", "rtf", "txt", "csv", "html", "htm", "xml", "json", "one",
    "zip", "rar", "7z", "gz", "iso", "img", "eml", "msg",
    # images
    "png", "jpg", "jpeg", "gif", "bmp", "webp", "svg", "jfif", "heic",
    # audio / video
    "mp3", "wav", "m4a", "ogg", "oga", "opus", "flac", "aac", "amr", "mp4", "mov", "mkv", "webm", "avi", "3gp", "m4v",
    # executables & scripts (analysed statically only, never run)
    "exe", "dll", "scr", "msi", "bat", "cmd", "ps1", "vbs", "js", "jse", "hta", "lnk", "jar", "apk", "sh", "py", "com", "pif", "bin", "",
}


async def read_upload(file: UploadFile) -> tuple[bytes, str]:
    name = PurePath(file.filename or "upload").name
    ext = PurePath(name).suffix.lower().lstrip(".")
    if ext not in ALLOWED_EXTS:
        raise HTTPException(415, f"File type '.{ext}' is not accepted. Allowed: documents, archives, images, audio/video, email, executables/scripts (static analysis only).")
    limit = settings.max_upload_mb * 1024 * 1024
    data = await file.read(limit + 1)
    if len(data) > limit:
        raise HTTPException(413, f"File exceeds the {settings.max_upload_mb} MB limit.")
    if not data:
        raise HTTPException(400, "Uploaded file is empty.")
    return data, name


class MessageIn(BaseModel):
    text: str = Field(min_length=1, max_length=100_000)
    channel: str = Field(default="message", pattern="^(message|sms|whatsapp|chat|email|call)$")


class ValueIn(BaseModel):
    value: str = Field(min_length=1, max_length=4000)


def _persist(db: Session, res, user: User):
    a = save_result(db, res, user.username)
    db.commit()
    db.refresh(a)
    return ser_analysis(a, full=True)


@router.post("/analyze/message", dependencies=[Depends(rate_limit)])
def analyze_message(body: MessageIn, db: Session = Depends(get_db), user: User = Depends(current_user)):
    ctx = build_context(db)
    if body.channel == "email" or looks_like_headers(body.text):
        return _persist(db, pipeline.run_email(body.text, ctx), user)
    return _persist(db, pipeline.run_message(body.text, ctx, body.channel), user)


@router.post("/analyze/url", dependencies=[Depends(rate_limit)])
def analyze_url(body: ValueIn, db: Session = Depends(get_db), user: User = Depends(current_user)):
    v = body.value.strip()
    if " " in v or "." not in v:
        raise HTTPException(422, "Enter a valid URL or domain (e.g. https://example.com/login).")
    return _persist(db, pipeline.run_url(v, build_context(db)), user)


@router.post("/analyze/domain", dependencies=[Depends(rate_limit)])
def analyze_domain(body: ValueIn, db: Session = Depends(get_db), user: User = Depends(current_user)):
    v = body.value.strip().lower()
    if not re.fullmatch(r"(?:[a-z0-9¡-￿-]{1,63}\.)+[a-z¡-￿-]{2,63}\.?", v):
        raise HTTPException(422, "Enter a valid domain name (e.g. example.com).")
    return _persist(db, pipeline.run_domain(v, build_context(db)), user)


@router.post("/analyze/ip", dependencies=[Depends(rate_limit)])
def analyze_ip(body: ValueIn, db: Session = Depends(get_db), user: User = Depends(current_user)):
    try:
        res = pipeline.run_ip(body.value, build_context(db))
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    return _persist(db, res, user)


@router.post("/analyze/phone", dependencies=[Depends(rate_limit)])
def analyze_phone(body: ValueIn, db: Session = Depends(get_db), user: User = Depends(current_user)):
    try:
        res = pipeline.run_phone(body.value, build_context(db))
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    return _persist(db, res, user)


@router.post("/analyze/auto", dependencies=[Depends(rate_limit)])
def analyze_auto(body: MessageIn, db: Session = Depends(get_db), user: User = Depends(current_user)):
    """Universal input: detects whether the text is an IP, URL, domain, phone number, email or a message."""
    v = body.text.strip()
    ctx = build_context(db)
    try:
        ipaddress.ip_address(v.strip("[]"))
        return _persist(db, pipeline.run_ip(v, ctx), user)
    except ValueError:
        pass
    if "\n" not in v and " " not in v:
        if re.fullmatch(r"(https?|hxxps?)://\S+", v, re.I):
            return _persist(db, pipeline.run_url(v, ctx), user)
        if re.fullmatch(r"[+\d][\d\s()-]{5,20}", v):
            try:
                return _persist(db, pipeline.run_phone(v, ctx), user)
            except ValueError:
                pass
        if re.fullmatch(r"(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}(/\S*)?", v, re.I):
            return _persist(db, pipeline.run_url(v, ctx), user)
    if looks_like_headers(v):
        return _persist(db, pipeline.run_email(v, ctx), user)
    return _persist(db, pipeline.run_message(v, ctx, body.channel), user)


@router.post("/analyze/file", dependencies=[Depends(rate_limit)])
async def analyze_file(file: UploadFile = File(...), transcript: str | None = Form(default=None), note: str | None = Form(default=None),
                       db: Session = Depends(get_db), user: User = Depends(current_user)):
    data, name = await read_upload(file)
    if name.lower().endswith(".eml"):
        return _persist(db, pipeline.run_email(data, build_context(db)), user)
    if transcript and len(transcript) > 100_000:
        raise HTTPException(422, "Transcript too long (max 100k characters).")
    try:
        res = pipeline.run_file(data, name, file.content_type, build_context(db), transcript=transcript, context_note=note)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    return _persist(db, res, user)


@router.get("/analyses")
def list_analyses(kind: str | None = None, status: str | None = None, q: str | None = None, limit: int = Query(100, le=500),
                  db: Session = Depends(get_db), user: User = Depends(current_user)):
    stmt = select(Analysis).order_by(Analysis.created_at.desc())
    if kind:
        kinds = kind.split(",")
        stmt = stmt.where(Analysis.kind.in_(kinds))
    if status:
        stmt = stmt.where(Analysis.status == status)
    if q:
        stmt = stmt.where(Analysis.title.ilike(f"%{q}%"))
    return [ser_analysis(a) for a in db.scalars(stmt.limit(limit)).all()]


@router.get("/analyses/{aid}")
def get_analysis(aid: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    a = db.get(Analysis, aid)
    if not a:
        raise HTTPException(404, "Analysis not found")
    return ser_analysis(a, full=True)


@router.delete("/analyses/{aid}")
def delete_analysis(aid: str, db: Session = Depends(get_db), user: User = Depends(require("analyst"))):
    a = db.get(Analysis, aid)
    if not a:
        raise HTTPException(404, "Analysis not found")
    if a.stored_path:
        try:
            PurePath(a.stored_path)
            from pathlib import Path

            Path(a.stored_path).unlink(missing_ok=True)
        except Exception:
            pass
    audit(db, user.username, "analysis.delete", aid, {"title": a.title, "note": "local WOLVE record only"})
    db.delete(a)
    db.commit()
    return {"ok": True, "message": "Local WOLVE record deleted. No external mailbox was modified."}


@router.get("/analyses/{aid}/export")
def export_analysis(aid: str, format: str = "html", db: Session = Depends(get_db), user: User = Depends(current_user)):
    a = db.get(Analysis, aid)
    if not a:
        raise HTTPException(404, "Analysis not found")
    audit(db, user.username, "analysis.export", aid, {"format": format})
    db.commit()
    if format == "json":
        return JSONResponse(ser_analysis(a, full=True), headers={"Content-Disposition": f'attachment; filename="{a.id}.json"'})
    rep = a.report
    e = html.escape

    def rows(fs):
        return "".join(f"<tr><td>{e(f['severity'])}</td><td>{e(f['source'])}</td><td><b>{e(f['title'])}</b><br>{e(f['detail'])}"
                       f"{'<br><code>' + e(f['evidence']) + '</code>' if f.get('evidence') else ''}</td></tr>" for f in fs)

    ai = (rep.get("ai") or {}).get("assessment")
    body = f"""<!doctype html><html><head><meta charset="utf-8"><title>WOLVE AI report {e(a.id)}</title>
<style>body{{font-family:Segoe UI,Arial,sans-serif;max-width:900px;margin:30px auto;color:#111}}h1{{color:#0b3d91}}table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #ccc;padding:6px;vertical-align:top;font-size:13px}}.badge{{display:inline-block;padding:4px 10px;border-radius:4px;background:#222;color:#fff}}</style></head><body>
<h1>WOLVE AI — Threat Analysis Report</h1>
<p><b>ID:</b> {e(a.id)} · <b>Type:</b> {e(a.kind)} · <b>Created:</b> {e(a.created_at.isoformat())} · <b>Submitted by:</b> {e(a.submitted_by)}</p>
<h2>{e(a.title)}</h2>
<p><span class="badge">{e(a.severity.upper())}</span> Risk score <b>{a.risk_score}/100</b> · Classification <b>{e(a.classification)}</b> · Confidence <b>{e(a.confidence)}</b></p>
<p><i>{e(rep.get('score_note', ''))}</i></p>
{'<h3>AI explanation (model-generated)</h3><p>' + e(ai['summary']) + '</p>' if ai else ''}
<h3>Verified technical findings</h3><table><tr><th>Severity</th><th>Source</th><th>Finding</th></tr>{rows(rep.get('verified_findings', []))}</table>
<h3>Heuristic findings</h3><table><tr><th>Severity</th><th>Source</th><th>Finding</th></tr>{rows(rep.get('heuristic_findings', []))}</table>
<h3>Recommended actions</h3><ul>{''.join(f'<li>{e(r)}</li>' for r in rep.get('recommended_actions', []))}</ul>
<h3>Limitations</h3><ul>{''.join(f'<li>{e(r)}</li>' for r in rep.get('limitations', []))}</ul>
<hr><small>Generated by WOLVE AI. Detection is evidence-based and cannot guarantee that every attack is identified.</small></body></html>"""
    return HTMLResponse(body, headers={"Content-Disposition": f'attachment; filename="{a.id}.html"'})
