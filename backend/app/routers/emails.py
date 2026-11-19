"""Email Security workflow. Actions operate on WOLVE's local records only — there is no live
Microsoft 365 / Google Workspace connection in the MVP (see integrations status)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import ROLE_RANK, current_user, rate_limit, ser_analysis
from ..models import Analysis, ResponseAction, User
from ..services import pipeline
from ..services.store import add_event, audit, build_context, create_incident_from_analysis, save_result
from .analyze import read_upload

router = APIRouter(prefix="/api/emails", tags=["email"])


@router.post("/analyze", dependencies=[Depends(rate_limit)])
async def analyze_email(file: UploadFile | None = File(default=None), raw: str | None = Form(default=None),
                        db: Session = Depends(get_db), user: User = Depends(current_user)):
    if file is not None and file.filename:
        data, name = await read_upload(file)
        if not name.lower().endswith((".eml", ".txt", ".msg")):
            raise HTTPException(415, "Upload a .eml file (or paste the raw email).")
        if name.lower().endswith(".msg"):
            raise HTTPException(415, "Outlook .msg files are not supported yet — in Outlook use 'Save as' → .eml, or paste the message source.")
        source = data
    elif raw and raw.strip():
        if len(raw) > 2_000_000:
            raise HTTPException(413, "Pasted email too large.")
        source = raw
    else:
        raise HTTPException(422, "Provide an .eml file or paste the email source/body.")
    res = pipeline.run_email(source, build_context(db))
    a = save_result(db, res, user.username)
    db.commit()
    db.refresh(a)
    return ser_analysis(a, full=True)


@router.get("")
def list_emails(status: str | None = None, db: Session = Depends(get_db), user: User = Depends(current_user)):
    stmt = select(Analysis).where(Analysis.kind == "email").order_by(Analysis.created_at.desc())
    if status:
        stmt = stmt.where(Analysis.status == status)
    return [ser_analysis(a) for a in db.scalars(stmt.limit(300)).all()]


class EmailAction(BaseModel):
    action: str = Field(pattern="^(mark_suspicious|quarantine|release|mark_safe|report)$")
    note: str | None = Field(default=None, max_length=2000)


ACTION_ROLE = {"mark_suspicious": "employee", "report": "employee", "quarantine": "analyst", "release": "analyst", "mark_safe": "analyst"}
ACTION_STATUS = {"mark_suspicious": "suspicious", "quarantine": "quarantined", "release": "suspicious", "mark_safe": "safe", "report": "reported"}


@router.post("/{aid}/action")
def email_action(aid: str, body: EmailAction, db: Session = Depends(get_db), user: User = Depends(current_user)):
    a = db.get(Analysis, aid)
    if not a or a.kind != "email":
        raise HTTPException(404, "Email analysis not found")
    need = ACTION_ROLE[body.action]
    if ROLE_RANK[user.role] < ROLE_RANK[need]:
        raise HTTPException(403, f"'{body.action}' requires the {need} role.")
    if body.action == "mark_safe" and a.risk_score >= 80 and not body.note:
        raise HTTPException(422, "Marking a critical-risk email as safe requires a review note.")
    old = a.status
    if body.action == "report" and old == "quarantined":
        a.status = "quarantined"
    else:
        a.status = ACTION_STATUS[body.action]
    msg = {
        "quarantine": "Email moved to WOLVE quarantine (local record). Not removed from any external mailbox — no mail integration is connected.",
        "release": "Email released from WOLVE quarantine.",
        "mark_safe": "Email marked safe after analyst review.",
        "mark_suspicious": "Email marked as suspicious.",
        "report": "Reported to IT security: an incident was opened/updated in WOLVE.",
    }[body.action]
    if body.action == "report" and not a.incident_id:
        create_incident_from_analysis(db, a, actor=user.username)
    if a.incident_id:
        from ..models import Incident

        inc = db.get(Incident, a.incident_id)
        if inc:
            add_event(db, inc, "action", f"{user.full_name}: {msg}" + (f" Note: {body.note}" if body.note else ""), user.username)
            if body.action == "mark_safe" and inc.status not in ("resolved",):
                inc.status = "false_positive"
                add_event(db, inc, "status", "Incident marked false positive after email was reviewed as safe.", user.username)
    db.add(ResponseAction(action=f"email.{body.action}", target_type="email", target_id=a.id, actor=user.username, simulated=False,
                          result=msg))
    audit(db, user.username, f"email.{body.action}", a.id, {"from": old, "to": a.status, "note": body.note})
    db.commit()
    return {"ok": True, "message": msg, "analysis": ser_analysis(a)}
