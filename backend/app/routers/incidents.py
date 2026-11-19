from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import current_user, iso, require, ser_analysis, ser_event, ser_incident
from ..models import Analysis, EndpointEvent, Incident, Indicator, ResponseAction, User
from ..services.store import add_event, audit

router = APIRouter(prefix="/api/incidents", tags=["incidents"])

STATUSES = "^(open|investigating|contained|resolved|false_positive)$"
SEVERITIES = "^(low|medium|high|critical)$"


@router.get("")
def list_incidents(status: str | None = None, severity: str | None = None, assigned_to: str | None = None, q: str | None = None,
                   db: Session = Depends(get_db), user: User = Depends(current_user)):
    stmt = select(Incident).order_by(Incident.created_at.desc())
    if status:
        stmt = stmt.where(Incident.status.in_(status.split(",")))
    if severity:
        stmt = stmt.where(Incident.severity.in_(severity.split(",")))
    if assigned_to:
        stmt = stmt.where(Incident.assigned_to == assigned_to)
    if q:
        stmt = stmt.where(Incident.title.ilike(f"%{q}%"))
    return [ser_incident(i) for i in db.scalars(stmt.limit(500)).all()]


@router.get("/{iid}")
def get_incident(iid: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    inc = db.get(Incident, iid)
    if not inc:
        raise HTTPException(404, "Incident not found")
    analyses = db.scalars(select(Analysis).where(Analysis.incident_id == iid)).all()
    events = db.scalars(select(EndpointEvent).where(EndpointEvent.incident_id == iid)).all()
    a_ids = [a.id for a in analyses]
    e_ids = [e.id for e in events]
    inds = []
    if a_ids or e_ids:
        rows = db.scalars(select(Indicator).where((Indicator.analysis_id.in_(a_ids)) | (Indicator.endpoint_event_id.in_(e_ids)))).all()
        seen = set()
        for r in rows:
            k = (r.type, r.value)
            if k in seen:
                continue
            seen.add(k)
            inds.append({"id": r.id, "type": r.type, "value": r.value, "role": r.role, "malicious": r.malicious, "reviewed": r.reviewed})
    actions = db.scalars(select(ResponseAction).where(ResponseAction.target_id.in_([iid, *a_ids])).order_by(ResponseAction.created_at.desc())).all()
    return {**ser_incident(inc, full=True), "analyses": [ser_analysis(a) for a in analyses], "endpoint_events": [ser_event(e) for e in events],
            "indicators": inds, "actions": [{"action": x.action, "actor": x.actor, "result": x.result, "simulated": x.simulated,
                                             "created_at": iso(x.created_at)} for x in actions]}


class IncidentIn(BaseModel):
    title: str = Field(min_length=3, max_length=400)
    severity: str = Field(pattern=SEVERITIES)
    summary: str = Field(default="", max_length=5000)
    analysis_id: str | None = None


@router.post("")
def create_incident(body: IncidentIn, db: Session = Depends(get_db), user: User = Depends(require("analyst"))):
    inc = Incident(title=body.title, severity=body.severity, source="Manual", summary=body.summary,
                   recommended_response=["Triage the evidence and assign an owner."])
    db.add(inc)
    db.flush()
    add_event(db, inc, "created", f"Incident created manually by {user.full_name}.", user.username)
    if body.analysis_id:
        a = db.get(Analysis, body.analysis_id)
        if not a:
            raise HTTPException(404, "Linked analysis not found")
        a.incident_id = inc.id
        inc.risk_score = a.risk_score
        add_event(db, inc, "evidence", f"Linked analysis {a.id}: {a.title}", user.username)
    audit(db, user.username, "incident.create", inc.id, {"manual": True})
    db.commit()
    return ser_incident(inc, full=True)


class IncidentPatch(BaseModel):
    status: str | None = Field(default=None, pattern=STATUSES)
    severity: str | None = Field(default=None, pattern=SEVERITIES)
    assigned_to: str | None = Field(default=None, max_length=80)
    note: str | None = Field(default=None, max_length=5000)


@router.patch("/{iid}")
def update_incident(iid: str, body: IncidentPatch, db: Session = Depends(get_db), user: User = Depends(require("analyst"))):
    inc = db.get(Incident, iid)
    if not inc:
        raise HTTPException(404, "Incident not found")
    changes = {}
    if body.status and body.status != inc.status:
        if body.status in ("resolved", "false_positive") and not body.note:
            raise HTTPException(422, "A resolution note is required to resolve or close an incident.")
        add_event(db, inc, "status", f"Status {inc.status} → {body.status}", user.username)
        changes["status"] = [inc.status, body.status]
        inc.status = body.status
    if body.severity and body.severity != inc.severity:
        add_event(db, inc, "status", f"Severity {inc.severity} → {body.severity}", user.username)
        changes["severity"] = [inc.severity, body.severity]
        inc.severity = body.severity
    if body.assigned_to is not None and body.assigned_to != inc.assigned_to:
        add_event(db, inc, "assignment", f"Assigned to {body.assigned_to or 'nobody'}", user.username)
        changes["assigned_to"] = [inc.assigned_to, body.assigned_to]
        inc.assigned_to = body.assigned_to or None
    if body.note:
        add_event(db, inc, "note", body.note, user.username)
        changes["note"] = True
    if not changes:
        raise HTTPException(422, "No changes supplied")
    audit(db, user.username, "incident.update", iid, changes)
    db.commit()
    return ser_incident(inc, full=True)


@router.post("/{iid}/escalate")
def escalate(iid: str, db: Session = Depends(get_db), user: User = Depends(require("analyst"))):
    inc = db.get(Incident, iid)
    if not inc:
        raise HTTPException(404, "Incident not found")
    inc.escalated = True
    if inc.status == "open":
        inc.status = "investigating"
    msg = "Escalated to SOC lead / CISO queue (WOLVE notification centre). No external email/SMS/paging integration is configured."
    add_event(db, inc, "escalation", f"{user.full_name}: {msg}", user.username)
    db.add(ResponseAction(action="incident.escalate", target_type="incident", target_id=iid, actor=user.username, simulated=False, result=msg))
    audit(db, user.username, "incident.escalate", iid)
    db.commit()
    return {"ok": True, "message": msg, "incident": ser_incident(inc)}
