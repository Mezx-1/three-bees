from __future__ import annotations

import secrets

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import current_user, require, ser_device, ser_event
from ..models import Device, EndpointEvent, Incident, ResponseAction, User, utcnow
from ..services.endpoint_engine import ingest_event
from ..services.store import add_event, audit

router = APIRouter(prefix="/api/endpoints", tags=["endpoints"])

EVENT_TYPES = "^(process|network_connection|file|login|heartbeat)$"


class DeviceIn(BaseModel):
    hostname: str = Field(min_length=1, max_length=200)
    os: str = Field(default="unknown", max_length=200)
    owner_email: str | None = Field(default=None, max_length=200)
    ip_address: str | None = Field(default=None, max_length=64)


class AgentRegisterIn(DeviceIn):
    agent_version: str = Field(default="0.1.0", max_length=40)
    system_info: dict = Field(default_factory=dict)
    consent: bool = Field(description="The device user agreed to WOLVE monitoring")


class EventIn(BaseModel):
    event_type: str = Field(pattern=EVENT_TYPES)
    title: str = Field(min_length=1, max_length=300)
    details: dict = Field(default_factory=dict)


@router.get("")
def list_devices(db: Session = Depends(get_db), user: User = Depends(current_user)):
    return [ser_device(d) for d in db.scalars(select(Device).order_by(Device.risk_score.desc(), Device.hostname)).all()]


@router.post("")
def add_device(body: DeviceIn, db: Session = Depends(get_db), user: User = Depends(require("analyst"))):
    d = Device(hostname=body.hostname, os=body.os, owner_email=body.owner_email, ip_address=body.ip_address, source="manual")
    db.add(d)
    db.flush()
    audit(db, user.username, "device.register", d.id, {"hostname": d.hostname})
    db.commit()
    return {**ser_device(d), "token": d.token}


@router.get("/{device_id}")
def get_device(device_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    d = db.get(Device, device_id)
    if not d:
        raise HTTPException(404, "Device not found")
    events = db.scalars(select(EndpointEvent).where(EndpointEvent.device_id == d.id).order_by(EndpointEvent.created_at.desc()).limit(200)).all()
    return {**ser_device(d), "events": [ser_event(e) for e in events]}


@router.delete("/{device_id}")
def delete_device(device_id: str, db: Session = Depends(get_db), user: User = Depends(require("admin"))):
    d = db.get(Device, device_id)
    if not d:
        raise HTTPException(404, "Device not found")
    audit(db, user.username, "device.delete", device_id, {"hostname": d.hostname})
    db.delete(d)
    db.commit()
    return {"ok": True}


@router.post("/{device_id}/events/simulate")
def simulate_event(device_id: str, body: EventIn, db: Session = Depends(get_db), user: User = Depends(require("analyst"))):
    """Inject a SIMULATED endpoint event (clearly labelled) for demos and testing."""
    d = db.get(Device, device_id)
    if not d:
        raise HTTPException(404, "Device not found")
    ev, corr = ingest_event(db, d, body.event_type, body.title, body.details, simulated=True, actor=user.username)
    db.commit()
    return {"event": ser_event(ev), "correlation": corr, "device": ser_device(d)}


@router.post("/{device_id}/recommend-isolation")
def recommend_isolation(device_id: str, db: Session = Depends(get_db), user: User = Depends(require("analyst"))):
    d = db.get(Device, device_id)
    if not d:
        raise HTTPException(404, "Device not found")
    d.status = "isolation_recommended"
    msg = (f"Isolation recommended for {d.hostname}. WOLVE does not control the network in this MVP — "
           "IT must isolate the device via EDR/NAC or by disconnecting it.")
    db.add(ResponseAction(action="endpoint.recommend_isolation", target_type="device", target_id=d.id, actor=user.username, simulated=False, result=msg))
    for inc_id in {e.incident_id for e in d.events if e.incident_id}:
        inc = db.get(Incident, inc_id)
        if inc:
            add_event(db, inc, "action", f"{user.full_name}: {msg}", user.username)
    audit(db, user.username, "endpoint.recommend_isolation", d.id)
    db.commit()
    return {"ok": True, "message": msg, "device": ser_device(d)}


@router.post("/{device_id}/mark-healthy")
def mark_healthy(device_id: str, db: Session = Depends(get_db), user: User = Depends(require("analyst"))):
    d = db.get(Device, device_id)
    if not d:
        raise HTTPException(404, "Device not found")
    d.status, d.risk_score = "healthy", 0
    audit(db, user.username, "endpoint.mark_healthy", d.id)
    db.commit()
    return {"ok": True, "device": ser_device(d)}


# ---- real agent API (device token auth) ---------------------------------------------------

agent_router = APIRouter(prefix="/api/agent", tags=["agent"])


@agent_router.post("/register")
def agent_register(body: AgentRegisterIn, db: Session = Depends(get_db), user: User = Depends(require("admin"))):
    """Called by the WOLVE agent installer with an admin enrolment identity. Returns the device token."""
    if not body.consent:
        raise HTTPException(422, "Device user consent is required before WOLVE monitoring can be enabled.")
    d = db.scalars(select(Device).where(Device.hostname == body.hostname, Device.source == "agent")).first()
    if not d:
        d = Device(hostname=body.hostname, source="agent")
        db.add(d)
    d.os, d.owner_email, d.ip_address = body.os, body.owner_email, body.ip_address
    d.agent_version, d.system_info, d.last_seen = body.agent_version, body.system_info, utcnow()
    d.token = secrets.token_urlsafe(24)
    db.flush()
    audit(db, user.username, "agent.register", d.id, {"hostname": d.hostname, "consent": True})
    db.commit()
    return {"device_id": d.id, "token": d.token}


def _agent_device(db: Session, token: str | None) -> Device:
    if not token:
        raise HTTPException(401, "Missing X-Device-Token")
    d = db.scalars(select(Device).where(Device.token == token)).first()
    if not d:
        raise HTTPException(401, "Invalid device token")
    return d


@agent_router.post("/heartbeat")
def agent_heartbeat(system_info: dict | None = None, x_device_token: str | None = Header(default=None), db: Session = Depends(get_db)):
    d = _agent_device(db, x_device_token)
    d.last_seen = utcnow()
    if system_info:
        d.system_info = {**(d.system_info or {}), **system_info}
    if d.status == "offline":
        d.status = "healthy"
    db.commit()
    return {"ok": True, "status": d.status}


@agent_router.post("/events")
def agent_events(events: list[EventIn], x_device_token: str | None = Header(default=None), db: Session = Depends(get_db)):
    d = _agent_device(db, x_device_token)
    if len(events) > 200:
        raise HTTPException(413, "Max 200 events per batch")
    d.last_seen = utcnow()
    out = []
    for e in events:
        ev, corr = ingest_event(db, d, e.event_type, e.title, e.details, simulated=bool(e.details.get("simulated")), actor=f"agent:{d.hostname}")
        out.append({"event_id": ev.id, "risk_score": ev.risk_score, "incident_id": corr.get("incident_id")})
    db.commit()
    return {"ingested": len(out), "results": out}
