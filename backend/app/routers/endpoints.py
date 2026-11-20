from __future__ import annotations

import secrets

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import current_user, require, ser_device, ser_event
import ipaddress
import json

from ..deps import iso
from ..models import AgentCommand, Connection, Device, EndpointEvent, Incident, ResponseAction, User, utcnow
from ..services.connection_engine import device_summary, enrich_ips, ingest_connections, posture_findings
from ..services.endpoint_engine import ingest_event, score_event
from ..services.risk import combine
from ..services.store import add_event, audit, external_lookups_enabled, get_setting

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
    consent: bool = Field(description="The device user agreed to 3B monitoring")
    pairing_code: str = Field(min_length=6, max_length=20)


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
    msg = (f"Isolation recommended for {d.hostname}. 3B does not control the network in this MVP — "
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
def agent_register(body: AgentRegisterIn, db: Session = Depends(get_db)):
    """Called by the 3B agent with a one-time pairing code (created by an analyst). Returns the device token."""
    from ..services.auth import redeem_pairing_code

    if not body.consent:
        raise HTTPException(422, "Device user consent is required before 3B monitoring can be enabled.")
    pc = redeem_pairing_code(db, body.pairing_code, "agent")
    if not pc:
        raise HTTPException(401, "Pairing code is wrong, already used or expired.")
    d = db.scalars(select(Device).where(Device.hostname == body.hostname, Device.source == "agent")).first()
    if not d:
        d = Device(hostname=body.hostname, source="agent")
        db.add(d)
    d.os, d.owner_email, d.ip_address = body.os, body.owner_email, body.ip_address
    d.agent_version, d.system_info, d.last_seen = body.agent_version, body.system_info, utcnow()
    d.token = secrets.token_urlsafe(32)
    db.flush()
    audit(db, pc.created_by, "agent.register", d.id, {"hostname": d.hostname, "consent": True})
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
    skipped = 0
    for e in events:
        simulated = bool(e.details.get("simulated"))
        # Real telemetry: ordinary process starts are not stored — only ones that trip a detection rule.
        # (score < 25: e.g. a developer tool starting cmd.exe — too common on real machines to be useful as an alert)
        if not simulated and e.event_type == "process" and combine(score_event("process", e.details, {"ip": set(), "domain": set()})) < 25:
            skipped += 1
            continue
        ev, corr = ingest_event(db, d, e.event_type, e.title, e.details, simulated=bool(e.details.get("simulated")), actor=f"agent:{d.hostname}")
        out.append({"event_id": ev.id, "risk_score": ev.risk_score, "incident_id": corr.get("incident_id")})
    db.commit()
    return {"ingested": len(out), "skipped_benign": skipped, "results": out}


# ---- live connections, posture & response commands -----------------------------------------

class ConnIn(BaseModel):
    process_name: str | None = Field(default=None, max_length=200)
    pid: int | None = None
    exe: str | None = Field(default=None, max_length=500)
    protocol: str = Field(default="tcp", max_length=8)
    local_ip: str | None = Field(default=None, max_length=64)
    local_port: int | None = None
    remote_ip: str = Field(max_length=64)
    remote_port: int | None = None
    status: str = Field(default="", max_length=20)
    direction: str = Field(default="outbound", pattern="^(inbound|outbound)$")


class ConnBatch(BaseModel):
    connections: list[ConnIn] = Field(default_factory=list, max_length=1000)
    listening: list[dict] = Field(default_factory=list, max_length=500)
    collection_error: str | None = Field(default=None, max_length=500)


def ser_conn(c: Connection, origin: dict | None = None) -> dict:
    return {"id": c.id, "process_name": c.process_name, "exe": c.exe, "pid": c.pid, "protocol": c.protocol, "direction": c.direction,
            "local_port": c.local_port, "remote_ip": c.remote_ip, "remote_port": c.remote_port, "status": c.status, "active": c.active,
            "hits": c.hits, "risk_score": c.risk_score, "flags": c.flags, "first_seen": iso(c.first_seen), "last_seen": iso(c.last_seen),
            "origin": origin or {}}


@agent_router.post("/connections")
def agent_connections(body: ConnBatch, x_device_token: str | None = Header(default=None), db: Session = Depends(get_db)):
    d = _agent_device(db, x_device_token)
    d.last_seen = utcnow()
    res = ingest_connections(db, d, [c.model_dump() for c in body.connections], body.listening,
                             external=external_lookups_enabled(db), actor=f"agent:{d.hostname}", collection_error=body.collection_error)
    db.commit()
    return res


@agent_router.post("/posture")
def agent_posture(posture: dict, x_device_token: str | None = Header(default=None), db: Session = Depends(get_db)):
    d = _agent_device(db, x_device_token)
    info = dict(d.system_info or {})
    old_titles = {f["title"] for f in (info.get("posture_findings") or [])}
    findings = posture_findings(posture)
    info["posture"], info["posture_findings"] = posture, [f.to_dict() for f in findings]
    d.system_info = info
    for f in findings:  # raise an endpoint event only when a weakness newly appears
        if f.title not in old_titles:
            ingest_event(db, d, "posture", f.title, {"title": f.title, "finding": f.detail, "severity": f.severity, "weight": f.weight,
                                                     "source": "agent posture check"}, simulated=False, actor=f"agent:{d.hostname}")
    db.commit()
    return {"ok": True, "findings": len(findings)}


@agent_router.get("/commands")
def agent_commands(x_device_token: str | None = Header(default=None), db: Session = Depends(get_db)):
    d = _agent_device(db, x_device_token)
    cmds = db.scalars(select(AgentCommand).where(AgentCommand.device_id == d.id, AgentCommand.status == "pending")).all()
    for c in cmds:
        c.status = "sent"
    db.commit()
    return {"commands": [{"id": c.id, "type": c.type, "params": c.params} for c in cmds]}


class CmdResult(BaseModel):
    status: str = Field(pattern="^(done|failed|refused)$")
    result: str = Field(default="", max_length=20000)


@agent_router.post("/commands/{cid}/result")
def agent_command_result(cid: int, body: CmdResult, x_device_token: str | None = Header(default=None), db: Session = Depends(get_db)):
    d = _agent_device(db, x_device_token)
    c = db.get(AgentCommand, cid)
    if not c or c.device_id != d.id:
        raise HTTPException(404, "Command not found")
    c.status, c.result, c.completed_at = body.status, body.result, utcnow()
    if c.type == "list_rules" and body.status == "done":
        info = dict(d.system_info or {})
        try:
            info["threeb_firewall_rules"] = json.loads(body.result)
        except ValueError:
            info["threeb_firewall_rules"] = []
        info["threeb_firewall_rules_at"] = utcnow().isoformat()
        d.system_info = info
    db.add(ResponseAction(action=f"agent.{c.type}", target_type="device", target_id=d.id, actor=c.created_by, simulated=False,
                          result=f"{body.status}: {body.result} ({c.params})"))
    audit(db, f"agent:{d.hostname}", f"agent.command.{body.status}", str(cid), {"type": c.type, "params": c.params, "result": body.result})
    db.commit()
    return {"ok": True}


@router.get("/{device_id}/connections")
def device_connections(device_id: str, active: bool = True, db: Session = Depends(get_db), user: User = Depends(current_user)):
    d = db.get(Device, device_id)
    if not d:
        raise HTTPException(404, "Device not found")
    stmt = select(Connection).where(Connection.device_id == d.id)
    if active:
        stmt = stmt.where(Connection.active.is_(True))
    rows = db.scalars(stmt.order_by(Connection.risk_score.desc(), Connection.last_seen.desc()).limit(500)).all()
    origins = enrich_ips(db, {r.remote_ip for r in rows}, external=False)
    return {"connections": [ser_conn(r, origins.get(r.remote_ip)) for r in rows], "summary": device_summary(db, d),
            "listening": (d.system_info or {}).get("listening_ports", []), "updated_at": (d.system_info or {}).get("connections_updated_at"),
            "posture": (d.system_info or {}).get("posture"), "posture_findings": (d.system_info or {}).get("posture_findings", []),
            "collection_error": (d.system_info or {}).get("collection_error"), "external_lookups": external_lookups_enabled(db),
            "threeb_firewall_rules": (d.system_info or {}).get("threeb_firewall_rules"),
            "threeb_firewall_rules_at": (d.system_info or {}).get("threeb_firewall_rules_at")}


class CommandIn(BaseModel):
    type: str = Field(pattern="^(block_ip|unblock_ip|list_rules)$")
    ip: str | None = None
    confirm: bool = False  # block/unblock must be explicitly confirmed by the analyst


@router.post("/{device_id}/commands")
def queue_command(device_id: str, body: CommandIn, db: Session = Depends(get_db), user: User = Depends(require("analyst"))):
    d = db.get(Device, device_id)
    if not d:
        raise HTTPException(404, "Device not found")
    if d.source != "agent":
        raise HTTPException(422, "This device has no 3B agent installed, so it cannot receive commands.")
    params: dict = {}
    if body.type in ("block_ip", "unblock_ip"):
        if not body.confirm:
            raise HTTPException(422, "Firewall changes must be explicitly confirmed.")
        try:
            ipo = ipaddress.ip_address((body.ip or "").strip())
        except ValueError:
            raise HTTPException(422, "Invalid IP address")
        if ipo.is_private or ipo.is_loopback or ipo.is_unspecified or ipo.is_multicast or ipo.is_link_local or ipo.is_reserved:
            raise HTTPException(422, "Refusing to block a private, local or special-purpose address: it could cut the device off from its network or from 3B.")
        params = {"ip": str(ipo), "direction": "inbound+outbound", "rule_name": f"3B-block-{ipo}"}
    dup = db.scalars(select(AgentCommand).where(AgentCommand.device_id == d.id, AgentCommand.type == body.type,
                                                AgentCommand.status.in_(["pending", "sent"]))).all()
    dup = [x for x in dup if x.params.get("ip") == params.get("ip")]
    if dup:
        return {"ok": True, "id": dup[0].id, "duplicate": True, "message": "The same command is already waiting for the agent."}
    c = AgentCommand(device_id=d.id, type=body.type, params=params, created_by=user.username)
    db.add(c)
    audit(db, user.username, f"endpoint.command.{body.type}", d.id, params)
    db.commit()
    if body.type == "list_rules":
        return {"ok": True, "id": c.id, "message": f"Asked the agent on {d.hostname} to list 3B firewall rules (read-only)."}
    return {"ok": True, "id": c.id, "message": f"Command queued. The agent on {d.hostname} will run it on its next check-in (only if it was started with --allow-response)."}


@router.get("/{device_id}/commands")
def list_commands(device_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    rows = db.scalars(select(AgentCommand).where(AgentCommand.device_id == device_id).order_by(AgentCommand.created_at.desc()).limit(50)).all()
    return [{"id": c.id, "type": c.type, "params": c.params, "status": c.status, "result": c.result, "created_by": c.created_by,
             "created_at": iso(c.created_at), "completed_at": iso(c.completed_at)} for c in rows]
