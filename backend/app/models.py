"""Database models.

All analyses (email, message, URL, IP, phone, file, media) share one `analyses` table keyed by
`kind`, with the full structured report stored as JSON. Indicators extracted from analyses and
endpoint events live in `indicators` and are what the correlation engine joins on.
"""
from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10].upper()}"


class Organization(Base):
    __tablename__ = "organizations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    domain: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True)
    full_name: Mapped[str] = mapped_column(String(200))
    email: Mapped[str] = mapped_column(String(200))
    role: Mapped[str] = mapped_column(String(20))  # admin | analyst | employee
    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"))
    password_hash: Mapped[str | None] = mapped_column(String(200), nullable=True)


class AuthSession(Base):
    """Signed-in session. Only a SHA-256 hash of the bearer token is stored."""

    __tablename__ = "auth_sessions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class PairingCode(Base):
    """One-time code that lets a phone or laptop agent join 3B (replaces trusting a user name)."""

    __tablename__ = "pairing_codes"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    code_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    purpose: Mapped[str] = mapped_column(String(10))  # phone | agent
    created_by: Mapped[str] = mapped_column(String(80))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Device(Base):
    __tablename__ = "devices"
    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("DEV"))
    hostname: Mapped[str] = mapped_column(String(200))
    os: Mapped[str] = mapped_column(String(200), default="unknown")
    owner_email: Mapped[str | None] = mapped_column(String(200), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    agent_version: Mapped[str] = mapped_column(String(40), default="none")
    # "agent" = registered by the real 3B agent; "simulated" = demo device; "manual" = inventory entry
    source: Mapped[str] = mapped_column(String(20), default="manual")
    status: Mapped[str] = mapped_column(String(20), default="healthy")  # healthy|at_risk|compromised|isolation_recommended|offline
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    token: Mapped[str] = mapped_column(String(80), default=lambda: secrets.token_urlsafe(24))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    system_info: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    events: Mapped[list["EndpointEvent"]] = relationship(back_populates="device", cascade="all, delete-orphan")


class EndpointEvent(Base):
    __tablename__ = "endpoint_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"))
    event_type: Mapped[str] = mapped_column(String(40))  # process|network_connection|file|heartbeat|login
    severity: Mapped[str] = mapped_column(String(20), default="low")
    title: Mapped[str] = mapped_column(String(300))
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    simulated: Mapped[bool] = mapped_column(Boolean, default=False)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    findings: Mapped[list] = mapped_column(JSON, default=list)
    incident_id: Mapped[str | None] = mapped_column(ForeignKey("incidents.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    device: Mapped[Device] = relationship(back_populates="events")


class Analysis(Base):
    __tablename__ = "analyses"
    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("ANL"))
    kind: Mapped[str] = mapped_column(String(20))  # email|message|url|ip|phone|domain|file|image|audio|video
    title: Mapped[str] = mapped_column(String(400))
    classification: Mapped[str] = mapped_column(String(80))
    risk_score: Mapped[int] = mapped_column(Integer)
    severity: Mapped[str] = mapped_column(String(20))
    confidence: Mapped[str] = mapped_column(String(20))
    # email workflow state: new | suspicious | quarantined | safe | reported
    status: Mapped[str] = mapped_column(String(20), default="new")
    report: Mapped[dict] = mapped_column(JSON, default=dict)
    submitted_by: Mapped[str] = mapped_column(String(80), default="system")
    recipient: Mapped[str | None] = mapped_column(String(200), nullable=True)
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    stored_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    demo: Mapped[bool] = mapped_column(Boolean, default=False)
    incident_id: Mapped[str | None] = mapped_column(ForeignKey("incidents.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Indicator(Base):
    __tablename__ = "indicators"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    type: Mapped[str] = mapped_column(String(30))  # email|domain|url|ip|hash|phone|filename|device|person
    value: Mapped[str] = mapped_column(String(1000), index=True)
    analysis_id: Mapped[str | None] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), nullable=True)
    endpoint_event_id: Mapped[int | None] = mapped_column(ForeignKey("endpoint_events.id", ondelete="CASCADE"), nullable=True)
    role: Mapped[str] = mapped_column(String(40), default="observed")  # sender|reply_to|link|attachment|recipient|dest|process...
    malicious: Mapped[bool] = mapped_column(Boolean, default=False)
    reviewed: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class BlockedIndicator(Base):
    """Local demo blocklist. Enforced inside 3B analyses only — not pushed to any firewall/proxy."""

    __tablename__ = "blocklist"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    type: Mapped[str] = mapped_column(String(30))
    value: Mapped[str] = mapped_column(String(1000), index=True)
    reason: Mapped[str] = mapped_column(String(500), default="")
    added_by: Mapped[str] = mapped_column(String(80))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Incident(Base):
    __tablename__ = "incidents"
    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("INC"))
    title: Mapped[str] = mapped_column(String(400))
    severity: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(20), default="open")  # open|investigating|contained|resolved|false_positive
    source: Mapped[str] = mapped_column(String(80))
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    summary: Mapped[str] = mapped_column(Text, default="")
    ai_explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    recommended_response: Mapped[list] = mapped_column(JSON, default=list)
    assigned_to: Mapped[str | None] = mapped_column(String(80), nullable=True)
    escalated: Mapped[bool] = mapped_column(Boolean, default=False)
    correlated: Mapped[bool] = mapped_column(Boolean, default=False)
    demo: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    events: Mapped[list["IncidentEvent"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", order_by="IncidentEvent.created_at"
    )


class IncidentEvent(Base):
    __tablename__ = "incident_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"))
    event_type: Mapped[str] = mapped_column(String(40))  # created|evidence|correlation|status|assignment|note|action|escalation
    message: Mapped[str] = mapped_column(Text)
    actor: Mapped[str] = mapped_column(String(80), default="system")
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    incident: Mapped[Incident] = relationship(back_populates="events")


class ResponseAction(Base):
    __tablename__ = "response_actions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    action: Mapped[str] = mapped_column(String(60))
    target_type: Mapped[str] = mapped_column(String(40))
    target_id: Mapped[str] = mapped_column(String(1000))
    actor: Mapped[str] = mapped_column(String(80))
    simulated: Mapped[bool] = mapped_column(Boolean, default=False)
    result: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor: Mapped[str] = mapped_column(String(80))
    action: Mapped[str] = mapped_column(String(80))
    target: Mapped[str] = mapped_column(String(500), default="")
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Connection(Base):
    """A network connection observed by the endpoint agent (metadata only — never packet contents)."""

    __tablename__ = "connections"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    process_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    exe: Mapped[str | None] = mapped_column(String(500), nullable=True)
    pid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str] = mapped_column(String(8), default="tcp")
    direction: Mapped[str] = mapped_column(String(10), default="outbound")  # outbound | inbound
    local_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    remote_ip: Mapped[str] = mapped_column(String(64), index=True)
    remote_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    hits: Mapped[int] = mapped_column(Integer, default=1)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    flags: Mapped[list] = mapped_column(JSON, default=list)
    event_created: Mapped[bool] = mapped_column(Boolean, default=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class IpIntel(Base):
    """Cache of IP origin lookups (approximate geolocation / network owner) with source + timestamp."""

    __tablename__ = "ip_intel"
    ip: Mapped[str] = mapped_column(String(64), primary_key=True)
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    source: Mapped[str] = mapped_column(String(80), default="")
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AgentCommand(Base):
    """Response action queued for an endpoint agent (e.g. block an IP in Windows Firewall)."""

    __tablename__ = "agent_commands"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    type: Mapped[str] = mapped_column(String(40))
    params: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending|sent|done|failed|refused
    result: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(80))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AppSetting(Base):
    __tablename__ = "app_settings"
    key: Mapped[str] = mapped_column(String(80), primary_key=True)
    value: Mapped[str] = mapped_column(Text)


class ScamReport(Base):
    """A scam reported by a person. Not an official police complaint — 3B prepares, the person files.

    data_mode separates the two kinds of records that must never be mixed: "user" (submitted through the
    app) and "demo" (fictional records loaded with the Load demo data button)."""
    __tablename__ = "scam_reports"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    reference: Mapped[str] = mapped_column(String(40), unique=True, index=True)
    data_mode: Mapped[str] = mapped_column(String(10), default="user", index=True)  # user | demo
    category: Mapped[str] = mapped_column(String(40), index=True)
    channel: Mapped[str] = mapped_column(String(20), default="sms")  # sms|whatsapp|call|email|website|social|other
    phone: Mapped[str | None] = mapped_column(String(40), nullable=True, index=True)
    url: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    domain: Mapped[str | None] = mapped_column(String(253), nullable=True, index=True)
    message: Mapped[str] = mapped_column(Text, default="")
    description: Mapped[str] = mapped_column(Text, default="")
    incident_date: Mapped[str | None] = mapped_column(String(10), nullable=True)  # YYYY-MM-DD
    amount_lost: Mapped[int | None] = mapped_column(Integer, nullable=True)
    currency: Mapped[str] = mapped_column(String(3), default="AED")
    emirate: Mapped[str | None] = mapped_column(String(40), nullable=True)
    contact: Mapped[str | None] = mapped_column(String(200), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="submitted", index=True)  # submitted|under_review|escalated|resolved|rejected
    flagged: Mapped[bool] = mapped_column(Boolean, default=False)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    severity: Mapped[str] = mapped_column(String(20), default="low")
    analysis_id: Mapped[str | None] = mapped_column(ForeignKey("analyses.id", ondelete="SET NULL"), nullable=True)
    evidence_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    evidence_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    evidence_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    notes: Mapped[list] = mapped_column(JSON, default=list)  # [{by, at, text}]
    history: Mapped[list] = mapped_column(JSON, default=list)  # [{by, at, status}]
    reporter: Mapped[str] = mapped_column(String(80), default="anonymous")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


# ---------------------------------------------------------------- Scam Methods Knowledge Base
class ScamMethod(Base):
    """One known scam method. A knowledge source for the engine — never a rigid rule.

    review_status: draft | needs_review | verified. Only a reviewer can mark Verified, and only with a source."""
    __tablename__ = "scam_methods"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    category: Mapped[str] = mapped_column(String(40), index=True)
    data: Mapped[dict] = mapped_column(JSON, default=dict)  # full structured entry
    review_status: Mapped[str] = mapped_column(String(20), default="draft", index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    origin: Mapped[str] = mapped_column(String(20), default="seed")  # seed | admin | import | candidate
    created_by: Mapped[str] = mapped_column(String(80), default="system")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class ScamMethodVersion(Base):
    __tablename__ = "scam_method_versions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    method_id: Mapped[str] = mapped_column(String(40), index=True)
    version: Mapped[int] = mapped_column(Integer)
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    review_status: Mapped[str] = mapped_column(String(20))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    changed_by: Mapped[str] = mapped_column(String(80))
    note: Mapped[str] = mapped_column(String(500), default="")
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CandidatePattern(Base):
    """A possible new technique seen in a high-risk analysis with no close knowledge-base match.

    Stays a candidate until a reviewer turns it into a Draft method — never auto-promoted."""
    __tablename__ = "candidate_patterns"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[str | None] = mapped_column(String(40), nullable=True, index=True)
    excerpt: Mapped[str] = mapped_column(Text, default="")  # redacted: digits/links/emails masked
    intent: Mapped[dict] = mapped_column(JSON, default=dict)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(20), default="open")  # open | promoted | dismissed
    method_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# ---------------------------------------------------------------- Phone intelligence (caller ID)
class PhoneIntel(Base):
    """phone_intelligence: one row per normalised E.164 number. Verified facts and community data kept apart."""
    __tablename__ = "phone_intelligence"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    e164: Mapped[str] = mapped_column(String(20), index=True)
    data_mode: Mapped[str] = mapped_column(String(10), default="user", index=True)  # user | demo
    country_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    region: Mapped[str | None] = mapped_column(String(4), nullable=True)
    verified_business: Mapped[str | None] = mapped_column(String(200), nullable=True)  # set by an admin from a verified source only
    verified_source: Mapped[str | None] = mapped_column(String(300), nullable=True)
    community_labels: Mapped[dict] = mapped_column(JSON, default=dict)  # {category: count}
    report_count: Mapped[int] = mapped_column(Integer, default=0)
    distinct_reporters: Mapped[int] = mapped_column(Integer, default=0)
    review_status: Mapped[str] = mapped_column(String(20), default="unreviewed")  # unreviewed|confirmed_scam|legitimate|disputed
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_reported: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class PhoneReport(Base):
    """A community report about a phone number. Reporter identity is never shown to other users."""
    __tablename__ = "phone_reports"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    e164: Mapped[str] = mapped_column(String(20), index=True)
    data_mode: Mapped[str] = mapped_column(String(10), default="user", index=True)
    category: Mapped[str] = mapped_column(String(40))
    description: Mapped[str] = mapped_column(Text, default="")
    reporter_key: Mapped[str] = mapped_column(String(64), index=True)  # sha256(user or anonymous client), never shown
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending | accepted | rejected
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


# ---------------------------------------------------------------- Collective protection network
class ThreatIndicator(Base):
    """Shared threat intelligence. status: reported -> suspicious -> verified; revoked / allowlisted.

    A single report never reaches 'verified'. Only verified (block-eligible) and suspicious (warn-only)
    indicators are distributed to clients, as SHA-256 hashes of the normalised value."""
    __tablename__ = "threat_indicators"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    type: Mapped[str] = mapped_column(String(20), index=True)  # phone|email|email_domain|domain|url|ip|handle|payment
    value: Mapped[str] = mapped_column(String(1000), index=True)
    value_hash: Mapped[str] = mapped_column(String(64), index=True)
    data_mode: Mapped[str] = mapped_column(String(10), default="user", index=True)
    status: Mapped[str] = mapped_column(String(20), default="reported", index=True)
    category: Mapped[str] = mapped_column(String(40), default="other")
    confidence: Mapped[int] = mapped_column(Integer, default=10)  # 0-100, strength of evidence
    reasons: Mapped[list] = mapped_column(JSON, default=list)  # [{at, by, text}]
    report_count: Mapped[int] = mapped_column(Integer, default=0)
    reporter_keys: Mapped[list] = mapped_column(JSON, default=list)  # hashed, for distinct counting
    evidence_refs: Mapped[list] = mapped_column(JSON, default=list)  # report refs / analysis ids
    campaign_id: Mapped[str | None] = mapped_column(String(20), nullable=True)
    version: Mapped[int] = mapped_column(Integer, default=0, index=True)  # sync version of last change
    review_due: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class IndicatorEvent(Base):
    """Append-only audit trail; its id is the global sync version."""
    __tablename__ = "indicator_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    indicator_id: Mapped[int] = mapped_column(Integer, index=True)
    action: Mapped[str] = mapped_column(String(30))
    from_status: Mapped[str | None] = mapped_column(String(20), nullable=True)
    to_status: Mapped[str | None] = mapped_column(String(20), nullable=True)
    by: Mapped[str] = mapped_column(String(80))
    note: Mapped[str] = mapped_column(String(1000), default="")
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class IndicatorAppeal(Base):
    """False-positive report / appeal by a user or the owner of a number, email or domain."""
    __tablename__ = "indicator_appeals"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    indicator_id: Mapped[int] = mapped_column(Integer, index=True)
    reason: Mapped[str] = mapped_column(Text, default="")
    contact: Mapped[str | None] = mapped_column(String(200), nullable=True)
    submitted_by: Mapped[str] = mapped_column(String(80), default="anonymous")
    status: Mapped[str] = mapped_column(String(20), default="open")  # open | upheld | rejected
    decision_note: Mapped[str] = mapped_column(String(1000), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ProtectionPrefs(Base):
    __tablename__ = "protection_prefs"
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    prefs: Mapped[dict] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class UserListEntry(Base):
    """Personal blocked / trusted entries (numbers, emails, domains)."""
    __tablename__ = "user_list_entries"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    list: Mapped[str] = mapped_column(String(10))  # blocked | trusted
    type: Mapped[str] = mapped_column(String(20))
    value: Mapped[str] = mapped_column(String(500))
    note: Mapped[str] = mapped_column(String(200), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ProtectionEvent(Base):
    """Something 3B warned about or blocked for this user (shown under 'Recent protection events')."""
    __tablename__ = "protection_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    kind: Mapped[str] = mapped_column(String(20))  # warned | blocked | allowed_trusted
    channel: Mapped[str] = mapped_column(String(20))  # call | sms | email | url | message
    indicator_type: Mapped[str] = mapped_column(String(20))
    indicator_masked: Mapped[str] = mapped_column(String(200))
    reason: Mapped[str] = mapped_column(String(500))
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
