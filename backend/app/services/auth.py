"""Password hashing, sessions and one-time pairing codes."""
from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..models import AuthSession, PairingCode, User, utcnow

_N, _R, _P = 2 ** 14, 8, 1
PAIR_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"  # no 0/O/1/I/L


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=32)
    return f"scrypt${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str | None) -> bool:
    if not stored or not stored.startswith("scrypt$"):
        # Still spend the same work so missing users are not distinguishable by timing.
        hashlib.scrypt(password.encode(), salt=b"0" * 16, n=_N, r=_R, p=_P, dklen=32)
        return False
    _, salt_hex, digest_hex = stored.split("$", 2)
    digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex), n=_N, r=_R, p=_P, dklen=32)
    return hmac.compare_digest(digest.hex(), digest_hex)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def create_session(db: Session, user: User) -> str:
    token = secrets.token_urlsafe(32)
    db.add(AuthSession(token_hash=_sha(token), user_id=user.id, expires_at=utcnow() + timedelta(hours=settings.session_hours)))
    return token


def user_for_token(db: Session, token: str) -> User | None:
    s = db.scalars(select(AuthSession).where(AuthSession.token_hash == _sha(token))).first()
    if not s or _aware(s.expires_at) < utcnow():
        return None
    return db.get(User, s.user_id)


def end_session(db: Session, token: str) -> None:
    s = db.scalars(select(AuthSession).where(AuthSession.token_hash == _sha(token))).first()
    if s:
        db.delete(s)


def new_pairing_code(db: Session, purpose: str, created_by: str, minutes: int = 15) -> tuple[str, datetime]:
    code = "".join(secrets.choice(PAIR_ALPHABET) for _ in range(8))
    expires = utcnow() + timedelta(minutes=minutes)
    db.add(PairingCode(code_hash=_sha(code), purpose=purpose, created_by=created_by, expires_at=expires))
    return code, expires


def redeem_pairing_code(db: Session, code: str, purpose: str) -> PairingCode | None:
    clean = "".join(ch for ch in (code or "").upper() if ch.isalnum())
    pc = db.scalars(select(PairingCode).where(PairingCode.code_hash == _sha(clean), PairingCode.purpose == purpose)).first()
    if not pc or pc.used_at or _aware(pc.expires_at) < utcnow():
        return None
    pc.used_at = utcnow()
    return pc
