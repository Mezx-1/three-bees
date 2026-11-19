"""Sign-in, sign-out, password change and one-time pairing codes."""
from __future__ import annotations

import time
from collections import defaultdict, deque

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import current_user, iso, require
from ..models import User
from ..services.auth import create_session, end_session, hash_password, new_pairing_code, verify_password
from ..services.store import audit

router = APIRouter(prefix="/api", tags=["auth"])
_attempts: dict[str, deque] = defaultdict(deque)


def _login_limit(request: Request) -> None:
    """At most 10 sign-in attempts per minute per client address (slows password guessing)."""
    key = request.client.host if request.client else "?"
    now = time.monotonic()
    q = _attempts[key]
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= 10:
        raise HTTPException(429, "Too many sign-in attempts — wait a minute.")
    q.append(now)


def ser_user(u: User) -> dict:
    return {"username": u.username, "full_name": u.full_name, "role": u.role, "email": u.email}


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=200)


@router.post("/auth/login", dependencies=[Depends(_login_limit)])
def login(body: LoginIn, request: Request, db: Session = Depends(get_db)):
    user = db.scalars(select(User).where(User.username == body.username.strip().lower())).first()
    if not verify_password(body.password, user.password_hash if user else None) or not user:
        audit(db, body.username[:80], "auth.login_failed", "", {}, ip=request.client.host if request.client else None)
        db.commit()
        raise HTTPException(401, "Wrong user name or password.")
    token = create_session(db, user)
    audit(db, user.username, "auth.login", "", {}, ip=request.client.host if request.client else None)
    db.commit()
    return {"token": token, "user": ser_user(user)}


@router.post("/auth/logout")
def logout(authorization: str | None = Header(default=None), db: Session = Depends(get_db), user: User = Depends(current_user)):
    if authorization and authorization.lower().startswith("bearer "):
        end_session(db, authorization[7:].strip())
    audit(db, user.username, "auth.logout")
    db.commit()
    return {"ok": True}


@router.get("/auth/me")
def me(user: User = Depends(current_user)):
    return ser_user(user)


class PasswordIn(BaseModel):
    current_password: str = Field(min_length=1, max_length=200)
    new_password: str = Field(min_length=10, max_length=200)


@router.post("/auth/password")
def change_password(body: PasswordIn, db: Session = Depends(get_db), user: User = Depends(current_user)):
    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(401, "Current password is wrong.")
    user.password_hash = hash_password(body.new_password)
    audit(db, user.username, "auth.password_changed")
    db.commit()
    return {"ok": True}


class PairIn(BaseModel):
    purpose: str = Field(pattern="^(phone|agent)$")
    minutes: int = Field(default=15, ge=5, le=10080)  # up to 7 days, e.g. a code for Apple's App Review team


@router.post("/pairing-codes")
def create_pairing_code(body: PairIn, db: Session = Depends(get_db), user: User = Depends(require("analyst"))):
    code, expires = new_pairing_code(db, body.purpose, user.username, minutes=body.minutes)
    audit(db, user.username, "pairing.code_created", body.purpose, {"expires_at": iso(expires)})
    db.commit()
    return {"code": code, "purpose": body.purpose, "expires_at": iso(expires)}
