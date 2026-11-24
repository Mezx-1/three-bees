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


# ---------------------------------------------------------------- Firebase sign-in

class FirebaseIn(BaseModel):
    id_token: str = Field(min_length=20, max_length=5000)


@router.post("/auth/firebase", dependencies=[Depends(_login_limit)])
def firebase_login(body: FirebaseIn, request: Request, db: Session = Depends(get_db)):
    """Exchange a verified Firebase ID token for a 3B session.

    The account is matched by its (verified) email. A first-time Firebase user gets the lowest role (employee);
    only a 3B administrator can raise it. Nothing the browser sends decides the role."""
    import re

    from ..models import Organization
    from ..services.cloud import FirebaseTokenError, verify_firebase_token

    ip = request.client.host if request.client else None
    try:
        claims = verify_firebase_token(body.id_token)
    except FirebaseTokenError as exc:
        audit(db, "firebase", "auth.firebase_failed", "", {"reason": str(exc)}, ip=ip)
        db.commit()
        raise HTTPException(401, str(exc))
    email = claims["email"].strip().lower()
    user = db.scalars(select(User).where(User.email.ilike(email))).first()
    if user is not None and not claims.get("email_verified"):
        # Anyone can create a Firebase account with someone else's address; only a verified address may
        # take over an existing 3B account (and its role).
        audit(db, user.username, "auth.firebase_unverified_email", "", {"uid": claims["sub"]}, ip=ip)
        db.commit()
        raise HTTPException(403, "Verify your email address first (check your inbox), then sign in again.")
    if user is None:
        base = re.sub(r"[^a-z0-9._-]", "", email.split("@")[0])[:60] or "user"
        name, n = base, 1
        while db.scalars(select(User).where(User.username == name)).first():
            n += 1
            name = f"{base}{n}"
        org = db.scalars(select(Organization)).first()
        user = User(username=name, full_name=claims.get("name") or email.split("@")[0], email=email, role="employee",
                    organization_id=org.id, password_hash=None)
        db.add(user)
        db.flush()
        audit(db, user.username, "auth.firebase_user_created", "", {"uid": claims["sub"]}, ip=ip)
    token = create_session(db, user)
    audit(db, user.username, "auth.login", "", {"method": "firebase", "uid": claims["sub"]}, ip=ip)
    db.commit()
    return {"token": token, "user": ser_user(user)}


@router.get("/auth/providers")
def auth_providers():
    """Which sign-in methods this server accepts (public: the login page needs it)."""
    from ..config import settings

    return {"password": True, "firebase": bool(settings.firebase_project_id)}
