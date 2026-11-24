"""Cloudflare Turnstile and Firebase Authentication checks, done on the server.

Turnstile: the browser gets a token from Cloudflare's widget; the backend asks Cloudflare whether it is valid.
  Without CLOUDFLARE_TURNSTILE_SECRET_KEY the check is skipped and the app says so ("not_configured").
Firebase: the browser signs in with Firebase (email + password) and sends the Firebase ID token once; the backend
  verifies its RS256 signature against Google's published certificates, the audience (project ID), the issuer and
  the expiry, then issues a normal 3B session. The role is never taken from the browser — it comes from 3B's users
  table, where only an administrator can change it.
"""
from __future__ import annotations

import logging
import threading
import time

import httpx

from ..config import settings

log = logging.getLogger("threebees.cloud")

# ---------------------------------------------------------------- Turnstile

TURNSTILE_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
_turnstile_health: dict = {}


def turnstile_verify(token: str | None, ip: str | None = None, *, client: httpx.Client | None = None) -> dict:
    """{"ok": bool, "skipped": bool, "errors": [...]}. Fails closed when configured; skipped when not."""
    if not settings.turnstile_secret_key:
        return {"ok": True, "skipped": True, "errors": []}
    if not token:
        return {"ok": False, "skipped": False, "errors": ["missing-input-response"]}
    own = client is None
    client = client or httpx.Client(timeout=6.0)
    try:
        r = client.post(TURNSTILE_URL, data={"secret": settings.turnstile_secret_key, "response": token, **({"remoteip": ip} if ip else {})})
        j = r.json()
        errors = j.get("error-codes", [])
        _turnstile_health.update(last_check=time.time(), secret_ok="invalid-input-secret" not in errors, reachable=True)
        return {"ok": bool(j.get("success")), "skipped": False, "errors": errors}
    except Exception as exc:
        _turnstile_health.update(last_check=time.time(), reachable=False)
        log.warning("Turnstile verification failed: %s", exc.__class__.__name__)
        return {"ok": False, "skipped": False, "errors": ["verification-unavailable"]}
    finally:
        if own:
            client.close()


def turnstile_status(probe: bool = False) -> dict:
    if not settings.turnstile_secret_key:
        return {"status": "not_configured"}
    if probe:  # a deliberately invalid token: Cloudflare answers "invalid-input-response" if our secret is good
        turnstile_verify("health-check-invalid-token")
    h = _turnstile_health
    if not h:
        return {"status": "unknown"}
    if not h.get("reachable"):
        return {"status": "unavailable"}
    return {"status": "connected" if h.get("secret_ok") else "unavailable", "detail": None if h.get("secret_ok") else "Secret key rejected"}


# ---------------------------------------------------------------- Firebase ID tokens

CERTS_URL = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"
_certs: dict = {"expires": 0.0, "keys": {}}
_certs_lock = threading.Lock()


def _google_certs(client: httpx.Client | None = None) -> dict:
    with _certs_lock:
        if _certs["keys"] and _certs["expires"] > time.time():
            return _certs["keys"]
    own = client is None
    client = client or httpx.Client(timeout=6.0)
    try:
        r = client.get(CERTS_URL)
        r.raise_for_status()
        max_age = 3600
        for part in r.headers.get("cache-control", "").split(","):
            if part.strip().startswith("max-age="):
                max_age = int(part.strip()[8:])
        with _certs_lock:
            _certs.update(keys=r.json(), expires=time.time() + max_age)
            return _certs["keys"]
    finally:
        if own:
            client.close()


class FirebaseTokenError(Exception):
    pass


def verify_firebase_token(id_token: str, *, client: httpx.Client | None = None) -> dict:
    """Return the verified claims (uid, email, email_verified …) or raise FirebaseTokenError."""
    import jwt
    from cryptography.x509 import load_pem_x509_certificate

    project = settings.firebase_project_id
    if not project:
        raise FirebaseTokenError("Firebase sign-in is not configured on this server.")
    try:
        header = jwt.get_unverified_header(id_token)
    except jwt.PyJWTError:
        raise FirebaseTokenError("Malformed token.")
    if header.get("alg") != "RS256":
        raise FirebaseTokenError("Unexpected token algorithm.")
    try:
        certs = _google_certs(client)
    except Exception:
        raise FirebaseTokenError("Could not reach Google to verify the token.")
    pem = certs.get(header.get("kid", ""))
    if not pem:
        raise FirebaseTokenError("Unknown signing key.")
    key = load_pem_x509_certificate(pem.encode()).public_key()
    try:
        claims = jwt.decode(id_token, key, algorithms=["RS256"], audience=project, issuer=f"https://securetoken.google.com/{project}",
                            options={"require": ["exp", "iat", "sub", "aud", "iss"]}, leeway=30)
    except jwt.ExpiredSignatureError:
        raise FirebaseTokenError("Sign-in expired, please sign in again.")
    except jwt.PyJWTError as exc:
        raise FirebaseTokenError(f"Invalid sign-in token ({exc.__class__.__name__}).")
    if not claims.get("sub"):
        raise FirebaseTokenError("Token has no user.")
    if not claims.get("email"):
        raise FirebaseTokenError("The Firebase account has no email address.")
    return claims


def firebase_status(probe: bool = False) -> dict:
    if not settings.firebase_project_id:
        return {"status": "not_configured"}
    if probe:
        try:
            _certs.update(expires=0.0)
            _google_certs()
            return {"status": "connected", "project": settings.firebase_project_id}
        except Exception:
            return {"status": "unavailable", "project": settings.firebase_project_id, "detail": "Google certificates unreachable"}
    return {"status": "connected" if _certs["keys"] else "unknown", "project": settings.firebase_project_id}
