"""Gemini, Turnstile and Firebase checks against MOCKED responses (test fixtures — not live results)."""
import json
import time

import httpx
import jwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient

from app.config import settings
from app.main import app
from app.services import ai, cloud

GOOD = {"classification": "otp_theft", "risk_score": 88, "confidence": "high", "summary": "Asks for the SMS code.",
        "social_engineering_techniques": ["authority"], "impersonated_entity": "a bank", "additional_indicators": [],
        "recommended_actions": ["Do not share the code"], "manipulation_indicators": [], "extracted_text": None}


def gemini_client(text):
    return httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"candidates": [{"content": {"parts": [{"text": text}]}, "finishReason": "STOP"}]})))


def test_gemini_valid_and_malformed(monkeypatch):
    monkeypatch.setattr(settings, "gemini_api_key", "test")
    status = {"available": True, "provider": "gemini", "model": "gemini-test", "reason": None}
    ok = ai._assess_gemini("send me the code", "sms", [], None, status, client=gemini_client(json.dumps(GOOD)))
    assert ok["assessment"]["classification"] == "otp_theft" and ok["error"] is None
    bad = ai._assess_gemini("x", "sms", [], None, status, client=gemini_client("I think it is a scam!"))
    assert bad["assessment"] is None and "malformed" in bad["error"]


def test_turnstile_skipped_when_not_configured_and_enforced_when_configured(monkeypatch):
    monkeypatch.setattr(settings, "turnstile_secret_key", None)
    assert cloud.turnstile_verify(None)["skipped"]
    monkeypatch.setattr(settings, "turnstile_secret_key", "secret")
    assert cloud.turnstile_verify(None)["ok"] is False
    good = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"success": True})))
    bad = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"success": False, "error-codes": ["invalid-input-response"]})))
    assert cloud.turnstile_verify("tok", client=good)["ok"] is True
    assert cloud.turnstile_verify("tok", client=bad)["ok"] is False


def test_report_rejected_without_turnstile_when_configured(monkeypatch):
    monkeypatch.setattr(settings, "turnstile_secret_key", "secret")
    with TestClient(app) as c:
        r = c.post("/api/reports", data={"category": "other", "description": "x", "privacy_ack": "true"}, headers={"X-3B-User": "sara.ahmed"})
    assert r.status_code == 403


def _keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1)).sign(key, hashes.SHA256()))
    return key, cert.public_bytes(serialization.Encoding.PEM).decode()


def test_firebase_token_verification(monkeypatch):
    monkeypatch.setattr(settings, "firebase_project_id", "three-bees-test")
    key, pem = _keypair()
    monkeypatch.setattr(cloud, "_certs", {"expires": time.time() + 3600, "keys": {"k1": pem}})
    now = int(time.time())
    claims = {"iss": "https://securetoken.google.com/three-bees-test", "aud": "three-bees-test", "sub": "uid1", "iat": now, "exp": now + 600,
              "email": "new.person@example.com", "email_verified": False}
    tok = jwt.encode(claims, key, algorithm="RS256", headers={"kid": "k1"})
    assert cloud.verify_firebase_token(tok)["email"] == "new.person@example.com"
    for bad in (jwt.encode({**claims, "aud": "other-project"}, key, algorithm="RS256", headers={"kid": "k1"}),
                jwt.encode({**claims, "exp": now - 600}, key, algorithm="RS256", headers={"kid": "k1"}),
                jwt.encode(claims, rsa.generate_private_key(public_exponent=65537, key_size=2048), algorithm="RS256", headers={"kid": "k1"}),
                "not-a-token"):
        with pytest.raises(cloud.FirebaseTokenError):
            cloud.verify_firebase_token(bad)
    with TestClient(app) as c:
        new = c.post("/api/auth/firebase", json={"id_token": tok})
        assert new.status_code == 200 and new.json()["user"]["role"] == "employee"  # role never from the browser
        # an unverified Firebase account using an existing 3B user's email must not take over that account
        admin_email = c.get("/api/users", headers={"X-3B-User": "aisha.admin"}).json()
        email = next(u["email"] for u in admin_email if u["role"] == "admin")
        takeover = jwt.encode({**claims, "email": email, "sub": "uid2"}, key, algorithm="RS256", headers={"kid": "k1"})
        assert c.post("/api/auth/firebase", json={"id_token": takeover}).status_code == 403
