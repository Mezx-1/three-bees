"""Real sign-in with the development header shortcut switched OFF."""
import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.db import SessionLocal
from app.main import app
from app.models import User
from app.services.auth import hash_password


@pytest.fixture()
def c(monkeypatch):
    with TestClient(app) as client:
        monkeypatch.setattr(settings, "dev_header_auth", False)
        with SessionLocal() as db:
            u = db.query(User).filter_by(username="omar.analyst").one()
            u.password_hash = hash_password("Correct-Horse-9")
            db.commit()
        yield client


def test_header_identity_rejected_when_dev_mode_off(c):
    assert c.get("/api/dashboard", headers={"X-WOLVE-User": "aisha.admin"}).status_code == 401
    assert c.get("/api/users").status_code == 401


def test_login_session_logout(c):
    assert c.post("/api/auth/login", json={"username": "omar.analyst", "password": "wrong"}).status_code == 401
    assert c.post("/api/auth/login", json={"username": "nobody", "password": "x"}).status_code == 401
    r = c.post("/api/auth/login", json={"username": "Omar.Analyst", "password": "Correct-Horse-9"})
    assert r.status_code == 200
    auth = {"Authorization": f"Bearer {r.json()['token']}"}
    assert c.get("/api/auth/me", headers=auth).json()["role"] == "analyst"
    assert c.get("/api/dashboard", headers=auth).status_code == 200
    assert c.put("/api/settings", json={"ai_enabled": False}, headers=auth).status_code == 403  # role still enforced
    assert c.post("/api/auth/password", json={"current_password": "x", "new_password": "Another-Pass-77"}, headers=auth).status_code == 401
    assert c.post("/api/auth/logout", headers=auth).status_code == 200
    assert c.get("/api/auth/me", headers=auth).status_code == 401, "token must stop working after logout"
    assert c.get("/api/auth/me", headers={"Authorization": "Bearer forged-token"}).status_code == 401
