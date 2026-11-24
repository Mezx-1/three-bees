"""Scam reports: submission, reference numbers, roles, evidence, demo data, links and printing."""
import io

from fastapi.testclient import TestClient
from PIL import Image

from app.main import app

EMP = {"X-3B-User": "sara.ahmed"}
ANALYST = {"X-3B-User": "omar.analyst"}
FORM = {"category": "bank_impersonation", "channel": "call", "phone": "+971 00 000 0999",
        "message": "I am from your bank security team, your card is blocked, send me the verification code from the SMS",
        "description": "Test report", "privacy_ack": "true", "amount_lost": "0", "currency": "AED", "emirate": "Abu Dhabi"}


def _png() -> bytes:
    b = io.BytesIO()
    Image.new("RGB", (40, 20), "white").save(b, "PNG")
    return b.getvalue()


def test_submit_gives_reference_and_analysis_and_roles_are_enforced():
    with TestClient(app) as c:
        r = c.post("/api/reports", data=FORM, files={"evidence": ("shot.png", _png(), "image/png")}, headers=EMP)
        assert r.status_code == 200, r.text
        rep = r.json()
        assert rep["reference"].startswith("3B-UAE-") and rep["data_mode"] == "user"
        assert rep["risk_score"] >= 60 and rep["has_evidence"]
        assert "not an official police complaint" in rep["disclaimer"]
        ref = rep["reference"]
        # the reporter sees their own report but not investigator fields or the list
        mine = c.get(f"/api/reports/{ref}", headers=EMP).json()
        assert "notes" not in mine and "related" not in mine
        assert c.get("/api/reports", headers=EMP).status_code == 403
        assert c.get(f"/api/reports/{ref}/evidence", headers=EMP).status_code == 403
        # the investigator can review
        assert c.get(f"/api/reports/{ref}/evidence", headers=ANALYST).headers["content-type"] == "image/png"
        upd = c.patch(f"/api/reports/{ref}", json={"status": "under_review", "note": "Checked the number"}, headers=ANALYST).json()
        assert upd["status"] == "under_review" and upd["notes"][0]["text"] == "Checked the number"
        assert "window.print()" in c.get(f"/api/reports/{ref}/print", headers=ANALYST).text


def test_validation_rejects_bad_input():
    with TestClient(app) as c:
        assert c.post("/api/reports", data={**FORM, "privacy_ack": "false"}, headers=EMP).status_code == 422
        assert c.post("/api/reports", data={**FORM, "category": "nope"}, headers=EMP).status_code == 422
        fake = c.post("/api/reports", data=FORM, files={"evidence": ("x.png", b"not an image", "image/png")}, headers=EMP)
        assert fake.status_code == 415


def test_demo_data_is_separate_linked_and_resettable():
    with TestClient(app) as c:
        c.post("/api/reports/demo/reset", headers=ANALYST)
        loaded = c.post("/api/reports/demo/load", headers=ANALYST).json()
        assert loaded["loaded"] >= 20
        assert c.post("/api/reports/demo/load", headers=ANALYST).json()["loaded"] == 0  # no duplicates
        demo = c.get("/api/reports/stats?mode=demo", headers=ANALYST).json()
        assert demo["total"] >= 20 and demo["demo_label"] and demo["groups"]
        assert any(p["count"] > 1 for p in demo["top_phones"]) and any(d["count"] > 1 for d in demo["top_domains"])
        user_refs = {r["reference"] for r in c.get("/api/reports?mode=user", headers=ANALYST).json()}
        assert not any(ref.startswith("3B-DEMO-") for ref in user_refs)
        first = c.get("/api/reports?mode=demo&q=salik-pay", headers=ANALYST).json()[0]["reference"]
        detail = c.get(f"/api/reports/{first}", headers=ANALYST).json()
        assert detail["related"] and all(x["reference"].startswith("3B-DEMO-") for x in detail["related"])
        assert any(l["method"] == "same_domain" for x in detail["related"] for l in x["links"])
        assert c.post("/api/reports/demo/reset", headers=ANALYST).json()["deleted"] >= 20
        assert c.get("/api/reports/stats?mode=demo", headers=ANALYST).json()["total"] == 0
