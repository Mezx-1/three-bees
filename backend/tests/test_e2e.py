"""End-to-end API test of the hackathon demo scenario and core workflows (offline: no AI, no external lookups)."""
import os
import tempfile

_tmp = tempfile.mkdtemp()
os.environ["WOLVE_DATABASE_URL"] = f"sqlite:///{_tmp}/test.db".replace("\\", "/")
os.environ["WOLVE_UPLOAD_DIR"] = _tmp
os.environ["WOLVE_EXTERNAL_LOOKUPS"] = "false"
os.environ["ANTHROPIC_API_KEY"] = ""
os.environ["WOLVE_RATE_LIMIT_PER_MINUTE"] = "1000"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.demo import scenario  # noqa: E402
from app.main import app  # noqa: E402

ANALYST = {"X-WOLVE-User": "omar.analyst"}
ADMIN = {"X-WOLVE-User": "aisha.admin"}
EMPLOYEE = {"X-WOLVE-User": "sara.ahmed"}


@pytest.fixture(scope="module")
def c():
    with TestClient(app) as client:
        yield client


def test_auth_required(c):
    assert c.get("/api/dashboard").status_code == 401
    assert c.get("/api/dashboard", headers={"X-WOLVE-User": "nobody"}).status_code == 401


def test_full_demo_scenario(c):
    # 1-8: email arrives, parsed, image OCR'd, URL analysed, scored, incident created
    r = c.post("/api/emails/analyze", files={"file": ("phish.eml", scenario.make_phishing_eml(), "message/rfc822")}, headers=EMPLOYEE)
    assert r.status_code == 200, r.text
    a = r.json()
    rep = a["report"]
    assert a["risk_score"] >= 80 and a["severity"] == "critical"
    assert a["incident_id"], "high-risk email must auto-create an incident"
    titles = {f["title"] for f in rep["findings"]}
    assert "DMARC check failed" in titles and "Reply-To differs from sender" in titles
    assert "Link text disguises the real destination" in titles
    assert any("text in image" in t for t in titles), "OCR text from the lure image should be analysed"
    assert any(u["host"] == "verify.alnoor-logistics-portal.top" for u in rep["urls"])
    assert rep["ai"]["available"] is False  # transparent fallback
    assert any("AI review not used" in l for l in rep["limitations"])
    inc_id = a["incident_id"]

    # 9-10: employee can't quarantine; analyst can
    assert c.post(f"/api/emails/{a['id']}/action", json={"action": "quarantine"}, headers=EMPLOYEE).status_code == 403
    r = c.post(f"/api/emails/{a['id']}/action", json={"action": "quarantine"}, headers=ANALYST)
    assert r.status_code == 200 and r.json()["analysis"]["status"] == "quarantined"
    assert "Not removed from any external mailbox" in r.json()["message"]

    # 11-12: simulated endpoint events correlate into the same incident
    r = c.post("/api/demo/scenario/endpoint", headers=ANALYST)
    assert r.status_code == 200, r.text
    res = r.json()["results"]
    assert all(x["event"]["simulated"] for x in res)
    assert res[0]["correlation"]["incident_id"] == inc_id
    assert any(l["type"] == "observed" for l in res[0]["correlation"]["links"]), "hash/filename should match the attachment"

    inc = c.get(f"/api/incidents/{inc_id}", headers=ANALYST).json()
    assert inc["correlated"] is True and inc["severity"] == "critical"
    assert any(e["type"] == "correlation" for e in inc["timeline"])
    assert len(inc["endpoint_events"]) == 2

    g = c.get(f"/api/graph?incident_id={inc_id}", headers=ANALYST).json()
    kinds = {n["type"] for n in g["nodes"]}
    assert {"incident", "email", "device", "endpoint_event", "domain", "hash"} <= kinds
    assert any(e["kind"] == "observed" and e["source"].startswith("incident:") and e["target"].startswith("event:") for e in g["edges"])

    # 13: dashboard reflects it
    d = c.get("/api/dashboard", headers=EMPLOYEE).json()
    assert d["security_status"] == "critical"
    assert d["totals"]["emails_analyzed"] >= 1 and d["totals"]["active_incidents"] >= 1
    assert d["totals"]["endpoints_at_risk"] >= 1


def test_block_and_review(c):
    r = c.post("/api/blocklist", json={"type": "domain", "value": "https://evil-example.top/login"}, headers=ANALYST)
    assert r.status_code == 200 and r.json()["value"] == "evil-example.top"
    assert c.post("/api/blocklist", json={"type": "domain", "value": "evil-example.top"}, headers=ANALYST).status_code == 409
    r = c.post("/api/analyze/url", json={"value": "http://login.evil-example.top/x"}, headers=EMPLOYEE).json()
    assert any(f["title"] == "Domain is on the WOLVE blocklist" for f in r["report"]["findings"])


def test_messages_and_inputs(c):
    for key, s in scenario.SAMPLE_MESSAGES.items():
        r = c.post("/api/analyze/message", json={"text": s["text"], "channel": s["channel"]}, headers=EMPLOYEE)
        assert r.status_code == 200, r.text
        assert r.json()["risk_score"] >= 40, key
    r = c.post("/api/analyze/auto", json={"text": "8.8.8.8"}, headers=EMPLOYEE).json()
    assert r["kind"] == "ip"
    r = c.post("/api/analyze/auto", json={"text": "+971501234567"}, headers=EMPLOYEE).json()
    assert r["kind"] == "phone" and r["report"]["phone"]["registered_region"] == "United Arab Emirates"
    assert c.post("/api/analyze/ip", json={"value": "999.1.1.1"}, headers=EMPLOYEE).status_code == 422
    legit = c.post("/api/emails/analyze", files={"file": ("ok.eml", scenario.make_legit_eml(), "message/rfc822")}, headers=EMPLOYEE).json()
    assert legit["risk_score"] < 30 and legit["incident_id"] is None


def test_file_forensics(c):
    r = c.post("/api/analyze/file", files={"file": ("Invoice_Q4_2026.pdf", scenario.make_disguised_attachment(), "application/pdf")}, headers=EMPLOYEE).json()
    titles = {f["title"] for f in r["report"]["findings"]}
    assert "File extension does not match real file type" in titles and "Double extension inside archive" in titles
    assert r["quarantined_file"] is True
    img = c.post("/api/analyze/file", files={"file": ("lure.png", scenario.make_lure_image(), "image/png")}, headers=EMPLOYEE).json()
    assert img["kind"] == "image"
    assert img["report"]["file"]["qr"]["codes"], "QR code should decode"
    assert c.post("/api/analyze/file", files={"file": ("x.xyz", b"abc", "text/plain")}, headers=EMPLOYEE).status_code == 415


def test_incident_lifecycle_and_audit(c):
    inc = c.post("/api/incidents", json={"title": "Manual test incident", "severity": "medium"}, headers=ANALYST).json()
    iid = inc["id"]
    assert c.patch(f"/api/incidents/{iid}", json={"status": "resolved"}, headers=ANALYST).status_code == 422  # note required
    r = c.patch(f"/api/incidents/{iid}", json={"status": "resolved", "note": "Closed in test", "assigned_to": "layla.analyst"}, headers=ANALYST)
    assert r.status_code == 200 and r.json()["status"] == "resolved"
    assert c.post(f"/api/incidents/{iid}/escalate", headers=ANALYST).status_code == 200
    assert c.patch(f"/api/incidents/{iid}", json={"note": "x"}, headers=EMPLOYEE).status_code == 403
    logs = c.get("/api/audit", headers=ANALYST).json()
    actions = {l["action"] for l in logs}
    assert {"incident.create", "incident.update", "email.quarantine", "incident.escalate"} <= actions


def test_export_and_settings(c):
    a = c.get("/api/analyses?kind=email", headers=ANALYST).json()[0]
    r = c.get(f"/api/analyses/{a['id']}/export", headers=ANALYST)
    assert r.status_code == 200 and "WOLVE AI" in r.text
    assert c.put("/api/settings", json={"ai_enabled": False}, headers=ANALYST).status_code == 403
    assert c.put("/api/settings", json={"auto_incident_threshold": 70}, headers=ADMIN).json()["auto_incident_threshold"] == 70
    assert c.get("/api/system/status").json()["integrations"]["microsoft_365"]["connected"] is False


def test_zz_demo_reset(c):
    """Runs last: admin-only reset wipes data and reseeds the baseline organisation."""
    assert c.post("/api/demo/reset", headers=ANALYST).status_code == 403
    r = c.post("/api/demo/reset", headers=ADMIN)
    assert r.status_code == 200, r.text
    d = c.get("/api/dashboard", headers=ADMIN).json()
    assert d["totals"]["total_analyses"] == 0 and d["totals"]["active_incidents"] == 0
    assert d["totals"]["endpoints"] == 4 and d["security_status"] == "normal"
    # everything still works after reset
    a = c.post("/api/demo/scenario/email", headers=ANALYST).json()
    assert a["risk_score"] >= 80 and a["incident_id"]
