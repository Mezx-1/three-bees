"""End-to-end API test of the hackathon demo scenario and core workflows (offline: no AI, no external lookups)."""
import os
import tempfile

_tmp = tempfile.mkdtemp()
os.environ["THREEB_DATABASE_URL"] = f"sqlite:///{_tmp}/test.db".replace("\\", "/")
os.environ["THREEB_UPLOAD_DIR"] = _tmp
os.environ["THREEB_EXTERNAL_LOOKUPS"] = "false"
os.environ["ANTHROPIC_API_KEY"] = ""
os.environ["THREEB_RATE_LIMIT_PER_MINUTE"] = "1000"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.demo import scenario  # noqa: E402
from app.main import app  # noqa: E402

ANALYST = {"X-3B-User": "omar.analyst"}
ADMIN = {"X-3B-User": "aisha.admin"}
EMPLOYEE = {"X-3B-User": "sara.ahmed"}


@pytest.fixture(scope="module")
def c():
    with TestClient(app) as client:
        assert client.post("/api/demo/reset", headers=ADMIN).status_code == 200  # isolate from other test modules
        yield client


def test_auth_required(c):
    assert c.get("/api/dashboard").status_code == 401
    assert c.get("/api/dashboard", headers={"X-3B-User": "nobody"}).status_code == 401


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
    assert any(f["title"] == "Domain is on the 3B blocklist" for f in r["report"]["findings"])


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


def test_external_lookups_need_consent(c):
    st = c.get("/api/settings", headers=ADMIN).json()
    assert st["external_lookups"] is False, "external lookups must be off by default"
    assert c.put("/api/settings", json={"external_lookups": True}, headers=ADMIN).status_code == 422
    on = c.put("/api/settings", json={"external_lookups": True, "consent_acknowledged": True}, headers=ADMIN).json()
    assert on["external_lookups"] is True and on["external_lookups_consent"]["by"] == "aisha.admin"
    off = c.put("/api/settings", json={"external_lookups": False}, headers=ADMIN).json()
    assert off["external_lookups"] is False and off["external_lookups_consent"] is None
    providers = c.get("/api/system/status").json()["external_providers"]
    assert any(p["name"] == "ip-api.com" and "Public IP" in p["sends"] for p in providers)


def test_export_and_settings(c):
    a = c.get("/api/analyses?kind=email", headers=ANALYST).json()[0]
    r = c.get(f"/api/analyses/{a['id']}/export", headers=ANALYST)
    assert r.status_code == 200 and "3B" in r.text and 'dir="ltr"' in r.text
    assert c.put("/api/settings", json={"ai_enabled": False}, headers=ANALYST).status_code == 403
    assert c.put("/api/settings", json={"auto_incident_threshold": 70}, headers=ADMIN).json()["auto_incident_threshold"] == 70
    assert c.get("/api/system/status").json()["integrations"]["microsoft_365"]["connected"] is False


def test_live_agent_monitoring(c):
    code = c.post("/api/pairing-codes", json={"purpose": "agent"}, headers=ANALYST).json()["code"]
    r = c.post("/api/agent/register", json={"hostname": "TEST-LAPTOP", "os": "Windows 11", "owner_email": "tester@alnoorlogistics.ae",
                                            "consent": True, "system_info": {}, "pairing_code": code})
    assert r.status_code == 200, r.text
    dev, tok = r.json()["device_id"], {"X-Device-Token": r.json()["token"]}
    assert c.post("/api/agent/register", json={"hostname": "X", "consent": False, "pairing_code": "AAAAAAAA"}).status_code == 422
    assert c.post("/api/agent/register", json={"hostname": "X", "consent": True, "pairing_code": code}).status_code == 401, "codes are single-use"
    c.post("/api/blocklist", json={"type": "ip", "value": "198.51.100.66", "reason": "test"}, headers=ANALYST)
    batch = {"connections": [
        {"process_name": "chrome.exe", "pid": 100, "remote_ip": "142.250.180.14", "remote_port": 443, "direction": "outbound", "status": "ESTABLISHED"},
        {"process_name": "powershell.exe", "pid": 200, "remote_ip": "198.51.100.66", "remote_port": 4444, "direction": "outbound", "status": "ESTABLISHED"},
        {"process_name": "svchost.exe", "pid": 300, "remote_ip": "192.168.1.20", "remote_port": 50000, "direction": "outbound", "status": "ESTABLISHED"},
    ], "listening": [{"protocol": "tcp", "port": 445, "process_name": "System"}]}
    r = c.post("/api/agent/connections", json=batch, headers=tok).json()
    assert r["new"] == 3 and r["flagged"] == 1 and r["events"] == 1
    r2 = c.post("/api/agent/connections", json=batch, headers=tok).json()
    assert r2["new"] == 0 and r2["events"] == 0, "same connection must not raise duplicate events"
    data = c.get(f"/api/endpoints/{dev}/connections", headers=ANALYST).json()
    bad = next(x for x in data["connections"] if x["remote_ip"] == "198.51.100.66")
    assert bad["risk_score"] >= 60 and any(f["title"] == "Connection to a blocked IP" for f in bad["flags"])
    lan = next(x for x in data["connections"] if x["remote_ip"] == "192.168.1.20")
    assert lan["origin"]["scope"] == "private"
    assert data["summary"]["active_connections"] == 3 and data["listening"][0]["port"] == 445
    # benign process starts are dropped, suspicious ones kept
    ev = c.post("/api/agent/events", json=[
        {"event_type": "process", "title": "Process started: notepad.exe", "details": {"process_name": "notepad.exe", "parent_process": "explorer.exe"}},
        {"event_type": "process", "title": "Process started: powershell.exe", "details": {"process_name": "powershell.exe", "parent_process": "winword.exe", "command_line": "powershell -enc AAAA"}},
    ], headers=tok).json()
    assert ev["ingested"] == 1 and ev["skipped_benign"] == 1
    # posture weakness -> event once
    p = {"firewall": {"domain": "on", "private": "off", "public": "on"}, "defender": {"realtime": True, "antivirus": True, "signature_age_days": 1}}
    assert c.post("/api/agent/posture", json=p, headers=tok).json()["findings"] == 1
    c.post("/api/agent/posture", json=p, headers=tok)
    d = c.get(f"/api/endpoints/{dev}", headers=ANALYST).json()
    assert sum(1 for e in d["events"] if e["event_type"] == "posture") == 1
    assert d["online"] is True and d["status"] in ("at_risk", "compromised")
    # response command round-trip
    assert c.post(f"/api/endpoints/{dev}/commands", json={"type": "block_ip", "ip": "198.51.100.66", "confirm": True}, headers=EMPLOYEE).status_code == 403
    assert c.post(f"/api/endpoints/{dev}/commands", json={"type": "block_ip", "ip": "198.51.100.66"}, headers=ANALYST).status_code == 422  # unconfirmed
    assert c.post(f"/api/endpoints/{dev}/commands", json={"type": "block_ip", "ip": "192.168.1.1", "confirm": True}, headers=ANALYST).status_code == 422
    assert c.post(f"/api/endpoints/{dev}/commands", json={"type": "block_ip", "ip": "198.51.100.66", "confirm": True}, headers=ANALYST).status_code == 422  # documentation range
    q = c.post(f"/api/endpoints/{dev}/commands", json={"type": "block_ip", "ip": "8.8.4.4", "confirm": True}, headers=ANALYST).json()
    assert c.post(f"/api/endpoints/{dev}/commands", json={"type": "block_ip", "ip": "8.8.4.4", "confirm": True}, headers=ANALYST).json()["duplicate"]
    cmds = c.get("/api/agent/commands", headers=tok).json()["commands"]
    assert cmds and cmds[0]["id"] == q["id"]
    assert c.get("/api/agent/commands", headers=tok).json()["commands"] == []
    c.post(f"/api/agent/commands/{q['id']}/result", json={"status": "refused", "result": "not allowed"}, headers=tok)
    assert c.get(f"/api/endpoints/{dev}/commands", headers=ANALYST).json()[0]["status"] == "refused"
    assert c.post("/api/agent/connections", json=batch, headers={"X-Device-Token": "bad"}).status_code == 401


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


def test_call_guard(c):
    import pathlib

    wav = (pathlib.Path(__file__).resolve().parents[1] / "app" / "demo" / "sample_scam_call.wav").read_bytes()
    assert c.post("/api/calls/analyze", data={"caller_number": "+8821234567"}, files={"audio": ("call.wav", wav, "audio/wav")}, headers=EMPLOYEE).status_code == 422  # no consent
    r = c.post("/api/calls/analyze", data={"caller_number": "+8821234567", "consent": "true"}, files={"audio": ("call.wav", wav, "audio/wav")}, headers=EMPLOYEE)
    assert r.status_code == 200, r.text
    a = r.json()
    assert a["kind"] == "call" and a["risk_score"] >= 80 and a["incident_id"]
    call = a["report"]["call"]
    if call["stt"].get("available"):
        assert "verification code" in call["transcript"].lower()
    assert call["caller"]["registered_region"].startswith("International Networks")
    assert any("not where the caller physically is" in l for l in a["report"]["limitations"])
    # live session: two chunks accumulate into one analysis
    sid = c.post("/api/calls/session", headers=EMPLOYEE).json()["session_id"]
    first = c.post("/api/calls/analyze", data={"consent": "true", "session_id": sid, "caller_number": "+971501234567", "transcript": "Hello, this is your bank."}, headers=EMPLOYEE).json()
    second = c.post("/api/calls/analyze", data={"consent": "true", "session_id": sid, "caller_number": "+971501234567", "transcript": "Please tell me the OTP code now, it is urgent."}, headers=EMPLOYEE).json()
    assert first["id"] == second["id"] and second["risk_score"] > first["risk_score"]
    # blocked scam number
    c.post("/api/blocklist", json={"type": "phone", "value": "+971 50 999 8888", "reason": "reported scam"}, headers=ANALYST)
    b = c.post("/api/calls/analyze", data={"consent": "true", "caller_number": "0509998888", "transcript": "hello"}, headers=EMPLOYEE).json()
    assert any(f["title"] == "Caller number is on the 3B blocklist" for f in b["report"]["findings"])


def test_mobile_protection(c):
    salik = ("[Salik] FINAL REMINDER: a toll balance of AED 4.00 is PENDING. Settle before 11:59 PM TODAY to avoid an AED 50.00 fine "
             "and RESTRICTIONS on vehicle registration. To settle, visit: https://salik.ae.ticka.top")
    r = c.post("/api/mobile/sms/classify", json={"sender": "simkukjin@hanmail.net", "body": salik}, headers=EMPLOYEE).json()
    assert r["action"] == "junk" and r["stored"] and "Text message sent from an email address" in r["reasons"]
    ok = c.post("/api/mobile/sms/classify", json={"sender": "AD-SALIK", "body": "Your Salik account was recharged with AED 50. Thank you."}, headers=EMPLOYEE).json()
    assert ok["action"] == "allow" and ok["stored"] is False, "legitimate messages must not be stored"
    missed = c.post("/api/mobile/sms/classify", json={"sender": "+491775111338", "body": "You MISSED 1 Call(s) from +491775111338, last call: 22 Sep 2026 at 03:44 PM."}, headers=EMPLOYEE).json()
    assert missed["risk_score"] >= 50
    sat = c.get("/api/mobile/caller-check?number=%2B8821234567", headers=EMPLOYEE).json()
    assert sat["warn"] and sat["level"] in ("caution", "danger")
    local = c.get("/api/mobile/caller-check?number=0501112233", headers=EMPLOYEE).json()
    assert local["warn"] is False
    c.post("/api/blocklist", json={"type": "phone", "value": "+44 7399 367678"}, headers=ANALYST)
    blocked = c.get("/api/mobile/caller-check?number=%2B447399367678", headers=EMPLOYEE).json()
    assert blocked["level"] == "danger" and blocked["label"]
    d = c.get("/api/mobile/call-directory", headers=EMPLOYEE).json()
    assert any(e["number"] == "+447399367678" and e["block"] for e in d["entries"])
    assert any(e["number"] == "+491775111338" and not e["block"] for e in d["entries"]), "numbers from high-risk SMS must be warned about"
    assert c.get("/api/mobile/caller-check?number=123").status_code == 401


def test_phone_pairing_and_filter_config(c):
    assert c.post("/api/pairing-codes", json={"purpose": "phone"}, headers=EMPLOYEE).status_code == 403
    code = c.post("/api/pairing-codes", json={"purpose": "phone"}, headers=ANALYST).json()["code"]
    assert c.post("/api/mobile/register", json={"pairing_code": code, "device_name": "iPhone", "consent": False}).status_code == 422
    assert c.post("/api/mobile/register", json={"pairing_code": "WRONG123", "device_name": "iPhone", "consent": True}).status_code == 401
    r = c.post("/api/mobile/register", json={"pairing_code": code.lower(), "device_name": "Sara's iPhone", "consent": True}).json()
    tok = {"X-Device-Token": r["token"]}
    c.post("/api/blocklist", json={"type": "domain", "value": "ticka.top"}, headers=ANALYST)
    cfg = c.get("/api/mobile/filter-config", headers=tok).json()
    assert "ticka.top" in cfg["blocked_domains"] and "top" in cfg["suspicious_tlds"] and "salik" in cfg["official_domains"]
    chk = c.get("/api/mobile/caller-check?number=%2B8821234567", headers=tok)
    assert chk.status_code == 200
    assert c.delete("/api/mobile/device", headers=tok).json()["ok"]
    assert c.get("/api/mobile/filter-config", headers=tok).status_code == 401, "deleted phone loses access"


def test_privacy_page_public(c):
    r = c.get("/privacy")
    assert r.status_code == 200 and "سياسة الخصوصية" in r.text and "Privacy Policy" in r.text
