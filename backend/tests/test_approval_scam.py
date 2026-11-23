"""'Approve the notification' bank scam (push-payment approval) during a call."""
from fastapi.testclient import TestClient

from app.main import app
from app.services.claims import find_approval_given

SCRIPT = ("Hello, good evening! This is Ahmed from your bank's security department. We've detected suspicious activity on your account. "
          "We've detected an attempted transaction of AED 5,800. You should have received a verification notification. "
          "The notification is part of the security verification process. Please confirm the request. "
          "Okay, I've confirmed it. Is my account safe now?")


def test_approval_said_is_found_only_after_a_request():
    assert find_approval_given(SCRIPT) == "Okay, I've confirmed"
    assert find_approval_given("I've confirmed it. Please confirm the request.") is None
    assert find_approval_given("Did you authorize this payment? No, I didn't.") is None


def test_approval_scam_call_is_critical_with_alarm_and_next_step():
    with TestClient(app) as c:
        r = c.post("/api/calls/analyze", data={"transcript": SCRIPT, "consent": "true", "caller_number": "+971 50 123 4567"},
                   headers={"X-3B-User": "omar.analyst"}).json()
    assert r["severity"] == "critical"
    call = r["report"]["call"]
    assert call["approval_given"] is True
    assert call["questions"][0]["id"] == "why_approve"
    assert r["report"]["next_steps"]["items"][0]["id"] == "approved"


def test_genuine_fraud_check_question_is_not_an_approval_request():
    with TestClient(app) as c:
        r = c.post("/api/calls/analyze", data={"transcript": "Hi, did you authorize this payment of AED 200 at the supermarket?",
                                                "consent": "true"}, headers={"X-3B-User": "omar.analyst"}).json()
    assert "approval_given" not in r["report"]["call"]
    assert r["severity"] in ("low", "medium")
