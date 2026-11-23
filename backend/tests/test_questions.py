"""Questions that expose a scam caller."""
from fastapi.testclient import TestClient

from app.main import app
from app.services.questions import default_questions

ANALYST = {"X-3B-User": "omar.analyst"}


def _questions(c, transcript, lang=None):
    headers = dict(ANALYST, **({"X-3B-Lang": lang} if lang else {}))
    r = c.post("/api/calls/analyze", data={"transcript": transcript, "consent": "true", "caller_number": "+971 50 123 4567"}, headers=headers)
    assert r.status_code == 200, r.text
    return [q["id"] for q in r.json()["report"]["call"]["questions"]], r.json()


def test_bank_caller_asking_for_code_gets_bank_questions():
    with TestClient(app) as c:
        ids, _ = _questions(c, "I am from Abu Dhabi Islamic Bank, your card needs an update, send me the verification code")
    assert ids == ["why_code", "callback", "card_digits"]


def test_police_caller_gets_badge_and_official_app():
    with TestClient(app) as c:
        ids, _ = _questions(c, "معك الملازم أحمد من شرطة أبوظبي، عليك غرامة ولازم تدفعها اليوم")
    assert ids[:2] == ["badge", "pay_official"]


def test_time_question_dropped_once_answered():
    with TestClient(app) as c:
        ids, _ = _questions(c, "hello, how are you? it's seven o'clock")
    assert "time" not in ids and len(ids) == 3


def test_defaults_before_speech_and_arabic_translation():
    assert [q["id"] for q in default_questions()] == ["time", "company", "callback"]
    with TestClient(app) as c:
        status = c.get("/api/calls/status", headers=dict(ANALYST, **{"X-3B-Lang": "ar"})).json()
    assert status["questions"][0]["question"] == "كم الساعة عندك الآن؟"
