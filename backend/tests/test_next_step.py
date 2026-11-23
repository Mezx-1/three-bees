"""Scammer's next-step prediction and the 'code said during the call' alert."""
from fastapi.testclient import TestClient

from app.main import app
from app.services.claims import find_spoken_codes

BANK = ("i am from abu dhabi islamic bank, we received in our system that your visa card needs an update "
        "so send me the verification code of the sms that you will receive. ")
ANALYST = {"X-3B-User": "omar.analyst"}


def _call(c, transcript, lang=None):
    headers = dict(ANALYST, **({"X-3B-Lang": lang} if lang else {}))
    r = c.post("/api/calls/analyze", data={"transcript": transcript, "consent": "true", "caller_number": "+971 50 123 4567"}, headers=headers)
    assert r.status_code == 200, r.text
    return r.json()


def test_spoken_code_is_found_in_digits_and_words():
    assert [h["masked"] for h in find_spoken_codes(BANK + "ok the code is 7 3 9 2 0 1")] == ["73••01"]
    assert [h["masked"] for h in find_spoken_codes(BANK + "seven three nine two zero one")] == ["73••01"]
    assert [h["masked"] for h in find_spoken_codes("عطني الرمز اللي وصلك. سبعة ثلاثة تسعة اثنين صفر واحد")] == ["73••01"]


def test_times_amounts_and_phone_numbers_are_not_codes():
    text = BANK + "it's 4:03, my number is +971 50 123 4567, the amount is AED 4850, call me at 2030"
    assert find_spoken_codes(text) == []
    assert find_spoken_codes("my pin is not needed, here is 739201") == []  # no code request before it


def test_code_said_in_call_raises_alert_and_is_masked():
    with TestClient(app) as c:
        r = _call(c, BANK + "ok the code is 739201")
    call = r["report"]["call"]
    assert call["code_spoken"] is True
    assert "739201" not in call["transcript"] and "73••01" in call["transcript"]
    assert any(f["title"] == "A code may have been said during the call" for f in r["report"]["findings"])
    assert r["report"]["next_steps"]["items"][0]["id"] == "code_used"


def test_next_step_before_the_code_is_asked():
    with TestClient(app) as c:
        r = _call(c, "good evening, i am from abu dhabi islamic bank, your visa card needs an update today")
    ids = [i["id"] for i in r["report"].get("next_steps", {}).get("items", [])]
    assert ids and ids[0] == "ask_code"


def test_next_step_is_translated_and_absent_for_normal_calls():
    with TestClient(app) as c:
        ar = _call(c, BANK, lang="ar")
        normal = _call(c, "hi, are we still meeting for dinner tonight?")
    step = ar["report"]["next_steps"]["items"][0]["step"]
    assert any("؀" <= ch <= "ۿ" for ch in step)
    assert "next_steps" not in normal["report"]
