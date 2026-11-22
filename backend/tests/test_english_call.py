"""English bank-impersonation call and spoken clock times."""
from datetime import datetime, timezone

from app.services import claims, text_analyzer
from app.services.risk import combine

SCRIPT = ("Good evening sir my name is saif mustafa darwish i am from abu dhabi islamic bank we received in our system "
          "that your visa card needs an update so i need you to send me the verification code of the sms that you will receive")


def _score(text: str) -> int:
    findings, _ = text_analyzer.analyze_text(text, "call")
    return combine(findings)


def test_bank_card_code_script_is_critical():
    findings, art = text_analyzer.analyze_text(SCRIPT, "call")
    keys = set(art["matched_patterns"])
    assert {"authority", "otp", "account_pretext"} <= keys
    assert _score(SCRIPT) >= 80


def test_everyday_english_call_is_not_flagged():
    assert _score("hi, are we still meeting for dinner tonight? my card is in the car, I'll pay this time") < 30


def test_spoken_times_are_parsed():
    parse = lambda s: [(h, m) for h, m, _ in claims.extract_time_claims(s)]
    assert parse("it's 4:03") == [(4, 3)]
    assert parse("it is four oh three") == [(4, 3)]
    assert parse("the time is seven") == [(7, 0)]
    assert parse("right now it's five forty five") == [(5, 45)]


def test_wrong_time_is_flagged_and_right_time_is_not():
    now = datetime(2026, 11, 24, 15, 0, tzinfo=timezone.utc)  # 19:00 in the UAE
    wrong, _ = claims.check_claims("what's the time right now? it's 4:03", now=now)
    right, _ = claims.check_claims("what's the time right now? it's seven", now=now)
    assert any("wrong UAE time" in f.title for f in wrong)
    assert not right
