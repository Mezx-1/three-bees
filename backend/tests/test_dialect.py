"""Spoken Gulf/Levantine scam phrases (as a speech-to-text transcript would write them)."""
from app.services.text_analyzer import analyze_text


def titles(text: str) -> set[str]:
    return {f.title for f in analyze_text(text, "call")[0]}


def test_gulf_bank_scam_call_is_recognised():
    t = titles("معك محمد من بنك الإمارات دبي الوطني قسم الحماية. في عملية مشبوهة على حسابك ولازم نوقف البطاقة الحين. "
               "راح يوصلك رمز على جوالك عطني الرمز بسرعة عشان ما ينقفل حسابك خلال ساعة.")
    assert "Request for one-time password (OTP) / verification code" in t
    assert "Threat of negative consequences" in t
    assert "Urgency / time pressure" in t
    assert "Authority figure asking for a code" in t


def test_card_details_and_hang_up_pressure():
    t = titles("لا تسكر الخط، عطني رقم البطاقة والأرقام اللي ورا البطاقة.")
    assert "Request for credentials / login" in t
    assert "Urgency / time pressure" in t


def test_everyday_talk_is_not_flagged_as_code_theft():
    for text in ("هلا والله شو أخبارك؟ نلتقي بكرة بعد الدوام عند المطعم؟",
                 "عطني رقمك الجديد عشان أضيفك.",
                 "مرحبا ماما، رح أوصل خلال ساعة."):
        t = titles(text)
        assert "Request for one-time password (OTP) / verification code" not in t
        assert "Authority figure asking for a code" not in t
