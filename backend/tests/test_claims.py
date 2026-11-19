"""Caller claim verification with a fixed clock (11:05 Friday in the UAE)."""
from datetime import datetime, timezone

from app.services.claims import check_claims

NOW = datetime(2026, 11, 20, 7, 5, tzinfo=timezone.utc)  # 11:05 GST, Friday


def titles(text, region="United Arab Emirates", uae=True):
    f, c = check_claims(text, region, uae, NOW)
    return [x.title for x in f], c


def test_wrong_time_arabic_and_english():
    assert "Caller gave the wrong UAE time" in titles("أنا في أبوظبي الآن، الساعة 12 عندنا")[0]
    assert "Caller gave the wrong UAE time" in titles("It's three o'clock here")[0]
    assert "Caller gave the wrong UAE time" in titles("الساعة ثنعش ونص")[0]


def test_correct_or_rounded_time_is_not_flagged():
    for t in ("الساعة 11", "الساعة احدعش", "it's 11:10", "الساعة 11 ونص"):
        f, c = titles(t)
        assert f == [] and c and c[0]["ok"], t


def test_wrong_day():
    assert "Caller gave the wrong day" in titles("اليوم الخميس")[0]
    assert titles("اليوم الجمعة")[0] == []


def test_local_authority_from_foreign_number():
    f, _ = titles("معك شرطة أبوظبي", "Germany", False)
    assert any(t.startswith("Claims to be Abu Dhabi Police") for t in f)
    assert titles("معك شرطة أبوظبي")[0] == [], "UAE number claiming local authority is not contradicted"


def test_unknown_organisation_is_unverified_not_called_fake():
    f, c = titles("I am calling from Golden Star Investments company")
    assert "Organisation could not be verified" in f
    assert any(x["actual"] == "Not found among known UAE organisations" for x in c)


def test_everyday_words_are_not_organisations():
    assert titles("تم تحويل المبلغ، شكرا كريم") == ([], [])
