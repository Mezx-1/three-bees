"""One search box for everything, and the police report draft."""
from fastapi.testclient import TestClient

from app.main import app

ANALYST = {"X-3B-User": "omar.analyst"}
SCRIPT = ("Good evening, I am from Abu Dhabi Islamic Bank. Your visa card needs an update, so send me the verification code "
          "of the SMS. OK the code is 739201")


def _call(c):
    r = c.post("/api/calls/analyze", data={"transcript": SCRIPT, "consent": "true", "caller_number": "+44 20 7946 0958"}, headers=ANALYST)
    assert r.status_code == 200, r.text
    return r.json()


def test_search_finds_checks_and_evidence():
    with TestClient(app) as c:
        a = _call(c)
        by_number = c.get("/api/search", params={"q": "2079460958"}, headers=ANALYST).json()
        by_id = c.get("/api/search", params={"q": a["id"]}, headers=ANALYST).json()
        short = c.get("/api/search", params={"q": "a"}, headers=ANALYST)
    assert any(e["analysis_id"] == a["id"] for e in by_number["evidence"])
    assert by_id["analyses"][0]["id"] == a["id"]
    assert short.status_code == 422  # at least two characters


def test_police_report_is_short_masked_and_translated():
    with TestClient(app) as c:
        a = _call(c)
        en = c.get(f"/api/analyses/{a['id']}/police-report", headers=ANALYST).json()
        ar = c.get(f"/api/analyses/{a['id']}/police-report", headers=dict(ANALYST, **{"X-3B-Lang": "ar"})).json()
        missing = c.get("/api/analyses/ANL-NOPE/police-report", headers=ANALYST)
    names = [s["name"] for s in en["sections"]]
    assert {"Reference", "Type of fraud", "What happened", "Phone numbers"} <= set(names)
    assert "739201" not in en["body"] and "73••01" in en["body"]
    assert "ADIB" in " ".join(v for s in en["sections"] for v in s["values"])
    assert ar["title"] == "مسودة بلاغ للشرطة" and "رقم المرجع" in ar["body"]
    assert missing.status_code == 404
