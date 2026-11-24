"""Redirect following, RDAP domain age, official-domain handling, look-alike watch, evidence pack (network mocked)."""
from datetime import datetime, timedelta, timezone

import httpx
from fastapi.testclient import TestClient

from app.main import app
from app.services import domain_watch, url_analyzer as ua, url_deep
from app.db import SessionLocal

ANALYST = {"X-3B-User": "omar.analyst"}


def _client(routes):
    def handler(req: httpx.Request):
        return routes(req)
    return httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)


def test_shortener_is_followed_to_the_real_page(monkeypatch):
    monkeypatch.setattr(url_deep, "_safe_target", lambda host: None)

    def routes(req):
        if req.url.host == "bit.ly":
            return httpx.Response(301, headers={"location": "https://adcb-secure-login.top/verify"})
        return httpx.Response(200, text="<title>ADCB Online Banking</title><form><input type='password'></form>")

    exp = url_deep.expand("https://bit.ly/abc", client=_client(routes))
    assert [c["status"] for c in exp["chain"]] == [301, 200] and exp["final_url"].startswith("https://adcb-secure-login.top")
    _, info = ua.analyze_url("https://bit.ly/abc")
    f, summary = url_deep.deep_findings(info, exp, None)
    titles = [x.title for x in f]
    assert "Link redirects to a different site" in titles
    assert "Page asks for a password on an unofficial site" in titles
    assert any(t.startswith("Page title claims to be 'adcb'") for t in titles)
    assert any(t.endswith("(after redirect)") for t in titles)


def test_meta_refresh_counts_as_a_redirect(monkeypatch):
    monkeypatch.setattr(url_deep, "_safe_target", lambda host: None)

    def routes(req):
        if req.url.host == "a.example":
            return httpx.Response(200, text='<meta http-equiv="refresh" content="0; url=https://b.example/pay">')
        return httpx.Response(200, text="<title>Pay</title>")

    exp = url_deep.expand("https://a.example/", client=_client(routes))
    assert exp["final_url"] == "https://b.example/pay" and len(exp["chain"]) == 2


def test_private_addresses_are_refused():
    exp = url_deep.expand("http://localhost:8000/admin")
    assert exp["error"].startswith("Refused") and exp["chain"] == []


def test_rdap_age_and_abuse_contact():
    reg = (datetime.now(timezone.utc) - timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
    body = {"events": [{"eventAction": "registration", "eventDate": reg}],
            "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]],
                          "entities": [{"roles": ["abuse"], "vcardArray": ["vcard", [["email", {}, "text", "abuse@registrar.example"]]]}]}],
            "nameservers": [{"ldhName": "NS1.EXAMPLE"}]}
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json=body)))
    url_deep._RDAP_CACHE.clear()
    info = url_deep.rdap("fresh-scam.example", client=client)
    assert info["age_days"] == 3 and info["registrar"] == "Example Registrar" and info["abuse_email"] == "abuse@registrar.example"
    f, _ = url_deep.deep_findings({"registered_domain": "fresh-scam.example"}, None, info)
    assert f[0].title == "Newly registered domain" and f[0].source == "intel"


def test_official_uae_domains_are_not_flagged_and_lookalikes_are():
    from app.services import pipeline

    ctx = pipeline.Context(ai_enabled=False)
    for u in ("https://www.adib.ae/en/personal/cards", "https://www.adnocdistribution.ae/en/", "https://www.dewa.gov.ae/en/consumer/billing/easy-pay",
              "https://tamm.abudhabi/en/login"):
        r = pipeline.run_url(u, ctx).report
        assert r["risk_score"] < 30, (u, r["risk_score"])
        assert any(f["title"] == "Official domain" for f in r["findings"])
    for u in ("https://tamm-abudhabi.vercel.app/fines", "https://adcb.com.ly/login", "https://salik-pay.top/settle", "https://uaepass-verify.com/"):
        assert pipeline.run_url(u, ctx).report["risk_score"] >= 30, u


def test_lookalike_watch_scores_hits_and_skips_official(monkeypatch):
    certs = [{"name_value": "adcb-secure-update.com\nwww.adcb-secure-update.com", "not_before": "2026-11-23T00:00:00"},
             {"name_value": "adcb.com\nwww.adcb.com", "not_before": "2026-01-01T00:00:00"}]
    monkeypatch.setattr(domain_watch, "_search", lambda kw, client: certs if kw == "adcb" else [])
    with TestClient(app):
        with SessionLocal() as db:
            res = domain_watch.scan(db, ["adcb"], client=httpx.Client())
        assert res["new_hits"] >= 1
    with TestClient(app) as c:
        hits = c.get("/api/network/watch", headers=ANALYST).json()["hits"]
        hit = next(h for h in hits if h["host"] == "adcb-secure-update.com")
        assert hit["score"] >= 30 and all(h["registered_domain"] != "adcb.com" for h in hits)
        c.patch(f"/api/network/watch/{hit['id']}", json={"status": "flagged"}, headers=ANALYST)
        ind = c.post("/api/network/check", json={"type": "domain", "value": "adcb-secure-update.com"}, headers=ANALYST).json()
        assert ind["status"] == "suspicious", "a look-alike alone is a warning, never verified"


def test_evidence_pack_and_takedown_draft():
    with TestClient(app) as c:
        a = c.post("/api/analyze/url", json={"value": "https://adcb-secure-login.top/verify?acct=1"}, headers=ANALYST).json()
        pack = c.get(f"/api/analyses/{a['id']}/evidence-pack", headers=ANALYST).json()
        assert pack["analysis_id"] == a["id"] and pack["links"][0]["registered_domain"] == "adcb-secure-login.top"
        assert pack["findings"] and len(pack["sha256_of_pack"]) == 64 and pack["analysed_at_utc"]
        txt = c.get(f"/api/analyses/{a['id']}/takedown", headers=ANALYST).text
        assert "adcb-secure-login.top" in txt and "3B does not send this request" in txt
        assert c.get(f"/api/analyses/{a['id']}/evidence-pack", headers={"X-3B-User": "sara.ahmed"}).status_code == 403
