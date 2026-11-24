"""Threat-intel providers against MOCKED responses (test fixtures — not live API results).

These prove the parsing, normalisation, caching and failure handling. A live integration is only shown as
"connected" in the app after a real request succeeds with the user's own key.
"""
import httpx
import pytest

from app.config import settings
from app.services import threat_intel as ti

URL = "http://bad.example.net/login"


@pytest.fixture(autouse=True)
def keys(monkeypatch):
    monkeypatch.setattr(settings, "urlhaus_auth_key", "test-key")
    monkeypatch.setattr(settings, "virustotal_api_key", "test-key")
    monkeypatch.setattr(settings, "google_safe_browsing_key", "test-key")
    ti.clear_cache()
    yield
    ti.clear_cache()


def client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def by(results, provider):
    return next(r for r in results if r["provider"] == provider)


def test_hits_are_normalised_with_provenance():
    def handler(req: httpx.Request):
        host = req.url.host
        if host == "urlhaus-api.abuse.ch":
            return httpx.Response(200, json={"query_status": "ok", "threat": "malware_download", "url_status": "online",
                                             "date_added": "2026-11-20", "urlhaus_reference": "https://urlhaus.abuse.ch/url/1/"})
        if host == "www.virustotal.com":
            return httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": {"malicious": 9, "suspicious": 1, "harmless": 60, "undetected": 20},
                                                                     "last_analysis_date": 1795000000, "categories": {"x": "phishing"}}}})
        return httpx.Response(200, json={"matches": [{"threatType": "SOCIAL_ENGINEERING"}]})

    res = ti.check_url(URL, client=client(handler))
    assert by(res, "urlhaus")["result"] == "known_malware" and by(res, "urlhaus")["category"] == "malware_distribution"
    assert by(res, "virustotal")["result"] == "known_phishing" and "9 of 90" in by(res, "virustotal")["detail"]
    assert by(res, "google_safe_browsing")["result"] == "known_phishing"
    for r in res:
        assert {"provider", "indicator", "result", "source_reference", "checked_at", "cache_expires", "provider_status"} <= set(r)
    titles = {f.title for f in ti.findings(res)}
    assert "Listed as malware by URLhaus (abuse.ch)" in titles and "Listed as phishing by Google Safe Browsing" in titles


def test_no_match_timeout_and_rate_limit_are_never_safe():
    def handler(req: httpx.Request):
        if req.url.host == "urlhaus-api.abuse.ch":
            return httpx.Response(200, json={"query_status": "no_results"})
        if req.url.host == "www.virustotal.com":
            return httpx.Response(429)
        raise httpx.ReadTimeout("slow", request=req)

    res = ti.check_url(URL, client=client(handler))
    assert by(res, "urlhaus")["result"] == "not_listed"
    assert by(res, "virustotal")["result"] == "unavailable" and by(res, "virustotal")["provider_status"] == "rate_limited"
    assert by(res, "google_safe_browsing")["result"] == "unavailable" and by(res, "google_safe_browsing")["provider_status"] == "timeout"
    assert ti.findings(res) == []  # no risk added …
    notes = " ".join(ti.limitations(res))
    assert "not proof that a link is safe" in notes and "reputation unknown, not clean" in notes  # … and no false reassurance
    status = {s["provider"]: s["status"] for s in ti.status()}
    assert status["urlhaus"] == "connected" and status["google_safe_browsing"] == "unavailable"


def test_results_are_cached_and_missing_keys_reported(monkeypatch):
    calls = []

    def handler(req: httpx.Request):
        calls.append(req.url.host)
        if req.url.host == "urlhaus-api.abuse.ch":
            return httpx.Response(200, json={"query_status": "no_results"})
        if req.url.host == "www.virustotal.com":
            return httpx.Response(404)
        return httpx.Response(200, json={})

    ti.check_url(URL, client=client(handler))
    again = ti.check_url(URL, client=client(handler))
    assert len(calls) == 3 and all(r.get("cached") for r in again)
    monkeypatch.setattr(settings, "virustotal_api_key", None)
    ti.clear_cache()
    res = ti.check_url(URL, client=client(handler))
    assert by(res, "virustotal")["result"] == "not_configured"
    assert {s["provider"]: s["status"] for s in ti.status()}["virustotal"] == "not_configured"
