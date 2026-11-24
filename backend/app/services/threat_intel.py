"""Real URL / domain reputation from external providers, behind one interface.

Providers (each needs its own free key in backend/.env; without a key it reports "not_configured"):
  * URLhaus (abuse.ch)        — known MALWARE-distribution URLs (not a phishing list)
  * VirusTotal                — multi-engine verdicts for a URL or domain (lookup only; nothing is submitted)
  * Google Safe Browsing v4   — Google's phishing / malware lists (free for non-commercial use;
                                Google Web Risk is the commercial equivalent)

Every result is normalised to the same shape and keeps its provenance:
    provider, indicator, result, category, detail, source_reference, checked_at, cache_expires, provider_status
result is one of: known_phishing · known_malware · suspicious · not_listed · unavailable · error · not_configured
"not_listed", "unavailable" and "error" are NEVER treated as safe — they add no risk and say so.
Lookups send the URL to the provider, so they only run when external lookups are switched on with consent.
"""
from __future__ import annotations

import base64
import logging
import threading
import time
from datetime import datetime, timedelta, timezone

import httpx

from ..config import settings
from .risk import Finding

log = logging.getLogger("threebees.intel")
TIMEOUT = 6.0
HIT_TTL = 6 * 3600       # cache known-bad answers for 6 h
MISS_TTL = 3600          # cache "not listed" for 1 h (lists change)

_cache: dict[tuple[str, str], tuple[float, dict]] = {}
_health: dict[str, dict] = {}
_lock = threading.Lock()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _result(provider: str, indicator: str, result: str, *, category: str | None = None, detail: str = "",
            ref: str | None = None, status: str = "ok", ttl: int = 0) -> dict:
    now = _now()
    return {"provider": provider, "indicator": indicator, "result": result, "category": category, "detail": detail,
            "source_reference": ref, "checked_at": now.isoformat(timespec="seconds"),
            "cache_expires": (now + timedelta(seconds=ttl)).isoformat(timespec="seconds") if ttl else None,
            "provider_status": status}


def _record(provider: str, ok: bool, error: str | None = None, rate_limited: bool = False) -> None:
    with _lock:
        h = _health.setdefault(provider, {"last_success": None, "last_error": None, "errors": 0, "rate_limited": False})
        if ok:
            h["last_success"] = _now().isoformat(timespec="seconds")
            h["errors"] = 0
            h["rate_limited"] = False
        else:
            h["last_error"] = {"at": _now().isoformat(timespec="seconds"), "message": error}
            h["errors"] += 1
            h["rate_limited"] = rate_limited


class Provider:
    name = ""
    label = ""
    covers = ""

    def configured(self) -> bool:
        raise NotImplementedError

    def check_url(self, url: str, client: httpx.Client) -> dict:
        raise NotImplementedError

    def health_probe(self, client: httpx.Client) -> dict:
        """A cheap real request to the provider, used by the integrations page."""
        return self.check_url("http://example.com/", client)


class URLhaus(Provider):
    name, label, covers = "urlhaus", "URLhaus (abuse.ch)", "Known malware-distribution URLs"

    def configured(self) -> bool:
        return bool(settings.urlhaus_auth_key)

    def check_url(self, url, client):
        r = client.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url}, headers={"Auth-Key": settings.urlhaus_auth_key})
        if r.status_code in (401, 403):
            return _result(self.name, url, "error", detail="Auth-Key rejected", status="error")
        r.raise_for_status()
        j = r.json()
        st = j.get("query_status")
        if st == "ok":
            return _result(self.name, url, "known_malware", category="malware_distribution", ttl=HIT_TTL,
                           detail=f"Listed by URLhaus ({j.get('threat') or 'malware'}; URL status: {j.get('url_status')}, added {j.get('date_added')})",
                           ref=j.get("urlhaus_reference"))
        if st == "no_results":
            return _result(self.name, url, "not_listed", detail="No URLhaus record. This list covers malware distribution only.", ttl=MISS_TTL)
        return _result(self.name, url, "error", detail=f"URLhaus answered: {st}", status="error")


class VirusTotal(Provider):
    name, label, covers = "virustotal", "VirusTotal", "Verdicts from many security engines (lookup only)"

    def configured(self) -> bool:
        return bool(settings.virustotal_api_key)

    def check_url(self, url, client):
        vid = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        r = client.get(f"https://www.virustotal.com/api/v3/urls/{vid}", headers={"x-apikey": settings.virustotal_api_key})
        if r.status_code == 404:
            return _result(self.name, url, "not_listed", detail="VirusTotal has no analysis of this exact URL (it was not submitted).", ttl=MISS_TTL)
        if r.status_code == 429:
            return _result(self.name, url, "unavailable", detail="VirusTotal rate limit reached (free tier: about 4 lookups per minute).", status="rate_limited")
        if r.status_code in (401, 403):
            return _result(self.name, url, "error", detail="API key rejected", status="error")
        r.raise_for_status()
        attrs = r.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {}) or {}
        mal, sus = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
        total = sum(int(v) for v in stats.values()) or 0
        when = attrs.get("last_analysis_date")
        when_s = datetime.fromtimestamp(when, timezone.utc).date().isoformat() if when else "unknown date"
        ref = f"https://www.virustotal.com/gui/url/{vid}"
        detail = f"{mal} of {total} engines flagged it as malicious, {sus} as suspicious (last analysis {when_s})."
        if mal >= 3:
            cats = " ".join(str(v).lower() for v in (attrs.get("categories") or {}).values())
            cat = "phishing" if "phish" in cats else "malicious"
            return _result(self.name, url, "known_phishing" if cat == "phishing" else "known_malware", category=cat, detail=detail, ref=ref, ttl=HIT_TTL)
        if mal or sus:
            return _result(self.name, url, "suspicious", category="suspicious", detail=detail, ref=ref, ttl=HIT_TTL)
        return _result(self.name, url, "not_listed", detail=detail + " No engine flagged it — that is not proof it is safe.", ref=ref, ttl=MISS_TTL)

    def health_probe(self, client):
        r = client.get("https://www.virustotal.com/api/v3/domains/example.com", headers={"x-apikey": settings.virustotal_api_key})
        if r.status_code == 429:
            return _result(self.name, "example.com", "unavailable", status="rate_limited")
        if r.status_code in (401, 403):
            return _result(self.name, "example.com", "error", detail="API key rejected", status="error")
        r.raise_for_status()
        return _result(self.name, "example.com", "not_listed")


class SafeBrowsing(Provider):
    name, label, covers = "google_safe_browsing", "Google Safe Browsing", "Google's phishing and malware lists (non-commercial use)"
    THREATS = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"]

    def configured(self) -> bool:
        return bool(settings.google_safe_browsing_key)

    def check_url(self, url, client):
        body = {"client": {"clientId": "three-bees", "clientVersion": "1.0"},
                "threatInfo": {"threatTypes": self.THREATS, "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"],
                               "threatEntries": [{"url": url}]}}
        r = client.post("https://safebrowsing.googleapis.com/v4/threatMatches:find", params={"key": settings.google_safe_browsing_key}, json=body)
        if r.status_code in (400, 401, 403):
            return _result(self.name, url, "error", detail="API key rejected or API not enabled", status="error")
        if r.status_code == 429:
            return _result(self.name, url, "unavailable", detail="Quota exceeded", status="rate_limited")
        r.raise_for_status()
        matches = r.json().get("matches") or []
        if not matches:
            return _result(self.name, url, "not_listed", detail="Not on Google's lists — that is not proof it is safe.", ttl=MISS_TTL)
        types = sorted({m.get("threatType", "") for m in matches})
        phishing = "SOCIAL_ENGINEERING" in types
        return _result(self.name, url, "known_phishing" if phishing else "known_malware", category="phishing" if phishing else "malware",
                       detail="Listed by Google Safe Browsing as " + ", ".join(t.replace("_", " ").lower() for t in types) + ".",
                       ref="https://transparencyreport.google.com/safe-browsing/search", ttl=HIT_TTL)


PROVIDERS: list[Provider] = [URLhaus(), VirusTotal(), SafeBrowsing()]


def check_url(url: str, *, client: httpx.Client | None = None) -> list[dict]:
    """Ask every configured provider about one URL. Never raises; failures come back as results."""
    out = []
    own = client is None
    client = client or httpx.Client(timeout=TIMEOUT, follow_redirects=False)
    try:
        for p in PROVIDERS:
            if not p.configured():
                out.append(_result(p.name, url, "not_configured", detail="No API key set", status="not_configured"))
                continue
            key = (p.name, url)
            with _lock:
                hit = _cache.get(key)
            if hit and hit[0] > time.time():
                out.append({**hit[1], "cached": True})
                continue
            try:
                res = p.check_url(url, client)
            except httpx.TimeoutException:
                res = _result(p.name, url, "unavailable", detail="Provider timed out", status="timeout")
            except Exception as exc:  # network down, 5xx, bad JSON …
                log.warning("intel provider %s failed: %s", p.name, exc.__class__.__name__)
                res = _result(p.name, url, "unavailable", detail=f"Provider unavailable ({exc.__class__.__name__})", status="unavailable")
            ok = res["result"] not in ("error", "unavailable")
            _record(p.name, ok, None if ok else res["detail"], rate_limited=res["provider_status"] == "rate_limited")
            ttl = HIT_TTL if res["result"].startswith("known") or res["result"] == "suspicious" else MISS_TTL if res["result"] == "not_listed" else 0
            if ttl:
                with _lock:
                    _cache[key] = (time.time() + ttl, res)
            out.append(res)
    finally:
        if own:
            client.close()
    return out


def findings(results: list[dict]) -> list[Finding]:
    fs = []
    for r in results:
        label = next((p.label for p in PROVIDERS if p.name == r["provider"]), r["provider"])
        if r["result"] == "known_phishing":
            fs.append(Finding(f"Listed as phishing by {label}", r["detail"], "intel", "critical", 80, "intel", ["phishing", "malicious_link"], evidence=r.get("source_reference")))
        elif r["result"] == "known_malware":
            fs.append(Finding(f"Listed as malware by {label}", r["detail"], "intel", "critical", 80, "intel", ["malware_delivery", "malicious_link"], evidence=r.get("source_reference")))
        elif r["result"] == "suspicious":
            fs.append(Finding(f"Flagged as suspicious by {label}", r["detail"], "intel", "high", 35, "intel", ["suspicious_infrastructure"], evidence=r.get("source_reference")))
    return fs


def limitations(results: list[dict]) -> list[str]:
    notes = []
    for r in results:
        label = next((p.label for p in PROVIDERS if p.name == r["provider"]), r["provider"])
        if r["result"] == "not_listed":
            notes.append(f"{label}: no record — not being listed is not proof that a link is safe.")
        elif r["result"] in ("unavailable", "error"):
            notes.append(f"{label}: {r['detail']} — reputation unknown, not clean.")
    return list(dict.fromkeys(notes))


def status() -> list[dict]:
    """Integration status without making requests: not_configured / connected / degraded / unavailable."""
    out = []
    with _lock:
        snap = {k: dict(v) for k, v in _health.items()}
    for p in PROVIDERS:
        h = snap.get(p.name, {})
        if not p.configured():
            st = "not_configured"
        elif not h:
            st = "unknown"  # configured but not used yet: run a health check to know
        elif h.get("errors", 0) == 0:
            st = "connected"
        elif h.get("rate_limited") or h.get("last_success"):
            st = "degraded"
        else:
            st = "unavailable"
        out.append({"provider": p.name, "label": p.label, "covers": p.covers, "status": st,
                    "last_success": h.get("last_success"), "last_error": h.get("last_error"), "rate_limited": h.get("rate_limited", False)})
    return out


def health_check() -> list[dict]:
    """Make one real, cheap request to each configured provider and report the outcome."""
    with httpx.Client(timeout=TIMEOUT, follow_redirects=False) as client:
        for p in PROVIDERS:
            if not p.configured():
                continue
            try:
                res = p.health_probe(client)
                ok = res["result"] not in ("error", "unavailable")
                _record(p.name, ok, None if ok else res.get("detail") or res["provider_status"], rate_limited=res["provider_status"] == "rate_limited")
            except httpx.TimeoutException:
                _record(p.name, False, "Provider timed out")
            except Exception as exc:
                _record(p.name, False, f"Provider unavailable ({exc.__class__.__name__})")
    return status()


def clear_cache() -> None:
    with _lock:
        _cache.clear()
        _health.clear()
