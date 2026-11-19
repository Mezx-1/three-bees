"""IP and phone-number intelligence.

Deterministic facts (validity, private/reserved ranges, country calling code) are always computed.
Geolocation/ASN/reputation come only from external providers when enabled, and every external result
carries its source and timestamp. Nothing is fabricated when a provider is unavailable.
"""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone

import httpx

from ..config import settings
from .risk import Finding

LIMITATIONS_IP = [
    "IP geolocation is approximate (city/region level at best) and reflects the network operator, not a person or device.",
    "VPNs, proxies, Tor and cloud hosting hide the true origin of traffic.",
]


def analyze_ip(value: str) -> tuple[list[Finding], dict, list[str]]:
    findings: list[Finding] = []
    limitations = list(LIMITATIONS_IP)
    value = value.strip().strip("[]")
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        raise ValueError(f"'{value}' is not a valid IPv4 or IPv6 address")
    info = {
        "ip": str(ip), "version": ip.version, "is_private": ip.is_private, "is_loopback": ip.is_loopback,
        "is_reserved": ip.is_reserved, "is_multicast": ip.is_multicast, "is_link_local": ip.is_link_local,
        "is_global": ip.is_global,
    }
    doc_ranges = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]
    if any(ip in n for n in doc_ranges if n.version == ip.version):
        info["documentation_range"] = True
        findings.append(Finding("Documentation/test IP range", "This address is reserved for documentation (RFC 5737/3849) and is not routable on the internet. Used in WOLVE demo scenarios.",
                                "network", "info", 0, "verified"))
    elif ip.is_private or ip.is_loopback or ip.is_link_local:
        findings.append(Finding("Private / internal address", "This is not a public internet address; it belongs to a local network. External geolocation does not apply.",
                                "network", "info", 0, "verified"))
    elif not ip.is_global:
        findings.append(Finding("Reserved / special-purpose address", "Address is in a special-purpose range.", "network", "low", 5, "verified"))
    return findings, info, limitations


def geolocate(ip: str) -> dict:
    """ip-api.com free endpoint (no key). Only called when external lookups are enabled."""
    out = {"source": "ip-api.com", "queried_at": datetime.now(timezone.utc).isoformat()}
    try:
        r = httpx.get(f"http://ip-api.com/json/{ip}", params={"fields": "status,message,country,countryCode,regionName,city,isp,org,as,asname,proxy,hosting,mobile,query"}, timeout=4.0)
        data = r.json()
        if data.get("status") != "success":
            out["error"] = data.get("message", "lookup failed")
        else:
            out["data"] = data
    except Exception as exc:
        out["error"] = f"Provider unreachable: {exc.__class__.__name__}"
    return out


def geo_findings(geo: dict) -> list[Finding]:
    f: list[Finding] = []
    d = geo.get("data") or {}
    if d.get("proxy"):
        f.append(Finding("Provider flags IP as proxy/VPN/Tor", "The geolocation provider marks this IP as an anonymising proxy.", "intel", "medium", 18, "intel",
                         ["suspicious_infrastructure"], evidence=f"{geo['source']} @ {geo['queried_at']}"))
    if d.get("hosting"):
        f.append(Finding("Hosting / data-centre IP", "IP belongs to a hosting provider rather than a residential or corporate network — typical for phishing servers, also for legitimate services.",
                         "intel", "low", 8, "intel", ["suspicious_infrastructure"], evidence=f"{d.get('isp')} ({d.get('as')})"))
    return f


def abuseipdb(ip: str) -> dict:
    out = {"source": "AbuseIPDB", "queried_at": datetime.now(timezone.utc).isoformat()}
    if not settings.abuseipdb_api_key:
        out["error"] = "not configured (set ABUSEIPDB_API_KEY)"
        out["configured"] = False
        return out
    try:
        r = httpx.get("https://api.abuseipdb.com/api/v2/check", params={"ipAddress": ip, "maxAgeInDays": 90},
                      headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"}, timeout=5.0)
        out["data"] = r.json().get("data", {})
    except Exception as exc:
        out["error"] = f"Provider unreachable: {exc.__class__.__name__}"
    return out


def abuse_findings(rep: dict) -> list[Finding]:
    d = rep.get("data") or {}
    score = d.get("abuseConfidenceScore")
    if score is None:
        return []
    if score >= 50:
        return [Finding("IP reported for abuse", f"AbuseIPDB confidence score {score}/100 from {d.get('totalReports', 0)} reports.", "intel", "high", min(70, 20 + score // 2), "intel",
                        ["suspicious_infrastructure"], evidence=f"AbuseIPDB @ {rep['queried_at']}")]
    if score > 0:
        return [Finding("IP has some abuse reports", f"AbuseIPDB score {score}/100.", "intel", "low", 8, "intel", ["suspicious_infrastructure"])]
    return []


# --- phone numbers ---------------------------------------------------------------------------

CALLING_CODES = {
    "971": "United Arab Emirates", "966": "Saudi Arabia", "974": "Qatar", "965": "Kuwait", "973": "Bahrain", "968": "Oman",
    "20": "Egypt", "962": "Jordan", "961": "Lebanon", "963": "Syria", "964": "Iraq", "98": "Iran", "90": "Turkey", "92": "Pakistan",
    "91": "India", "880": "Bangladesh", "94": "Sri Lanka", "977": "Nepal", "63": "Philippines", "62": "Indonesia", "60": "Malaysia",
    "86": "China", "852": "Hong Kong", "7": "Russia/Kazakhstan", "44": "United Kingdom", "1": "USA/Canada (NANP)", "33": "France",
    "49": "Germany", "234": "Nigeria", "233": "Ghana", "254": "Kenya", "27": "South Africa", "212": "Morocco", "213": "Algeria",
    "216": "Tunisia", "249": "Sudan", "252": "Somalia", "251": "Ethiopia", "84": "Vietnam", "855": "Cambodia", "95": "Myanmar",
    "856": "Laos", "882": "International Networks (satellite/IoT)", "883": "International Networks", "881": "Global Mobile Satellite",
}
HIGH_RISK_PREFIXES = {"882", "883", "881"}
UAE_MOBILE_PREFIXES = {"50", "52", "54", "55", "56", "58"}


def analyze_phone(raw: str) -> tuple[list[Finding], dict, list[str]]:
    findings: list[Finding] = []
    digits = re.sub(r"[^\d+]", "", raw)
    if digits.startswith("00"):
        digits = "+" + digits[2:]
    if digits.startswith("05") and len(digits) == 10:  # UAE local mobile format
        digits = "+971" + digits[1:]
    if not re.fullmatch(r"\+?\d{6,15}", digits):
        raise ValueError("Not a valid phone number (expected 6–15 digits, optionally with + country code)")
    info: dict = {"input": raw, "normalized": digits}
    if digits.startswith("+"):
        num = digits[1:]
        code = next((num[:n] for n in (3, 2, 1) if num[:n] in CALLING_CODES), None)
        info["country_code"] = code
        info["registered_region"] = CALLING_CODES.get(code) if code else "Unknown"
        if code == "971":
            rest = num[3:]
            if rest[:2] in UAE_MOBILE_PREFIXES and len(rest) == 9:
                info["line_type_hint"] = "UAE mobile number format"
            elif rest.startswith("800") or rest.startswith("600"):
                info["line_type_hint"] = "UAE toll-free / shared-cost number format"
        elif code:
            findings.append(Finding("International number", f"Calling code +{code} is assigned to {CALLING_CODES[code]}. Scam calls claiming to be local authorities or banks often come from abroad.",
                                    "phone", "low", 10, "verified", ["vishing"], evidence=f"+{code}"))
        if code in HIGH_RISK_PREFIXES:
            findings.append(Finding("Satellite / international-network number", "These ranges are frequently used for premium-rate and wangiri fraud.",
                                    "phone", "high", 30, "verified", ["vishing", "payment_fraud"], evidence=f"+{code}"))
    else:
        info["country_code"] = None
        info["registered_region"] = "Unknown (no country code)"
    limitations = [
        "A country calling code shows where the number range is registered — NOT where the caller physically is.",
        "Caller ID can be spoofed: a call showing a local or official number may originate anywhere.",
        "No carrier/HLR or reputation lookup is configured; WOLVE cannot confirm the number's owner.",
    ]
    return findings, info, limitations
