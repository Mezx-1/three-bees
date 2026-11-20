"""URL & domain inspection. Structural checks are deterministic; DNS/reputation are optional external intel."""
from __future__ import annotations

import ipaddress
import re
import unicodedata
from datetime import datetime, timezone
from urllib.parse import unquote, urlsplit

from .risk import Finding

MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "co.ae", "gov.ae", "ac.ae", "net.ae", "org.ae", "sch.ae",
    "mil.ae", "com.sa", "gov.sa", "com.eg", "com.qa", "com.kw", "com.bh", "com.om", "co.in", "co.jp", "com.br", "com.tr",
}

SUSPICIOUS_TLDS = {
    "top", "xyz", "zip", "mov", "click", "link", "gq", "tk", "ml", "cf", "ga", "work", "support", "rest", "cam", "icu",
    "buzz", "monster", "cfd", "sbs", "lol", "quest", "bond", "cyou", "beauty", "hair", "autos", "boats", "mom", "loan",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc",
    "rebrand.ly", "s.id", "t.ly", "lnkd.in", "qrco.de", "bit.do",
}

# Brand keyword -> registered domains that legitimately belong to it.
OFFICIAL_DOMAINS: dict[str, list[str]] = {
    "microsoft": ["microsoft.com", "live.com", "office.com", "microsoftonline.com", "outlook.com", "office365.com"],
    "office365": ["office.com", "microsoft.com", "office365.com"],
    "outlook": ["outlook.com", "live.com", "office.com"],
    "google": ["google.com", "gmail.com", "youtube.com", "google.ae"],
    "apple": ["apple.com", "icloud.com"],
    "paypal": ["paypal.com"],
    "amazon": ["amazon.com", "amazon.ae", "amazonaws.com"],
    "netflix": ["netflix.com"],
    "whatsapp": ["whatsapp.com", "whatsapp.net"],
    "adpolice": ["adpolice.gov.ae"],
    "dubaipolice": ["dubaipolice.gov.ae"],
    "etisalat": ["etisalat.ae", "eand.com"],
    "emiratesnbd": ["emiratesnbd.com"],
    "adcb": ["adcb.com"],
    "bankfab": ["bankfab.com"],
    "mashreq": ["mashreq.com", "mashreqbank.com"],
    "adnoc": ["adnoc.ae"],
    "aramex": ["aramex.com"],
    "dhl": ["dhl.com"],
    "emiratespost": ["emiratespost.ae"],
    "uaepass": ["uaepass.ae"],
    "tamm": ["tamm.abudhabi"],
    "salik": ["salik.ae"],
}

SENSITIVE_PATH_WORDS = ["login", "signin", "verify", "verification", "secure", "account", "update", "wallet", "otp", "password",
                        "confirm", "unlock", "billing", "payment", "invoice", "suspend", "webscr", "auth", "token"]


def registered_domain(host: str) -> str:
    host = host.lower().rstrip(".")
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "@": "a", "$": "s", "|": "l"})


def normalize_url(raw: str) -> str:
    raw = raw.strip().strip("<>\"'()[]")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", raw):
        raw = "http://" + raw
    return raw


def analyze_url(raw: str, *, blocklist: set[str] | None = None, org_domain: str | None = None) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    blocklist = blocklist or set()
    url = normalize_url(raw)
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    info: dict = {"url": url, "scheme": scheme, "host": host, "path": parts.path, "query": parts.query}

    if scheme in ("javascript", "data", "vbscript", "file"):
        findings.append(Finding("Dangerous URL scheme", f"The link uses the '{scheme}:' scheme, which can execute code or load local content.",
                                "url", "critical", 60, "verified", ["malicious_link"], evidence=url[:200]))
        return findings, info

    if not host:
        findings.append(Finding("Unparseable URL", "No valid host could be extracted from the URL.", "url", "low", 5, "verified"))
        return findings, info

    is_ip = False
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
        is_ip = True
        info["ip_literal"] = str(ip)
        findings.append(Finding("Link points to a raw IP address", "Legitimate services almost always use domain names; raw-IP links are common in phishing and malware delivery.",
                                "url", "high", 30, "verified", ["malicious_link"], evidence=host))
        if ip.is_private:
            findings.append(Finding("Link targets a private/internal IP", "The URL points at a private network address.", "url", "medium", 10, "verified", ["suspicious_infrastructure"]))
    except ValueError:
        pass

    reg = host if is_ip else registered_domain(host)
    info["registered_domain"] = reg
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    info["tld"] = tld

    if any(reg == b or host == b or host.endswith("." + b) for b in blocklist):
        findings.append(Finding("Domain is on the 3B blocklist", "An analyst previously blocked this domain in the local 3B environment.",
                                "url", "critical", 70, "verified", ["malicious_link"], evidence=reg))

    if scheme == "http":
        findings.append(Finding("Unencrypted HTTP link", "The link does not use HTTPS. Credentials sent here could be intercepted.", "url", "low", 8, "verified", ["phishing"]))

    if parts.username or "@" in parts.netloc:
        findings.append(Finding("Credentials/@ trick in URL", "The URL contains an '@' in the host part. Browsers ignore everything before '@', a trick to disguise the real destination.",
                                "url", "high", 35, "verified", ["phishing", "malicious_link"], evidence=parts.netloc))

    if parts.port and parts.port not in (80, 443):
        findings.append(Finding("Non-standard port", f"The link uses port {parts.port}.", "url", "low", 8, "verified", ["suspicious_infrastructure"]))

    if not is_ip:
        if "xn--" in host:
            try:
                decoded = host.encode("ascii").decode("idna")
            except Exception:
                decoded = host
            info["punycode_decoded"] = decoded
            findings.append(Finding("Internationalised (punycode) domain", f"Domain decodes to '{decoded}'. Punycode is used in homograph attacks that imitate real brands.",
                                    "url", "high", 28, "verified", ["phishing", "impersonation"], evidence=host))
        if any(ord(c) > 127 for c in host):
            scripts = {unicodedata.name(c, "?").split(" ")[0] for c in host if ord(c) > 127}
            findings.append(Finding("Non-ASCII characters in domain", f"Domain contains non-Latin characters ({', '.join(sorted(scripts))}) that can visually imitate Latin letters.",
                                    "url", "high", 28, "verified", ["phishing", "impersonation"], evidence=host))
        if tld in SUSPICIOUS_TLDS:
            findings.append(Finding("High-abuse top-level domain", f"'.{tld}' is a low-cost TLD heavily abused for phishing. Not proof of malice.",
                                    "url", "medium", 16, "heuristic", ["malicious_link"], evidence=f".{tld}"))
        if reg in SHORTENERS:
            findings.append(Finding("URL shortener", "Shortened links hide the true destination.", "url", "medium", 14, "verified", ["malicious_link"], evidence=reg))
        sub_count = host.count(".") - reg.count(".")
        if sub_count >= 3:
            findings.append(Finding("Excessive subdomains", f"The host has {sub_count} subdomain levels, often used to push the real domain out of view.",
                                    "url", "medium", 14, "heuristic", ["phishing"], evidence=host))
        label = reg.split(".")[0]
        if label.count("-") >= 2:
            findings.append(Finding("Hyphen-heavy domain", "Domains like 'secure-login-verify' are typical of phishing kits.", "url", "low", 10, "heuristic", ["phishing"], evidence=reg))

        # Brand impersonation and look-alikes.
        host_flat = host.replace("-", "").replace(".", "")
        normalized_label = label.translate(HOMOGLYPHS).replace("-", "")
        for brand, officials in OFFICIAL_DOMAINS.items():
            if reg in officials:
                info["official_brand"] = brand
                break
        else:
            for brand, officials in OFFICIAL_DOMAINS.items():
                if brand in host_flat:
                    findings.append(Finding(f"Brand name '{brand}' used on an unrelated domain",
                                            f"The host contains '{brand}' but the registered domain is '{reg}', not an official domain ({', '.join(officials)}).",
                                            "url", "high", 34, "heuristic", ["impersonation", "phishing"], evidence=host))
                    break
                official_labels = {o.split(".")[0] for o in officials}
                for ol in official_labels:
                    if len(ol) >= 4 and normalized_label != ol and _levenshtein(normalized_label, ol) <= (1 if len(ol) <= 5 else 2):
                        findings.append(Finding(f"Look-alike of '{ol}'",
                                                f"'{reg}' is visually close to the official '{ol}' domain (typosquatting/homoglyph).",
                                                "url", "high", 38, "heuristic", ["impersonation", "phishing"], evidence=f"{reg} ≈ {ol}"))
                        break
        if org_domain:
            org_label = registered_domain(org_domain).split(".")[0]
            if reg != registered_domain(org_domain) and org_label in host_flat:
                findings.append(Finding("Imitates your organisation's domain",
                                        f"The host contains '{org_label}' but is not your domain ({org_domain}).",
                                        "url", "high", 36, "heuristic", ["impersonation", "phishing"], evidence=host))

    path_q = unquote((parts.path + "?" + parts.query).lower())
    words = [w for w in SENSITIVE_PATH_WORDS if w in path_q]
    if words:
        findings.append(Finding("Sensitive keywords in link path", f"Path/query contains: {', '.join(words[:6])}.",
                                "url", "low", 8 + min(len(words), 4) * 2, "heuristic", ["phishing"], evidence=", ".join(words[:6])))
    if len(url) > 120:
        findings.append(Finding("Very long URL", f"URL is {len(url)} characters, which can hide its real destination.", "url", "low", 6, "heuristic", ["phishing"]))
    if re.search(r"\.(exe|scr|js|vbs|bat|cmd|msi|apk|hta|ps1|jar|iso|img|lnk)(\?|$)", parts.path.lower()):
        findings.append(Finding("Link downloads an executable file", "The URL points directly at an executable/script file type.",
                                "url", "high", 40, "verified", ["malware_delivery"], evidence=parts.path[-60:]))
    if re.search(r"(https?%3a|https?://).*(https?%3a|https?://)", url.lower()) or "redirect=" in path_q or "url=http" in path_q:
        findings.append(Finding("Embedded redirect", "The URL embeds another URL, a pattern used for open-redirect abuse.", "url", "low", 10, "heuristic", ["malicious_link"]))

    return findings, info


def resolve_dns(host: str) -> dict:
    """Live DNS lookup (external). Returns records with source + timestamp, or an error."""
    out: dict = {"source": "DNS (system resolver via dnspython)", "queried_at": datetime.now(timezone.utc).isoformat(), "records": {}}
    try:
        import dns.resolver  # type: ignore
    except Exception:
        out["error"] = "dnspython not installed"
        return out
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 3.0
    for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
        try:
            ans = resolver.resolve(host, rtype)
            out["records"][rtype] = [r.to_text() for r in ans][:8]
        except dns.resolver.NXDOMAIN:
            out["nxdomain"] = True
            break
        except Exception:
            continue
    return out


def dns_findings(dns_info: dict) -> list[Finding]:
    f: list[Finding] = []
    if dns_info.get("nxdomain"):
        f.append(Finding("Domain does not exist (NXDOMAIN)", "DNS reports the domain is not registered/resolvable. It may be taken down, not yet live, or fabricated.",
                         "intel", "medium", 12, "intel", ["suspicious_infrastructure"], evidence=dns_info.get("source")))
    elif dns_info.get("records") is not None and not dns_info.get("error"):
        recs = dns_info["records"]
        if recs and "MX" not in recs and "A" in recs:
            f.append(Finding("No mail (MX) records", "The domain resolves but has no mail servers — unusual for a domain sending business email.",
                             "intel", "low", 6, "intel", ["suspicious_infrastructure"]))
    return f
