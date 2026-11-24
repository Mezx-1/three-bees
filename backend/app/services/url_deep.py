"""Deeper URL checks: follow redirects / shorteners, read domain age from RDAP, recognise official UAE domains.

* Redirect following sends one HTTP request per hop to the site itself. It only runs when External lookups
  are switched on (with consent). Pages are never rendered and no script runs: at most 64 KB of the final
  page is read as text, to spot a password form, a brand name in the title or a client-side redirect.
  Private, loopback and link-local addresses are refused (no requests into the local network).
* RDAP (the registry successor of WHOIS) gives the registration date, registrar and abuse contact. It asks
  the public rdap.org bootstrap service about the domain name only.
* Official domains: a curated list of UAE government, bank, telecom, transport and delivery domains plus
  every *.gov.ae domain. An official domain lowers weak structural warnings (fewer false positives on real
  banks and government sites); it never hides a blocklist or reputation hit.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import time
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit

import httpx

from .risk import Finding
from . import url_analyzer as ua

UA_HEADER = {"User-Agent": "Mozilla/5.0 (compatible; 3B-ScamCheck/1.0; +https://github.com/Mezx-1/three-bees)"}
MAX_HOPS = 6
READ_BYTES = 64 * 1024

OFFICIAL_UAE = {
    # government / services
    "u.ae", "tamm.abudhabi", "uaepass.ae", "adpolice.gov.ae", "dubaipolice.gov.ae", "moi.gov.ae", "icp.gov.ae", "gdrfad.gov.ae", "mohre.gov.ae",
    "rta.ae", "salik.ae", "dewa.gov.ae", "addc.ae", "aadc.ae", "sewa.gov.ae", "etihadwe.ae", "tra.gov.ae", "tdra.gov.ae", "mof.gov.ae",
    "tax.gov.ae", "centralbank.ae", "sca.gov.ae", "dfsa.ae", "adgm.com", "difc.ae", "dubai.ae", "abudhabi.ae", "sharjah.ae", "zakat.ae",
    "itc.gov.ae", "adjd.gov.ae", "dc.gov.ae", "mofa.gov.ae", "emiratesid.ae",
    # banks
    "adcb.com", "bankfab.com", "emiratesnbd.com", "mashreq.com", "mashreqbank.com", "adib.ae", "dib.ae", "rakbank.ae", "cbd.ae",
    "nbf.ae", "ajmanbank.ae", "sib.ae", "eib.ae", "uab.ae", "wio.io", "liv.me", "hsbc.ae", "citibank.ae", "alhilalbank.ae", "cbi.ae",
    # telecom, delivery, airlines, utilities, retail
    "etisalat.ae", "eand.com", "eand.ae", "du.ae", "virginmobile.ae", "emiratespost.ae", "aramex.com", "dhl.com", "fedex.com", "ups.com",
    "emirates.com", "etihad.com", "flydubai.com", "airarabia.com", "adnoc.ae", "adnocdistribution.ae", "noon.com", "amazon.ae", "careem.com",
    "talabat.com", "dubizzle.com", "propertyfinder.ae", "bayut.com", "lulumall.ae", "carrefouruae.com",
}
# Free site builders / hosting platforms: anyone can publish a page under their name in minutes.
FREE_HOSTS = {
    "vercel.app", "netlify.app", "pages.dev", "workers.dev", "r2.dev", "web.app", "firebaseapp.com", "github.io", "gitlab.io", "glitch.me",
    "godaddysites.com", "weebly.com", "weeblysite.com", "wixsite.com", "wix.com", "square.site", "webflow.io", "framer.app", "framer.website",
    "blogspot.com", "wordpress.com", "000webhostapp.com", "ngrok.io", "ngrok-free.app", "ngrok.app", "replit.app", "repl.co", "herokuapp.com",
    "azurewebsites.net", "appspot.com", "onrender.com", "fly.dev", "surge.sh", "tiiny.site", "mystrikingly.com", "jimdosite.com",
    "sites.google.com", "forms.gle", "docs.google.com", "ipfs.io", "dweb.link", "cloudflare-ipfs.com", "translate.goog", "webcindario.com",
    "canva.site", "my.canva.site", "notion.site", "carrd.co", "typedream.app", "start.page", "linktr.ee", "qr-codes.io", "beacons.ai",
    "gitbook.io", "railway.app", "up.railway.app", "4everland.app", "qrcodechimp.page", "webnode.page", "ucoz.net", "wixstudio.io",
    "duckdns.org", "no-ip.org", "ddns.net", "hostel.town", "zh.kg", "pp.ua", "biz.ua", "web.core.windows.net", "blob.core.windows.net",
    "storage.googleapis.com", "s3.amazonaws.com", "codeanyapp.com", "lovable.app", "bolt.host", "temp.domains",
}


def is_official(reg: str, host: str = "") -> bool:
    reg = (reg or "").lower()
    if reg in OFFICIAL_UAE or reg.endswith(".gov.ae") or reg.endswith(".mil.ae"):
        return True
    return any(reg in v for v in ua.OFFICIAL_DOMAINS.values())


def free_host(host: str) -> str | None:
    host = (host or "").lower()
    for f in FREE_HOSTS:
        if host == f or host.endswith("." + f):
            return f
    return None


def _safe_target(host: str) -> str | None:
    """Refuse hosts that resolve to private / loopback / link-local / reserved addresses. Returns an error text or None."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return "Domain does not resolve"
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            return "Refused: resolves to a private or reserved address"
    return None


def expand(url: str, *, client: httpx.Client | None = None) -> dict:
    """Follow redirects hop by hop (HTTP and client-side meta refresh), without rendering anything."""
    out: dict = {"source": "Direct HTTP request (no rendering, no scripts)", "queried_at": datetime.now(timezone.utc).isoformat(),
                 "chain": [], "final_url": None}
    cur = ua.normalize_url(url)
    own = client is None
    client = client or httpx.Client(timeout=6.0, follow_redirects=False, headers=UA_HEADER, verify=True)
    try:
        for _ in range(MAX_HOPS):
            host = urlsplit(cur).hostname or ""
            err = _safe_target(host) if host else "No host"
            if err:
                out["error"] = err
                break
            with client.stream("GET", cur) as r:
                body = b""
                if r.status_code < 300 or r.status_code >= 400:
                    for chunk in r.iter_bytes():
                        body += chunk
                        if len(body) >= READ_BYTES:
                            break
                out["chain"].append({"url": cur, "status": r.status_code})
                loc = r.headers.get("location")
                if 300 <= r.status_code < 400 and loc:
                    cur = urljoin(cur, loc)
                    continue
                text = body.decode(r.encoding or "utf-8", errors="replace")
                page = inspect_html(text)
                out.update(page)
                if page.get("meta_refresh_to") and len(out["chain"]) < MAX_HOPS:
                    cur = urljoin(cur, page["meta_refresh_to"])
                    continue
                break
        out["final_url"] = cur
    except httpx.HTTPError as exc:
        out["error"] = f"Could not fetch: {exc.__class__.__name__}"
        out["final_url"] = cur
    finally:
        if own:
            client.close()
    return out


def inspect_html(text: str) -> dict:
    low = text.lower()
    title = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    meta = re.search(r"<meta[^>]+http-equiv=[\"']?refresh[\"']?[^>]+content=[\"'][^\"']*url=([^\"'>\s]+)", text, re.I)
    return {
        "title": re.sub(r"\s+", " ", title.group(1)).strip()[:200] if title else None,
        "password_form": bool(re.search(r"<input[^>]+type=[\"']?password", low)),
        "card_form": bool(re.search(r"(card ?number|cardnumber|cvv|cvc|expiry|رقم البطاقة)", low)),
        "meta_refresh_to": meta.group(1) if meta else None,
        "js_redirect": bool(re.search(r"(window|document|top)\.location(\.href)?\s*=|location\.replace\(", low)),
    }


_RDAP_CACHE: dict[str, tuple[float, dict]] = {}


def rdap(domain: str, *, client: httpx.Client | None = None) -> dict:
    """Registration data for a registered domain from RDAP (via the rdap.org bootstrap). Cached 24 h."""
    domain = domain.lower()
    hit = _RDAP_CACHE.get(domain)
    if hit and time.time() - hit[0] < 86400:
        return hit[1]
    out: dict = {"source": "RDAP via rdap.org", "queried_at": datetime.now(timezone.utc).isoformat(), "domain": domain}
    own = client is None
    client = client or httpx.Client(timeout=8.0, follow_redirects=True, headers=UA_HEADER)
    try:
        r = client.get(f"https://rdap.org/domain/{domain}")
        if r.status_code == 404:
            out["error"] = "No RDAP record (registry may not publish RDAP, or the domain is not registered)"
        elif r.status_code >= 400:
            out["error"] = f"RDAP error {r.status_code}"
        else:
            d = r.json()
            for ev in d.get("events", []):
                if ev.get("eventAction") == "registration":
                    out["registered"] = ev.get("eventDate")
                elif ev.get("eventAction") == "expiration":
                    out["expires"] = ev.get("eventDate")
                elif ev.get("eventAction") == "last changed":
                    out["last_changed"] = ev.get("eventDate")
            for ent in d.get("entities", []):
                roles = ent.get("roles", [])
                name = _vcard(ent, "fn")
                if "registrar" in roles:
                    out["registrar"] = name
                    for sub in ent.get("entities", []):
                        if "abuse" in sub.get("roles", []):
                            out["abuse_email"] = _vcard(sub, "email")
                            out["abuse_phone"] = _vcard(sub, "tel")
                if "abuse" in roles and not out.get("abuse_email"):
                    out["abuse_email"] = _vcard(ent, "email")
            out["nameservers"] = [n.get("ldhName", "").lower() for n in d.get("nameservers", [])][:6]
            out["status"] = d.get("status", [])
            if out.get("registered"):
                try:
                    reg = datetime.fromisoformat(out["registered"].replace("Z", "+00:00"))
                    out["age_days"] = (datetime.now(timezone.utc) - reg).days
                except ValueError:
                    pass
    except (httpx.HTTPError, ValueError) as exc:
        out["error"] = f"RDAP unavailable: {exc.__class__.__name__}"
    finally:
        if own:
            client.close()
    if not out.get("error"):
        _RDAP_CACHE[domain] = (time.time(), out)
    return out


def _vcard(ent: dict, field: str) -> str | None:
    for item in (ent.get("vcardArray") or [None, []])[1]:
        if item and item[0] == field:
            v = item[3]
            return v if isinstance(v, str) else None
    return None


# ----------------------------------------------------------------- findings

def static_findings(info: dict) -> list[Finding]:
    """Offline checks added on top of url_analyzer (no network)."""
    out: list[Finding] = []
    host, reg = info.get("host") or "", info.get("registered_domain") or ""
    fh = free_host(host)
    path = (info.get("path") or "").lower()
    if fh and host in (fh, "www." + fh):
        fh = None  # the platform's own home page
    if fh and not is_official(reg):
        sub = host[: -len(fh)].rstrip(".")
        out.append(Finding("Page on a free website builder or hosting platform",
                           f"'{host}' is a page anyone can publish for free on {fh}. Banks, government services and couriers don't run their login or payment pages there.",
                           "url", "medium", 28, "heuristic", ["phishing", "malicious_link"], evidence=fh))
        flat = sub.replace("-", "").replace(".", "")
        brand = next((b for b in ua.OFFICIAL_DOMAINS if b in flat), None)
        if brand:
            out.append(Finding(f"Brand name '{brand}' on a free hosting page", f"A free hosting page named after '{brand}' is not the brand's site.",
                               "url", "high", 36, "heuristic", ["impersonation", "phishing"], evidence=sub[:80]))
        if re.search(r"\d{3,}|[a-z0-9]{14,}", sub.replace("-", "")) or any(w in sub for w in ua.SENSITIVE_PATH_WORDS):
            out.append(Finding("Random or login-themed name on a free platform",
                               "The sub-site name looks generated or uses login/verify words — typical of throw-away phishing pages.",
                               "url", "medium", 18, "heuristic", ["phishing"], evidence=sub[:80]))
    label = reg.split(".")[0] if reg else ""
    if label and not is_official(reg) and not fh:
        if re.search(r"\d{4,}", label) or (len(label) >= 20 and label.count("-") == 0 and not re.search(r"[aeiou]{1}", label[-6:])):
            out.append(Finding("Machine-generated looking domain name", "The domain name looks random or auto-generated, which is common for short-lived scam sites.",
                               "url", "low", 10, "heuristic", ["malicious_link"], evidence=reg))
        brandish = [w for w in ("login", "secure", "verify", "account", "update", "support", "service", "billing", "wallet", "auth", "signin", "confirm", "pay")
                    if w in label]
        if brandish and label.count("-") >= 1:
            out.append(Finding("Domain name built from account/security words",
                               f"The domain itself contains words like '{brandish[0]}' joined with hyphens — real organisations rarely register names like this.",
                               "url", "medium", 16, "heuristic", ["phishing"], evidence=reg))
    if re.search(r"\.(php|html?)$", path) and any(w in path for w in ("login", "signin", "verify", "account", "secure", "update", "billing")):
        out.append(Finding("Login or verify page file in the link", "The link opens a page file named like a login/verification form.", "url", "low", 10, "heuristic", ["phishing"], evidence=path[-60:]))
    if re.search(r"/wp-(admin|content|includes)/", path) and re.search(r"\.(php|html?)(/|$)|index", path) and not is_official(reg):
        out.append(Finding("Page hidden inside a website's WordPress folders",
                           "The link opens a page inside the WordPress system or plugin folders — a typical sign of a hacked website hosting a phishing page.",
                           "url", "medium", 24, "heuristic", ["phishing", "malicious_link"], evidence=path[-80:]))
    if not is_official(reg):
        p_flat = re.sub(r"[^a-z0-9]", "", path)
        brand = next((b for b in ua.OFFICIAL_DOMAINS if len(b) >= 5 and b in p_flat and b not in (reg or "")), None)
        if brand:
            out.append(Finding(f"Brand name '{brand}' in the link path of another site", f"The page path mentions '{brand}' but the site is '{reg}'.",
                               "url", "medium", 18, "heuristic", ["impersonation", "phishing"], evidence=path[-80:]))
    tail = f"{info.get('query') or ''}#{(info.get('url') or '').split('#', 1)[1] if '#' in (info.get('url') or '') else ''}"
    if re.search(r"[\w.+-]+@[\w-]+\.[\w.]+", tail) or _b64_email(tail):
        out.append(Finding("Link carries an email address", "The link contains an email address (sometimes encoded). Phishing kits use this to pre-fill the victim's address on a fake login page.",
                           "url", "medium", 20, "heuristic", ["phishing", "credential_theft"]))
    return out


def _b64_email(s: str) -> bool:
    import base64
    import binascii

    for tok in re.findall(r"[A-Za-z0-9+/=_-]{16,}", s):
        try:
            dec = base64.b64decode(tok + "=" * (-len(tok) % 4), altchars=b"-_", validate=False).decode("utf-8", "ignore")
        except (binascii.Error, ValueError):
            continue
        if re.fullmatch(r"[\w.+-]+@[\w-]+\.[\w.]+", dec.strip()):
            return True
    return False


def deep_findings(info: dict, exp: dict | None, reg_info: dict | None) -> tuple[list[Finding], dict]:
    """Findings from redirect following and RDAP. Returns findings and a summary for the report."""
    out: list[Finding] = []
    summary: dict = {}
    if exp:
        chain = exp.get("chain") or []
        summary["redirects"] = chain
        final = exp.get("final_url")
        start_reg = info.get("registered_domain")
        if final:
            f_parts = urlsplit(final)
            f_host = (f_parts.hostname or "").lower()
            f_reg = ua.registered_domain(f_host) if f_host else ""
            summary["final_url"], summary["final_registered_domain"] = final, f_reg
            if f_reg and f_reg != start_reg and len(chain) > 1:
                sev, w = ("medium", 18) if not is_official(f_reg) else ("info", 0)
                out.append(Finding("Link redirects to a different site", f"The link starts at '{start_reg}' but ends at '{f_reg}' after {len(chain) - 1} redirect(s). "
                                   "Shorteners and redirects hide the real destination.", "url", sev, w, "verified", ["malicious_link"],
                                   evidence=" → ".join(c["url"][:60] for c in chain[:5])))
                ff, finfo = ua.analyze_url(final)
                for f in ff + static_findings(finfo):
                    if f.weight >= 10:
                        out.append(Finding(f"{f.title} (after redirect)", f.detail, f.category, f.severity, f.weight, f.source, f.tags, evidence=f"{f_reg}: {f.evidence or ''}"))
        dest_reg = summary.get("final_registered_domain") or start_reg
        official = is_official(dest_reg or "")
        if exp.get("password_form") and not official:
            out.append(Finding("Page asks for a password on an unofficial site", "The page contains a password field, but the site isn't an official domain of any brand we know.",
                               "url", "high", 34, "verified", ["phishing", "credential_theft"], evidence=exp.get("title")))
        if exp.get("card_form") and not official:
            out.append(Finding("Page asks for card details on an unofficial site", "The page asks for card number / CVV / expiry on a site that isn't an official payment page.",
                               "url", "high", 34, "verified", ["phishing", "payment_fraud"], evidence=exp.get("title")))
        title = (exp.get("title") or "").lower().replace(" ", "")
        if title and not official:
            for brand, officials in ua.OFFICIAL_DOMAINS.items():
                if brand in title:
                    out.append(Finding(f"Page title claims to be '{brand}'", f"The page calls itself '{exp.get('title')}' but is hosted on '{dest_reg}', not {', '.join(officials)}.",
                                       "url", "high", 36, "verified", ["impersonation", "phishing"], evidence=exp.get("title")))
                    break
        if exp.get("js_redirect") and not official:
            out.append(Finding("Page moves you on with a script", "The page redirects with JavaScript, a trick used to show scanners a different page than people (cloaking).",
                               "url", "low", 10, "heuristic", ["malicious_link"]))
        if exp.get("error"):
            summary["fetch_error"] = exp["error"]
    if reg_info:
        summary["rdap"] = {k: reg_info.get(k) for k in ("registered", "age_days", "registrar", "abuse_email", "abuse_phone", "nameservers", "expires", "error")}
        age = reg_info.get("age_days")
        if age is not None and not is_official(info.get("registered_domain") or ""):
            if age < 30:
                out.append(Finding("Newly registered domain", f"The domain was registered {age} day(s) ago. Most scam sites are used within days of registration.",
                                   "intel", "high", 38, "intel", ["suspicious_infrastructure", "phishing"], evidence=f"RDAP registration {reg_info.get('registered')}"))
            elif age < 180:
                out.append(Finding("Young domain", f"The domain is {age} days old.", "intel", "medium", 16, "intel", ["suspicious_infrastructure"],
                                   evidence=f"RDAP registration {reg_info.get('registered')}"))
    return out, summary


def official_adjust(findings: list[Finding], info: dict) -> Finding | None:
    """On an official domain, weak structural signals are scaled down (they create false positives on real sites)."""
    reg = info.get("registered_domain") or ""
    if not is_official(reg, info.get("host") or ""):
        return None
    for f in findings:
        if f.category == "url" and f.source == "heuristic" and f.title.startswith(("Brand name", "Look-alike", "Domain starts with")):
            f.weight, f.severity = 0, "info"
        elif f.category == "url" and f.source == "heuristic" and f.weight < 30:
            f.weight = max(0, f.weight // 3)
            f.severity = "low" if f.weight else "info"
    return Finding("Official domain", f"'{reg}' is on 3B's list of official UAE government, bank and service domains. Weak link warnings were reduced; "
                   "it is still checked against blocklists and reputation services.", "url", "info", 0, "verified", [], evidence=reg)
