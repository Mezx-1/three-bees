"""Email parsing and header/sender/authentication inspection (RFC 5322 / MIME).

Works on raw .eml bytes or pasted text (headers + body, or body only)."""
from __future__ import annotations

import email
import html as html_lib
import re
from email import policy
from email.message import EmailMessage
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser

from .risk import Finding
from .url_analyzer import HOMOGLYPHS, OFFICIAL_DOMAINS, _levenshtein, registered_domain

FREEMAIL = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "live.com", "aol.com", "icloud.com", "proton.me", "protonmail.com",
            "gmx.com", "mail.com", "yandex.com", "zoho.com", "mail.ru"}
EXEC_TITLES = re.compile(r"\b(ceo|cfo|coo|chief|director|chairman|president|managing|head of|manager|police|ministry|bank|support|security|it )\b", re.I)
URL_RE = re.compile(r"""(?:(?:https?|hxxps?)://|www\.)[^\s<>"'()\[\]{}]+""", re.I)


class _LinkExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: list[dict] = []
        self.text_parts: list[str] = []
        self._href: str | None = None
        self._anchor: list[str] = []
        self.forms = 0
        self.password_inputs = 0
        self.images: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in ("script", "style"):
            self._skip += 1
        if tag == "a" and a.get("href"):
            self._href = a["href"]
            self._anchor = []
        elif tag == "form":
            self.forms += 1
        elif tag == "input" and (a.get("type") or "").lower() == "password":
            self.password_inputs += 1
        elif tag == "img" and a.get("src"):
            self.images.append(a["src"])
        if tag in ("br", "p", "div", "tr", "li"):
            self.text_parts.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        if tag == "a" and self._href is not None:
            self.links.append({"href": self._href, "text": "".join(self._anchor).strip()})
            self._href = None

    def handle_data(self, data):
        if self._skip:
            return
        self.text_parts.append(data)
        if self._href is not None:
            self._anchor.append(data)


def looks_like_headers(text: str) -> bool:
    head = text.lstrip()[:2000]
    return bool(re.search(r"^(from|subject|to|received|return-path|delivered-to|message-id|date):", head, re.I | re.M))


_INLINE_STOP = r"(?=\s+(?:from|subject|to|date|sent|email|reply-to)\s*:|\s+(?:dear|hello|hi|hey|greetings|good (?:morning|afternoon|evening))\b|\n|$)"


def _pasted_as_message(text: str) -> str:
    """Rebuild a pasted email whose headers and body were run together (e.g. copied as one line from a mail client).

    Known header fields are pulled out of the text; the whole paste is kept as the body so no content is lost."""
    headers = ["Content-Type: text/plain; charset=utf-8"]
    for name in ("From", "Subject", "To", "Date", "Reply-To"):
        m = re.search(r"(?:^|\s)" + name + r"\s*:\s*(.+?)" + _INLINE_STOP, text, re.I)
        if m and m.group(1).strip():
            headers.append(f"{name}: {re.sub(r'[\r\n]+', ' ', m.group(1).strip())[:300]}")
    return "\n".join(headers) + "\n\n" + text


def parse_email(raw: bytes | str) -> EmailMessage:
    if isinstance(raw, str):
        text = raw
        if not looks_like_headers(text):
            raw = "Content-Type: text/plain; charset=utf-8\n\n" + text
        else:
            msg = email.message_from_bytes(text.encode("utf-8", "replace"), policy=policy.default)
            body = msg.get_body(preferencelist=("plain", "html"))
            content = body.get_content() if body is not None else ""
            # Headers with (almost) no body: the paste ran headers and text together, so rebuild it.
            if len(content.strip()) < 40 and len(text) > 120:
                raw = _pasted_as_message(text)
            else:
                return msg  # type: ignore[return-value]
        raw = raw.encode("utf-8", "replace")
    return email.message_from_bytes(raw, policy=policy.default)  # type: ignore[return-value]


def _domain(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower().strip(">").strip() if "@" in addr else ""


def parse_auth_results(msg: EmailMessage) -> dict:
    res: dict = {}
    blobs = [str(v) for v in (msg.get_all("Authentication-Results") or [])] + [str(v) for v in (msg.get_all("ARC-Authentication-Results") or [])]
    for blob in blobs:
        for mech in ("spf", "dkim", "dmarc"):
            m = re.search(rf"\b{mech}\s*=\s*([a-z]+)", blob, re.I)
            if m and mech not in res:
                res[mech] = m.group(1).lower()
    spf_hdr = msg.get("Received-SPF")
    if spf_hdr and "spf" not in res:
        res["spf"] = str(spf_hdr).split()[0].lower()
    res["dkim_signature_present"] = msg.get("DKIM-Signature") is not None
    return res


def extract_parts(msg: EmailMessage) -> dict:
    text_body, html_body = "", ""
    attachments: list[dict] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        disp = (part.get_content_disposition() or "").lower()
        filename = part.get_filename()
        if ctype == "text/plain" and disp != "attachment" and not filename:
            try:
                text_body += part.get_content() + "\n"
            except Exception:
                text_body += (part.get_payload(decode=True) or b"").decode("utf-8", "replace")
        elif ctype == "text/html" and disp != "attachment" and not filename:
            try:
                html_body += part.get_content() + "\n"
            except Exception:
                html_body += (part.get_payload(decode=True) or b"").decode("utf-8", "replace")
        else:
            payload = part.get_payload(decode=True) or b""
            attachments.append({
                "filename": filename or f"inline-{len(attachments) + 1}.{ctype.split('/')[-1]}",
                "declared_mime": ctype, "disposition": disp or "inline", "content_id": (part.get("Content-ID") or "").strip("<>"),
                "data": payload,
            })
    return {"text": text_body, "html": html_body, "attachments": attachments}


def inspect_headers(msg: EmailMessage, org_domain: str | None) -> tuple[list[Finding], dict, list[str]]:
    findings: list[Finding] = []
    limitations: list[str] = []
    from_name, from_addr = parseaddr(str(msg.get("From", "")))
    reply_name, reply_addr = parseaddr(str(msg.get("Reply-To", "")))
    _, return_path = parseaddr(str(msg.get("Return-Path", "")))
    from_dom, reply_dom, rp_dom = _domain(from_addr), _domain(reply_addr), _domain(return_path)
    to = [a for _, a in getaddresses([str(v) for v in (msg.get_all("To") or [])])]
    received = [str(v) for v in (msg.get_all("Received") or [])]
    msg_id = str(msg.get("Message-ID", "") or "")
    auth = parse_auth_results(msg)

    meta = {
        "from_name": from_name, "from_address": from_addr, "from_domain": from_dom, "reply_to": reply_addr or None,
        "return_path": return_path or None, "to": to, "cc": [a for _, a in getaddresses([str(v) for v in (msg.get_all("Cc") or [])])],
        "subject": str(msg.get("Subject", "") or ""), "date": str(msg.get("Date", "") or ""), "message_id": msg_id,
        "x_mailer": str(msg.get("X-Mailer", "") or "") or None, "received_hops": len(received),
        "received_chain": received[:8], "authentication": auth,
    }

    if not from_addr:
        limitations.append("No From header found — sender checks were skipped (pasted body only?).")
        return findings, meta, limitations

    # --- authentication results ---
    if not any(k in auth for k in ("spf", "dkim", "dmarc")):
        limitations.append("No Authentication-Results header: SPF/DKIM/DMARC outcome unknown. Paste full headers or upload the .eml for this check.")
    labels = {"spf": "SPF", "dkim": "DKIM", "dmarc": "DMARC"}
    for mech, label in labels.items():
        val = auth.get(mech)
        if val in ("fail", "permerror", "hardfail"):
            w = 34 if mech == "dmarc" else 26
            findings.append(Finding(f"{label} check failed", f"The receiving server reported {label}={val}. The message was not authorised by the domain it claims to come from.",
                                    "authentication", "high", w, "verified", ["phishing", "impersonation"], evidence=f"{mech}={val}"))
        elif val in ("softfail", "none", "neutral", "temperror"):
            findings.append(Finding(f"{label} not passing ({val})", f"{label} result was '{val}', so the sender's domain could not be confirmed.",
                                    "authentication", "medium", 12, "verified", ["phishing"], evidence=f"{mech}={val}"))
        elif val == "pass":
            findings.append(Finding(f"{label} passed", f"{label} passed for the sending domain. Note: attackers can pass these checks on domains they own.",
                                    "authentication", "info", 0, "verified", evidence=f"{mech}=pass"))

    # --- sender consistency ---
    if reply_dom and reply_dom != from_dom:
        sev, w = ("high", 30) if reply_dom in FREEMAIL or registered_domain(reply_dom) != registered_domain(from_dom) else ("low", 8)
        findings.append(Finding("Reply-To differs from sender", f"Replies go to {reply_addr}, not the sender {from_addr}. Attackers use this to receive replies on a mailbox they control.",
                                "sender", sev, w, "verified", ["bec", "impersonation"], evidence=f"From {from_dom} → Reply-To {reply_dom}"))
    if rp_dom and registered_domain(rp_dom) != registered_domain(from_dom):
        findings.append(Finding("Return-Path domain differs from From domain", f"Envelope sender is {return_path}. Common for mailing services, but also for spoofing.",
                                "sender", "low", 8, "verified", ["impersonation"], evidence=f"{rp_dom} vs {from_dom}"))
    if from_name:
        name_addrs = re.findall(r"[\w.+-]+@[\w-]+\.[\w.-]+", from_name)
        if name_addrs and _domain(name_addrs[0]) != from_dom:
            findings.append(Finding("Display name contains a different email address", f"Display name shows '{name_addrs[0]}' but the real address is {from_addr}.",
                                    "sender", "high", 36, "verified", ["impersonation", "phishing"], evidence=from_name))
        if EXEC_TITLES.search(from_name) and from_dom in FREEMAIL:
            findings.append(Finding("Executive/authority name from a free email account", f"'{from_name}' is sending from a free webmail address ({from_dom}).",
                                    "sender", "high", 30, "heuristic", ["bec", "impersonation"], evidence=f"{from_name} <{from_addr}>"))
        low_name = re.sub(r"[^a-z]", "", from_name.lower())
        for brand, officials in OFFICIAL_DOMAINS.items():
            if len(brand) >= 4 and brand in low_name and registered_domain(from_dom) not in officials:
                findings.append(Finding(f"Display name claims '{brand}' but domain is unrelated",
                                        f"Sender name references {brand} while sending from {from_dom}.", "sender", "high", 32, "heuristic",
                                        ["impersonation", "phishing"], evidence=f"{from_name} <{from_addr}>"))
                break
    if org_domain:
        org_reg = registered_domain(org_domain)
        org_label = org_reg.split(".")[0]
        from_reg = registered_domain(from_dom)
        from_label = from_reg.split(".")[0].replace("-", "")
        if from_reg != org_reg and org_label and org_label.replace("-", "") in from_dom.replace("-", "").replace(".", ""):
            findings.append(Finding("Sender domain imitates your organisation", f"{from_dom} contains '{org_label}' but is not {org_reg}.",
                                    "sender", "high", 40, "heuristic", ["impersonation", "bec"], evidence=from_dom))
        elif from_reg != org_reg and len(org_label) >= 5 and _levenshtein(from_label.translate(HOMOGLYPHS), org_label.replace("-", "")) <= 2:
            findings.append(Finding("Look-alike of your organisation's domain", f"{from_dom} is one or two characters away from {org_reg} (typosquatting).",
                                    "sender", "critical", 48, "heuristic", ["impersonation", "bec"], evidence=f"{from_reg} ≈ {org_reg}"))
        internal_claim = from_name and org_label and org_label.lower() in from_name.lower().replace(" ", "")
        if internal_claim and from_reg != org_reg:
            findings.append(Finding("Claims to be internal but comes from outside", f"Display name suggests {org_reg} staff, but the address is external.",
                                    "sender", "medium", 20, "heuristic", ["impersonation"]))
    if msg_id and "@" in msg_id:
        mid_dom = msg_id.strip("<>").rsplit("@", 1)[-1].lower()
        if registered_domain(mid_dom) not in (registered_domain(from_dom), registered_domain(rp_dom or from_dom)) and not mid_dom.endswith(("google.com", "outlook.com", "prod.outlook.com", "amazonses.com", "mail.gmail.com")):
            findings.append(Finding("Message-ID domain mismatch", f"Message-ID was generated by '{mid_dom}', not the sender's domain.",
                                    "sender", "low", 6, "verified", ["impersonation"], evidence=mid_dom))
    if not received:
        limitations.append("No Received headers: the delivery path could not be traced.")
    return findings, meta, limitations


def html_to_text_and_links(html_body: str) -> tuple[str, list[dict], dict]:
    p = _LinkExtractor()
    try:
        p.feed(html_body)
    except Exception:
        pass
    text = html_lib.unescape(re.sub(r"\n\s*\n+", "\n\n", "".join(p.text_parts))).strip()
    return text, p.links, {"forms": p.forms, "password_inputs": p.password_inputs, "remote_images": [i for i in p.images if i.startswith("http")][:20]}


def extract_urls(text: str) -> list[str]:
    out = []
    for m in URL_RE.finditer(text or ""):
        u = m.group(0).rstrip(".,;:!?'\")]}")
        u = re.sub(r"^hxxp", "http", u, flags=re.I)
        if u not in out:
            out.append(u)
    return out
