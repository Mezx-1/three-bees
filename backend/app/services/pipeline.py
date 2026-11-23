"""Analysis orchestration: each `run_*` returns a uniform AnalysisResult the API layer persists."""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from ..config import settings
from . import ai, email_analyzer as ea, file_analyzer as fa, network_intel as ni, text_analyzer as ta, url_analyzer as ua
from .risk import Finding, build_report, combine, severity_for

MEDIA_EXTS_AUDIO = {"mp3", "wav", "m4a", "ogg", "oga", "opus", "flac", "aac", "amr"}
MEDIA_EXTS_VIDEO = {"mp4", "mov", "mkv", "webm", "avi", "3gp", "m4v"}


@dataclass
class Context:
    org_domain: str | None = None
    blocked_domains: set[str] = field(default_factory=set)
    blocked_urls: set[str] = field(default_factory=set)
    blocked_ips: set[str] = field(default_factory=set)
    blocked_phones: set[str] = field(default_factory=set)
    known_bad_hashes: dict[str, str] = field(default_factory=dict)
    ai_enabled: bool = True
    external_lookups: bool = False


@dataclass
class AnalysisResult:
    kind: str
    title: str
    report: dict
    indicators: list[tuple[str, str, str, bool]] = field(default_factory=list)  # (type, value, role, malicious)
    recipient: str | None = None
    sha256: str | None = None
    file_bytes: bytes | None = None
    filename: str | None = None


def _ai_block(content: str, kind: str, findings: list[Finding], ctx: Context, images=None) -> tuple[list[Finding], dict]:
    res = ai.assess(content, kind, findings, images=images, enabled_setting=ctx.ai_enabled)
    return ai.ai_findings(res), {
        "available": res.get("available", False), "model": res.get("model"), "reason": res.get("reason"),
        "error": res.get("error"), "assessment": res.get("assessment"),
    }


# ---------------------------------------------------------------- URL / domain

def url_subanalysis(url: str, ctx: Context, *, lookups: bool | None = None) -> dict:
    lookups = ctx.external_lookups if lookups is None else lookups
    findings, info = ua.analyze_url(url, blocklist=ctx.blocked_domains, org_domain=ctx.org_domain)
    if ua.normalize_url(url) in ctx.blocked_urls:
        findings.append(Finding("URL is on the 3B blocklist", "An analyst blocked this exact URL.", "url", "critical", 70, "verified", ["malicious_link"]))
    intel: dict = {}
    if lookups and info.get("host") and not info.get("ip_literal"):
        dns_info = ua.resolve_dns(info["host"])
        intel["dns"] = dns_info
        findings += ua.dns_findings(dns_info)
    score = combine(findings)
    return {"url": info.get("url", url), "host": info.get("host"), "registered_domain": info.get("registered_domain"),
            "score": score, "severity": severity_for(score), "findings": findings, "info": info, "intel": intel}


def run_url(url: str, ctx: Context) -> AnalysisResult:
    sub = url_subanalysis(url, ctx)
    limitations = ["Structural URL analysis only — the page was not visited or rendered."]
    if not ctx.external_lookups:
        limitations.append("External lookups disabled: DNS was not queried.")
    limitations.append("No URL reputation provider configured (e.g. Google Safe Browsing, VirusTotal); 3B does not claim reputation results.")
    report = build_report(sub["findings"], limitations, default_classification="No significant threat detected",
                          extra={"url": sub["info"], "intel": sub["intel"], "ai": {"available": False, "reason": "AI not used for single-URL structural checks."}})
    malicious = report["risk_score"] >= 60
    inds = [("url", sub["url"], "submitted", malicious)]
    if sub.get("registered_domain"):
        inds.append(("domain", sub["registered_domain"], "submitted", malicious))
    return AnalysisResult("url", sub["url"][:300], report, inds)


def run_domain(domain: str, ctx: Context) -> AnalysisResult:
    res = run_url(domain if "://" in domain else f"https://{domain}", ctx)
    res.kind = "domain"
    res.title = domain
    return res


# ---------------------------------------------------------------- IP / phone

def run_ip(ip: str, ctx: Context) -> AnalysisResult:
    findings, info, limitations = ni.analyze_ip(ip)
    intel: dict = {}
    if info["ip"] in ctx.blocked_ips:
        findings.append(Finding("IP is on the 3B blocklist", "An analyst blocked this IP in the local environment.", "network", "critical", 70, "verified", ["suspicious_infrastructure"]))
    if info["is_global"] and not info.get("documentation_range"):
        if ctx.external_lookups:
            intel["geolocation"] = ni.geolocate(info["ip"])
            findings += ni.geo_findings(intel["geolocation"])
        else:
            limitations.append("External lookups disabled: no geolocation/ASN was queried.")
        intel["reputation"] = ni.abuseipdb(info["ip"])
        findings += ni.abuse_findings(intel["reputation"])
        if intel["reputation"].get("configured") is False:
            limitations.append("No IP reputation provider configured (AbuseIPDB key not set) — reputation is unknown, not clean.")
    report = build_report(findings, limitations, default_classification="No significant threat detected",
                          extra={"ip": info, "intel": intel})
    return AnalysisResult("ip", info["ip"], report, [("ip", info["ip"], "submitted", report["risk_score"] >= 60)])


def run_phone(phone: str, ctx: Context) -> AnalysisResult:
    findings, info, limitations = ni.analyze_phone(phone)
    report = build_report(findings, limitations, default_classification="No significant threat detected", extra={"phone": info})
    return AnalysisResult("phone", info["normalized"], report, [("phone", info["normalized"], "submitted", False)])


# ---------------------------------------------------------------- message text

def _analyze_embedded(text: str, ctx: Context, findings: list[Finding], extra: dict, inds: list, url_list: list[str] | None = None):
    urls = url_list if url_list is not None else ea.extract_urls(text)
    url_reports = [url_subanalysis(u, ctx) for u in urls[:15]]
    url_reports.sort(key=lambda r: r["score"], reverse=True)
    for r in url_reports[:3]:  # worst three URLs drive the score
        for f in r["findings"]:
            if f.weight > 0:
                findings.append(Finding(f.title, f.detail, f.category, f.severity, f.weight, f.source, f.tags, evidence=f"{r['host']}: {f.evidence or ''}".strip()))
    extra["urls"] = [{k: v for k, v in r.items() if k != "findings"} | {"findings": [f.to_dict() for f in r["findings"]]} for r in url_reports]
    for r in url_reports:
        mal = r["score"] >= 60
        inds.append(("url", r["url"], "link", mal))
        if r.get("registered_domain"):
            inds.append(("domain", r["registered_domain"], "link", mal))
    return url_reports


def run_message(text: str, ctx: Context, channel: str = "message", title: str | None = None) -> AnalysisResult:
    if not text.strip():
        raise ValueError("Message text is empty")
    findings, artefacts = ta.analyze_text(text, channel)
    extra: dict = {"channel": channel, "text_analysis": artefacts}
    inds: list = []
    _analyze_embedded(text, ctx, findings, extra, inds)
    phones = []
    for p in artefacts["phone_numbers"][:5]:
        try:
            pf, pinfo, _ = ni.analyze_phone(p)
            findings += pf
            phones.append(pinfo)
            inds.append(("phone", pinfo["normalized"], "mentioned", False))
        except ValueError:
            pass
    extra["phones"] = phones
    brand_link = any(f.title.startswith(("Brand name", "Look-alike", "Imitates")) for r in extra.get("urls", []) for f in [Finding(**x) for x in r["findings"]])
    if brand_link and "payment" in artefacts["matched_patterns"]:
        findings.append(Finding("Payment request with a link that imitates a known brand",
                                "The message asks you to pay and sends you to a website pretending to be an official service — the pattern of fake toll, fine and parcel-fee scams.",
                                "content", "high", 30, "heuristic", ["phishing", "payment_fraud"]))
    if channel in ("call", "voice") and findings:
        for f in findings:
            if f.category == "content" and "vishing" not in f.tags:
                f.tags.append("vishing")
    limitations = ["Text heuristics detect common scam techniques; novel or well-written scams may score low.",
                   "Sender identity of SMS/WhatsApp/chat messages cannot be verified from text alone."]
    ai_f, ai_info = _ai_block(text, channel, findings, ctx)
    findings += ai_f
    extra["ai"] = ai_info
    if not ai_info["available"]:
        limitations.append(f"AI review not used: {ai_info.get('reason') or ai_info.get('error')}")
    report = build_report(findings, limitations, extra=extra)
    label = {"sms": "SMS", "whatsapp": "WhatsApp", "chat": "Chat", "call": "Call transcript", "email": "Email text"}.get(channel, "Message")
    return AnalysisResult("message", title or f"{label}: {text.strip()[:80]}", report, inds)


# ---------------------------------------------------------------- files, images, media

def _ffprobe(path: Path) -> dict:
    if not shutil.which("ffprobe"):
        return {"available": False}
    try:
        out = subprocess.run(["ffprobe", "-v", "error", "-show_format", "-show_streams", "-of", "json", str(path)],
                             capture_output=True, timeout=20, check=False)
        data = json.loads(out.stdout or b"{}")
        fmt = data.get("format", {})
        return {"available": True, "duration": fmt.get("duration"), "format": fmt.get("format_long_name"), "tags": fmt.get("tags", {}),
                "streams": [{"type": s.get("codec_type"), "codec": s.get("codec_name"), "width": s.get("width"), "height": s.get("height"),
                             "sample_rate": s.get("sample_rate"), "tags": s.get("tags", {})} for s in data.get("streams", [])][:6]}
    except Exception as exc:
        return {"available": True, "error": str(exc)}


def _video_frames(path: Path, count: int = 4) -> list[bytes]:
    if not shutil.which("ffmpeg"):
        return []
    frames = []
    with tempfile.TemporaryDirectory(dir=settings.upload_dir / "tmp") as td:
        try:
            subprocess.run(["ffmpeg", "-v", "error", "-i", str(path), "-vf", "fps=1/3,scale='min(1280,iw)':-2", "-frames:v", str(count),
                            str(Path(td) / "f%02d.png")], capture_output=True, timeout=60, check=False)
        except Exception:
            return []
        for p in sorted(Path(td).glob("f*.png")):
            frames.append(p.read_bytes())
    return frames


def _media_findings(probe: dict) -> list[Finding]:
    out: list[Finding] = []
    tags = {**probe.get("tags", {})}
    for s in probe.get("streams", []):
        tags.update(s.get("tags", {}))
    enc = " ".join(str(v) for k, v in tags.items() if k.lower() in ("encoder", "software", "handler_name", "comment")).lower()
    for tool in ("elevenlabs", "resemble", "deepfacelab", "faceswap", "descript", "synthesia", "heygen", "tts"):
        if tool in enc:
            out.append(Finding("Metadata references a synthetic-media tool", f"Encoder/software metadata mentions '{tool}'. This suggests (but does not prove) synthetic or edited media.",
                               "metadata", "medium", 22, "verified", ["deepfake_possible"], evidence=enc[:160]))
            break
    return out


def run_file(data: bytes, filename: str, declared_mime: str | None, ctx: Context, *, transcript: str | None = None,
             context_note: str | None = None) -> AnalysisResult:
    if not data:
        raise ValueError("Uploaded file is empty")
    findings, info, limitations = fa.analyze_file(data, filename, declared_mime, known_bad=ctx.known_bad_hashes)
    extra: dict = {"file": info}
    inds: list = [("hash", info["hashes"]["sha256"], "file", False), ("filename", info["filename"], "file", False)]
    ai_text_parts = [f"Filename: {info['filename']} | detected: {info['detected_type']} | size: {info['size']} bytes"]
    images_for_ai: list[tuple[bytes, str]] = []
    kind = "file"
    ext = info["extension"]
    is_image = info["detected_mime"].startswith("image/") and "image" in info

    if is_image:
        kind = "image"
        ocr_text = (info.get("ocr") or {}).get("text") or ""
        if ocr_text:
            tf, art = ta.analyze_text(ocr_text, "image")
            for f in tf:
                f.category, f.title = "image", f"{f.title} (text in image)"
            findings += tf
            extra["ocr_analysis"] = art
            ai_text_parts.append(f"OCR text:\n{ocr_text}")
        qr_urls = [c for c in (info.get("qr") or {}).get("codes", []) if c.lower().startswith(("http", "www"))]
        url_candidates = qr_urls + [u for u in ea.extract_urls(ocr_text) if u not in qr_urls]
        if url_candidates:
            _analyze_embedded("", ctx, findings, extra, inds, url_list=url_candidates)
        if info["detected_mime"] in ("image/png", "image/jpeg", "image/gif", "image/webp"):
            images_for_ai.append((data, info["detected_mime"]))

    elif ext in MEDIA_EXTS_AUDIO | MEDIA_EXTS_VIDEO or info["detected_mime"].startswith(("audio/", "video/")):
        is_video = ext in MEDIA_EXTS_VIDEO or info["detected_mime"].startswith("video/")
        kind = "video" if is_video else "audio"
        with tempfile.NamedTemporaryFile(dir=settings.upload_dir / "tmp", suffix=f".{ext or 'bin'}", delete=False) as tmp:
            tmp.write(data)
            tmp_path = Path(tmp.name)
        try:
            probe = _ffprobe(tmp_path)
            extra["media"] = probe
            findings += _media_findings(probe)
            if not probe.get("available"):
                limitations.append("ffprobe not installed: media metadata unavailable.")
            if is_video:
                frames = _video_frames(tmp_path)
                extra["frames_analyzed"] = len(frames)
                frame_texts = []
                qr_all: list[str] = []
                from . import ocr as ocr_mod
                for fr in frames:
                    t = ocr_mod.extract_text(fr).get("text", "")
                    if t:
                        frame_texts.append(t)
                    qr_all += ocr_mod.decode_qr(fr).get("codes", [])
                joined = "\n".join(dict.fromkeys(frame_texts))
                extra["frame_ocr_text"] = joined[:4000]
                if joined:
                    tf, art = ta.analyze_text(joined, "video")
                    for f in tf:
                        f.category, f.title = "image", f"{f.title} (text on screen)"
                    findings += tf
                    ai_text_parts.append(f"On-screen text from frames:\n{joined}")
                urls = list(dict.fromkeys([c for c in qr_all if c.startswith("http")] + ea.extract_urls(joined)))
                if urls:
                    _analyze_embedded("", ctx, findings, extra, inds, url_list=urls)
                images_for_ai += [(fr, "image/png") for fr in frames[:3]]
                limitations.append("Video: only sampled frames (1 every 3 s, max 4) were inspected; audio track was not transcribed.")
        finally:
            tmp_path.unlink(missing_ok=True)
        limitations.append("Speech-to-text is not installed in this deployment; provide a transcript to analyse spoken content.")
        limitations.append("Synthetic-voice / deepfake detection is not implemented. 3B never labels media as fake based on impressions.")

    if transcript and transcript.strip():
        tf, art = ta.analyze_text(transcript, "call")
        for f in tf:
            if "vishing" not in f.tags:
                f.tags.append("vishing")
        findings += tf
        extra["transcript_analysis"] = art
        ai_text_parts.append(f"Transcript (provided by user):\n{transcript}")
    if context_note:
        ai_text_parts.append(f"Submitter's note: {context_note}")

    ai_f, ai_info = _ai_block("\n\n".join(ai_text_parts), kind, findings, ctx, images=images_for_ai)
    findings += ai_f
    if ai_info.get("assessment") and ai_info["assessment"].get("extracted_text") and is_image and not (info.get("ocr") or {}).get("text"):
        extra["ai_extracted_text"] = ai_info["assessment"]["extracted_text"]
    extra["ai"] = ai_info
    if not ai_info["available"]:
        limitations.append(f"AI review not used: {ai_info.get('reason') or ai_info.get('error')}")
    report = build_report(findings, limitations, extra=extra)
    malicious = report["risk_score"] >= 60
    inds[0] = ("hash", info["hashes"]["sha256"], "file", malicious)
    return AnalysisResult(kind, info["filename"], report, inds, sha256=info["hashes"]["sha256"], file_bytes=data, filename=info["filename"])


# ---------------------------------------------------------------- email

def run_email(raw: bytes | str, ctx: Context) -> AnalysisResult:
    msg = ea.parse_email(raw)
    findings, meta, limitations = ea.inspect_headers(msg, ctx.org_domain)
    parts = ea.extract_parts(msg)
    html_text, links, html_info = ea.html_to_text_and_links(parts["html"]) if parts["html"] else ("", [], {})
    body = (parts["text"].strip() or html_text).strip()
    extra: dict = {"email": meta, "html": html_info, "body_preview": body[:3000]}
    inds: list = []
    if meta.get("from_address"):
        inds.append(("email", meta["from_address"].lower(), "sender", False))
        inds.append(("domain", ua.registered_domain(meta["from_domain"]), "sender_domain", False))
    if meta.get("reply_to"):
        inds.append(("email", meta["reply_to"].lower(), "reply_to", False))
    for r in meta.get("to", []):
        inds.append(("email", r.lower(), "recipient", False))

    # Anchor text vs real destination.
    for ln in links:
        href, text = ln["href"], ln["text"]
        shown = ea.extract_urls(text)
        if shown and href.startswith("http"):
            shown_dom = ua.registered_domain(ua.urlsplit(ua.normalize_url(shown[0])).hostname or "")
            real_dom = ua.registered_domain(ua.urlsplit(href).hostname or "")
            if shown_dom and real_dom and shown_dom != real_dom:
                findings.append(Finding("Link text disguises the real destination", f"The link shows '{shown[0]}' but actually opens '{real_dom}'.",
                                        "url", "high", 40, "verified", ["phishing", "malicious_link"], evidence=f"shown {shown_dom} → real {real_dom}"))
    if html_info.get("password_inputs"):
        findings.append(Finding("Email body contains a password field", "HTML emails should never ask for passwords inline.", "content", "high", 38, "verified", ["credential_theft"]))

    # Content analysis.
    subject = meta.get("subject", "")
    tf, art = ta.analyze_text(f"{subject}\n{body}", "email")
    findings += tf
    extra["text_analysis"] = art

    url_list = list(dict.fromkeys([ln["href"] for ln in links if ln["href"].startswith(("http", "www"))] + ea.extract_urls(parts["text"])))

    # Attachments & inline images.
    att_reports = []
    images_for_ai: list[tuple[bytes, str]] = []
    ocr_texts: list[str] = []
    for att in parts["attachments"][:10]:
        data = att["data"]
        if not data:
            continue
        f_findings, f_info, f_lims = fa.analyze_file(data, att["filename"], att["declared_mime"], known_bad=ctx.known_bad_hashes)
        sub_score = combine(f_findings)
        rep = {"filename": f_info["filename"], "declared_mime": att["declared_mime"], "disposition": att["disposition"], "info": f_info,
               "score": sub_score, "severity": severity_for(sub_score), "findings": [f.to_dict() for f in f_findings]}
        for f in f_findings:
            if f.weight > 0:
                findings.append(Finding(f.title, f.detail, f.category, f.severity, f.weight, f.source, f.tags, evidence=f"{f_info['filename']}: {f.evidence or ''}"))
        if f_info.get("ocr", {}).get("text"):
            ocr_texts.append(f_info["ocr"]["text"])
            otf, _ = ta.analyze_text(f_info["ocr"]["text"], "image")
            for f in otf:
                findings.append(Finding(f"{f.title} (text in image)", f.detail, "image", f.severity, f.weight, f.source, f.tags,
                                        evidence=f"{f_info['filename']}: {f.evidence}"))
            url_list += [u for u in ea.extract_urls(f_info["ocr"]["text"]) if u not in url_list]
        for code in (f_info.get("qr") or {}).get("codes", []):
            if code.lower().startswith(("http", "www")) and code not in url_list:
                url_list.append(code)
        if f_info["detected_mime"] in ("image/png", "image/jpeg", "image/gif", "image/webp"):
            images_for_ai.append((data, f_info["detected_mime"]))
        att_reports.append(rep)
        inds.append(("hash", f_info["hashes"]["sha256"], "attachment", sub_score >= 60))
        inds.append(("filename", f_info["filename"], "attachment", sub_score >= 60))
        for e in (f_info.get("archive") or {}).get("entries", []):
            if e.get("sha256"):
                inds.append(("hash", e["sha256"], "attachment_inner", True))
                inds.append(("filename", e["name"], "attachment_inner", True))
        for lim in f_lims:
            if lim not in limitations:
                limitations.append(lim)
    extra["attachments"] = att_reports
    if ocr_texts:
        extra["ocr_text"] = "\n---\n".join(ocr_texts)[:4000]

    _analyze_embedded("", ctx, findings, extra, inds, url_list=url_list)
    if meta.get("from_address") and findings:
        # Sender is malicious-flagged when the overall email is high risk (set below).
        pass

    ai_content = (f"From: {meta.get('from_name')} <{meta.get('from_address')}>\nReply-To: {meta.get('reply_to')}\nTo: {', '.join(meta.get('to', []))}\n"
                  f"Subject: {subject}\nAuthentication: {meta.get('authentication')}\n"
                  f"Attachments: {', '.join(a['filename'] + ' (' + a['info']['detected_type'] + ')' for a in att_reports) or 'none'}\n\n{body[:20000]}")
    if ocr_texts:
        ai_content += "\n\n[Text extracted by OCR from embedded images]\n" + "\n".join(ocr_texts)[:4000]
    ai_f, ai_info = _ai_block(ai_content, "email", findings, ctx, images=images_for_ai)
    findings += ai_f
    extra["ai"] = ai_info
    if not ai_info["available"]:
        limitations.append(f"AI review not used: {ai_info.get('reason') or ai_info.get('error')}")
    limitations.append("Email was analysed from submitted content; 3B is not connected to a live mailbox, so actions apply to the 3B record only.")

    report = build_report(findings, limitations, extra=extra)
    if report["risk_score"] >= 60:
        inds = [(t, v, r, True if r in ("sender", "sender_domain", "reply_to") else m) for t, v, r, m in inds]
    title = subject or "(no subject)"
    recipient = (meta.get("to") or [None])[0]
    return AnalysisResult("email", title, report, inds, recipient=recipient)


# ---------------------------------------------------------------- phone calls

def run_call(transcript: str, caller_number: str | None, features: dict | None, stt: dict | None, ctx: Context) -> AnalysisResult:
    """Score a phone call from its transcript, the caller's number and voice-tone measurements."""
    from .voice import tone_findings

    findings: list[Finding] = []
    limitations = [
        "3B cannot intercept phone calls. It only analyses audio captured by this computer's microphone with consent, or recordings you upload.",
        "A number's country code shows where the number range is registered — not where the caller physically is. Caller ID can be spoofed.",
        "Claim checks compare what was said with the real UAE time/date and a directory of known UAE organisations. 3B cannot tell the two voices apart: ask your question and let the caller answer.",
    ]
    extra: dict = {"call": {"transcript": transcript, "stt": stt or {}, "features": features or {}}}
    inds: list = []
    if caller_number and caller_number.strip():
        try:
            pf, pinfo, _ = ni.analyze_phone(caller_number)
            findings += pf
            extra["call"]["caller"] = pinfo
            inds.append(("phone", pinfo["normalized"], "caller", False))
            if pinfo["normalized"] in ctx.blocked_phones:
                findings.append(Finding("Caller number is on the 3B blocklist", "An analyst previously blocked this number as a scam number.",
                                        "phone", "critical", 70, "verified", ["vishing"], evidence=pinfo["normalized"]))
        except ValueError as exc:
            limitations.append(f"Caller number not analysed: {exc}")
    else:
        limitations.append("No caller number provided (hidden/unknown caller).")
    if transcript.strip():
        from .claims import check_claims

        caller = extra["call"].get("caller") or {}
        cc = caller.get("country_code")
        claim_f, claims = check_claims(transcript, caller.get("registered_region"), (cc == "971") if cc else None)
        findings += claim_f
        extra["call"]["claims"] = claims
        tf, art = ta.analyze_text(transcript, "call")
        for f in tf:
            if f.category == "content" and "vishing" not in f.tags:
                f.tags.append("vishing")
        findings += tf
        extra["text_analysis"] = art
        if "otp" in art.get("matched_patterns", {}):
            from .claims import find_spoken_codes

            codes = find_spoken_codes(transcript)
            if codes:
                masked = [c["masked"] for c in codes]
                extra["call"]["code_spoken"] = True
                extra["call"]["transcript"] = codes[-1]["redacted_text"]
                findings.append(Finding(
                    "A code may have been said during the call",
                    "After the caller asked for a code, a number that looks like a one-time code was heard. "
                    "If it was your code, the caller can now use it — call your bank immediately.",
                    "claims", "critical", 60, "verified", ["otp_theft", "vishing"], evidence=", ".join(masked)))
        if "approval" in art.get("matched_patterns", {}):
            from .claims import find_approval_given

            said = find_approval_given(transcript)
            if said:
                extra["call"]["approval_given"] = True
                findings.append(Finding(
                    "The request may have been approved",
                    "After the caller asked for a notification to be approved, someone on the call said they approved it. "
                    "If that was a payment, call your bank now — it can sometimes still be stopped.",
                    "claims", "critical", 55, "verified", ["payment_fraud", "vishing"], evidence=said))
        from .questions import suggest

        extra["call"]["questions"] = suggest(transcript, claims, art.get("matched_patterns", {}))
    else:
        from .questions import default_questions

        extra["call"]["questions"] = default_questions()
        limitations.append("No speech was transcribed yet, so the conversation content was not analysed.")
    if stt and not stt.get("available", True):
        limitations.append("Speech-to-text is not installed; type what the caller said into the transcript box.")
    tf, notes = tone_findings(features or {})
    findings += tf
    limitations += notes
    ai_text = (f"Phone call. Caller number: {caller_number or 'unknown'} ({(extra['call'].get('caller') or {}).get('registered_region', 'unknown')}).\n"
               f"Voice measurements: {features or {}}\nTranscript:\n{transcript}")
    ai_f, ai_info = _ai_block(ai_text, "call", findings, ctx)
    findings += ai_f
    extra["ai"] = ai_info
    if not ai_info["available"]:
        limitations.append(f"AI review not used: {ai_info.get('reason') or ai_info.get('error')}")
    report = build_report(findings, limitations, extra=extra)
    title = f"Call from {(extra['call'].get('caller') or {}).get('normalized') or caller_number}" if caller_number else "Call (unknown number)"
    return AnalysisResult("call", title, report, inds)
