"""Static file inspection. Files are only ever *read as bytes* — never executed, opened by an
application, or extracted to disk. Archives are listed in memory with size limits."""
from __future__ import annotations

import hashlib
import io
import math
import re
import zipfile
from pathlib import PurePath

from . import ocr
from .risk import Finding

# (magic bytes, offset, detected type, canonical extensions, mime)
SIGNATURES: list[tuple[bytes, int, str, set[str], str]] = [
    (b"MZ", 0, "Windows executable (PE)", {"exe", "dll", "scr", "sys", "com", "cpl", "ocx", "msi"}, "application/x-msdownload"),
    (b"\x7fELF", 0, "Linux executable (ELF)", {"elf", "so", "bin", ""}, "application/x-executable"),
    (b"%PDF", 0, "PDF document", {"pdf"}, "application/pdf"),
    (b"\x89PNG\r\n\x1a\n", 0, "PNG image", {"png"}, "image/png"),
    (b"\xff\xd8\xff", 0, "JPEG image", {"jpg", "jpeg", "jpe", "jfif"}, "image/jpeg"),
    (b"GIF87a", 0, "GIF image", {"gif"}, "image/gif"),
    (b"GIF89a", 0, "GIF image", {"gif"}, "image/gif"),
    (b"BM", 0, "BMP image", {"bmp"}, "image/bmp"),
    (b"RIFF", 0, "RIFF container (WAV/AVI/WEBP)", {"wav", "avi", "webp"}, "application/octet-stream"),
    (b"PK\x03\x04", 0, "ZIP archive / Office Open XML", {"zip", "docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "jar", "apk", "odt"}, "application/zip"),
    (b"Rar!\x1a\x07", 0, "RAR archive", {"rar"}, "application/vnd.rar"),
    (b"7z\xbc\xaf\x27\x1c", 0, "7-Zip archive", {"7z"}, "application/x-7z-compressed"),
    (b"\x1f\x8b", 0, "GZIP archive", {"gz", "tgz"}, "application/gzip"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0, "OLE2 compound file (legacy Office/MSI)", {"doc", "xls", "ppt", "msi", "msg"}, "application/x-ole-storage"),
    (b"{\\rtf", 0, "RTF document", {"rtf", "doc"}, "application/rtf"),
    (b"ID3", 0, "MP3 audio", {"mp3"}, "audio/mpeg"),
    (b"OggS", 0, "OGG media", {"ogg", "oga", "opus"}, "audio/ogg"),
    (b"fLaC", 0, "FLAC audio", {"flac"}, "audio/flac"),
    (b"ftyp", 4, "MP4/MOV/M4A media", {"mp4", "m4a", "mov", "3gp", "m4v"}, "video/mp4"),
    (b"\x1aE\xdf\xa3", 0, "Matroska/WebM video", {"mkv", "webm"}, "video/webm"),
    (b"CD001", 0x8001, "ISO disk image", {"iso"}, "application/x-iso9660-image"),
    (b"L\x00\x00\x00\x01\x14\x02\x00", 0, "Windows shortcut (LNK)", {"lnk"}, "application/x-ms-shortcut"),
]

EXECUTABLE_EXTS = {"exe", "scr", "com", "pif", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh", "ps1", "hta", "msi", "jar",
                   "lnk", "dll", "cpl", "apk", "iso", "img", "reg", "sh", "py", "docm", "xlsm", "pptm", "one", "chm"}
DOC_EXTS = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png", "gif", "rtf", "csv", "zip"}
MAX_ARCHIVE_ENTRIES = 200
MAX_SCAN_BYTES = 8 * 1024 * 1024


def hashes(data: bytes) -> dict:
    return {"md5": hashlib.md5(data).hexdigest(), "sha1": hashlib.sha1(data).hexdigest(), "sha256": hashlib.sha256(data).hexdigest()}


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    sample = data[:MAX_SCAN_BYTES]
    counts = [0] * 256
    for b in sample:
        counts[b] += 1
    n = len(sample)
    return round(-sum((c / n) * math.log2(c / n) for c in counts if c), 3)


def detect_type(data: bytes) -> tuple[str, set[str], str]:
    for magic, off, name, exts, mime in SIGNATURES:
        if data[off:off + len(magic)] == magic:
            if name.startswith("RIFF") and len(data) > 12:
                sub = data[8:12]
                if sub == b"WAVE":
                    return "WAV audio", {"wav"}, "audio/wav"
                if sub == b"WEBP":
                    return "WEBP image", {"webp"}, "image/webp"
                if sub == b"AVI ":
                    return "AVI video", {"avi"}, "video/x-msvideo"
            return name, exts, mime
    head = data[:2048]
    try:
        text = head.decode("utf-8")
        low = text.lower()
        if "<html" in low or "<!doctype html" in low or "<script" in low:
            return "HTML document", {"html", "htm"}, "text/html"
        if "<svg" in low:
            return "SVG image (XML)", {"svg"}, "image/svg+xml"
        return "Plain text", {"txt", "csv", "log", "md", "json", "xml", "eml", "js", "vbs", "ps1", "bat", "cmd", "py", "sh"}, "text/plain"
    except UnicodeDecodeError:
        return "Unknown binary", set(), "application/octet-stream"


SCRIPT_MARKERS = [
    (rb"powershell(\.exe)?\s+(-[a-z]+\s+)*(-enc|-encodedcommand|-e\s|iex|invoke-expression)", "PowerShell encoded/IEX execution"),
    (rb"wscript\.shell|createobject\(\s*[\"']wscript", "WScript.Shell object (runs commands)"),
    (rb"cmd(\.exe)?\s+/c", "cmd.exe /c command execution"),
    (rb"frombase64string|atob\(", "Base64 payload decoding"),
    (rb"(urldownloadtofile|downloadstring|downloadfile|invoke-webrequest|xmlhttp|bitsadmin|certutil\s+-urlcache)", "Downloads content from the internet"),
    (rb"(auto_?open|document_open|workbook_open)", "Auto-executing macro entry point"),
    (rb"eval\s*\(\s*(unescape|atob|function)", "Obfuscated eval()"),
    (rb"regsvr32|rundll32|mshta", "Living-off-the-land binary (LOLBin) invocation"),
]


def _script_findings(data: bytes, where: str) -> list[Finding]:
    out: list[Finding] = []
    sample = data[:MAX_SCAN_BYTES].lower()
    for rx, label in SCRIPT_MARKERS:
        if re.search(rx, sample):
            out.append(Finding(f"Suspicious code pattern: {label}", f"Static pattern found in {where}. The file was not executed.",
                               "attachment", "high", 30, "verified", ["malware_delivery"], evidence=label))
    return out


def _inspect_zip(data: bytes, filename: str) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    info: dict = {"entries": []}
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        findings.append(Finding("Corrupted ZIP structure", "File has a ZIP signature but could not be parsed.", "attachment", "medium", 12, "verified", ["malware_delivery"]))
        return findings, info
    names = zf.namelist()
    info["entry_count"] = len(names)
    is_ooxml = "[Content_Types].xml" in names
    info["office_open_xml"] = is_ooxml
    encrypted = any(i.flag_bits & 0x1 for i in zf.infolist())
    if encrypted:
        findings.append(Finding("Password-protected archive", "Encrypted archives prevent security scanning and are often used to smuggle malware past email filters.",
                                "attachment", "high", 32, "verified", ["malware_delivery"]))
    total_uncompressed = 0
    for zi in zf.infolist()[:MAX_ARCHIVE_ENTRIES]:
        total_uncompressed += zi.file_size
        entry = {"name": zi.filename, "size": zi.file_size, "compressed": zi.compress_size}
        ext = PurePath(zi.filename).suffix.lower().lstrip(".")
        if not is_ooxml and ext in EXECUTABLE_EXTS:
            entry["flag"] = "executable/script"
            findings.append(Finding("Archive contains executable or script", f"'{zi.filename}' inside the archive is an executable/script type.",
                                    "attachment", "critical", 48, "verified", ["malware_delivery"], evidence=zi.filename))
        if re.search(r"\.(pdf|docx?|xlsx?|jpe?g|png|txt)\.(exe|scr|js|vbs|bat|cmd|hta|lnk|ps1)$", zi.filename.lower()):
            findings.append(Finding("Double extension inside archive", f"'{zi.filename}' disguises an executable as a document.",
                                    "attachment", "critical", 45, "verified", ["malware_delivery"], evidence=zi.filename))
        if not encrypted and zi.file_size <= 2 * 1024 * 1024 and ext in {"js", "vbs", "ps1", "bat", "cmd", "hta", "wsf", "html", "htm"}:
            try:
                findings.extend(_script_findings(zf.read(zi), f"archive entry '{zi.filename}'"))
                entry["sha256"] = hashlib.sha256(zf.read(zi)).hexdigest()
            except Exception:
                pass
        info["entries"].append(entry)
    if is_ooxml:
        macro = [n for n in names if n.lower().endswith("vbaproject.bin")]
        if macro:
            info["macros"] = macro
            findings.append(Finding("Office document contains VBA macros", "Macro-enabled documents can run code when the user clicks 'Enable Content'.",
                                    "attachment", "high", 40, "verified", ["malware_delivery"], evidence=", ".join(macro)))
        ext_rels = []
        for n in names:
            if n.endswith(".rels"):
                try:
                    rel = zf.read(n)[:200000]
                    if b'TargetMode="External"' in rel and (b"attachedTemplate" in rel or b"oleObject" in rel):
                        ext_rels.append(n)
                except Exception:
                    pass
        if ext_rels:
            findings.append(Finding("Remote template / external OLE reference", "Document loads content from an external location when opened (template injection).",
                                    "attachment", "high", 36, "verified", ["malware_delivery"], evidence=", ".join(ext_rels)))
    if data and total_uncompressed / max(len(data), 1) > 200:
        findings.append(Finding("Possible zip bomb", "Extremely high compression ratio.", "attachment", "medium", 20, "verified", ["malware_delivery"]))
    return findings, info


def _inspect_pdf(data: bytes) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    sample = data[:MAX_SCAN_BYTES]
    keys = {k: len(re.findall(rb"/" + k.encode(), sample)) for k in ["JavaScript", "JS", "OpenAction", "AA", "Launch", "EmbeddedFile", "URI", "SubmitForm", "AcroForm", "XFA"]}
    info = {"pdf_keywords": {k: v for k, v in keys.items() if v}}
    if keys["JavaScript"] or keys["JS"]:
        findings.append(Finding("PDF contains JavaScript", "Embedded JavaScript can exploit PDF readers or redirect users.", "attachment", "high", 32, "verified", ["malware_delivery"]))
    if keys["OpenAction"] or keys["AA"]:
        findings.append(Finding("PDF auto-action on open", "The PDF triggers an action automatically when opened.", "attachment", "medium", 18, "verified", ["malware_delivery"]))
    if keys["Launch"]:
        findings.append(Finding("PDF /Launch action", "Can launch external programs.", "attachment", "critical", 45, "verified", ["malware_delivery"]))
    if keys["EmbeddedFile"]:
        findings.append(Finding("PDF has embedded files", "Files hidden inside the PDF.", "attachment", "medium", 18, "verified", ["malware_delivery"]))
    if keys["SubmitForm"] or keys["AcroForm"]:
        findings.append(Finding("PDF contains a submittable form", "Forms inside PDFs are used to harvest credentials.", "attachment", "low", 10, "verified", ["credential_theft"]))
    uris = [u.decode("latin-1") for u in re.findall(rb"/URI\s*\(([^)]{4,300})\)", sample)][:20]
    info["uris"] = uris
    return findings, info


def _image_metadata(data: bytes) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    info: dict = {}
    try:
        from PIL import ExifTags, Image

        img = Image.open(io.BytesIO(data))
        info.update({"format": img.format, "width": img.width, "height": img.height, "mode": img.mode})
        exif = {}
        try:
            raw = img.getexif()
            for k, v in raw.items():
                name = ExifTags.TAGS.get(k, str(k))
                if isinstance(v, bytes):
                    v = v[:60].hex()
                exif[name] = str(v)[:200]
            if raw.get_ifd(0x8825):
                exif["GPSInfo"] = "present (location data embedded)"
        except Exception:
            pass
        info["exif"] = exif
        if "GPSInfo" in exif:
            findings.append(Finding("Image contains GPS location metadata", "EXIF GPS data is embedded — a privacy concern, and useful for forensics.",
                                    "metadata", "info", 2, "verified"))
        software = exif.get("Software", "")
        if software:
            info["software"] = software
        for k in ("comment", "Comment", "parameters", "Description"):
            if k in img.info and isinstance(img.info[k], (str, bytes)):
                val = img.info[k] if isinstance(img.info[k], str) else img.info[k][:500].decode("latin-1", "ignore")
                info.setdefault("text_chunks", {})[k] = val[:500]
                if re.search(r"<script|powershell|eval\(|base64,", val, re.I):
                    findings.append(Finding("Script-like content in image metadata", "Metadata contains code-like strings, which can indicate steganographic payload staging.",
                                            "image", "high", 30, "verified", ["malware_delivery"], evidence=val[:120]))
    except Exception as exc:
        findings.append(Finding("Image could not be decoded", f"The file claims to be an image but failed to decode: {exc}", "image", "medium", 15, "verified", ["malware_delivery"]))
    # Data appended after the end-of-image marker (polyglot / hidden payload).
    trailer = None
    if data.startswith(b"\x89PNG"):
        idx = data.rfind(b"IEND")
        if idx != -1:
            trailer = len(data) - (idx + 8)
    elif data.startswith(b"\xff\xd8"):
        idx = data.rfind(b"\xff\xd9")
        if idx != -1:
            trailer = len(data) - (idx + 2)
    if trailer and trailer > 16:
        info["appended_bytes"] = trailer
        tail = data[-trailer:]
        tail_type, _, _ = detect_type(tail)
        sev, w = ("critical", 50) if tail_type in ("Windows executable (PE)", "ZIP archive / Office Open XML") else ("medium", 22)
        findings.append(Finding("Hidden data appended after image end", f"{trailer} bytes follow the end-of-image marker (detected as: {tail_type}). This is a known way to hide payloads in images.",
                                "image", sev, w, "verified", ["malware_delivery"], evidence=f"{trailer} trailing bytes"))
    return findings, info


def analyze_file(data: bytes, filename: str, declared_mime: str | None = None, *, known_bad: dict[str, str] | None = None,
                 do_ocr: bool = True) -> tuple[list[Finding], dict, list[str]]:
    """Returns findings, a technical info dict, and a list of analysis limitations."""
    findings: list[Finding] = []
    limitations: list[str] = []
    safe_name = PurePath(filename or "unnamed").name
    ext = PurePath(safe_name).suffix.lower().lstrip(".")
    h = hashes(data)
    detected, valid_exts, detected_mime = detect_type(data)
    info: dict = {"filename": safe_name, "extension": ext, "size": len(data), "hashes": h, "detected_type": detected,
                  "detected_mime": detected_mime, "declared_mime": declared_mime, "entropy": entropy(data)}

    # Hash reputation (local list of known-bad hashes; external provider optional elsewhere).
    if known_bad and h["sha256"] in known_bad:
        findings.append(Finding("Hash matches a known-malicious file", f"SHA-256 is on the 3B blocklist: {known_bad[h['sha256']]}",
                                "attachment", "critical", 80, "verified", ["malware_delivery"], evidence=h["sha256"]))

    # Extension vs. real signature.
    if valid_exts and ext not in valid_exts and not (detected == "Plain text"):
        sev, w = ("critical", 55) if detected in ("Windows executable (PE)", "Linux executable (ELF)", "Windows shortcut (LNK)") else ("high", 34)
        findings.append(Finding("File extension does not match real file type",
                                f"Named '.{ext or '(none)'}' but the file signature identifies it as: {detected}.",
                                "attachment", sev, w, "verified", ["malware_delivery"], evidence=f".{ext} vs {detected}"))
    if declared_mime and declared_mime not in ("application/octet-stream",) and detected_mime != "application/octet-stream":
        dm_major = declared_mime.split("/")[0]
        if dm_major != detected_mime.split("/")[0] and not (detected_mime == "application/zip" and "officedocument" in declared_mime) \
                and detected != "Plain text":
            findings.append(Finding("Declared MIME type differs from content", f"Sender declared '{declared_mime}', content is '{detected_mime}'.",
                                    "attachment", "medium", 18, "verified", ["malware_delivery"]))
    if re.search(r"\.(pdf|docx?|xlsx?|jpe?g|png|txt|zip)\.(exe|scr|js|vbs|bat|cmd|hta|lnk|ps1|com|pif)$", safe_name.lower()):
        findings.append(Finding("Double file extension", f"'{safe_name}' hides an executable extension behind a document extension.",
                                "attachment", "critical", 50, "verified", ["malware_delivery"], evidence=safe_name))
    if "‮" in (filename or ""):
        findings.append(Finding("Right-to-left override in filename", "The filename uses the RLO character to visually reverse its extension.",
                                "attachment", "critical", 55, "verified", ["malware_delivery"]))
    if ext in EXECUTABLE_EXTS or detected in ("Windows executable (PE)", "Linux executable (ELF)", "Windows shortcut (LNK)"):
        findings.append(Finding("Executable or script file type", f"Type '{ext or detected}' can run code on the recipient's computer.",
                                "attachment", "high", 35, "verified", ["malware_delivery"], evidence=ext or detected))
    if info["entropy"] > 7.6 and detected in ("Windows executable (PE)", "Unknown binary"):
        findings.append(Finding("Very high entropy", f"Entropy {info['entropy']}/8 suggests packed or encrypted content.", "attachment", "medium", 15, "verified", ["malware_delivery"]))

    # Type-specific inspection.
    if detected.startswith("ZIP"):
        f, zinfo = _inspect_zip(data, safe_name)
        findings += f
        info["archive"] = zinfo
    elif detected == "PDF document":
        f, pinfo = _inspect_pdf(data)
        findings += f
        info["pdf"] = pinfo
    elif detected.startswith("OLE2"):
        if re.search(rb"(?i)(vba|macros|_vba_project|attribut\x00e vb_)", data[:MAX_SCAN_BYTES]):
            findings.append(Finding("Legacy Office file with macro streams", "OLE document appears to contain VBA macro storage.",
                                    "attachment", "high", 36, "verified", ["malware_delivery"]))
        limitations.append("Legacy OLE documents were inspected for macro markers only; full OLE stream parsing is not implemented.")
    elif detected in ("RAR archive", "7-Zip archive", "GZIP archive", "ISO disk image"):
        findings.append(Finding(f"{detected} attachment", "Container formats are commonly used to deliver malware past filters. Contents were not extracted.",
                                "attachment", "medium", 18, "verified", ["malware_delivery"]))
        limitations.append(f"{detected} contents were not extracted (only ZIP listing is supported in the MVP).")
    elif detected == "Windows executable (PE)":
        limitations.append("PE executables are not detonated. Dynamic behaviour requires the isolated sandbox (planned).")

    if detected in ("HTML document", "Plain text", "SVG image (XML)") or ext in {"js", "vbs", "ps1", "bat", "cmd", "hta", "html", "htm", "svg"}:
        findings += _script_findings(data, "file content")
        if detected in ("HTML document", "SVG image (XML)"):
            low = data[:MAX_SCAN_BYTES].lower()
            if b"<form" in low and (b"password" in low or b"type=\"password\"" in low):
                findings.append(Finding("HTML attachment contains a login form", "Local HTML files with password fields are a common credential-phishing technique.",
                                        "attachment", "high", 40, "verified", ["credential_theft", "phishing"]))
            if b"<script" in low:
                findings.append(Finding("Active script in HTML/SVG", "The file contains <script> tags that run when opened in a browser.",
                                        "attachment", "medium", 20, "verified", ["malware_delivery"]))

    is_image = detected_mime.startswith("image/") and detected != "SVG image (XML)"
    if is_image:
        f, iinfo = _image_metadata(data)
        findings += f
        info["image"] = iinfo
        qr = ocr.decode_qr(data)
        info["qr"] = qr
        if do_ocr:
            info["ocr"] = ocr.extract_text(data)
            if not info["ocr"].get("available"):
                limitations.append("OCR unavailable: text inside the image was not extracted.")
        if qr.get("codes"):
            findings.append(Finding("QR code found in image", f"Decoded {len(qr['codes'])} QR code(s). QR codes hide destinations from the reader ('quishing').",
                                    "image", "medium", 14, "verified", ["phishing"], evidence="; ".join(c[:120] for c in qr["codes"])))

    limitations.append("Static analysis only — the file was never executed. Malware that is obfuscated or only acts at runtime may not be detected.")
    return findings, info, limitations
