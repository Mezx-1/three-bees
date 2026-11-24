"""Phone number intelligence (caller ID).

What 3B can honestly say about a number:
  * Format, country and international dialling code: Google's libphonenumber (offline, free). The country
    is where the NUMBER RANGE is assigned, not where the caller is.
  * Original network and line type: libphonenumber's prefix data. Numbers can be ported to another operator,
    so this is labelled "original network (from number range)", never "carrier confirmed".
  * Caller name: NOT available. 3B has no licensed caller-name source and never guesses one.
  * Verified business: only when an administrator records it with a source.
  * Community reports, scam reports and shared threat status: 3B's own data, with counts and dates.
"""
from __future__ import annotations

import hashlib

import phonenumbers
from phonenumbers import NumberParseException, PhoneNumberType, carrier, geocoder, timezone as pn_tz
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import PhoneIntel, PhoneReport, ScamReport, ThreatIndicator
from .risk import Finding, build_report

REPORT_CATEGORIES = {
    "banking": "Banking scam", "government": "Government impersonation", "delivery": "Fake delivery call", "investment": "Investment fraud",
    "job": "Fake job offer", "harassment": "Harassment or spam", "phishing": "Phishing attempt", "support": "Fake customer support",
    "payment": "Suspicious payment request", "other": "Other suspicious activity",
}
LINE_TYPES = {
    PhoneNumberType.MOBILE: "Mobile", PhoneNumberType.FIXED_LINE: "Landline", PhoneNumberType.FIXED_LINE_OR_MOBILE: "Landline or mobile",
    PhoneNumberType.TOLL_FREE: "Toll-free", PhoneNumberType.PREMIUM_RATE: "Premium rate", PhoneNumberType.SHARED_COST: "Shared cost",
    PhoneNumberType.VOIP: "VoIP", PhoneNumberType.PERSONAL_NUMBER: "Personal number", PhoneNumberType.PAGER: "Pager",
    PhoneNumberType.UAN: "Universal access number", PhoneNumberType.VOICEMAIL: "Voicemail",
}


def flag(region: str | None) -> str:
    if not region or len(region) != 2 or not region.isalpha():
        return ""
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in region.upper())


def parse(raw: str, default_region: str = "AE") -> phonenumbers.PhoneNumber:
    s = (raw or "").strip()
    if s.startswith("00"):
        s = "+" + s[2:]
    try:
        return phonenumbers.parse(s, default_region)
    except NumberParseException as exc:
        raise ValueError("That doesn't look like a phone number. Use international format, e.g. +971 50 123 4567.") from exc


def e164(raw: str, default_region: str = "AE") -> str:
    """E.164 form. Idempotent: an invalid number written with + keeps all its digits (libphonenumber would
    strip a 'national zero' each time it is re-parsed, turning one number into several)."""
    n = parse(raw, default_region)
    if not phonenumbers.is_valid_number(n):
        s = (raw or "").strip()
        digits = "".join(ch for ch in s if ch.isdigit())
        if s.startswith("+"):
            return "+" + digits
        if s.startswith("00"):
            return "+" + digits[2:]
    return phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.E164)


def key9(number: str | None) -> str | None:
    d = "".join(ch for ch in (number or "") if ch.isdigit())
    return d[-9:] if len(d) >= 7 else None


def facts(raw: str, default_region: str = "AE") -> dict:
    n = parse(raw, default_region)
    region = phonenumbers.region_code_for_number(n)
    valid = phonenumbers.is_valid_number(n)
    t = phonenumbers.number_type(n)
    net = carrier.name_for_number(n, "en") if valid else ""
    return {
        "e164": e164(raw, default_region),
        "international": phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
        "country_code": n.country_code, "dialing_code": f"+{n.country_code}",
        "region": region if region and region != "001" else None,
        "country": geocoder.country_name_for_number(n, "en") or ("International network (non-geographic)" if region == "001" else "Unknown"),
        "flag": flag(region),
        "valid": valid, "possible": phonenumbers.is_possible_number(n),
        "line_type": LINE_TYPES.get(t, "Unknown") if valid else "Unknown",
        "original_network": net or None,
        "time_zones": list(pn_tz.time_zones_for_number(n)) if valid else [],
        "caller_name": None,
        "caller_name_note": "Not available — 3B has no licensed caller-name source and never guesses names.",
        "source": "Google libphonenumber (offline numbering-plan data)",
        "notes": ["The country is where the number range is assigned, not where the caller is.",
                  "Caller ID can be spoofed: a call can show any number.",
                  "'Original network' comes from the number range; the number may have moved to another operator."],
    }


def reporter_key(identity: str) -> str:
    return hashlib.sha256(f"3b-phone-report:{identity}".encode()).hexdigest()


def intel_row(db: Session, num: str, mode: str = "user", create: bool = False) -> PhoneIntel | None:
    row = db.scalars(select(PhoneIntel).where(PhoneIntel.e164 == num, PhoneIntel.data_mode == mode)).first()
    if row is None and create:
        f = facts(num)
        row = PhoneIntel(e164=num, data_mode=mode, country_code=f["country_code"], region=f["region"])
        db.add(row)
        db.flush()
    return row


def refresh_counts(db: Session, row: PhoneIntel) -> None:
    reps = db.scalars(select(PhoneReport).where(PhoneReport.e164 == row.e164, PhoneReport.data_mode == row.data_mode,
                                                PhoneReport.status != "rejected")).all()
    row.report_count = len(reps)
    row.distinct_reporters = len({r.reporter_key for r in reps})
    labels: dict[str, int] = {}
    for r in reps:
        labels[r.category] = labels.get(r.category, 0) + 1
    row.community_labels = labels
    row.last_reported = max((r.created_at for r in reps), default=None)


def lookup(db: Session, raw: str, *, investigator: bool = False, include_demo: bool = True) -> dict:
    f = facts(raw)
    num = f["e164"]
    findings: list[Finding] = []
    limitations = list(f["notes"])

    from . import network_intel as ni
    try:
        nf, _, _ = ni.analyze_phone(num)
        findings += [x for x in nf if x.title != "International number" or f["region"] != "AE"]
    except ValueError:
        pass
    if not f["valid"]:
        findings.append(Finding("Number is not valid in its country's numbering plan",
                                "This number can't be a real line in that country's plan. Spoofed or placeholder numbers often look like this.",
                                "phone", "low", 8, "verified", ["vishing"], evidence=f["international"]))
    if f["line_type"] == "VoIP":
        findings.append(Finding("Internet (VoIP) number", "VoIP numbers are easy to obtain anonymously. Many are legitimate; combined with other signs they matter more.",
                                "phone", "low", 8, "verified", ["vishing"]))
    if f["line_type"] == "Premium rate":
        findings.append(Finding("Premium-rate number", "Calling back may cost money per minute.", "phone", "medium", 25, "verified", ["payment_fraud"]))

    modes = ["user", "demo"] if include_demo else ["user"]
    community = []
    for mode in modes:
        row = intel_row(db, num, mode)
        if not row:
            continue
        community.append(row)
        label = " (DEMO data)" if mode == "demo" else ""
        if row.review_status == "legitimate":
            findings.append(Finding("Reviewed as legitimate" + label, f"An analyst reviewed this number and marked it legitimate{(' — ' + row.verified_business) if row.verified_business else ''}.",
                                    "phone", "info", 0, "verified", []))
            continue
        if row.review_status == "confirmed_scam":
            findings.append(Finding("Confirmed scam number" + label, "An analyst reviewed the reports and evidence and confirmed this number was used for scams.",
                                    "phone", "critical", 75, "verified", ["vishing", "payment_fraud"]))
        n = row.distinct_reporters
        if n:
            w = 14 if n == 1 else 28 if n == 2 else 42 if n < 6 else 55
            cats = ", ".join(REPORT_CATEGORIES.get(k, k) for k, _ in sorted(row.community_labels.items(), key=lambda kv: -kv[1])[:3])
            findings.append(Finding(f"{n} community report{'s' if n > 1 else ''}{label}",
                                    f"Reported by {n} different user{'s' if n > 1 else ''} as: {cats}. Reports are claims by users, not proof.",
                                    "phone", "high" if n >= 3 else "medium", w, "heuristic", ["vishing"]))
    k = key9(num)
    scam_reports = [r for r in db.scalars(select(ScamReport).where(ScamReport.phone.is_not(None))).all()
                    if key9(r.phone) == k and (include_demo or r.data_mode == "user")]
    if scam_reports:
        demo = all(r.data_mode == "demo" for r in scam_reports)
        cats = sorted({r.category for r in scam_reports})
        findings.append(Finding(f"Named in {len(scam_reports)} scam report{'s' if len(scam_reports) > 1 else ''}{' (DEMO data)' if demo else ''}",
                                f"People who reported scams to 3B gave this number ({', '.join(cats)}).", "phone", "high", 40 if len(scam_reports) > 1 else 25,
                                "heuristic", ["vishing"]))
    shared = db.scalars(select(ThreatIndicator).where(ThreatIndicator.type == "phone", ThreatIndicator.value == num)).all()
    for s in shared:
        if s.status == "verified":
            findings.append(Finding("On the 3B verified threat list" + (" (DEMO data)" if s.data_mode == "demo" else ""),
                                    "Verified by an analyst or a trusted source. Opted-in devices warn about or block this number.", "phone", "critical", 80, "verified", ["vishing"]))
        elif s.status == "suspicious":
            findings.append(Finding("On the 3B suspicious list (not verified)" + (" (DEMO data)" if s.data_mode == "demo" else ""),
                                    "Several independent signals, awaiting analyst review. Devices show a warning only.", "phone", "high", 35, "heuristic", ["vishing"]))
    business = next((r.verified_business for r in community if r.verified_business), None)
    if business and not any(r.review_status == "confirmed_scam" for r in community):
        findings.append(Finding("Verified business number", f"Recorded as {business} by an administrator from a verified source.", "phone", "info", 0, "verified", []))
        findings = [x for x in findings if x.source != "heuristic" or x.weight < 20]
    if not findings:
        limitations.append("No reports or warnings for this number. Unknown does not mean dangerous — and it does not mean safe.")
    rep = build_report(findings, limitations, default_classification="No reports for this number")
    rep.pop("next_steps", None)
    latest = max([r.last_reported for r in community if r.last_reported] + [r.created_at for r in scam_reports], default=None)
    out = {
        **f, "verified_business": business,
        "verified_business_source": next((r.verified_source for r in community if r.verified_business), None),
        "community": {"reports": sum(r.report_count for r in community), "distinct_reporters": sum(r.distinct_reporters for r in community),
                      "categories": {REPORT_CATEGORIES.get(k, k): v for r in community for k, v in r.community_labels.items()},
                      "review_status": next((r.review_status for r in community if r.review_status != "unreviewed"), "unreviewed"),
                      "demo": bool(community) and all(r.data_mode == "demo" for r in community)},
        "scam_reports": len(scam_reports), "last_reported": latest,
        "shared_status": next((s.status for s in shared if s.status in ("verified", "suspicious")), None),
        "risk": {k: rep[k] for k in ("risk_score", "severity", "confidence", "classification", "findings", "limitations", "recommended_actions")},
    }
    out["risk"]["level"] = rep["severity"].upper()
    if investigator:
        out["scam_report_refs"] = [r.reference for r in scam_reports][:20]
        out["related_numbers"] = related_numbers(db, scam_reports, num)
    return out


def related_numbers(db: Session, reports: list[ScamReport], num: str) -> list[dict]:
    """Other numbers that appear in reports linked (same domain or very similar message) to this number's reports."""
    from . import report_links as rl

    if not reports:
        return []
    others = db.scalars(select(ScamReport).where(ScamReport.phone.is_not(None))).all()
    k = key9(num)
    out: dict[str, dict] = {}
    for r in reports:
        for o in others:
            if key9(o.phone) == k or o.data_mode != r.data_mode:
                continue
            ls = [l for l in rl.links_between(r, o) if l["method"] != "same_phone"]
            if ls:
                e = out.setdefault(o.phone, {"number": o.phone, "via": set(), "reports": set()})
                e["via"].update(l["method"] for l in ls)
                e["reports"].add(o.reference)
    return [{"number": v["number"], "via": sorted(v["via"]), "reports": len(v["reports"]),
             "note": "Linked through shared links or near-identical messages — not proof of the same people."} for v in out.values()][:10]
