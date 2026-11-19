"""Fact-check what a caller says against things WOLVE can verify.

Checked facts:
  * time  — "it's 12 o'clock" vs the real UAE time (UTC+4, no daylight saving)
  * day   — "today is Thursday" vs the real UAE weekday
  * organisation — named organisation vs a directory of known UAE organisations
  * number vs claim — a UAE government body / bank / telecom calling from a foreign number
WOLVE cannot tell the two voices apart in a speakerphone recording, so the user should ask the question
and let the caller answer. Absence from the directory means "not verified", never "does not exist".
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from .risk import Finding

UAE_TZ = timezone(timedelta(hours=4), "GST")
TIME_TOLERANCE_MIN = 30  # people round to the half hour

AR_HOURS = {"واحدة": 1, "الواحدة": 1, "وحدة": 1, "اثنين": 2, "اثنتين": 2, "ثنتين": 2, "الثانية": 2, "ثلاث": 3, "ثلاثة": 3, "الثالثة": 3,
            "اربع": 4, "أربع": 4, "أربعة": 4, "الرابعة": 4, "خمس": 5, "خمسة": 5, "الخامسة": 5, "ست": 6, "ستة": 6, "السادسة": 6,
            "سبع": 7, "سبعة": 7, "السابعة": 7, "ثمان": 8, "ثمانية": 8, "ثمني": 8, "الثامنة": 8, "تسع": 9, "تسعة": 9, "التاسعة": 9,
            "عشر": 10, "عشرة": 10, "العاشرة": 10, "حدعش": 11, "احدعش": 11, "إحدى عشر": 11, "احدى عشر": 11, "الحادية عشر": 11,
            "الحادية عشرة": 11, "ثنعش": 12, "اطنعش": 12, "اثنا عشر": 12, "اثني عشر": 12, "الثانية عشر": 12, "الثانية عشرة": 12}
EN_HOURS = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10,
            "eleven": 11, "twelve": 12}
WEEKDAYS = {  # Python weekday(): Monday=0
    0: ["الاثنين", "الإثنين", "monday"], 1: ["الثلاثاء", "tuesday"], 2: ["الأربعاء", "الاربعاء", "wednesday"],
    3: ["الخميس", "thursday"], 4: ["الجمعة", "friday"], 5: ["السبت", "saturday"], 6: ["الأحد", "الاحد", "sunday"],
}

# Known UAE organisations (name aliases in Arabic and English). local=True: they call from UAE numbers.
ORGANISATIONS = [
    ("Abu Dhabi Police", ["شرطة أبوظبي", "شرطة ابوظبي", "شرطة أبو ظبي", "abu dhabi police", "adpolice"]),
    ("Dubai Police", ["شرطة دبي", "dubai police"]),
    ("Ministry of Interior", ["وزارة الداخلية", "ministry of interior"]),
    ("ICP (Identity & Citizenship)", ["الهوية والجنسية", "الهيئة الاتحادية للهوية", "icp", "federal authority for identity"]),
    ("Central Bank of the UAE", ["المصرف المركزي", "البنك المركزي", "central bank"]),
    ("Emirates NBD", ["الإمارات دبي الوطني", "الامارات دبي الوطني", "emirates nbd"]),
    ("ADCB", ["بنك أبوظبي التجاري", "بنك ابوظبي التجاري", "adcb", "abu dhabi commercial bank"]),
    ("First Abu Dhabi Bank", ["بنك أبوظبي الأول", "بنك ابوظبي الاول", "first abu dhabi bank", "fab bank"]),
    ("Mashreq", ["المشرق", "بنك المشرق", "mashreq"]),
    ("Dubai Islamic Bank", ["دبي الإسلامي", "بنك دبي الاسلامي", "dubai islamic bank"]),
    ("ADIB", ["أبوظبي الإسلامي", "مصرف أبوظبي الإسلامي", "adib", "abu dhabi islamic bank"]),
    ("RAKBANK", ["بنك رأس الخيمة", "rakbank"]),
    ("e& (Etisalat)", ["شركة اتصالات", "اتصالات الإمارات", "etisalat"]),
    ("du", ["شركة دو", "du telecom"]),
    ("Salik", ["سالك", "salik"]),
    ("RTA", ["هيئة الطرق والمواصلات", "هيئة الطرق", "rta", "roads and transport authority"]),
    ("Emirates Post", ["بريد الإمارات", "بريد الامارات", "emirates post"]),
    ("Aramex", ["أرامكس", "ارامكس", "aramex"]),
    ("DHL", ["دي اتش ال", "dhl"]),
    ("FedEx", ["فيديكس", "fedex"]),
    ("ADNOC", ["أدنوك", "ادنوك", "adnoc"]),
    ("DEWA", ["هيئة كهرباء ومياه دبي", "ديوا", "dewa"]),
    ("TAQA / ADDC", ["شركة طاقة", "taqa", "addc"]),
    ("Emirates (airline)", ["طيران الإمارات", "emirates airline"]),
    ("Etihad Airways", ["طيران الاتحاد", "etihad"]),
    ("UAE Pass", ["الهوية الرقمية", "uae pass", "uaepass"]),
    ("TAMM", ["منصة تم", "tamm"]),
    ("Amazon", ["أمازون", "امازون", "amazon"]),
    ("Noon", ["موقع نون", "noon.com"]),
    ("Careem", ["شركة كريم", "careem"]),
    ("Microsoft", ["مايكروسوفت", "microsoft"]),
    ("Apple", ["شركة أبل", "apple"]),
]
LOCAL_AUTHORITY = {"Abu Dhabi Police", "Dubai Police", "Ministry of Interior", "ICP (Identity & Citizenship)", "Central Bank of the UAE",
                   "Emirates NBD", "ADCB", "First Abu Dhabi Bank", "Mashreq", "Dubai Islamic Bank", "ADIB", "RAKBANK", "e& (Etisalat)", "du",
                   "Salik", "RTA", "Emirates Post", "DEWA", "TAQA / ADDC", "UAE Pass", "TAMM"}

# "I'm calling from <Name> company" / "من شركة <الاسم>"
ORG_PHRASES = [
    re.compile(r"(?:من|مع|معك|معاك)\s+(?:شركة|مؤسسة|بنك|مصرف|مكتب)\s+((?:[\w؀-ۿ]+\s?){1,3})"),
    re.compile(r"(?:شركة|مؤسسة)\s+((?:[\w؀-ۿ]+\s?){1,3})"),
    re.compile(r"\bcalling (?:you )?from\s+((?:[A-Z][\w&'-]*\s?){1,4})"),
    re.compile(r"\bfrom\s+((?:[A-Z][\w&'-]*\s?){1,3})\s+(?:company|bank|ltd|llc|group|services|logistics|investments?)\b"),
]
ORG_STOP = {"the", "a", "your", "our", "this", "هذه", "هذا", "الـ", "ال"}


def _now(now: datetime | None) -> datetime:
    return (now or datetime.now(timezone.utc)).astimezone(UAE_TZ)


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s.strip().lower())


def extract_time_claims(text: str) -> list[tuple[int, int, str]]:
    """Returns (hour, minute, quote) for every stated clock time."""
    out: list[tuple[int, int, str]] = []
    # digits: "الساعة 12", "الساعة الآن 12:30", "it's 12", "the time is 3:15 pm"
    for m in re.finditer(r"(?:الساعة|الساعه|ساعة)\s*(?:الآن|الان|هلأ|هلق|هسا|حاليا|حالياً|عندي|عندنا|بالإمارات|في الإمارات)?\s*(\d{1,2})(?:[:.](\d{2}))?"
                         r"|\b(?:it'?s|it is|the time is|time is|time now is)\s*(?:now\s*)?(\d{1,2})(?:[:.](\d{2}))?\s*(?:am|pm|o'?clock)?", text, re.I):
        h = int(m.group(1) or m.group(3))
        mi = int(m.group(2) or m.group(4) or 0)
        out.append((h, mi, m.group(0).strip()))
    # words: "الساعة اثنا عشر ونص", "twelve o'clock"
    for word, h in sorted(AR_HOURS.items(), key=lambda kv: -len(kv[0])):
        for m in re.finditer(r"(?:الساعة|الساعه)\s*(?:الآن|الان|هلأ|هلق|هسا|حاليا)?\s*" + re.escape(word) + r"(\s*(?:و\s*نص|ونص|والنصف|وربع|والربع|إلا ربع|الا ربع))?", text):
            tail = (m.group(1) or "").replace(" ", "")
            mi = 30 if "نص" in tail else 15 if tail.startswith("وربع") or tail.startswith("والربع") else -15 if "ربع" in tail else 0
            out.append((h, mi, m.group(0).strip()))
    for word, h in EN_HOURS.items():
        for m in re.finditer(r"\b(?:it'?s\s+)?" + word + r"\s+o'?clock\b|\b(?:it'?s|it is)\s+" + word + r"(?:\s+thirty|\s+fifteen)?\b", text, re.I):
            mi = 30 if "thirty" in m.group(0).lower() else 15 if "fifteen" in m.group(0).lower() else 0
            out.append((h, mi, m.group(0).strip()))
    return out


def _clock_diff_minutes(h: int, mi: int, now: datetime) -> int:
    """Smallest difference between a stated time (12h or 24h) and now, in minutes."""
    actual = now.hour * 60 + now.minute
    stated = (h % 24) * 60 + mi
    candidates = [stated, stated + 720] if h <= 12 else [stated]
    return min(min(abs(c - actual) % 1440, 1440 - abs(c - actual) % 1440) for c in candidates)


def check_claims(text: str, caller_region: str | None = None, caller_is_uae: bool | None = None,
                 now: datetime | None = None) -> tuple[list[Finding], list[dict]]:
    findings: list[Finding] = []
    claims: list[dict] = []
    t = _now(now)
    actual_str = t.strftime("%H:%M")

    # --- time
    times = extract_time_claims(text)
    if times:
        diffs = [(_clock_diff_minutes(h, mi, t), h, mi, q) for h, mi, q in times]
        best = min(diffs)
        ok = best[0] <= TIME_TOLERANCE_MIN
        claims.append({"type": "time", "said": best[3], "actual": f"{actual_str} (UAE, UTC+4)", "ok": ok,
                       "difference_minutes": best[0]})
        if not ok:
            hours = round(best[0] / 60, 1)
            findings.append(Finding(
                "Caller gave the wrong UAE time",
                f"The caller said “{best[3]}”, but the time in the UAE is {actual_str}, about {hours} hour(s) different. "
                "Someone really calling from the UAE would know the local time — this suggests the caller is abroad.",
                "claims", "high", 35, "verified", ["vishing", "impersonation"], evidence=f"said {best[3]} · actual {actual_str} GST"))

    # --- weekday
    low = text.lower()
    for wd, names in WEEKDAYS.items():
        for name in names:
            if re.search(r"(?:اليوم|today is|today'?s)\s*(?:هو\s*)?" + re.escape(name), low):
                ok = wd == t.weekday()
                actual_day = WEEKDAYS[t.weekday()][0]
                claims.append({"type": "day", "said": name, "actual": actual_day, "ok": ok})
                if not ok:
                    findings.append(Finding("Caller gave the wrong day", f"The caller said today is {name}, but in the UAE today is {actual_day}.",
                                            "claims", "medium", 22, "verified", ["vishing"], evidence=f"said {name} · actual {actual_day}"))
                break

    # --- organisations
    known_hits = sorted({canon for canon, aliases in ORGANISATIONS for a in aliases
                         if re.search(r"(?<![\w؀-ۿ])" + re.escape(a.lower()) + r"(?![\w؀-ۿ])", low)})
    for canon in known_hits:
        claims.append({"type": "organisation", "said": canon, "actual": "Known UAE organisation", "ok": True})
        if canon in LOCAL_AUTHORITY and caller_is_uae is False:
            findings.append(Finding(
                f"Claims to be {canon} but calls from a foreign number",
                f"{canon} is a UAE organisation, but the call comes from a number registered to {caller_region or 'another country'}. "
                "UAE government bodies, banks and telecoms call from UAE numbers.",
                "claims", "high", 40, "verified", ["vishing", "impersonation"], evidence=f"{canon} · {caller_region}"))
    all_aliases = {_norm(a) for _, aliases in ORGANISATIONS for a in aliases}
    for rx in ORG_PHRASES:
        for m in rx.finditer(text):
            name = _norm(m.group(1))
            words = [w for w in name.split() if w not in ORG_STOP]
            if not words:
                continue
            name = " ".join(words[:3])
            if any(name.startswith(a) or a.startswith(name) for a in all_aliases if len(a) >= 3):
                continue
            if any(c["type"] == "organisation" and c["said"] == name for c in claims):
                continue
            claims.append({"type": "organisation", "said": name, "actual": "Not found among known UAE organisations", "ok": False})
            findings.append(Finding(
                "Organisation could not be verified",
                f"The caller says they are from “{name}”, which is not in WOLVE's directory of known UAE organisations. "
                "It may be a small company, a mishearing, or an invented name — ask for the official number and call back yourself.",
                "claims", "medium", 18, "heuristic", ["impersonation"], evidence=name))
    return findings, claims
