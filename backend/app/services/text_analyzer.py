"""Deterministic social-engineering detection for message text (English + Arabic).

These are heuristics: they flag *techniques* attackers use (urgency, authority, OTP requests…).
Legitimate messages can contain them too, which is why each carries a moderate weight.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .risk import Finding


@dataclass
class Pattern:
    key: str
    title: str
    detail: str
    weight: int
    severity: str
    tags: list[str]
    regexes: list[str]


PATTERNS: list[Pattern] = [
    Pattern(
        "urgency", "Urgency / time pressure",
        "Message pressures the reader to act immediately, a classic tactic to prevent careful verification.",
        14, "medium", ["social_engineering"],
        [r"\burgent(ly)?\b", r"\bimmediately\b", r"\bwithin (24|48|12|2|1) ?(hours?|hrs?|minutes?)\b", r"\bact now\b",
         r"\bas soon as possible\b", r"\basap\b", r"\blast (chance|warning|notice)\b", r"\bexpires? (today|soon|in)\b",
         r"\bfinal (notice|reminder|warning)\b", r"\btoday only\b", r"\bdeadline\b",
         r"عاجل", r"فورا|فوراً", r"خلال \d+ ساعة", r"آخر فرصة", r"تنبيه نهائي",
         # spoken / dialect forms (call transcripts)
         r"خلال (ساعة|ساعتين|نص ساعة|دقائق|دقايق|\d+ (دقيقة|دقائق|دقايق|ساعات))", r"لا (تسكر|تسكّر|تقفل|تغلق|تنهي) (الخط|المكالمة)",
         r"بسرعة (عشان|قبل|لأن|لان)", r"ضروري (الحين|اليوم|هلق|هلأ|حالا|حالاً)", r"قبل ما (ينقفل|يتقفل|يتوقف|ينحظر|يتجمد|ينسحب)"],
    ),
    Pattern(
        "threat", "Threat of negative consequences",
        "Threatens account suspension, legal action, fines or arrest to scare the reader into complying.",
        16, "medium", ["social_engineering"],
        [r"\b(account|mailbox|card|service)s? (will be|has been|is) (suspended|blocked|locked|closed|deactivated|terminated)\b",
         r"\b(suspend|block|lock|deactivat|terminat)(ed|ion)? (your|the) (account|card|mailbox)\b",
         r"\blegal action\b", r"\b(arrest|warrant|fine|penalty|court)\b", r"\bpermanently (deleted|closed|blocked)\b",
         r"سيتم (إيقاف|تعليق|حظر|إغلاق)", r"غرامة", r"إجراء قانوني", r"أمر (قبض|اعتقال)",
         r"(ينقفل|يتقفل|بيتقفل|يتسكر|ينحظر|يتجمد|يتوقف|يتعلق|ينسحب) (حسابك|بطاقتك|البطاقة|الحساب|رصيدك)",
         r"(نوقف|نقفل|نجمد|نحظر|يوقفون|يقفلون) (البطاقة|بطاقتك|حسابك|الحساب)", r"(إيقاف|ايقاف|تجميد|قفل|حظر) (حسابك|بطاقتك|البطاقة|الحساب)",
         r"عملية مشبوهة", r"حسابك (مخترق|انخترق|تم اختراقه)"],
    ),
    Pattern(
        "otp", "Request for one-time password (OTP) / verification code",
        "Asks the reader to share an OTP, PIN or verification code. Legitimate organisations never ask for these.",
        42, "high", ["otp_theft", "credential_theft"],
        [r"\b(otp|one[- ]time (password|code|pin))\b", r"\bverification code\b", r"\b(share|send|provide|tell|give|enter|confirm)\b.{0,40}\b(code|pin)\b",
         r"\b6[- ]digit code\b", r"\bcode\b[^.?!]{0,40}\b(sms|text message)\b", r"\b(sms|text) code\b", r"\bsecurity code\b", r"\bcvv\b",
         r"رمز التحقق", r"الرمز السري", r"كلمة المرور المؤقتة", r"رمز (OTP|التفعيل)",
         r"(عطني|عطيني|اعطني|أعطني|اعطيني|ابعتلي|ابعثلي|ارسلي|ارسل لي|أرسل لي|قولي|قول لي|اقرالي|اقرا لي|اقرأ لي|خبرني|تعطيني|تقرالي)\s+(ال)?(رمز|كود|كوود|الرمز|الكود)",
         r"(الرمز|الكود|الرقم|الأرقام|الارقام) (اللي|الي|الذي) (وصلك|راح يوصلك|بيوصلك|بيجيك|جاك|وصل لك)", r"(رمز|كود) (على|في|ع) (جوالك|تلفونك|موبايلك|هاتفك)",
         r"كود (التحقق|التفعيل|السري)"],
    ),
    Pattern(
        "credentials", "Request for credentials / login",
        "Directs the reader to enter or confirm a password or log in through a link.",
        30, "high", ["credential_theft", "phishing"],
        [r"\b(enter|confirm|verify|update|validate|re-?enter)\b.{0,30}\b(password|credentials|login|username|account details)\b",
         r"\b(log ?in|sign ?in) (here|now|below|to (verify|confirm|restore))\b", r"\bverify your (account|identity|mailbox)\b",
         r"\b(re)?activate your account\b", r"\bpassword (expires|expired|reset required)\b",
         r"كلمة المرور", r"تحديث (بياناتك|البيانات)", r"تأكيد (حسابك|هويتك)", r"تسجيل الدخول",
         r"رقم (البطاقة|بطاقتك)", r"(الأرقام|الارقام|الرقم) (اللي )?(ورا|خلف|على ظهر) (البطاقة|بطاقتك)", r"الباسوورد|الباسورد|الرقم السري"],
    ),
    Pattern(
        "payment", "Payment / money transfer request",
        "Requests a payment, wire transfer, gift cards, crypto, or a change of bank details.",
        26, "high", ["payment_fraud"],
        [r"\b(wire|bank) transfer\b", r"\btransfer (the )?(funds|money|amount|payment)\b", r"\b(new|updated|changed) (bank|account) (details|number)\b",
         r"\biban\b", r"\bgift ?cards?\b", r"\b(bitcoin|crypto|usdt|btc)\b", r"\bpay (now|immediately|the fee|a fee)\b",
         r"\b(outstanding|unpaid|overdue) (invoice|payment|fine|balance)\b", r"\b(aed|dhs?|usd|\$)\s?\d[\d,\.]*\b",
         r"تحويل (مبلغ|الأموال|بنكي)", r"رقم الآيبان|الآيبان", r"دفع (الرسوم|المبلغ)", r"درهم",
         r"(حول|حوّل|تحول|تحوّل) (لي|المبلغ|الفلوس|فلوس)", r"(ادفع|تدفع|دفع) (رسوم|غرامة|المبلغ|الرسوم|الغرامة)", r"بطاقات? (ايتونز|آيتونز|جوجل بلاي|هدايا)"],
    ),
    Pattern(
        "secrecy", "Secrecy / bypass of normal process",
        "Asks the reader to keep the request confidential or skip normal approvals — common in CEO fraud (BEC).",
        24, "high", ["bec", "social_engineering"],
        [r"\b(keep|treat) (this|it) (confidential|private|between us|secret)\b", r"\bdo ?n[o']t (tell|inform|discuss|share with) (anyone|others|colleagues)\b",
         r"\bconfidential (matter|request|deal|acquisition)\b", r"\bi(?:'m| am) (in a meeting|unavailable|travelling|traveling)\b",
         r"\bcan'?t (talk|call|be reached)\b", r"\bbypass\b", r"\bno need to (verify|call|confirm)\b",
         r"سري(ة)? للغاية", r"لا تخبر أحد", r"بيني وبينك"],
    ),
    Pattern(
        "authority", "Authority impersonation cues",
        "Invokes authority (CEO, police, government, bank, IT department) to make the request seem legitimate.",
        14, "medium", ["impersonation"],
        [r"\b(ceo|cfo|managing director|chairman|director general)\b", r"\b(police|ministry|government|customs|court|prosecution)\b",
         r"\b(it (support|department|helpdesk|team)|helpdesk|system administrator|security team)\b",
         r"\b(bank|central bank) (security|team|department|officer)\b",
         r"\b(i am|i'm|we are|we're|this is|calling( you)?)\b[^.?!]{0,20}\bfrom\b[^.?!]{0,40}\bbank\b", r"\bfrom (the |your )?bank\b",
         r"الشرطة", r"وزارة", r"النيابة", r"المدير التنفيذي", r"البنك المركزي", r"الدعم الفني",
         r"شرطة", r"قسم (الحماية|الأمن|الامن|الاحتيال|مكافحة)", r"من (البنك|بنك)b", r"(الملازم|ملازم|النقيب|نقيب|الرائد|رائد|المقدم|العقيد|ضابط)"],
    ),
    Pattern(
        "reward", "Too-good-to-be-true reward",
        "Offers a prize, refund, lottery win or investment return to lure the reader.",
        20, "medium", ["social_engineering", "payment_fraud"],
        [r"\b(you('ve| have)? won|winner|congratulations)\b", r"\b(prize|lottery|jackpot|reward|cash ?back)\b",
         r"\b(refund|compensation) (is )?(pending|available|approved)\b", r"\bguaranteed (return|profit)s?\b", r"\b(double|triple) your\b",
         r"مبروك", r"ربحت|فزت", r"جائزة", r"استرداد"],
    ),
    Pattern(
        "remote_access", "Request to install software / remote access",
        "Asks the reader to install an app or grant remote access (AnyDesk, TeamViewer…), often used for fraud or malware.",
        30, "high", ["malware_delivery", "social_engineering"],
        [r"\b(anydesk|teamviewer|quicksupport|rustdesk|ultraviewer|screen ?share)\b", r"\binstall (this|the) (app|apk|software|update)\b",
         r"\b\.apk\b", r"\benable (macros|content|editing)\b", r"تحميل التطبيق", r"تثبيت"],
    ),
    Pattern(
        "delivery", "Parcel / delivery lure",
        "Uses a fake delivery problem or customs fee — very common smishing pretext in the UAE.",
        16, "medium", ["smishing", "phishing"],
        [r"\b(parcel|package|shipment|delivery) (is )?(on hold|pending|failed|could not be delivered|held)\b",
         r"\b(customs|delivery|redelivery) fee\b", r"\b(aramex|dhl|fedex|emirates post|ups)\b",
         r"شحنتك", r"الطرد", r"رسوم الجمارك"],
    ),
    Pattern(
        "generic_greeting", "Generic greeting",
        "Uses a generic greeting instead of your name — common in mass phishing.",
        6, "low", ["phishing"],
        [r"^\s*(dear|hello|hi) (customer|user|client|valued customer|sir/madam|account holder|employee)\b",
         r"عزيزي العميل", r"عميلنا العزيز"],
    ),
    Pattern(
        "missed_call", "Missed-call / call-back lure",
        "A 'you missed a call' notice from an unknown sender is a common trick to make you call back a premium-rate or scam number (wangiri).",
        20, "medium", ["vishing", "payment_fraud"],
        [r"\bmissed\s+\d*\s*call(\(s\))?s?\b", r"\bcall(\(s\))? from \+\d", r"\blast call\b", r"مكالمة فائتة", r"مكالمات فائتة"],
    ),
    Pattern(
        "account_pretext", "Card or account 'problem' pretext",
        "Claims your card or account needs an update, verification or has suspicious activity — the usual opening of a bank-impersonation call.",
        18, "medium", ["vishing", "impersonation"],
        [r"\b(visa|master ?card|credit card|debit card|bank card|atm card|card|account)\b[^.?!]{0,25}\b(needs?|requires?|must)\b[^.?!]{0,12}\b(update|updating|updated|verification|verified|activation|activated|renewal|renewed|reactivat\w*)\b",
         r"\b(update|verify|activate|reactivate|renew|unblock)\b[^.?!]{0,8}\b(your|the) (visa|master ?card|card|account|bank details)\b",
         r"\bwe (have )?(received|detected|noticed|found|got)\b[^.?!]{0,30}\b(in our system|on our system|suspicious|unusual)\b",
         r"\b(suspicious|unusual|unauthori[sz]ed) (activity|transaction|login|payment)\b",
         r"(تحديث|تحديث بيانات|تفعيل|تجديد) (بطاقتك|البطاقة|حسابك|الحساب|بياناتك|بيانات البطاقة)",
         r"(بطاقتك|البطاقة|حسابك) (تحتاج|بحاجة|يحتاج|لازم|محتاجة|محتاج)", r"(وصلنا|ظهر عندنا|طلع عندنا)[^.؟!]{0,20}(النظام|السيستم|نظامنا)"],
    ),
    Pattern(
        "voice_pretext", "Call-based pretext",
        "Tells the reader to call a number or expect a call to 'resolve' an issue — a vishing setup.",
        14, "medium", ["vishing"],
        [r"\bcall (us|this number|immediately|back) (on|at)?\b", r"\b(our|an) (agent|officer) will call you\b", r"اتصل (بنا|على الرقم)"],
    ),
]

BRANDS = [
    "abu dhabi police", "dubai police", "adnoc", "etisalat", "e&", "du", "emirates nbd", "adcb", "fab", "first abu dhabi bank",
    "mashreq", "dib", "adib", "rakbank", "emirates post", "aramex", "dhl", "fedex", "microsoft", "office 365", "outlook",
    "google", "apple", "paypal", "amazon", "netflix", "whatsapp", "uae pass", "icp", "tamm", "salik", "rta", "mohre",
]

PHONE_RE = re.compile(r"(?<!\d)(?:\+|00)\d{1,3}[\s-]?\d{1,4}[\s-]?\d{3,4}[\s-]?\d{3,4}(?!\d)|(?<!\d)05\d[\s-]?\d{3}[\s-]?\d{4}(?!\d)")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def analyze_text(text: str, channel: str = "message") -> tuple[list[Finding], dict]:
    """Return findings plus extracted artefacts (matched phrases, brands, phone numbers, emails)."""
    findings: list[Finding] = []
    lowered = text.lower()
    matched: dict[str, list[str]] = {}

    for p in PATTERNS:
        hits: list[str] = []
        for rx in p.regexes:
            for m in re.finditer(rx, text, flags=re.IGNORECASE | re.MULTILINE):
                snippet = m.group(0).strip()
                if snippet and snippet not in hits:
                    hits.append(snippet)
            if len(hits) >= 4:
                break
        if hits:
            matched[p.key] = hits
            tags = list(p.tags)
            if channel == "sms" and "phishing" in tags:
                tags.append("smishing")
            findings.append(Finding(
                title=p.title, detail=p.detail, category="content", severity=p.severity,
                weight=p.weight + min(len(hits) - 1, 3) * 2, source="heuristic", tags=tags,
                evidence="Matched: " + ", ".join(f'"{h}"' for h in hits[:4]),
            ))

    brands = sorted({b for b in BRANDS if re.search(r"(?<![a-z])" + re.escape(b) + r"(?![a-z])", lowered)})

    # Combination rules: specific tactic pairs are much stronger than either alone.
    keys = set(matched)
    if {"authority", "payment"} <= keys and ({"urgency"} & keys or {"secrecy"} & keys):
        findings.append(Finding(
            "Authority + payment + pressure combination",
            "The message combines an authority figure, a payment request and pressure/secrecy — the core pattern of CEO fraud / BEC.",
            "content", "high", 30, "heuristic", ["bec", "payment_fraud"],
        ))
    if {"authority", "otp"} <= keys:
        findings.append(Finding(
            "Authority figure asking for a code",
            "Someone claiming to be the police, a bank or an official department asks for a one-time code. Real officials never do this.",
            "content", "high", 30, "heuristic", ["otp_theft", "impersonation", "vishing"],
        ))
    if {"account_pretext", "otp"} <= keys:
        findings.append(Finding(
            "Card or account 'problem' used to ask for a code",
            "The caller says your card or account needs attention and then asks for the code sent by SMS. That code would let them take over the card.",
            "content", "high", 28, "heuristic", ["otp_theft", "vishing"],
        ))
    elif {"account_pretext", "authority"} <= keys:
        findings.append(Finding(
            "Bank or official says your account has a problem",
            "Someone claiming to be a bank or an official body says your card or account needs action. This is how most bank-impersonation scams open.",
            "content", "medium", 16, "heuristic", ["impersonation", "vishing"],
        ))
    if {"threat", "credentials"} <= keys or {"urgency", "credentials"} <= keys:
        findings.append(Finding(
            "Pressure combined with credential request",
            "Urgency or threats paired with a login/password request strongly matches credential-phishing kits.",
            "content", "high", 24, "heuristic", ["phishing", "credential_theft"],
        ))

    phones = sorted({re.sub(r"[\s-]", "", m.group(0)) for m in PHONE_RE.finditer(text)})
    if "missed_call" in keys and any(p.startswith(("+", "00")) and not p.lstrip("+0").startswith("971") for p in phones):
        findings.append(Finding(
            "Unknown international number wants a call-back",
            "A missed-call notice pointing to a foreign number is the classic set-up for call-back (wangiri) fraud. Do not call back.",
            "content", "high", 28, "heuristic", ["vishing", "payment_fraud"], evidence=", ".join(phones[:3]),
        ))
    emails = sorted({e.lower() for e in EMAIL_RE.findall(text)})
    return findings, {"matched_patterns": matched, "brands_mentioned": brands, "phone_numbers": phones, "emails": emails}
