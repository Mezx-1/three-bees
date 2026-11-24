"""Intent & behaviour analysis — "detect suspicious intent, not suspicious vocabulary".

The keyword patterns in text_analyzer.py react to *words*. This layer asks different questions:

  1. What is the recipient being asked to DO?      (move money, reveal a secret, give personal data,
                                                     open a link, install something, approve, call back,
                                                     move to another app, keep quiet)
  2. Who does the sender CLAIM to be?               (bank, government/police, delivery, employer, tech support,
                                                     a relative or friend on a new number…)
  3. Which psychological LEVERS are used?           (fear, urgency, greed/opportunity, sympathy, secrecy)
  4. Does the request CONTRADICT how that sender    (a bank asking for your code, an authority collecting a
     really behaves?                                 fine by message, "pay a fee to receive money"…)
  5. Is there PROTECTIVE context?                   ("never share this code", "use the official app")

Findings come from combinations of these roles, each with a plain explanation and the phrases that
support it. A single word never produces a strong finding, and if a message asks for nothing risky,
the keyword findings are scaled down (see `dampen_keyword_findings`).

Honest limits: this is a local, rule-based model of intent built on multilingual concept lists
(English, Arabic, Gulf/Levantine dialect and common Arabizi). It generalises far beyond fixed scam
templates, but it is not language understanding. When an AI key is configured, the AI layer reads the
whole message as well, and the two are combined.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .risk import Finding

_DIAC = re.compile(r"[ؗ-ًؚ-ْـ]")


def normalize(text: str) -> str:
    """Lower-case, unify Arabic letter forms, drop diacritics/tatweel, collapse spaces."""
    t = _DIAC.sub("", text or "").lower()
    t = re.sub("[إأآٱ]", "ا", t).replace("ى", "ي").replace("ة", "ه").replace("ؤ", "و").replace("ئ", "ي")
    t = t.replace("’", "'").replace("‘", "'")
    return re.sub(r"\s+", " ", t)


def _c(*rx: str) -> list[re.Pattern]:
    return [re.compile(normalize(r) if not r.isascii() else r, re.I) for r in rx]


# ----------------------------------------------------------------- what is the recipient asked to do?
ASKS: dict[str, list[re.Pattern]] = {
    "move_money": _c(
        r"\b(send|transfer|wire|deposit|pay|remit|top ?up|recharge|load|settle|lend|return|refund)\b[^.?!\n]{0,40}\b(money|amount|balance|funds|savings|dirhams?|aed|dhs?|usd|\$|cash|it back|me back|the rest|fee|fees|bill|charge|sum|payment|\d{2,})",
        r"\b(send|transfer|move|put|deposit)\b[^.?!\n]{0,25}\b(to|into) (the|this|a|my|our|following|new|another|safe|secure|protected|holding)\b[^.?!\n]{0,20}\b(account|wallet|number|iban)",
        r"\b(move|transfer|shift)\b[^.?!\n]{0,12}\b(your|the) (savings|balance|money|funds)\b",
        r"\b(buy|purchase|get)\b[^.?!\n]{0,20}\b(gift ?cards?|itunes|google play|steam|vouchers?)\b",
        r"\b(need|needs|needed|want)\b[^.?!\n]{0,15}\b(some )?(money|cash|\d{3,} ?(aed|dhs?|dirhams?))\b",
        r"\b(help|support) me with (some )?(money|cash|a payment|the payment|a bill)\b",
        r"\btop up\b[^.?!\n]{0,30}\b(account|wallet|balance)\b",
        r"\b(start|begin|invest)\b[^.?!\n]{0,20}\b(with|from) (any amount|as little as|only|just|\d)",
        r"\b(pay|settle|clear)\b[^.?!\n]{0,30}\b(through|via|using|on|at) (the |this )?(link|website|page|portal)\b",
        r"\b(deposit|invest)( now| today| with| from| as little| only| just|\s+\d)",
        r"(حول|حولي|تحول|تحولي|حولها|حوله|ارسل|ارسلي|ترسل|ابعت|ابعتلي|ابعث|ادفع|تدفع|دفع|سدد|تسدد|اودع|تودع|ايداع|اشحن|تشحن)\s?[^.؟!\n]{0,30}(مبلغ|المبلغ|فلوس|الفلوس|مصاري|درهم|دراهم|رصيد|الرصيد|الرسوم|رسوم|غرامه|الغرامه|المال|\d{2,})",
        r"(انقل|ننقل|نقل|تنقل|نحول|نحط|تحط)\s?[^.؟!\n]{0,20}(رصيدك|فلوسك|اموالك|المبلغ|الرصيد)",
        r"(رصيدك|فلوسك|اموالك|مدخراتك)[^.؟!\n]{0,25}(ننقل|نحول|انقل|حول|تنقل|تحول|نحط)",
        r"(سلفني|تسلفني|ديني|اقرضني|محتاج فلوس|محتاجه فلوس|محتاج مبلغ|ساعدني بمبلغ)",
        r"(ترجع|ترجعها|ترجعلي|رجعها|رجع) (لي|المبلغ|الفلوس|المصاري)",
        r"\b(7awel|7awwel|t7awel|t7awelli|t7awel li|7awelli|ed2a3|edfa3|ersel|ersil|ib3atli|eb3atli)\b",
        r"\b(flous|floos|fulus|masari)\b",
    ),
    "share_secret": _c(
        r"\b(send|share|give|tell|read|provide|forward|confirm|repeat|reply with|text me|say|enter)\b[^.?!\n]{0,40}\b(code|otp|pin|password|passcode|cvv|cvc|security number|the digits|the numbers|card number|card details|login details)\b",
        r"\b(code|otp|pin|digits|numbers?)\b[^.?!\n]{0,30}\b(you (just )?(received|got|will receive|'ll receive)|we (just )?sent|sent to your (phone|mobile))\b",
        r"\bwhat (is|are) the (code|digits|numbers)\b",
        r"(عطني|عطيني|اعطني|اعطيني|ابعتلي|ابعثلي|ارسلي|ارسل لي|قولي|قول لي|اقرالي|اقرا لي|خبرني|تعطيني|تقرالي|اكتبلي|شاركني|زودني)\s?[^.؟!\n]{0,20}(الرمز|رمز|الكود|كود|الرقم السري|كلمه المرور|الباسورد|الارقام|رقم البطاقه|الرقم اللي)",
        r"(الرمز|الكود|الرقم|الارقام) (اللي|الي|الذي) (وصلك|راح يوصلك|بيوصلك|بيجيك|جاك|وصل لك)",
        r"\b(el ?code|elcode|el ramz|elramz)\b",
    ),
    "share_personal": _c(
        r"\b(send|share|reply with|provide|confirm|upload|submit|give|attach|fill in|enter|update|re-?validate|validate|re-?verify|verify)\b[^.?!\n]{0,40}\b(emirates id|id number|id card|passport|date of birth|birth date|full name|home address|mother'?s maiden|photo of (the |your )?(front|back|card|id)|selfie|bank statement|salary certificate|residency|visa copy|account details|personal details|payroll (account )?details|bank details)\b",
        r"\b(re-?validate|validate|re-?confirm|re-?verify|verify|confirm|update)\b[^.?!\n]{0,12}\b(your|the) (account|identity|details|information|records|card)\b",
        r"(ارسل|ارسلي|ابعت|ابعتلي|زودنا|زودني|صوره|صورة|ارفق|حدث|تحديث|اكتب)\s?[^.؟!\n]{0,25}(الهويه|هويتك|رقم الهويه|الجواز|جواز السفر|تاريخ الميلاد|بياناتك|معلوماتك الشخصيه|عنوانك|كشف حساب|الاقامه)",
    ),
    "open_link": _c(
        r"\b(click|tap|open|visit|follow|use|go to|check)\b[^.?!\n]{0,25}\b(link|url|here|below|portal|page|website|site)\b",
        r"\b(through|via|using|on) the (secure |official |following |below |attached )?(link|portal|page)\b",
        r"https?://|www\.",
        r"(اضغط|افتح|ادخل|زور|من خلال|عبر) (على )?(الرابط|الرابط التالي|اللينك|الموقع)",
    ),
    "install": _c(
        r"\b(install|download|add)\b[^.?!\n]{0,25}\b(app|apk|application|software|anydesk|teamviewer|quicksupport|rustdesk|extension|update)\b",
        r"\b(share|show) (me )?your screen\b", r"\bscreen ?shar(e|ing)\b", r"\bremote (access|support|session)\b",
        r"(نزل|حمل|ثبت|تنزيل|تحميل|تثبيت) (التطبيق|برنامج|البرنامج|تطبيق)",
    ),
    "approve": _c(
        r"\b(approve|accept|allow|confirm)\b[^.?!\n]{0,20}\b(request|notification|prompt|pop-?up)\b",
        r"\b(press|tap|click)\b[^.?!\n]{0,10}\b(approve|accept|allow|yes)\b",
        r"(وافق|اضغط موافق|اقبل|اكد) (على )?(الطلب|الاشعار|العمليه)",
    ),
    "call_back": _c(
        r"\b(call|ring|phone|contact|whatsapp|message)\b[^.?!\n]{0,15}\b(me|us|our agent|this number|the number|back|on \+|on 0)",
        r"(اتصل|كلمني|تواصل|راسلني) (على|بـ|ب|معي|معنا)",
    ),
    "switch_channel": _c(
        r"\b(continue|talk|chat|move|add me|message me|contact me)\b[^.?!\n]{0,20}\b(whatsapp|telegram|signal|private chat|dm|direct message)\b",
        r"\b(group|channel)\b[^.?!\n]{0,15}\b(telegram|whatsapp)\b|\badd you to\b[^.?!\n]{0,20}\b(group|channel)\b",
        r"(كلمني|راسلني|تواصل معي|اضيفك|نضيفك) (على|ع)? ?(واتساب|واتس|تيليجرام|تلغرام|القروب|الجروب|المجموعه)",
    ),
}

# Phrases that turn an ask into protective advice ("never share this code").
NEGATION = re.compile(normalize(r"(\bdo ?n[o']?t\b|\bnever\b|\bnot\b|\bno one\b|\bnobody\b|\bavoid\b|\bwon'?t\b|\bwill never\b|لا |لن |ما |ممنوع|ابدا|إياك|اياك)[^.?!؟\n]{0,25}$"), re.I)

# ----------------------------------------------------------------- who does the sender claim to be?
CLAIMS: dict[str, list[re.Pattern]] = {
    "bank": _c(r"\bbank\b", r"\b(adcb|adib|fab|emirates nbd|enbd|mashreq|dib|rakbank|cbd|hsbc|citibank|wio|liv)\b",
               r"\b(fraud (prevention|team|unit|department)|card (services|centre|center)|customer protection)\b",
               r"(البنك|بنك|المصرف|قسم الاحتيال|حمايه العملاء|خدمه العملاء في البنك|قسم المتابعه)"),
    "government": _c(r"\b(police|ministry|court|prosecution|customs|immigration|federal|authority|government|municipality|icp|gdrfa|mohre|tamm|uae pass|traffic department|rta|tax)\b",
                     r"\b(case|file) (number|no\.?)\b", r"\b(officer|inspector|lieutenant|captain|investigator)\b",
                     r"(الشرطه|شرطه|وزاره|المحكمه|النيابه|الجمارك|الهيئه|هيئه|الاقامه|الهويه الاتحاديه|بلديه|ضابط|ملازم|نقيب|المرور|قضيه رقم)"),
    "delivery": _c(r"\b(parcel|package|shipment|courier|delivery|aramex|dhl|fedex|emirates post|ups|smsa)\b", r"(شحنه|شحنتك|الطرد|طرد|التوصيل|البريد)"),
    "employer": _c(r"\b(recruit\w*|hiring|hr (team|department)|position|vacancy|job offer|remote (job|position|work)|part[- ]time|work from home|online assistant|your (cv|profile|resume))\b",
                   r"(وظيفه|توظيف|فرصه عمل|عمل من المنزل|دوام جزئي|سيرتك الذاتيه)"),
    "tech_support": _c(r"\b(microsoft|apple|windows|it support|tech(nical)? support|helpdesk|help desk|security team|antivirus)\b", r"(الدعم الفني|فريق الدعم)"),
    "telecom": _c(r"\b(etisalat|e&|du|virgin mobile|telecom|sim card|your line)\b", r"(اتصالات|شريحه|خطك)"),
    "familiar": _c(r"\b(hi|hey|hello) (mum|mom|mama|dad|papa|bro|sis|uncle|auntie)\b", r"\bit'?s me\b", r"\b(my|this is my) new number\b",
                   r"\b(this is|it'?s) your (son|daughter|brother|sister|cousin|friend|nephew)\b", r"\bguess who\b",
                   r"\b(dropped|lost|broke) my (phone|mobile)\b",
                   r"(رقمي الجديد|هذا رقمي|انا ابنك|انا بنتك|انا اخوك|انا اختك|ضاع تلفوني|ضاع جوالي|خرب تلفوني|تلفوني خرب)",
                   r"\b(rqmi|ra2mi|raqmi) (el|al) ?(jdeed|jdid|jadeed)\b", r"\bana (ibnak|ibnik|5ook|akhook|akhok)\b"),
    "investment": _c(r"\b(invest\w*|trading|trader|crypto|bitcoin|usdt|forex|portfolio|returns?|profit|dividend|platform|signals?)\b", r"(استثمار|تداول|ارباح|عوائد|محفظه|عملات رقميه|منصه)"),
    "marketplace": _c(r"\b(listing|buyer|seller|dubizzle|marketplace|your ad|the item|courier will collect)\b", r"(اعلانك|المشتري|البائع|دوبيزل)"),
}

# ----------------------------------------------------------------- psychological levers
LEVERS: dict[str, list[re.Pattern]] = {
    "fear": _c(r"\b(block|blocked|suspend\w*|frozen|freeze|cancel\w*|deactivat\w*|terminat\w*|legal|case|arrest|warrant|fine[sd]?|penalt\w*|violation|compromised|hacked|laundering|fraudulent|investigat\w*|blacklist\w*|deport\w*|mismatch|irregularit\w*|attempt(ed)? to withdraw|withdrawal attempt|lose|lost|disruption|interrupt\w*|uninterrupted)\b",
               r"(حظر|ايقاف|تجميد|الغاء|مخالفه|قضيه|القبض|غرامه|غسيل اموال|مخترق|اختراق|محاوله سحب|سحب من حسابك|تحقيق|مطلوب|ترحيل|بلاغ ضدك|تتوقف|ينقفل|يتقفل)"),
    "urgency": _c(r"\b(now|right now|right away|immediately|today|tonight|asap|urgent\w*|quickly|hurry|before (it|the|midnight|tomorrow|end)|within \d+|by (end of (the )?day|tomorrow|monday|tuesday|wednesday|thursday|friday|saturday|sunday|\d)|last (chance|day)|only (today|\d+ (seats?|spots?|places?))|few (seats|spots|places) (are )?left|expires?|deadline|on the line)\b",
                  r"(الحين|الان|هلق|هلا|اليوم|فورا|بسرعه|حالا|خلال \d+|قبل ما|اخر فرصه|مستعجل|ضروري|على الخط)"),
    "greed": _c(r"\b(won|winner|prize|reward|bonus|free|guarantee\w*|steady|passive income|profit\w*|returns?|\d+ ?% (daily|weekly|monthly|a week|a month|per)|double|earn\w*|earnings|commission|cashback|refund|compensation|inheritance|selected|eligible|exclusive|lucky)\b",
                r"(ربح|ارباح|فزت|جائزه|مكافاه|مجانا|مضمون|دخل اضافي|عموله|استرداد|تعويض|مختار|محظوظ|نسبه \d+)"),
    "sympathy": _c(r"\b(accident|hospital|stuck|stranded|emergency|trouble|help me|in need|my (kids|children|family) (need|are)|desperate|please help)\b",
                   r"(حادث|مستشفى|ورطه|ساعدني|محتاج ضروري|عيالي|اولادي محتاجين|ضايق|في مشكله)", r"\b(mshkle|moshkle|mushkila)\b"),
    "secrecy": _c(r"\b(don'?t|do not|no need to) (tell|inform|discuss|mention|call|contact|share (this|it) with)\b[^.?!\n]{0,25}\b(anyone|anybody|branch|bank|staff|family|police|others|colleagues)\b",
                  r"\b(keep (this|it) (between us|confidential|private|secret)|internal case|confidential)\b",
                  r"(لا تخبر|لا تقول|لا تقل|ما تقول|لا تتصل بالبنك|بيني وبينك|سري|لا تعلم احد)", r"\b(la t2ool|la t2ul|ma t2ool) (la7ad|l7ad|lahad)\b"),
    "unsolicited": _c(r"\b(came across your|we found your|you (have been|were) (selected|chosen|shortlisted)|i (accidentally|mistakenly)|by mistake|wrong number|sent (it )?to you by mistake)\b",
                      r"(بالغلط|عن طريق الخطا|تم اختيارك|وقع اختيارنا)"),
}

UNUSUAL_DEST = _c(
    r"\b(safe|secure|protected|holding|temporary|new|another|different|personal|private|following|below|this) (bank )?(account|wallet|iban)\b",
    r"\baccount (i|we)('ll| will)? (share|send|give)\b", r"\b(wallet address|usdt|bitcoin|btc|crypto|binance|trc20)\b",
    r"\b(gift ?cards?|itunes|google play|steam|vouchers?)\b", r"\b(courier|agent|representative) will (come|collect|pick)\b",
    r"\b(task|work|trading|deposit) account\b", r"\bto (this|my|the following) number\b",
    r"(حساب (امن|آمن|مؤقت|جديد|اخر|ثاني|باسمك)|الحساب التالي|محفظه|عملات رقميه|بطاقات هدايا|مندوب (راح |بيجي |يستلم))",
    r"(ارسل لك|ابعتلك|بعطيك|اعطيك|راح ارسل) رقم (الحساب|الايبان|المحفظه)",
)
ADVANCE_FEE = _c(
    r"\b(fee|fees|deposit|charge|payment|top ?up|tax|insurance)\b[^.?!\n]{0,60}\b(release|receive|claim|unlock|withdraw|activate|deliver|returned|refunded|refundable|get (your|the)|process|start|begin|join|book|reserve|secure)\b",
    r"\b(release|receive|claim|unlock|withdraw|activate|activation|deliver)\b[^.?!\n]{0,60}\b(fee|fees|deposit|small charge|top ?up)\b",
    r"\bonly need to (pay|top ?up|deposit)\b",
    r"(رسوم|تأمين|تامين|دفعه)[^.؟!\n]{0,40}(لاستلام|للافراج|لتفعيل|لسحب|ترجع|مسترد)",
)
PROTECTIVE = _c(
    r"\b(never|will never|do not|don'?t) (share|give|disclose)\b", r"\bwe (will )?never ask\b",
    r"\b(through|via|in|using) (the |our )?(official|bank'?s|mobile|.{0,15} app)\b[^.?!\n]{0,10}",
    r"\b(call|contact) us on the number (on|printed on) the back of your card\b", r"\bif (this|it) was(n'?t| not) you\b",
    r"\bif you did(n'?t| not) (request|make|initiate)\b", r"\bvisit (any|your nearest|the) branch\b",
    r"(لا تشارك|لن نطلب|لا نطلب|عبر التطبيق الرسمي|من خلال التطبيق الرسمي|التطبيق الرسمي|زيارة اقرب فرع|اذا لم تكن انت)",
)


def _hits(pats: list[re.Pattern], t: str) -> list[tuple[str, int]]:
    out = []
    for p in pats:
        for m in p.finditer(t):
            s = m.group(0).strip()
            if s:
                out.append((s, m.start()))
    return out


@dataclass
class Intent:
    asks: dict[str, list[str]] = field(default_factory=dict)
    negated_asks: dict[str, list[str]] = field(default_factory=dict)
    claims: dict[str, list[str]] = field(default_factory=dict)
    levers: dict[str, list[str]] = field(default_factory=dict)
    unusual_destination: list[str] = field(default_factory=list)
    advance_fee: list[str] = field(default_factory=list)
    protective: list[str] = field(default_factory=list)

    @property
    def risky_asks(self) -> set[str]:
        return set(self.asks) - {"call_back"} if self.asks else set()

    def to_dict(self) -> dict:
        return {"asks": self.asks, "protective_asks": self.negated_asks, "claimed_identity": self.claims, "pressure": self.levers,
                "unusual_destination": self.unusual_destination, "advance_fee": self.advance_fee, "protective_context": self.protective}


def read_intent(text: str) -> Intent:
    t = normalize(text)
    it = Intent()
    for key, pats in ASKS.items():
        for snip, pos in _hits(pats, t):
            neg = NEGATION.search(t[max(0, pos - 40):pos])
            bucket = it.negated_asks if neg else it.asks
            if snip not in bucket.setdefault(key, []):
                bucket[key].append(snip)
    # A bare URL is not an ask by itself unless the message also tells you to act on it.
    if it.asks.get("open_link") and all(s.startswith(("http", "www")) for s in it.asks["open_link"]) and not (set(it.asks) - {"open_link"}):
        it.asks.pop("open_link")
    for key, pats in CLAIMS.items():
        hs = [s for s, _ in _hits(pats, t)]
        if hs:
            it.claims[key] = list(dict.fromkeys(hs))[:4]
    for key, pats in LEVERS.items():
        hs = [s for s, _ in _hits(pats, t)]
        if hs:
            it.levers[key] = list(dict.fromkeys(hs))[:4]
    it.unusual_destination = list(dict.fromkeys(s for s, _ in _hits(UNUSUAL_DEST, t)))[:4]
    it.advance_fee = list(dict.fromkeys(s for s, _ in _hits(ADVANCE_FEE, t)))[:3]
    it.protective = list(dict.fromkeys(s for s, _ in _hits(PROTECTIVE, t)))[:3]
    return it


def _ev(*parts: list[str] | None) -> str:
    seen: list[str] = []
    for p in parts:
        for s in (p or [])[:2]:
            if s not in seen:
                seen.append(s)
    return "Supporting phrases: " + ", ".join(f'"{s[:60]}"' for s in seen[:5]) if seen else ""


ORG_NAMES = {"bank": "a bank", "government": "a government body or the police", "delivery": "a delivery company", "employer": "an employer or recruiter",
             "tech_support": "technical support", "telecom": "a telecom provider", "investment": "an investment opportunity", "marketplace": "a buyer or seller"}


def behaviour_findings(it: Intent, *, has_link: bool = False) -> list[Finding]:
    """Turn the intent reading into explained findings. Combinations matter; single roles stay weak."""
    F: list[Finding] = []
    asks, claims, lev = it.asks, it.claims, it.levers
    official = [k for k in ("bank", "government", "telecom", "tech_support", "delivery") if k in claims]
    who = ORG_NAMES.get(official[0], "an organisation") if official else None
    pressure = [k for k in ("fear", "urgency", "secrecy") if k in lev]

    def add(title, detail, sev, w, tags, *ev):
        F.append(Finding(title, detail, "behavior", sev, w, "heuristic", tags, evidence=_ev(*ev)))

    if "share_secret" in asks and official:
        add(f"Claims to be {who} but asks for a secret code or password",
            f"The sender presents as {who} and asks you to reveal a code, PIN, password or card security number. The real organisation already has what it needs and never asks for these.",
            "critical", 55, ["otp_theft", "impersonation"], asks["share_secret"], claims[official[0]])
    elif "share_secret" in asks:
        add("Asks you to reveal a code, PIN or password",
            "Whoever holds this code can use your account. A genuine person or company has no reason to ask for it.",
            "high", 40, ["otp_theft", "credential_theft"], asks["share_secret"])

    if "move_money" in asks:
        if it.unusual_destination and (official or "secrecy" in lev):
            add("Asks you to move money to an account they choose",
                f"The sender{(' presents as ' + who + ' and') if who else ''} wants your money moved to a 'safe', new or personal account, wallet or gift cards. "
                "Banks and authorities never move customers' money this way — this is the core of 'safe-account' fraud.",
                "critical", 55, ["payment_fraud", "impersonation"], asks["move_money"], it.unusual_destination)
        elif official and ("government" in claims) and ("fear" in lev):
            add("An authority demands payment by message or phone, under threat",
                "Fines, visa or residency fees are paid through official government apps and websites, not by instructions in a call or message that threatens you.",
                "high", 55, ["payment_fraud", "impersonation"], asks["move_money"], claims["government"], lev.get("fear"))
        elif "familiar" in claims:
            add("A 'relative or friend' on an unusual number asks for money",
                "Someone says they are family or a friend (often 'my new number' or 'my phone broke') and then asks for money. Call them on the number you already have before paying anything.",
                "high", 58 if ("urgency" in lev or "secrecy" in lev) else 50, ["impersonation", "payment_fraud"], claims["familiar"], asks["move_money"])
        elif it.advance_fee:
            add("You must pay first to receive something",
                "The message asks for a fee, deposit or 'top-up' before you can receive a job, prize, refund, loan, parcel or profit. Paying to receive money is the signature of advance-fee fraud.",
                "high", 50, ["payment_fraud", "social_engineering"], it.advance_fee, asks["move_money"])
        elif "investment" in claims and "greed" in lev:
            add("Investment offer built on promised returns",
                "The sender promises steady or guaranteed returns and invites you to put money in. Real investments carry risk and come from licensed firms you contact yourself.",
                "high", 46 if "urgency" in lev else 40, ["payment_fraud", "social_engineering"], lev["greed"], asks["move_money"])
        elif "unsolicited" in lev or "sympathy" in lev:
            add("Unexpected money request built on a story",
                "The request comes with an emotional or 'by mistake' story (an accident, a wrong transfer, family need). Check the story independently — e.g. in your own banking app — before sending anything.",
                "high", 36, ["payment_fraud", "social_engineering"], lev.get("unsolicited"), lev.get("sympathy"), asks["move_money"])
        elif it.unusual_destination:
            add("Payment to an unusual destination",
                "You're asked to pay into a personal account, wallet, phone number or with gift cards/crypto instead of an official payment channel.",
                "medium", 26, ["payment_fraud"], it.unusual_destination, asks["move_money"])
        elif official and (pressure or "open_link" in asks or has_link):
            add(f"{(who or 'An organisation').capitalize()} asks for payment with pressure or a link",
                "A payment request that arrives with a deadline, a threat or a link is how fake fine, toll, bill and parcel-fee scams work. Pay only inside the official app or website you open yourself.",
                "high", 34, ["payment_fraud", "phishing"], asks["move_money"], lev.get("urgency"), lev.get("fear"))
        elif pressure and not it.protective:
            add("Money request under pressure", "You're asked to pay or transfer money while being rushed or kept quiet.",
                "medium", 24, ["payment_fraud", "social_engineering"], asks["move_money"], lev.get("urgency"), lev.get("secrecy"))
        elif not it.protective:
            add("Asks for money", "The message asks you to send or pay money. On its own this is normal; it matters only with other warning signs.",
                "low", 6, ["payment_fraud"], asks["move_money"])

    if "share_personal" in asks and not it.protective:
        id_docs = any(re.search(r"(emirates id|id number|id card|passport|photo of|selfie|الهويه|الجواز|صوره)", x) for x in asks["share_personal"])
        if official or "employer" in claims or "greed" in lev or has_link or "open_link" in asks or id_docs:
            add("Collects identity or account details",
                "You're asked for ID, passport, date of birth, account or payroll details — enough to open accounts or take over yours. Organisations that already know you don't collect this by message or link.",
                "high", 38, ["credential_theft", "impersonation"], asks["share_personal"], (claims.get(official[0]) if official else None))
        else:
            add("Asks for personal details", "Personal information is requested. Confirm who is asking through a channel you trust.",
                "medium", 20, ["credential_theft"], asks["share_personal"])

    if "install" in asks and (official or "tech_support" in claims or pressure):
        add("Asks you to install an app or share your screen",
            "Remote-access and 'support' apps give the other person control of your phone or computer, including your banking app.",
            "high", 40, ["malware_delivery", "social_engineering"], asks["install"])

    if "approve" in asks and (official or pressure):
        add("Asks you to approve a request in your app",
            "Approving the notification is what authorises the payment or login. A genuine bank never asks you to approve something to 'stop' a transaction.",
            "critical", 50, ["payment_fraud", "impersonation"], asks["approve"])

    if "employer" in claims and (it.advance_fee or ("move_money" in asks and "greed" in lev)):
        add("Job offer that costs you money", "Genuine employers don't charge for jobs, training, visas or 'activating' a work account, and don't pay for liking or rating things.",
            "high", 34, ["payment_fraud", "social_engineering"], claims["employer"], it.advance_fee or asks.get("move_money"))

    if "switch_channel" in asks and (("greed" in lev) or "move_money" in asks or official):
        add("Moves you to a private chat or group", "Moving the conversation to WhatsApp/Telegram groups keeps it away from moderation and is common in investment and job scams.",
            "medium", 18, ["social_engineering"], asks["switch_channel"])

    if "secrecy" in lev and (asks.keys() & {"move_money", "share_secret", "share_personal", "approve", "install"}):
        add("Tells you to keep it secret", "Being told not to involve the bank, family or colleagues removes the people most likely to stop the scam.",
            "high", 30, ["social_engineering", "bec"], lev["secrecy"])

    risky = asks.keys() & {"move_money", "share_secret", "share_personal", "install", "approve", "open_link"}
    if risky and len(pressure) >= 1 and not F and not it.protective:
        add("Risky request combined with pressure", "The message asks you to act (pay, log in, share details) and pushes you to do it fast or under threat.",
            "medium", 22, ["social_engineering"], *(asks[k] for k in risky), lev.get("urgency"), lev.get("fear"))

    if ("open_link" in asks or has_link) and "fear" in lev and (official or "share_personal" in asks) and not it.protective and not any(f.weight >= 30 for f in F):
        add("Link presented as the way to avoid a problem", "You're told something bad will happen unless you act through the link — the standard set-up of a phishing page.",
            "medium", 24, ["phishing"], asks.get("open_link"), lev["fear"])
    return F


# Findings that describe a whole lure rather than single words — never scaled down.
KEEP_FULL_WEIGHT = {"Missed-call / call-back lure", "Unknown international number wants a call-back"}


def dampen_keyword_findings(findings: list[Finding], it: Intent) -> str | None:
    """If the message asks for nothing risky (or only gives protective advice), scale down word-based findings.

    'Urgent', 'bank', 'code', 'congratulations' are normal words. Without a risky request they are weak signals.
    Returns a note for the report when dampening happened.
    """
    risky = it.asks.keys() & {"move_money", "share_secret", "share_personal", "install", "approve", "switch_channel"}
    link_ask = "open_link" in it.asks
    if risky or (link_ask and not it.protective):
        return None
    touched = False
    for f in findings:
        if f.category == "content" and f.source == "heuristic" and f.weight > 0 and f.title not in KEEP_FULL_WEIGHT:
            factor = 0.25 if (it.negated_asks or it.protective) else 0.4
            f.weight = max(1, int(round(f.weight * factor)))
            if f.severity in ("high", "critical"):
                f.severity = "low" if it.protective or it.negated_asks else "medium"
            touched = True
    if not touched:
        return None
    if it.negated_asks or it.protective:
        return "Scam-related words appear, but the message is protective advice (e.g. 'do not share this code') and asks you for nothing risky, so they were weighted down."
    return "Scam-related words appear, but the message doesn't ask you to pay, share secrets or personal data, install anything or open a link, so they were weighted down."
