import Foundation

/// Rules synced from the WOLVE server (`GET /api/mobile/filter-config`). A built-in copy is used until the first sync.
struct FilterConfig: Codable {
    var version: Int
    var blocked_domains: [String]
    var blocked_phones: [String]
    var suspicious_tlds: [String]
    var shorteners: [String]
    var official_domains: [String: [String]]
    var junk_threshold: Int

    static let builtIn = FilterConfig(
        version: 1, blocked_domains: [], blocked_phones: [],
        suspicious_tlds: ["top", "xyz", "zip", "mov", "click", "link", "gq", "tk", "ml", "cf", "ga", "work", "support", "rest", "cam",
                          "icu", "buzz", "monster", "cfd", "sbs", "lol", "quest", "bond", "cyou", "loan"],
        shorteners: ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "t.ly"],
        official_domains: ["salik": ["salik.ae"], "rta": ["rta.ae"], "adpolice": ["adpolice.gov.ae"], "dubaipolice": ["dubaipolice.gov.ae"],
                           "emiratespost": ["emiratespost.ae"], "aramex": ["aramex.com"], "dhl": ["dhl.com"], "etisalat": ["etisalat.ae", "eand.com"],
                           "emiratesnbd": ["emiratesnbd.com"], "adcb": ["adcb.com"], "bankfab": ["bankfab.com"], "uaepass": ["uaepass.ae"],
                           "tamm": ["tamm.abudhabi"], "paypal": ["paypal.com"], "apple": ["apple.com", "icloud.com"], "microsoft": ["microsoft.com", "live.com"]],
        junk_threshold: 50)
}

struct Verdict {
    let score: Int
    let reasons: [String]   // Arabic, shown in the app
    let isJunk: Bool
}

/// Offline scam scoring for SMS. Mirrors the server rules (noisy-OR of weighted signals, capped at 99).
enum ScamRules {
    private struct Pattern {
        let key: String
        let reason: String
        let weight: Int
        let regex: NSRegularExpression
        init(_ key: String, _ reason: String, _ weight: Int, _ pattern: String) {
            self.key = key; self.reason = reason; self.weight = weight
            // Patterns are constants written in this file, so failure here is a programming error.
            self.regex = try! NSRegularExpression(pattern: pattern, options: [.caseInsensitive])
        }
    }

    private static let patterns: [Pattern] = [
        Pattern("urgency", "ضغط واستعجال", 14,
                #"\burgent(ly)?\b|\bimmediately\b|\bwithin \d+ ?(hours?|hrs?|minutes?)\b|\btoday only\b|\bfinal (notice|reminder|warning)\b|\blast chance\b|\bbefore \d{1,2}:\d{2}|عاجل|فورا|فوراً|خلال \d+ ساعة|آخر فرصة|تنبيه نهائي|قبل الساعة"#),
        Pattern("threat", "تهديد بعقوبة أو إيقاف", 16,
                #"\b(suspend(ed)?|blocked|locked|deactivated)\b|\blegal action\b|\b(fine|penalty|arrest|warrant|restrictions?)\b|سيتم (إيقاف|تعليق|حظر|إغلاق)|غرامة|قيود|إيقاف"#),
        Pattern("otp", "طلب رمز التحقق (OTP)", 42,
                #"\botp\b|\bone[- ]time (password|code|pin)\b|\bverification code\b|\bsecurity code\b|\bcvv\b|رمز التحقق|الرمز السري|رمز التفعيل"#),
        Pattern("credentials", "طلب بيانات الدخول أو تحديث البيانات", 30,
                #"\bverify your (account|identity)\b|\bupdate (your )?(details|information|emirates id)\b|\bupdate now\b|\bnot (updated|verified)\b|\bpassword\b|\b(log|sign) ?in (here|now)\b|كلمة المرور|تحديث (بياناتك|البيانات)|تأكيد (حسابك|هويتك)"#),
        Pattern("payment", "طلب دفع أو سداد", 26,
                #"\b(pay|settle|unpaid|outstanding|overdue)\b|\b(balance|fee)s?\b|\baed\s?\d|\d+([.,]\d+)?\s?(aed|dhs?)\b|درهم|سداد|رسوم|دفع|مستحق"#),
        Pattern("delivery", "خدعة الطرود والتوصيل", 16,
                #"\b(parcel|package|shipment|delivery|customs)\b|\bemirates id\b|شحنة|شحنتك|الطرد|الجمارك"#),
        Pattern("reward", "جائزة أو ربح مغرٍ", 20,
                #"\bcongratulations\b|\b(winner|prize|lottery|jackpot)\b|\byou('ve| have)? won\b|\bguaranteed (profit|return)\b|مبروك|جائزة|ربحت|فزت"#),
        Pattern("missed_call", "إشعار مكالمة فائتة لدفعك لمعاودة الاتصال", 20,
                #"\bmissed\s+\d*\s*call|\bcall\(s\) from\b|\blast call\b|مكالمة فائتة|مكالمات فائتة"#),
    ]

    private static let multiPartSuffixes: Set<String> = ["co.ae", "gov.ae", "ac.ae", "net.ae", "org.ae", "com.sa", "gov.sa", "co.uk", "org.uk", "com.au", "co.in"]
    private static let satellitePrefixes = ["+881", "+882", "+883"]

    static func registeredDomain(_ host: String) -> String {
        let parts = host.lowercased().split(separator: ".").map(String.init)
        guard parts.count >= 2 else { return host.lowercased() }
        let lastTwo = parts.suffix(2).joined(separator: ".")
        if parts.count >= 3 && multiPartSuffixes.contains(lastTwo) { return parts.suffix(3).joined(separator: ".") }
        return lastTwo
    }

    static func normalizePhone(_ raw: String) -> String? {
        var s = raw.filter { $0.isNumber || $0 == "+" }
        if s.hasPrefix("00") { s = "+" + s.dropFirst(2) }
        if s.hasPrefix("05") && s.count == 10 { s = "+971" + s.dropFirst(1) }
        let digits = s.filter(\.isNumber)
        guard digits.count >= 6 && digits.count <= 15 else { return nil }
        return s
    }

    private static func urls(in text: String) -> [URL] {
        guard let detector = try? NSDataDetector(types: NSTextCheckingResult.CheckingType.link.rawValue) else { return [] }
        return detector.matches(in: text, range: NSRange(text.startIndex..., in: text)).compactMap { $0.url }
    }

    static func evaluate(sender: String?, body: String, config: FilterConfig = .builtIn) -> Verdict {
        var signals: [(String, Int)] = []
        var matched = Set<String>()
        let range = NSRange(body.startIndex..., in: body)
        for p in patterns where p.regex.firstMatch(in: body, range: range) != nil {
            matched.insert(p.key)
            signals.append((p.reason, p.weight))
        }

        // Links
        var brandLink = false
        for url in urls(in: body) {
            guard let host = url.host?.lowercased() else { continue }
            let reg = registeredDomain(host)
            let tld = host.split(separator: ".").last.map(String.init) ?? ""
            if config.blocked_domains.contains(where: { reg == $0 || host.hasSuffix("." + $0) || host == $0 }) {
                signals.append(("الرابط موجود في قائمة حظر WOLVE", 70))
            }
            if host.range(of: #"^\d{1,3}(\.\d{1,3}){3}$"#, options: .regularExpression) != nil {
                signals.append(("الرابط عنوان IP مباشر", 30))
            }
            if config.suspicious_tlds.contains(tld) { signals.append(("امتداد نطاق كثير الاستغلال (.\(tld))", 16)) }
            if config.shorteners.contains(reg) { signals.append(("رابط مختصر يُخفي الوجهة", 14)) }
            if url.scheme == "http" { signals.append(("رابط غير مشفّر (HTTP)", 8)) }
            let flat = host.replacingOccurrences(of: "-", with: "").replacingOccurrences(of: ".", with: "")
            let isOfficial = config.official_domains.values.contains { $0.contains(reg) }
            if !isOfficial, let brand = config.official_domains.keys.sorted().first(where: { $0.count >= 3 && flat.contains($0) }) {
                signals.append(("رابط ينتحل اسم «\(brand)» على نطاق لا يتبع له (\(reg))", 34))
                brandLink = true
            }
        }
        if brandLink && matched.contains("payment") {
            signals.append(("طلب دفع مع رابط ينتحل جهة معروفة", 30))
        }
        if (matched.contains("urgency") || matched.contains("threat")) && matched.contains("credentials") {
            signals.append(("ضغط مقترن بطلب بيانات الدخول", 24))
        }

        // Sender
        let s = (sender ?? "").trimmingCharacters(in: .whitespaces)
        if s.contains("@") {
            signals.append(("الرسالة مُرسلة من عنوان بريد إلكتروني وليس من جهة رسمية", 30))
        } else if let phone = normalizePhone(s) {
            if config.blocked_phones.contains(phone) { signals.append(("رقم المرسل في قائمة حظر WOLVE", 70)) }
            if satellitePrefixes.contains(where: { phone.hasPrefix($0) }) { signals.append(("رقم شبكة فضائية/دولية", 30)) }
            else if phone.hasPrefix("+") && !phone.hasPrefix("+971") { signals.append(("رقم دولي", 10)) }
            if matched.contains("missed_call") && phone.hasPrefix("+") && !phone.hasPrefix("+971") {
                signals.append(("رقم دولي مجهول يريد أن تعاود الاتصال به", 32))
            }
        }

        var remaining = 1.0
        for (_, w) in signals { remaining *= 1 - Double(min(max(w, 0), 95)) / 100 }
        let score = min(99, Int(((1 - remaining) * 100).rounded()))
        let reasons = signals.sorted { $0.1 > $1.1 }.map(\.0)
        return Verdict(score: score, reasons: reasons, isJunk: score >= config.junk_threshold)
    }
}
