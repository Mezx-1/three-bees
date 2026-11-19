import XCTest

/// Real messages received by the team (from the screenshots) plus legitimate ones.
final class ScamRulesTests: XCTestCase {
    func testFakeSalikTollFromEmailGoesToJunk() {
        let body = """
        [Salik] تنبيه عاجل: يرجى العلم بأنه حتى 14-04-2026 16:45، لا يزال يوجد رصيد رسوم مرور مستحق بقيمة 4.00 درهم تحت حسابك. يرجى السداد قبل الساعة 11:59 مساءً لتجنب غرامة 50 درهماً وقيود على تجديد ملكية المركبة في نظام RTA.
        [Salik] FINAL REMINDER: As of 2026-04-14 16:45, a toll balance of AED 4.00 is PENDING for settlement. Settle before 11:59 PM TODAY to avoid an AED 50.00 fine.
        To settle, visit: https://salik.ae.ticka.top
        """
        let v = ScamRules.evaluate(sender: "simkukjin@hanmail.net", body: body)
        XCTAssertTrue(v.isJunk, "score \(v.score): \(v.reasons)")
        XCTAssertGreaterThanOrEqual(v.score, 80)
        XCTAssertTrue(v.reasons.contains { $0.contains("salik") }, "should explain the fake Salik link")
    }

    func testMissedCallFromForeignNumberGoesToJunk() {
        let v = ScamRules.evaluate(sender: "+491775111338", body: "You MISSED 1 Call(s) from +491775111338, last call: 22 Sep 2026 at 03:44 PM.")
        XCTAssertTrue(v.isJunk, "score \(v.score): \(v.reasons)")
    }

    func testFakeParcelMessageGoesToJunk() {
        let v = ScamRules.evaluate(sender: "+44 7963 312359",
                                   body: "Hey! EMX has parcel AE58374120M ready for delivery today from 14:00 to 18:00, but we noticed your Emirates ID is not updated. Update now: http://emx-delivery-update.top")
        XCTAssertTrue(v.isJunk, "score \(v.score): \(v.reasons)")
    }

    func testOtpRequestGoesToJunk() {
        let v = ScamRules.evaluate(sender: "+971501112233", body: "عاجل: سيتم إيقاف بطاقتك. أرسل رمز التحقق الذي وصلك الآن لتأكيد هويتك.")
        XCTAssertTrue(v.isJunk, "score \(v.score): \(v.reasons)")
    }

    func testLegitimateMessagesAreNotJunk() {
        XCTAssertFalse(ScamRules.evaluate(sender: "AD-SALIK", body: "Your Salik account was recharged with AED 50. Thank you.").isJunk)
        XCTAssertFalse(ScamRules.evaluate(sender: "+971501112233", body: "Hi, are we still meeting at 7 tonight?").isJunk)
        XCTAssertFalse(ScamRules.evaluate(sender: "ADCB", body: "Your OTP is never shared by ADCB staff. Visit https://www.adcb.com for help.").score >= 80)
    }

    func testBlockedDomainFromServerConfig() {
        var config = FilterConfig.builtIn
        config.blocked_domains = ["evil-example.net"]
        let v = ScamRules.evaluate(sender: "Info", body: "See https://login.evil-example.net/x", config: config)
        XCTAssertTrue(v.isJunk)
    }

    func testPhoneNormalisation() {
        XCTAssertEqual(ScamRules.normalizePhone("0501234567"), "+971501234567")
        XCTAssertEqual(ScamRules.normalizePhone("00491775111338"), "+491775111338")
        XCTAssertNil(ScamRules.normalizePhone("12"))
    }
}
