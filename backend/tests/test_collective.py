"""Knowledge base, phone intelligence and the collective protection network (backend scenarios).

Mobile OS behaviour (Android call screening, iOS Call Directory) and mailbox scanning are not testable here;
see docs/COLLECTIVE_PROTECTION.md for what exists and what still needs a device or provider approval.
"""
from fastapi.testclient import TestClient

from app.main import app

A = {"X-3B-User": "sara.ahmed"}      # user A (employee)
B = {"X-3B-User": "layla.analyst"}   # user B
C = {"X-3B-User": "omar.analyst"}    # user C / analyst
ADMIN = {"X-3B-User": "aisha.admin"}


def _report(c, headers, **kw):
    form = {"category": "bank_impersonation", "channel": "call", "privacy_ack": "true", "currency": "AED",
            "message": "I am calling from your bank, your card is blocked, tell me the code we sent", "description": "test"}
    form.update(kw)
    r = c.post("/api/reports", data=form, headers=headers)
    assert r.status_code == 200, r.text
    return r.json()


# ---------------------------------------------------------------- knowledge base

def test_knowledge_base_has_100_plus_methods_in_20_categories():
    with TestClient(app) as c:
        s = c.get("/api/knowledge/stats", headers=A).json()
        assert s["total"] >= 100 and len(s["by_category"]) == 20 and s["uae_focus"] >= 50
        assert s["verified"] == 0, "seeded methods need a reviewer and a source before they are Verified"
        m = c.get("/api/knowledge/methods/SM-BANK-002", headers=A).json()["data"]
        for k in ("attack_sequence", "psychological_techniques", "behavioral_indicators", "examples", "detection_strategies", "protection_steps",
                  "severity", "related_methods", "sources", "last_reviewed", "review_status"):
            assert k in m, k
        assert m["examples"]["en"] and m["examples"]["ar"] and m["examples_are_fictional"]


def test_knowledge_admin_duplicates_versions_verify_rules_and_import_export():
    with TestClient(app) as c:
        new = {"name": "Fake school fee refund call", "category": "payment_refund", "description": "Caller says a school fee refund is due and asks card details.",
               "examples": {"en": ["The school owes you a refund, read me your card number to process it."], "ar": []}, "review_status": "draft"}
        assert c.post("/api/knowledge/methods", json=new, headers=A).status_code == 403  # employees can't edit
        m = c.post("/api/knowledge/methods", json=new, headers=C).json()
        assert m["review_status"] == "draft" and m["origin"] == "admin"
        dup = c.post("/api/knowledge/methods", json={**new, "name": "Fake school fee refund calls"}, headers=C)
        assert dup.status_code == 409 and dup.json()["detail"]["duplicates"]
        # Verified needs an admin AND a source
        assert c.put(f"/api/knowledge/methods/{m['id']}", json={**new, "review_status": "verified"}, headers=C).status_code == 403
        assert c.put(f"/api/knowledge/methods/{m['id']}", json={**new, "review_status": "verified"}, headers=ADMIN).status_code == 422
        ok = c.put(f"/api/knowledge/methods/{m['id']}", json={**new, "review_status": "verified", "sources": [{"title": "Internal case review", "url": "https://example.org/case"}]}, headers=ADMIN)
        assert ok.status_code == 200 and ok.json()["review_status"] == "verified"
        c.post(f"/api/knowledge/methods/{m['id']}/disable", headers=C)
        detail = c.get(f"/api/knowledge/methods/{m['id']}", headers=C).json()
        assert not detail["enabled"] and len(detail["versions"]) == 3
        csv_text = c.get("/api/knowledge/export?format=csv", headers=C).text
        assert csv_text.startswith("id,name,category") and "SM-BANK-002" in csv_text
        imp = c.post("/api/knowledge/import", json={"format": "json", "content": '[{"name": "Fake charity QR at a mall", "category": "qr", "description": "QR stickers for donations.", "review_status": "verified"}, '
                                                                             '{"name": "Safe-account transfer", "category": "banking", "description": "dup"}]'}, headers=C).json()
        assert len(imp["created"]) == 1 and imp["skipped_duplicates"]
        assert c.get(f"/api/knowledge/methods/{imp['created'][0]}", headers=C).json()["review_status"] == "needs_review", "unverified imports are never Verified"


# ---------------------------------------------------------------- phone intelligence

def test_phone_lookup_uae_international_unknown_and_honest_fields():
    with TestClient(app) as c:
        uae = c.get("/api/phone/lookup?number=0501234567", headers=A).json()
        assert uae["e164"] == "+971501234567" and uae["country"] == "United Arab Emirates" and uae["flag"] == "🇦🇪"
        assert uae["line_type"] == "Mobile" and uae["caller_name"] is None and uae["risk"]["level"] == "LOW"
        assert any("not where the caller is" in n for n in uae["notes"])
        uk = c.get("/api/phone/lookup?number=%2B442079460000", headers=A).json()
        assert uk["region"] == "GB" and uk["dialing_code"] == "+44"
        sat = c.get("/api/phone/lookup?number=%2B8821234567", headers=A).json()
        assert sat["risk"]["risk_score"] >= 25
        assert c.get("/api/phone/lookup?number=hello", headers=A).status_code == 422


def test_phone_reports_count_once_per_person_and_moderation_can_remove_them():
    with TestClient(app) as c:
        num = "+971 50 777 0001"
        assert c.post("/api/phone/report", json={"number": num, "category": "banking", "description": "asked for my code"}, headers=A).json()["ok"]
        assert c.post("/api/phone/report", json={"number": num, "category": "banking"}, headers=A).status_code == 409
        c.post("/api/phone/report", json={"number": num, "category": "banking"}, headers=B)
        r = c.post("/api/phone/report", json={"number": num, "category": "payment"}, headers=C).json()
        assert r["shared_status"] == "suspicious", "3 independent reports -> warning, never verified"
        look = c.get("/api/phone/lookup?number=0507770001", headers=A).json()
        assert look["community"]["distinct_reporters"] == 3 and look["shared_status"] == "suspicious" and look["risk"]["risk_score"] >= 30
        queue = c.get("/api/phone/reports", headers=C).json()
        assert queue and all(q["reporter"] == "hidden" for q in queue)
        assert c.get("/api/phone/reports", headers=A).status_code == 403
        mine = next(q for q in queue if q["number"] == "+971507770001" and q["category"] == "payment")
        c.patch(f"/api/phone/reports/{mine['id']}", json={"status": "rejected"}, headers=C)
        assert c.get("/api/phone/lookup?number=0507770001", headers=A).json()["shared_status"] is None, "below 3 reporters -> warning withdrawn"


# ---------------------------------------------------------------- collective protection scenarios

def test_1_verified_number_reported_by_A_is_recognised_for_B_and_sync_is_incremental():
    with TestClient(app) as c:
        v0 = c.get("/api/network/sync", headers=B).json()["version"]
        for h in (A, B, C):
            _report(c, h, phone="+971 50 777 0002")
        ind = next(i for i in c.get("/api/network/indicators?type=phone", headers=C).json() if i["value"] == "+971507770002")
        assert ind["status"] == "suspicious" and ind["distinct_reporters"] == 3
        c.patch(f"/api/network/indicators/{ind['id']}", json={"status": "verified", "note": "Three victims, same script, bank confirmed"}, headers=C)
        # user B (who never needs to report it) is protected: caller check, message analysis and sync
        chk = c.post("/api/network/check", json={"type": "phone", "value": "0507770002"}, headers=B).json()
        assert chk["status"] == "verified" and chk["level"] == "block" and "reporter" not in str(chk).lower().replace("distinct_reporters", "")
        msg = c.post("/api/analyze/message", json={"text": "Please call me back urgently on +971507770002 about your account", "channel": "sms"}, headers=B).json()
        assert any(f["title"].startswith("Known scam phone on the 3B shared list") for f in msg["report"]["findings"])
        delta = c.get(f"/api/network/sync?since={v0}", headers=B).json()
        up = [x for x in delta["changes"] if x["op"] == "upsert" and x["type"] == "phone"]
        assert up and up[-1]["level"] == "block" and "+971" not in str(delta["changes"]), "only hashes are distributed"
        # 10: device was offline; reconnecting with its last version gets only newer changes
        again = c.get(f"/api/network/sync?since={delta['version']}", headers=B).json()
        assert again["changes"] == []
        calldir = c.get("/api/mobile/call-directory", headers=B).json()
        assert any(e["number"] == "+971507770002" and e["block"] for e in calldir["entries"])


def test_2_and_4_email_reported_by_A_warns_B_even_from_a_new_address_on_the_same_domain():
    with TestClient(app) as c:
        for h in (A, B, C):
            _report(c, h, category="phishing_email", channel="email", message="Your mailbox is full, contact support@mail-secure-example.net to restore it")
        dom = next(i for i in c.get("/api/network/indicators?type=email_domain", headers=C).json() if i["value"] == "mail-secure-example.net")
        assert dom["status"] == "suspicious"
        raw = ("From: Helpdesk <restore-team@mail-secure-example.net>\nTo: layla@example.com\nSubject: Mailbox notice\n\n"
               "Your mailbox will stop receiving messages. Verify your account today.")
        r = c.post("/api/emails/analyze", data={"raw": raw}, headers=B).json()
        assert any(f["title"] == "Reported by several 3B users" for f in r["report"]["findings"]), "new address, same reported infrastructure"


def test_3_5_6_changed_number_wording_and_link_still_link_to_the_campaign():
    with TestClient(app) as c:
        first = _report(c, A, phone="+971 50 777 0011", url="https://secure-example-login.com/verify",
                        message="Dear customer, your account is on hold. Confirm your details at the secure page to avoid closure today.")
        second = _report(c, B, phone="+971 50 777 0099", url="https://secure-example-account.com/verify",
                         message="Dear client, your account has been put on hold. Confirm your details on the secure page to avoid closure today.")
        rel = c.get(f"/api/reports/{second['reference']}", headers=C).json()["related"]
        link = next(x for x in rel if x["reference"] == first["reference"])
        methods = {l["method"] for l in link["links"]}
        assert "similar_text" in methods and "similar_domain" in methods and "nearby_phone" in methods
        assert link["level"] in ("strongly_related", "potentially_related")
        # a NEW message with another number and different words still matches the reported template
        msg = c.post("/api/analyze/message", json={"text": "Dear customer, your account is on hold. Confirm your details at the secure page to avoid closure tonight. +971507770123", "channel": "sms"}, headers=A).json()
        assert any(f["title"].startswith("Matches a scam template already reported to 3B") for f in msg["report"]["findings"])
        g = c.get("/api/network/campaigns", headers=C).json()
        assert any(e["method"] == "similar_domain" for e in g["edges"] if "method" in e)
        assert all(cmp["campaign_id"].startswith("CAMP-") for cmp in g["campaigns"])
        assert c.get("/api/network/campaigns", headers=A).status_code == 403


def test_7_and_9_legitimate_business_appeals_and_revocation_removes_from_clients():
    with TestClient(app) as c:
        for h in (A, B, C):
            _report(c, h, phone="+971 50 777 0300", category="other", message="They called about my order")
        ind = next(i for i in c.get("/api/network/indicators?type=phone", headers=C).json() if i["value"] == "+971507770300")
        v = c.get("/api/network/sync", headers=B).json()["version"]
        ap = c.post("/api/network/appeals", json={"type": "phone", "value": "+971507770300", "reason": "This is our customer-service line; we did call about orders."}).json()
        assert ap["listed"] and ap["appeal_id"]
        open_ = c.get("/api/network/appeals", headers=C).json()
        assert any(a["id"] == ap["appeal_id"] for a in open_)
        c.patch(f"/api/network/appeals/{ap['appeal_id']}", json={"uphold": True, "note": "Verified company line"}, headers=C)
        delta = c.get(f"/api/network/sync?since={v}", headers=B).json()
        assert any(x["op"] == "remove" for x in delta["changes"])
        assert c.post("/api/network/check", json={"type": "phone", "value": "+971507770300"}, headers=A).json()["status"] == "allowlisted"
        # 9: a verified indicator overturned by new evidence is removed too
        x = c.post("/api/network/indicators", json={"type": "domain", "value": "overturned-example.com", "status": "verified", "reason": "Phishing kit seen on the site"}, headers=C).json()
        v2 = c.get("/api/network/sync", headers=B).json()["version"]
        c.patch(f"/api/network/indicators/{x['id']}", json={"status": "revoked", "note": "Owner cleaned the site; kit removed"}, headers=C)
        assert any(ch["op"] == "remove" for ch in c.get(f"/api/network/sync?since={v2}", headers=B).json()["changes"])
        assert c.patch(f"/api/network/indicators/{x['id']}", json={"status": "verified", "note": ""}, headers=C).status_code == 422


def test_8_user_settings_trusted_contacts_and_blocking_choice():
    with TestClient(app) as c:
        p = c.get("/api/network/prefs", headers=A).json()
        assert p["auto_block_calls"] is False and p["shared_intel"] is True
        p = c.put("/api/network/prefs", json={"auto_block_calls": True, "email_scanning": True}, headers=A).json()
        assert p["auto_block_calls"] is True and p["email_scanning"] is False, "mailbox scanning needs OAuth - not offered yet"
        p = c.put("/api/network/prefs", json={"auto_block_calls": False}, headers=A).json()
        assert p["auto_block_calls"] is False
        c.post("/api/network/lists", json={"list": "trusted", "type": "phone", "value": "+971 50 777 0002"}, headers=A)
        assert c.post("/api/network/check", json={"type": "phone", "value": "0507770002"}, headers=A).json()["level"] == "none"
        lst = c.get("/api/network/lists", headers=A).json()
        assert c.delete(f"/api/network/lists/{lst[0]['id']}", headers=A).json()["deleted"]


def test_network_stats_are_real_counts_and_demo_is_separate():
    with TestClient(app) as c:
        c.post("/api/reports/demo/reset", headers=C)
        c.post("/api/reports/demo/load", headers=C)
        s = c.get("/api/network/stats", headers=A).json()
        assert s["demo"]["verified"] >= 1 and s["demo"]["campaigns"] >= 1
        assert c.get("/api/phone/lookup?number=%2B971000000101", headers=A).json()["community"]["demo"] is True
        assert "DEMO" in str(c.get("/api/phone/lookup?number=%2B971000000101", headers=A).json()["risk"]["findings"])
        c.post("/api/reports/demo/reset", headers=C)
        assert c.get("/api/network/stats", headers=A).json()["demo"]["verified"] == 0
