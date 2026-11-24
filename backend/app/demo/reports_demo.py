"""Fictional scam reports for demonstrations — DEMO DATA, FICTIONAL, NOT REAL INCIDENTS.

* Links use the reserved example.com / example.net / example.org domains.
* Phone numbers use the 00 area code, which no UAE mobile number uses, so none can belong to a real person.
* No real victims, people or organisations are described as scammers. Brand names appear only as what the
  fictional scammer *claimed* to be.
Several reports deliberately share a number, a domain or a message template so the "potentially related"
links can be demonstrated.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

LABEL = "DEMO DATA — FICTIONAL — NOT REAL INCIDENTS"

P1, P2, P3, P4, P5 = "+971 00 000 0101", "+971 00 000 0202", "+971 00 000 0303", "+971 00 000 0404", "+971 00 000 0505"

SALIK = "[Salik] Final reminder: an unpaid toll of AED 4.00 is pending. Pay before 11:59 PM today to avoid an AED 50 fine: https://salik-pay.example.com/settle"
PARCEL = "Your parcel is on hold at the hub. Pay the AED 6.50 redelivery fee within 24 hours: https://parcel-redeliver.example.org/track"
BANK_CALL = "Caller said he was from the bank security team, that the card was blocked, and asked for the code sent by SMS to unblock it."
JOB = "Hello! We are hiring part-time online staff. Earn AED 800 per day liking videos. Pay AED 300 registration to start: https://jobs-easy.example.net"
INVEST = "Guaranteed 30% monthly profit on our crypto trading platform. Deposit today, limited places: https://gold-returns.example.net/join"
POLICE = "Caller claimed to be from the police, said there is a fine and an arrest warrant, and demanded immediate transfer."

# (days ago, category, channel, phone, url, message, description, amount, emirate, status)
ROWS = [
    (58, "toll_fine", "sms", None, "https://salik-pay.example.com/settle", SALIK, "Opened the link, entered card details on the page.", 1850, "Dubai", "resolved"),
    (55, "toll_fine", "sms", None, "https://salik-pay.example.com/settle", SALIK, "Did not pay; reporting the message.", None, "Sharjah", "resolved"),
    (51, "toll_fine", "sms", None, "https://salik-pay.example.com/pay", SALIK.replace("4.00", "6.00"), "Card charged twice after paying the 'fine'.", 2400, "Abu Dhabi", "escalated"),
    (44, "toll_fine", "sms", None, "https://salik-pay.example.com/settle", SALIK, "Elderly parent received it; family member noticed.", None, "Ajman", "under_review"),
    (40, "delivery", "sms", None, "https://parcel-redeliver.example.org/track", PARCEL, "Paid the small fee, then saw a larger unknown charge.", 980, "Dubai", "escalated"),
    (37, "delivery", "sms", None, "https://parcel-redeliver.example.org/track", PARCEL, "Was not expecting any parcel.", None, "Al Ain", "resolved"),
    (33, "delivery", "whatsapp", P4, "https://parcel-redeliver.example.org/pay", PARCEL, "Same message arrived on WhatsApp from a number.", None, "Abu Dhabi", "under_review"),
    (30, "bank_impersonation", "call", P1, None, BANK_CALL, "Gave the code; AED 7,200 was transferred within minutes.", 7200, "Abu Dhabi", "escalated"),
    (27, "bank_impersonation", "call", P1, None, BANK_CALL, "Refused to give the code and hung up.", None, "Dubai", "resolved"),
    (24, "bank_impersonation", "call", P1, None, "Caller from the 'bank' said there was suspicious activity and asked me to approve the notification in the app.", "Approved the notification; AED 5,000 left the account.", 5000, "Sharjah", "under_review"),
    (21, "bank_impersonation", "call", P2, None, BANK_CALL, "Different number, same story about a blocked card.", None, "Ras Al Khaimah", "submitted"),
    (19, "job", "whatsapp", P3, "https://jobs-easy.example.net", JOB, "Paid AED 300 registration, then asked for more 'tasks' deposits.", 2100, "Dubai", "under_review"),
    (17, "job", "whatsapp", P3, "https://jobs-easy.example.net", JOB, "Recruiter stopped replying after the payment.", 300, "Sharjah", "submitted"),
    (15, "job", "social", None, "https://jobs-easy.example.net/apply", JOB, "Saw the advert on social media.", None, "Abu Dhabi", "submitted"),
    (13, "investment", "social", P5, "https://gold-returns.example.net/join", INVEST, "Deposited AED 15,000; withdrawals blocked behind a 'tax'.", 15000, "Dubai", "escalated"),
    (11, "investment", "whatsapp", P5, "https://gold-returns.example.net/join", INVEST, "Added to a group with fake profit screenshots.", 4000, "Abu Dhabi", "under_review"),
    (10, "government_impersonation", "call", P2, None, POLICE, "Told not to hang up or tell anyone.", None, "Fujairah", "submitted"),
    (8, "government_impersonation", "call", P2, None, POLICE, "Transferred money to 'cancel the warrant'.", 3500, "Dubai", "escalated"),
    (7, "shopping", "website", None, "https://cheap-phones.example.org", "Brand-new phones at 70% off, bank transfer only.", "Paid; nothing was delivered and the site disappeared.", 1600, "Sharjah", "submitted"),
    (6, "qr", "other", None, "https://parking-qr.example.com/pay", "QR sticker on a parking machine leading to a payment page.", "Scanned the QR code to pay for parking.", 120, "Abu Dhabi", "submitted"),
    (4, "toll_fine", "sms", None, "https://salik-pay.example.com/settle", SALIK, "Received it twice in one day.", None, "Dubai", "submitted"),
    (3, "romance", "social", None, None, "Online friend asked for money for a medical emergency abroad.", "Sent money twice before realising.", 6000, "Ajman", "under_review"),
    (2, "account_takeover", "sms", P4, None, "Your account login code is 4821. If this was not you, call us immediately.", "Called the number; was asked to read the code.", None, "Umm Al Quwain", "submitted"),
    (1, "bank_impersonation", "call", P1, None, BANK_CALL, "Same caller number as earlier reports.", None, "Abu Dhabi", "submitted"),
]


def rows(now: datetime | None = None) -> list[dict]:
    now = now or datetime.now(timezone.utc)
    out = []
    for i, (ago, cat, ch, phone, url, msg, desc, amount, emirate, status) in enumerate(ROWS, start=1):
        created = (now - timedelta(days=ago)).replace(hour=9 + i % 9, minute=(i * 7) % 60, second=0, microsecond=0)
        out.append({"category": cat, "channel": ch, "phone": phone, "url": url, "message": msg,
                    "description": f"{desc} [{LABEL}]", "amount_lost": amount, "currency": "AED", "emirate": emirate,
                    "status": status, "incident_date": created.date().isoformat(), "created_at": created})
    return out
