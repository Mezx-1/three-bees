"""Questions that expose a scam caller.

Based on who the caller claims to be and what they have asked for so far, suggest up to three
questions the person can ask. Each one has a real answer that a genuine caller gives easily and a
scammer usually cannot — or a request (call back on the official number) that a genuine caller accepts.
Questions already answered in the call (for example the time) are not suggested again.
"""
from __future__ import annotations

import re

BANKS = {"Emirates NBD", "ADCB", "First Abu Dhabi Bank", "Mashreq", "Dubai Islamic Bank", "ADIB", "RAKBANK", "Central Bank of the UAE"}
OFFICIAL = {"Abu Dhabi Police", "Dubai Police", "Ministry of Interior", "ICP (Identity & Citizenship)", "RTA", "Salik", "TAMM", "UAE Pass"}
COURIERS = {"Emirates Post", "Aramex", "DHL", "FedEx", "Amazon", "Noon"}
TELECOMS = {"e& (Etisalat)", "du"}

# id -> (question, what to listen for)
Q = {
    "time": ("What time is it where you are right now?",
             "Someone really in the UAE answers at once. 3B checks the answer against the real UAE time."),
    "company": ("Which company are you from, and what is its official number?",
                "3B checks the name against known UAE organisations. Look the number up yourself — never use one they give."),
    "callback": ("Can I hang up and call you back on the number printed on my card?",
                 "A real bank always says yes. A scammer says it is urgent or that the line will be lost."),
    "card_digits": ("What are the last four digits of my card?",
                    "Your bank can see this. A scammer usually can't — and never read your own digits to them."),
    "why_approve": ("Why would approving a payment stop a payment?",
                    "A real bank blocks a suspicious payment itself. It never asks you to approve one."),
    "why_code": ("Why do you need a code that the bank itself sent to me?",
                 "Banks never ask for the code they send. Any answer here is a reason to hang up."),
    "badge": ("What is your full name and badge number? I will call the station to confirm.",
              "Real officers give these and let you call back. Scammers threaten or hurry you."),
    "pay_official": ("Can I pay this through the official app instead?",
                     "Real fines can always be paid in the official app or website. Scammers insist on a transfer or gift cards."),
    "tracking": ("What is the tracking number? I will check it in the courier's app.",
                 "A real courier gives it and the app shows the parcel. A scammer pushes a link or a fee."),
    "prize_fee": ("Why do I have to pay anything to receive a prize?",
                  "Real prizes never cost money to collect."),
    "install": ("Why would a company need control of my phone?",
                "No bank or official body asks you to install remote-access apps."),
    "day": ("What day is it today?",
            "Another fact 3B can check against the real UAE date."),
}


def suggest(transcript: str, claims: list[dict], matched_patterns: dict, limit: int = 3) -> list[dict]:
    """Up to `limit` questions, most revealing first."""
    text = (transcript or "").lower()
    asked = {c["type"] for c in claims}
    orgs = {c["said"] for c in claims if c["type"] == "organisation" and c.get("ok")}
    keys = set(matched_patterns or {})
    bank = bool(orgs & BANKS) or bool(re.search(r"\bbank\b|بنك|مصرف", text))
    official = bool(orgs & OFFICIAL) or bool(re.search(r"\bpolice\b|ministry|court|شرطة|الشرطة|وزارة|النيابة|محكمة", text))
    courier = bool(orgs & COURIERS) or "delivery" in keys
    order: list[str] = []
    if "approval" in keys:
        order.append("why_approve")
    if "otp" in keys:
        order.append("why_code")
    if bank:
        order += ["callback", "card_digits"]
    if official:
        order += ["badge", "pay_official"]
    if courier:
        order.append("tracking")
    if "reward" in keys:
        order.append("prize_fee")
    if "remote_access" in keys:
        order.append("install")
    if "time" not in asked:
        order.append("time")
    if "organisation" not in asked and not (orgs or bank or official or courier):
        order.append("company")
    if not bank and not official:
        order.append("callback")
    if "day" not in asked:
        order.append("day")
    out, seen = [], set()
    for qid in order:
        if qid in seen:
            continue
        seen.add(qid)
        q, listen = Q[qid]
        out.append({"id": qid, "question": q, "listen_for": listen})
        if len(out) == limit:
            break
    return out


def default_questions() -> list[dict]:
    """Before anything is heard: the three questions that work against most scam calls."""
    return [{"id": i, "question": Q[i][0], "listen_for": Q[i][1]} for i in ("time", "company", "callback")]
