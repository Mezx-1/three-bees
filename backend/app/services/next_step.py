"""Predict the scammer's likely next move from the tactics already seen.

Scams follow well-known scripts (pretext → request → use). Given the findings so far, this
names the step that usually comes next so the person can refuse it before it is asked.
It is a prediction from the pattern, never a fact about this particular sender.
"""
from __future__ import annotations

from .risk import Finding

NOTE = "Predicted from the scam pattern, not a certainty."

# (id, condition on (titles, tags), step, why, advice)
_RULES = [
    ("code_used",
     lambda t, g: "A code may have been said during the call" in t,
     "They will use the code straight away to log in or approve a payment — then may call back asking for “one more code to cancel it”.",
     "A one-time code is all they need to take over the card or account.",
     "Call your bank now on the number printed on your card and block the card. Never give a second code."),
    ("ask_code",
     lambda t, g: ("Card or account 'problem' pretext" in t or "Authority impersonation cues" in t)
                  and "Request for one-time password (OTP) / verification code" not in t,
     "They will ask for the code sent to you by SMS, or your card number and CVV, “to verify” or “to stop the transaction”.",
     "An account “problem” from a bank or official caller is the usual set-up before asking for a code.",
     "No bank or government body asks for a code by phone or message. Hang up and call the official number yourself."),
    ("use_code",
     lambda t, g: "Request for one-time password (OTP) / verification code" in t and "A code may have been said during the call" not in t,
     "Once they have the code they will log in or approve a payment immediately, often while keeping you on the line.",
     "They asked for a code — the code is the key to your account.",
     "Do not read out any code. If you already did, call your bank at once and block the card."),
    ("fee",
     lambda t, g: "Too-good-to-be-true reward" in t,
     "They will ask for a small “processing”, “customs” or “delivery” fee — or your card details — to release the prize.",
     "Fake prizes are always followed by a fee or a request for card details.",
     "A real prize never costs money to collect. Do not pay or share card details."),
    ("pay_page",
     lambda t, g: "Parcel / delivery lure" in t,
     "A link to pay a small redelivery fee; the page then asks for your card details and the code from your bank.",
     "Delivery problems are the most common pretext for card-stealing pages in the UAE.",
     "Check the parcel only in the courier's official app or website, typed in yourself."),
    ("fine",
     lambda t, g: "Threat of negative consequences" in t and ("Authority impersonation cues" in t or "impersonation" in g),
     "They will demand immediate payment of a “fine” — by transfer, gift cards or crypto — and tell you not to hang up or tell anyone.",
     "Threats from someone claiming authority are meant to rush you into paying.",
     "Police and courts never collect fines by phone. End the call and check through the official app or 8002626 (Aman)."),
    ("login",
     lambda t, g: "Request for credentials / login" in t or "HTML attachment contains a login form" in t,
     "The page or caller will ask for your username and password, then the code from your phone — after that they take over the account.",
     "Asking you to “verify” or “update” your account leads to a fake login page.",
     "Open the official app or website yourself. Never sign in from a link or attachment."),
    ("remote",
     lambda t, g: "Request to install software / remote access" in t,
     "After you install the app they will control your phone or computer and open your banking app while you watch.",
     "Remote-access apps give the caller full control of the device.",
     "Do not install anything a caller asks for. If you did, disconnect from the internet and uninstall it."),
    ("malware",
     lambda t, g: "malware_delivery" in g,
     "If the attachment is opened it may run code that steals saved passwords or lets the attacker in remotely.",
     "The file is built to run code, not to be read.",
     "Do not open it. If it was opened, disconnect the device and report it to IT."),
    ("transfer",
     lambda t, g: "Payment / money transfer request" in t and ("bec" in g or "Authority impersonation cues" in t),
     "They will push for the transfer to be made today, ask you to keep it confidential and to use new bank details.",
     "Payment requests with urgency or secrecy are how invoice and CEO fraud work.",
     "Confirm any payment or new bank details by calling a number you already know."),
]


def predict(findings: list[Finding], score: int, limit: int = 2) -> dict | None:
    """The scammer's likely next steps, or None when the result is low risk."""
    if score < 30:
        return None
    titles = {f.title for f in findings}
    tags = {t for f in findings for t in f.tags}
    items = [{"id": rid, "step": step, "why": why, "advice": advice}
             for rid, cond, step, why, advice in _RULES if cond(titles, tags)]
    if not items:
        return None
    return {"note": NOTE, "items": items[:limit]}
