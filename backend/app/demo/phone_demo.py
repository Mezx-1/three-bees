"""Fictional phone-intelligence demo data (data_mode='demo', clearly labelled DEMO everywhere).

Numbers use the +971 00 000 0XXX placeholder range, which is NOT valid in the UAE numbering plan, so no
real subscriber can be affected. Reporters are fictional keys.
"""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy.orm import Session

from ..models import PhoneReport, utcnow
from ..services import collective, phone_intel

# (number, category, description, distinct fictional reporters, days ago of first report)
ROWS = [
    ("+971 00 000 0101", "banking", "Caller said the card was blocked and asked for the SMS code. [DEMO]", 8, 30),
    ("+971 00 000 0202", "government", "Caller claimed to be the police and demanded a transfer to cancel a warrant. [DEMO]", 4, 21),
    ("+971 00 000 0303", "job", "WhatsApp job offer asking a registration fee. [DEMO]", 2, 19),
    ("+971 00 000 0404", "delivery", "Parcel fee message, then a call asking for the code. [DEMO]", 1, 3),
    ("+971 00 000 0505", "investment", "Guaranteed-profit trading group. [DEMO]", 3, 13),
]


def load(db: Session) -> int:
    now = utcnow()
    n = 0
    for number, cat, desc, reporters, ago in ROWS:
        num = phone_intel.e164(number)
        row = phone_intel.intel_row(db, num, "demo", create=True)
        for i in range(reporters):
            key = collective.reporter_hash(f"demo-reporter-{number}-{i}")
            db.add(PhoneReport(e164=num, data_mode="demo", category=cat, description=desc, reporter_key=key, status="accepted",
                               created_at=now - timedelta(days=ago - i)))
            collective.record_report(db, "phone", num, reporter=f"demo-reporter-{number}-{i}", category=cat, mode="demo")
            n += 1
        db.flush()
        phone_intel.refresh_counts(db, row)
        if reporters >= 8:
            row.review_status = "confirmed_scam"
            ind = collective.get_or_create(db, "phone", num, mode="demo", category=cat)
            collective.set_status(db, ind, "verified", "demo-analyst", "DEMO: analyst confirmed after reviewing 8 reports")
    return n
