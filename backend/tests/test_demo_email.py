"""The demo scam email in docs/demo and its harmless phishing attachment."""
from email.message import EmailMessage
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app
from app.services import file_analyzer

DEMO = Path(__file__).resolve().parents[2] / "docs" / "demo"
ATTACHMENT = "Account_Verification_Form.pdf.html"


def test_attachment_is_flagged():
    data = (DEMO / ATTACHMENT).read_bytes()
    findings, info, _ = file_analyzer.analyze_file(data, ATTACHMENT, "application/pdf")
    titles = {f.title for f in findings}
    assert "Document name hides a web page" in titles
    assert "HTML attachment contains a login form" in titles


def test_demo_email_with_attachment_is_critical():
    body = (DEMO / "scam-email.txt").read_text(encoding="utf-8").split("\n", 2)[2]
    m = EmailMessage()
    m["From"] = "Emirates Security Department <emirates.security.alert@gmail.com>"
    m["To"] = "demo.user@gmail.com"
    m["Subject"] = "URGENT: Your Bank Account Will Be Suspended"
    m.set_content(body)
    m.add_attachment((DEMO / ATTACHMENT).read_bytes(), maintype="application", subtype="pdf", filename=ATTACHMENT)
    with TestClient(app) as c:
        r = c.post("/api/emails/analyze", files={"file": ("scam.eml", bytes(m), "message/rfc822")}, headers={"X-3B-User": "omar.analyst"})
    assert r.status_code == 200, r.text
    assert r.json()["severity"] == "critical"


def test_email_pasted_as_one_line_is_still_analysed():
    one_line = ("From: Emirates Security Department Subject: URGENT: Your Bank Account Will Be Suspended Dear Customer, "
                "We have detected unusual activity on your bank account. To avoid account suspension, please verify your account "
                "immediately. Transaction amount: AED 4,850 Verification code: 739201 You are required to complete the verification "
                "process within 30 minutes. Failure to do so may result in temporary account suspension. Thank you, Security Department")
    with TestClient(app) as c:
        r = c.post("/api/emails/analyze", data={"raw": one_line}, headers={"X-3B-User": "omar.analyst"})
    assert r.status_code == 200, r.text
    assert r.json()["severity"] == "critical"
