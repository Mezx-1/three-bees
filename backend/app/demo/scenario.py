"""Safe, repeatable demo scenario.

Everything generated here is harmless test data:
  * the "malicious" attachment is a ZIP whose inner .js file contains only a comment — no code
  * the attacker infrastructure uses the IANA documentation IP range 203.0.113.0/24 (non-routable)
  * attacker domains use fictional names on parked-style TLDs
Simulated endpoint events are flagged `simulated=True` and labelled everywhere in the UI.
"""
from __future__ import annotations

import hashlib
import io
import zipfile
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

ORG_NAME = "Al Noor Logistics"
ORG_DOMAIN = "alnoorlogistics.ae"
VICTIM = {"name": "Sara Ahmed", "email": "sara.ahmed@alnoorlogistics.ae", "device": "ALN-FIN-LT07"}
ATTACKER_DOMAIN = "alnoor-logistics-portal.top"
ATTACKER_URL = f"http://verify.{ATTACKER_DOMAIN}/secure/login.php?acct=finance&session=8f2a"
ATTACKER_IP = "203.0.113.45"
INNER_SCRIPT_NAME = "Invoice_Q4_2026.pdf.js"
INNER_SCRIPT = (b"// WOLVE AI demo file - HARMLESS.\r\n"
                b"// This file contains no executable payload. It exists only so the analyser can\r\n"
                b"// detect a double-extension script hidden inside a mislabelled archive.\r\n")
INNER_SHA256 = hashlib.sha256(INNER_SCRIPT).hexdigest()


def _font(size: int):
    from PIL import ImageFont

    for name in ("arialbd.ttf", "arial.ttf", "DejaVuSans-Bold.ttf", "DejaVuSans.ttf"):
        try:
            return ImageFont.truetype(name, size)
        except Exception:
            continue
    try:
        return ImageFont.load_default(size=size)
    except TypeError:
        return ImageFont.load_default()


def make_lure_image(url: str = ATTACKER_URL) -> bytes:
    """Fake 'mailbox verification' banner with a QR code pointing to the phishing URL."""
    import cv2
    import numpy as np
    from PIL import Image, ImageDraw

    W, H = 1000, 420
    img = Image.new("RGB", (W, H), (245, 247, 250))
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, W, 70], fill=(0, 82, 155))
    d.text((30, 18), "Microsoft 365  |  Mailbox Security Center", font=_font(30), fill=(255, 255, 255))
    d.text((30, 100), "ACCOUNT VERIFICATION REQUIRED", font=_font(34), fill=(200, 30, 30))
    lines = ["Your mailbox will be suspended within 24 hours.", "Verify your account immediately to avoid losing access.",
             "Scan the QR code and enter your password and OTP code.", "IT Support Team"]
    for i, ln in enumerate(lines):
        d.text((30, 160 + i * 48), ln, font=_font(26), fill=(30, 30, 30))
    enc = cv2.QRCodeEncoder.create()
    qr = enc.encode(url)
    qr = np.where(qr > 0, 255, 0).astype("uint8")
    qr_img = Image.fromarray(qr).convert("RGB").resize((260, 260), Image.NEAREST)
    padded = Image.new("RGB", (300, 300), (255, 255, 255))
    padded.paste(qr_img, (20, 20))
    img.paste(padded, (W - 320, 95))
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()


def make_disguised_attachment() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(INNER_SCRIPT_NAME, INNER_SCRIPT)
        z.writestr("README-WOLVE-DEMO.txt", "Harmless WOLVE AI hackathon demo archive.")
    return buf.getvalue()


def make_phishing_eml() -> bytes:
    msg = EmailMessage()
    msg["From"] = '"Khalid Al Mansoori (CEO) - Al Noor Logistics" <ceo@alnoor-logistlcs.co>'
    msg["Reply-To"] = "khalid.mansoori.office@gmail.com"
    msg["To"] = f"{VICTIM['name']} <{VICTIM['email']}>"
    msg["Subject"] = "URGENT: Confidential payment + mailbox verification required today"
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain="mail-relay7.bulkmailer.xyz")
    msg["Return-Path"] = "<bounce-7731@bulkmailer.xyz>"
    msg["Received"] = f"from mail-relay7.bulkmailer.xyz ([{ATTACKER_IP}]) by mx.{ORG_DOMAIN} with ESMTP id 4F2A9; {formatdate(localtime=True)}"
    msg["Authentication-Results"] = (f"mx.{ORG_DOMAIN}; spf=fail smtp.mailfrom=bulkmailer.xyz; dkim=none; "
                                     "dmarc=fail (p=none) header.from=alnoor-logistlcs.co")
    msg["X-Mailer"] = "PHPMailer 5.2.1"
    text = (
        "Dear Employee,\n\n"
        "I am in a meeting and can't talk. I need you to process an urgent wire transfer of AED 185,000 to our new supplier today. "
        "The bank details have changed - use the new IBAN in the attached invoice. Keep this confidential and do not discuss it with anyone until the deal is announced.\n\n"
        "Also, IT reports your mailbox will be suspended within 24 hours. Verify your account immediately here: "
        f"https://portal.alnoorlogistics.ae/verify\n\n"
        "Khalid Al Mansoori\nChief Executive Officer\n"
    )
    html = (
        "<html><body style='font-family:Arial'>"
        "<p>Dear Employee,</p>"
        "<p>I am in a meeting and can't talk. I need you to process an <b>urgent wire transfer of AED 185,000</b> to our new supplier today. "
        "The bank details have changed &ndash; use the new IBAN in the attached invoice. <b>Keep this confidential</b> and do not discuss it with anyone until the deal is announced.</p>"
        "<p>Also, IT reports your mailbox will be suspended within 24 hours. Verify your account immediately here: "
        f"<a href='{ATTACKER_URL}'>https://portal.alnoorlogistics.ae/verify</a></p>"
        "<p><img src='cid:lure1' alt='Mailbox notice'></p>"
        "<p>Khalid Al Mansoori<br>Chief Executive Officer</p></body></html>"
    )
    msg.set_content(text)
    msg.add_alternative(html, subtype="html")
    msg.get_payload()[1].add_related(make_lure_image(), maintype="image", subtype="png", cid="<lure1>", filename="mailbox_notice.png")
    msg.add_attachment(make_disguised_attachment(), maintype="application", subtype="pdf", filename="Invoice_Q4_2026.pdf")
    return bytes(msg)


def make_legit_eml() -> bytes:
    msg = EmailMessage()
    msg["From"] = "HR Team <hr@alnoorlogistics.ae>"
    msg["To"] = f"{VICTIM['name']} <{VICTIM['email']}>"
    msg["Subject"] = "Team lunch on Thursday"
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=ORG_DOMAIN)
    msg["Authentication-Results"] = f"mx.{ORG_DOMAIN}; spf=pass smtp.mailfrom={ORG_DOMAIN}; dkim=pass header.d={ORG_DOMAIN}; dmarc=pass"
    msg.set_content("Hi Sara,\n\nWe're having a team lunch this Thursday at 1pm in the main meeting room. Let us know about any dietary needs.\n\nThanks,\nHR")
    return bytes(msg)


SAMPLE_MESSAGES = {
    "smishing_delivery": {"channel": "sms", "text": "Emirates Post: Your parcel is on hold due to unpaid customs fee of AED 12.50. Pay within 24 hours or it will be returned: http://emiratespost-redelivery.top/pay"},
    "otp_vishing": {"channel": "call", "text": "Caller: Hello, this is the Abu Dhabi Police financial crimes unit. Your bank account has been used in money laundering and will be blocked. To verify your identity, please tell me the 6-digit verification code we just sent to your phone. Do not tell anyone about this call, it is confidential."},
    "whatsapp_job": {"channel": "whatsapp", "text": "Congratulations! You have been selected for a part-time job, earn AED 1500 daily. Guaranteed profit. Send your details and pay a small registration fee via crypto (USDT). Contact +882 1234 5678"},
    "arabic_bank": {"channel": "sms", "text": "عزيزي العميل، سيتم إيقاف بطاقتك البنكية. يرجى تحديث بياناتك فورا عبر الرابط وإدخال رمز التحقق: http://adcb-secure-update.xyz/ar"},
}


def endpoint_events() -> list[dict]:
    """The simulated post-click activity on the victim's laptop."""
    return [
        {"event_type": "process", "title": f"wscript.exe executed {INNER_SCRIPT_NAME}",
         "details": {"process_name": "wscript.exe", "parent_process": "outlook.exe",
                     "command_line": f'"C:\\Windows\\System32\\wscript.exe" "C:\\Users\\sara.ahmed\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.Outlook\\X7Q2\\{INNER_SCRIPT_NAME}"',
                     "path": f"C:\\Users\\sara.ahmed\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.Outlook\\X7Q2\\{INNER_SCRIPT_NAME}",
                     "file_name": INNER_SCRIPT_NAME, "sha256": INNER_SHA256, "user": "sara.ahmed"}},
        {"event_type": "network_connection", "title": f"Outbound HTTP connection to verify.{ATTACKER_DOMAIN}",
         "details": {"process_name": "wscript.exe", "dest_ip": ATTACKER_IP, "dest_domain": f"verify.{ATTACKER_DOMAIN}", "dest_port": 8081, "protocol": "tcp"}},
    ]
