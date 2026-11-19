"""Arabic coverage: every display string the API returns for the demo flows must be translated."""
import os
import re
import tempfile

_tmp = tempfile.mkdtemp()
os.environ.setdefault("WOLVE_DATABASE_URL", f"sqlite:///{_tmp}/ar.db".replace("\\", "/"))
os.environ.setdefault("WOLVE_UPLOAD_DIR", _tmp)
os.environ["WOLVE_EXTERNAL_LOOKUPS"] = "false"
os.environ["ANTHROPIC_API_KEY"] = ""

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.demo import scenario  # noqa: E402
from app.i18n_ar import DISPLAY_KEYS  # noqa: E402
from app.main import app  # noqa: E402

AR = {"X-WOLVE-User": "omar.analyst", "X-WOLVE-Lang": "ar"}
ADMIN_AR = {"X-WOLVE-User": "aisha.admin", "X-WOLVE-Lang": "ar"}
# English that is allowed to remain: product/protocol names, IDs, hosts, file names, quoted data.
ALLOWED = re.compile(r"WOLVE|SPF|DKIM|DMARC|OTP|QR|PDF|ZIP|URL|IP|DNS|HTTPS?|VBA|OLE|JavaScript|PowerShell|Windows|Defender|"
                     r"[\w.-]+\.(exe|js|pdf|png|eml|top|co|ae|com|xyz)\b|[\w.+-]+@[\w.-]+|INC-\w+|ANL-\w+|DEV-\w+|\d")


def english_words(s: str) -> list[str]:
    s = re.sub(r"«[^»]*»|\"[^\"]*\"|'[^']*'|\([^)]*\)", " ", s)  # quoted data
    s = ALLOWED.sub(" ", s)
    return re.findall(r"[A-Za-z]{3,}(?:\s+[A-Za-z]{3,}){2,}", s)  # 3+ consecutive English words


def collect(obj, key=None, out=None):
    out = [] if out is None else out
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in ("body_preview", "text_analysis", "email", "ocr", "ocr_text", "info", "intel", "media", "file", "frame_ocr_text", "assessment"):
                continue
            collect(v, k, out)
    elif isinstance(obj, list):
        for v in obj:
            collect(v, key, out)
    elif isinstance(obj, str) and key in DISPLAY_KEYS and key not in ("title", "evidence", "label"):
        if english_words(obj):
            out.append(obj)
    return out


@pytest.fixture(scope="module")
def c():
    with TestClient(app) as client:
        client.post("/api/demo/reset", headers=ADMIN_AR)
        yield client


def test_reports_are_arabic(c):
    payloads = []
    payloads.append(c.post("/api/emails/analyze", files={"file": ("p.eml", scenario.make_phishing_eml(), "message/rfc822")}, headers=AR).json())
    payloads.append(c.post("/api/emails/analyze", files={"file": ("l.eml", scenario.make_legit_eml(), "message/rfc822")}, headers=AR).json())
    for s in scenario.SAMPLE_MESSAGES.values():
        payloads.append(c.post("/api/analyze/message", json={"text": s["text"], "channel": s["channel"]}, headers=AR).json())
    payloads.append(c.post("/api/analyze/file", files={"file": ("lure.png", scenario.make_lure_image(), "image/png")}, headers=AR).json())
    payloads.append(c.post("/api/analyze/file", files={"file": ("Invoice_Q4_2026.pdf", scenario.make_disguised_attachment(), "application/pdf")}, headers=AR).json())
    for v in ("http://login-paypa1.top/verify?acct=1", "8.8.8.8", "203.0.113.45", "+97150123456", "+8821234567"):
        payloads.append(c.post("/api/analyze/auto", json={"text": v}, headers=AR).json())
    payloads.append(c.post("/api/demo/scenario/endpoint", headers=AR).json())
    for inc in c.get("/api/incidents", headers=AR).json():
        payloads.append(c.get(f"/api/incidents/{inc['id']}", headers=AR).json())
    payloads.append(c.get("/api/dashboard", headers=AR).json())
    payloads.append(c.post(f"/api/emails/{payloads[0]['id']}/action", json={"action": "quarantine"}, headers=AR).json())
    payloads.append(c.post("/api/blocklist", json={"type": "domain", "value": "phish-test.top"}, headers=AR).json())
    # error messages
    payloads.append(c.post("/api/analyze/ip", json={"value": "999.1.1.1"}, headers=AR).json())
    payloads.append(c.put("/api/settings", json={"ai_enabled": False}, headers=AR).json())

    leftovers = sorted({s for p in payloads for s in collect(p)})
    assert not leftovers, "Untranslated:\n" + "\n".join(leftovers)
    rep = payloads[0]["report"]
    assert re.search(r"[؀-ۿ]", rep["classification"]) and re.search(r"[؀-ۿ]", rep["findings"][0]["title"])


def test_enums_untouched_and_english_default(c):
    a = c.post("/api/analyze/message", json={"text": "URGENT verify your account password now http://x-login.top", "channel": "sms"}, headers=AR).json()
    assert a["severity"] in ("low", "medium", "high", "critical") and a["kind"] == "message" and a["status"] in ("new", "suspicious")
    en = c.get(f"/api/analyses/{a['id']}", headers={"X-WOLVE-User": "omar.analyst"}).json()
    assert not re.search(r"[؀-ۿ]", en["report"]["classification"])


def test_html_export_arabic(c):
    a = c.get("/api/analyses?kind=email", headers=AR).json()[0]
    r = c.get(f"/api/analyses/{a['id']}/export?format=html", headers=AR)
    assert r.status_code == 200 and 'dir="rtl"' in r.text and "تقرير WOLVE" in r.text
