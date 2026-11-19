# WOLVE AI — ScamShield Security Command Center

> **Detect the threat. Understand the attack. Stop it before it spreads.**
> Abu Dhabi Police Hackathon · ScamShield AI track · MVP

WOLVE AI is a working cybersecurity platform that analyses emails, messages, links, phone numbers, IPs, images, documents and recordings for scams and attacks; correlates them with endpoint telemetry into incidents; and gives analysts a SOC-style console to respond. Every verdict shows **which evidence is a verified technical fact, which is a heuristic, which came from an external provider, and which is AI-generated**.

## Quick start (Windows)

```powershell
.\start.ps1
```

This installs dependencies on first run, starts the backend (http://localhost:8000, API docs at `/docs`) and the frontend (http://localhost:3000), and opens the browser.

Manual start:

```powershell
cd backend; python -m venv .venv; .venv\Scripts\pip install -r requirements.txt
.venv\Scripts\python -m uvicorn app.main:app --port 8000
# new terminal
cd frontend; npm install; npm run dev
```

Optional: copy `backend/.env.example` to `backend/.env` and set `ANTHROPIC_API_KEY` to enable Claude analysis. Without it, everything works in deterministic mode, and reports say AI is unavailable.

Tests: `cd backend; .venv\Scripts\python -m pytest tests -q` runs the full demo scenario end to end via the API.

## 3-minute demo script

1. **Command Center** shows status NORMAL and 4 *simulated* inventory devices.
2. Demo panel → **Run step 1**: the CEO-fraud email (look-alike sender, Reply-To to Gmail, SPF/DKIM/DMARC failing, urgent payment, lure image with QR code, "PDF" that is really a ZIP holding a `.pdf.js`) goes through the real email pipeline. Result: **99/100 Critical**, with an incident opened automatically.
3. Open the report: the employee warning banner, OCR text extracted from the image, the decoded QR URL, link-text-vs-real-destination mismatch, and attachment signature mismatch.
4. **Run step 2**: the analyst quarantines the email (the WOLVE record only; no live mailbox is connected, and the app says so).
5. **Run step 3**: *simulated* endpoint telemetry from `ALN-FIN-LT07` (outlook.exe → wscript.exe running the hidden script, then an outbound connection to the phishing domain). WOLVE matches the **script hash, filename and domain** from the email, correlates everything into the same incident, and escalates it to Critical.
6. **Run step 4** opens the threat graph: incident → email → indicators → endpoint events → device, with observed links drawn solid and inferred links dashed.
7. Incident page: timeline, assign an analyst, block the domain, escalate, resolve with a note. **Prevention Center → Audit log** shows every action.
8. The Command Center now shows CRITICAL, plus recommendations ("isolate ALN-FIN-LT07", "malicious domain not blocked", …).

Reset anytime: Settings → *Reset demo environment* (as the admin user).

## What is real, what is simulated, what is missing

See [docs/FEATURE_STATUS.md](docs/FEATURE_STATUS.md) for the full list. In short:

* **Real:** email/MIME parsing, header and auth checks, URL/domain heuristics, file signature/MIME/archive/macro/PDF/EXIF checks, OCR (RapidOCR), QR decoding (OpenCV), video frame sampling (ffmpeg), live DNS and IP geolocation (when enabled, shown with source and timestamp), risk engine, incidents, correlation, blocklist, audit log, role checks, consent-based agent heartbeat.
* **Simulated (always labelled):** seeded inventory devices and demo endpoint events.
* **Not implemented (shown as unavailable):** live M365/Gmail integration, speech-to-text, deepfake detection, dynamic sandbox, firewall/EDR enforcement, SSO.

Architecture and the future roadmap (Microsoft Graph, Gmail API, Windows agent, sandbox) are in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
