# Three Bees (3B) — Scam & Cyber-Threat Shield

> **Detect the scam. Prove it with facts. Stop it before it spreads.**
> Abu Dhabi Police Hackathon · MVP

Three Bees (3B) is a working scam-prevention and cybersecurity platform. It has three parts:

- **A security center (web app).** It analyses emails, SMS/WhatsApp messages, links, phone numbers, IPs, images, documents, recordings and **live phone calls**.
- **A consent-based Windows agent.** It shows which outside servers the laptop is talking to and where they are.
- **An iPhone app.** It files scam SMS into Junk and warns about scam numbers **before you answer**.

Every verdict shows which evidence is a **verified fact**, which is a **heuristic**, which came from an **external provider**, and which is **AI-generated**. The interface opens in Arabic by default, and reports are translated.

---

## 1. The problem

Scams in the UAE reach people through every channel: fake Salik and parcel-fee SMS, calls from "the police" or "the bank" asking for an OTP, CEO-fraud emails, and malicious attachments. Victims usually have seconds to decide, and existing tools fail them in three ways:

- **Single-channel.** A spam filter sees only email, and a caller-ID app sees only the number. Nobody connects the email, the link and the laptop that opened it.
- **Opaque.** A tool says "dangerous 87%" but cannot explain *why*. That leaves nothing an employee can learn from, or an analyst can act on.
- **Weak against voice scams.** The most damaging scams happen live on the phone, where nothing checks what the caller says.

## 2. Our solution

| Module | What it does |
|---|---|
| **Scam Analyzer** | Paste a message, link, number or IP; type is auto-detected. Arabic and English social-engineering patterns (urgency, OTP requests, impersonation, payment pressure), look-alike domains, punycode, shorteners, calling-code regions |
| **Email Security** | `.eml` upload or paste: header and sender consistency, SPF/DKIM/DMARC, link-text-vs-real-destination, attachment signature vs extension, OCR of inline images, QR decoding |
| **File & Image Forensics** | Magic bytes vs extension, archives listed in memory, macros, PDF JavaScript, EXIF, polyglot files, OCR, QR, video frame sampling. **Uploads are never executed** |
| **Call Guard** | Listens (with consent) through the laptop microphone while a call is on speaker. Speech is transcribed **offline** and the caller's **claims are fact-checked**: the time and day in the UAE, whether the company they name is a known UAE entity, and whether a "local authority" is calling from a foreign number. Also reports tone measurements (speech rate, pitch, pauses) as weak signals |
| **Phone protection (iPhone)** | SMS filter extension moves scam texts from unknown senders to Junk on the device; a Call Directory extension labels scam numbers before you answer |
| **Endpoints** | Consent-based agent: live outbound connections with process, remote organisation and approximate location; Windows Firewall/Defender posture; optional, reversible firewall blocks |
| **Incidents & Threat Graph** | Findings from email, files and endpoints are correlated on shared indicators (hash, filename, domain, IP) into one incident, drawn as a graph (observed = solid, inferred = dashed) |
| **Prevention Center** | Blocklist, IOC review, recommendations, full audit log |

## 3. Architecture

```
 Next.js 15 web app (Arabic RTL default)     iPhone app (SwiftUI + 2 extensions)     Windows agent (Python)
            │  HTTPS, bearer session                      │ device token                       │ device token
            ▼                                              ▼                                    ▼
 FastAPI ── routers: auth · analyze · emails · calls · mobile · endpoints · incidents · response · dashboard
            │
            ├─ pipeline            one orchestrator per input type
            │    ├─ email / text / url / file analyzers   (deterministic, explainable rules)
            │    ├─ ocr + qr          RapidOCR (ONNX) + OpenCV
            │    ├─ voice             ffmpeg → faster-whisper (offline) + acoustic features
            │    ├─ claims            fact-check engine (UAE clock, weekday, entity directory, number origin)
            │    ├─ network_intel     IP facts, opt-in geolocation/DNS, calling codes
            │    └─ ai (optional)     Claude structured assessment, weight-capped, injection-guarded
            ├─ risk                noisy-OR scoring of weighted findings → severity / confidence
            ├─ store + correlation incidents, indicators, audit
            └─ i18n_ar             Arabic translation of every report
            │
 SQLAlchemy → SQLite (default) or PostgreSQL
```

Presentation (architecture, model choices, privacy design): [docs/presentation/ThreeBees_3B.pptx](docs/presentation/ThreeBees_3B.pptx)

More detail: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) · privacy: [docs/PRIVACY.md](docs/PRIVACY.md) · what works: [docs/FEATURE_STATUS.md](docs/FEATURE_STATUS.md) · security audit: [docs/AUDIT_REPORT.md](docs/AUDIT_REPORT.md)

## 4. Technical choices and why

| Choice | Why |
|---|---|
| **Deterministic rules first, AI second** | A police-facing tool has to explain itself. Each rule produces a *Finding* with a title, an explanation, evidence and a source. The optional LLM can add at most 30 points and is labelled "AI". |
| **Noisy-OR risk score** | Independent pieces of evidence combine naturally (two medium signals score higher than one) without ever reaching 100. Severity thresholds are 30, 60 and 80. |
| **Fact-checking claims instead of "voice deepfake detection"** | No free, validated model reliably detects synthetic voices on a phone line. A caller who lies about checkable facts (the time in Abu Dhabi, "I'm from the police" from a German number, a company that doesn't exist) can be **proven** wrong. Tone measurements are kept, but only as weak signals. |
| **Offline speech-to-text (faster-whisper "small", int8 CPU)** | Call audio never leaves the laptop. "small" handles Arabic well enough and transcribes an 8-second chunk in about 4 seconds on a laptop CPU. |
| **RapidOCR + OpenCV** | They install with pip (no system packages), work offline, and read the Arabic/English text and QR codes that scammers hide in images. |
| **FastAPI + SQLite** | One process, zero setup, and the full API is typed and documented at `/docs`. SQLAlchemy lets the same code run on PostgreSQL in production. |
| **Next.js + Tailwind** | A fast, responsive UI. Arabic is the default and the layout is fully RTL. |
| **Native iOS extensions (IdentityLookup, CallKit)** | They are Apple's only supported way to filter SMS and label calls. Scoring runs on the phone, and messages are never uploaded. |

## 5. Privacy by design

- **Consent everywhere.** Call Guard, the agent and phone pairing each require an explicit consent tick. The agent is visible, never silent, and uninstalls cleanly.
- **Call audio is never stored.** It is transcribed in memory and discarded; only the transcript and findings are saved.
- **External lookups are off by default.** IP geolocation and DNS need an admin to opt in, and private IPs are never sent out.
- **SMS filtering happens on the iPhone.** The message text never reaches the server.
- **No secrets in the browser.** Passwords are stored as scrypt hashes, session tokens as SHA-256, and sessions expire after 12 hours. Pairing codes are single-use.
- **Uploads are inert.** They are read as bytes, stored with a `.quarantined` suffix, and never executed or served back.

## 6. Trade-offs, what we left out, and what we'd do next

**Trade-offs we made**
- **The claim directory is a local list of about 30 UAE entities.** The check is free and deterministic, but a real company missing from the list shows as "unverified" (never "fake").
- **Call Guard hears both people through one microphone.** It cannot tell the voices apart, so the user should stay quiet while the caller answers a check question.
- **The time check uses a 30-minute tolerance.** That avoids false accusations when someone rounds the time.
- **SQLite and in-memory rate limiting.** They are simple for a demo; production needs PostgreSQL and Redis.

**Left out (shown as unavailable in the app, never faked)**
- Live Microsoft 365 / Gmail mailbox integration.
- Dynamic malware sandbox.
- Deepfake-voice detection.
- SSO.
- URL reputation feeds (VirusTotal, Safe Browsing).

**With more time**
- Connect the entity check to an official UAE business registry.
- Add speaker separation (diarisation) so only the caller's claims are checked.
- Build a signed Windows service with ETW telemetry.
- Add Microsoft Graph mail integration.
- Publish the iPhone app through TestFlight.
- Run a proper evaluation set of real (anonymised) UAE scam messages to measure precision and recall.

## 7. Build and run

### Requirements
- Python 3.11 or newer (tested on 3.14)
- Node.js 20 or newer
- ffmpeg on the PATH (needed for Call Guard and media)
- About 1 GB of free disk for the speech model, which downloads on first use

### Windows (one command)
```powershell
.\start.ps1
```
On first run this installs everything and opens http://localhost:3000. The API runs at http://localhost:8000 (docs at `/docs`).
Passwords for the seeded demo users are generated on first start in `backend/demo-credentials.txt` (git-ignored). You can change them in Settings → My account.

### Manual (Windows, macOS, Linux)
```bash
cd backend
python -m venv .venv
# Windows: .venv\Scripts\activate    macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
python -m uvicorn app.main:app --port 8000

# second terminal
cd frontend
npm install
npm run dev          # http://localhost:3000
```

### Optional configuration
Copy `backend/.env.example` to `backend/.env`.
- `ANTHROPIC_API_KEY` turns on the AI assessment. Without it everything works in deterministic mode, and reports say so.
- `THREEB_STT_MODEL` picks the speech model (default `small`).

### Tests
```bash
cd backend
python -m pytest tests -q        # 39 tests: end-to-end scenario, auth, agent safety, Arabic reports, claim checks
cd ../frontend
npx tsc --noEmit && npm run lint
```

### Windows agent (optional)
See `agent/`. You create a pairing code in Settings → Pair a device, then run:
```powershell
agent\install_agent.ps1 -DryRun -PairCode <CODE>
```
Use `-DryRun` first to see exactly what it will do.

### iPhone app (optional, needs a Mac with Xcode)
See [mobile/ios/README.md](mobile/ios/README.md).

## 8. Demo script (5 minutes)

1. **Scam Analyzer:** paste the fake Salik SMS. It is rated **Critical, Phishing (81/100)**. Each reason is explained in Arabic: the Salik brand on an unrelated domain, the payment request, and the fine threat.
2. **Email Security → Demo panel:** run the CEO-fraud scenario.
   - The email scores 99/100 Critical: spoofed sender, failing DMARC, a QR code in an image, and a "PDF" that is really a script inside a ZIP.
   - The simulated endpoint then runs that script. 3B matches the hash and domain and escalates the same incident.
   - The threat graph shows the whole chain.
3. **Call Guard:** a teammate calls from another phone and plays a scammer ("I'm from Abu Dhabi Police…").
   - We ask "What time is it there?" and they answer wrongly.
   - 3B shows **✗ wrong UAE time** and **✗ local authority calling from a foreign number**, and rates the call as a scam with the verified facts listed.
4. **Endpoints:** live connections from this laptop with the owning organisation of each remote server.

Full script and backup plan: [docs/DEMO.md](docs/DEMO.md), [docs/LIVE_DEMO.md](docs/LIVE_DEMO.md).

## 9. What is real and what is simulated

- **Real:** everything listed in sections 2–5, running on real input.
- **Simulated (always labelled "simulated" in the UI):** the seeded inventory devices and the demo endpoint events used in the email scenario.
- **Not tested on real hardware yet:**
  - the iPhone build (the code is written and has unit tests, but has not been compiled in Xcode);
  - Docker deployment;
  - real firewall blocking (dry-run and rollback are tested).

## Team

| Name |
|---|
| محمد بلال الاحمد |
| سيف مصطفى درويش |
| حمزة عبد الباسط |

## Repository layout
```
backend/   FastAPI app, analyzers, risk engine, tests
frontend/  Next.js security center
agent/     consent-based Windows agent + installer
mobile/    iPhone app (XcodeGen project)
deploy/    Docker + Caddy (HTTPS) for a hosted demo
docs/      architecture, privacy, feature status, audit, demo scripts
```
