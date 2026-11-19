# WOLVE AI — Feature status

Legend: ✅ working · 🧪 simulated (labelled in UI) · ⛔ not implemented (UI says so)

## Core
| Feature | Status | Notes |
|---|---|---|
| Command Center dashboard | ✅ | Real backend data, 10 s refresh, dynamic recommendations, demo-data badge |
| Risk engine | ✅ | Noisy-OR over weighted findings, capped at 99; AI contribution capped at 30 points; severity/confidence/classification |
| Evidence-source separation | ✅ | Every finding tagged verified / heuristic / intel / AI |
| Claude AI assessment | ✅* | *Needs `ANTHROPIC_API_KEY`. Structured output, prompt-injection-hardened, server-side refusal fallback. Without a key, reports say AI is unavailable |
| Roles & authorisation | ✅ | employee / analyst / admin enforced server-side. Identity is a header-selected seeded user (**not** production auth) |
| Audit log | ✅ | All analyses, actions, settings, demo operations |
| Rate limiting | ✅ | In-memory, per client IP, on analysis endpoints |
| English / Arabic + RTL | ✅ partial | Navigation, headings and labels are translated and the RTL layout works; report bodies stay English |

## Email security
| Feature | Status |
|---|---|
| .eml upload / raw paste / body-only paste | ✅ |
| From / Reply-To / Return-Path / display-name / Message-ID checks | ✅ |
| Look-alike and impersonation of the organisation's domain, brand impersonation | ✅ |
| SPF / DKIM / DMARC from Authentication-Results | ✅ (reports "unknown" when headers are missing) |
| URL extraction (text and HTML), link-text-vs-real-destination mismatch | ✅ |
| Attachments: signature vs extension vs MIME, double extensions, archives, macros, PDF JS | ✅ |
| Inline images: OCR plus social-engineering analysis of the OCR text, QR decoding and URL analysis | ✅ |
| Quarantine / release / mark safe / mark suspicious / report to IT / delete / export | ✅ on WOLVE records |
| Outlook .msg parsing | ⛔ (asks the user to save as .eml) |
| Live Microsoft 365 / Google Workspace mailbox actions | ⛔ (architecture documented) |

## Scam analyzer / multimedia
| Feature | Status |
|---|---|
| SMS, WhatsApp, chat, call-transcript text (EN and AR patterns) | ✅ |
| Auto-detection of input type (IP / URL / domain / phone / email / message) | ✅ |
| Phone numbers: calling-code region, satellite/premium ranges, spoofing caveats | ✅ |
| Images and screenshots: EXIF, appended-data (polyglot) detection, OCR, QR | ✅ |
| Audio/video metadata (ffprobe), synthetic-tool encoder tags | ✅ |
| Video: frame sampling, then OCR and QR on frames | ✅ |
| Speech-to-text | ⛔ (a user-supplied transcript is analysed instead) |
| Deepfake / synthetic voice detection | ⛔ (never claimed) |

## Network intelligence
| Feature | Status |
|---|---|
| IP validity, private/reserved/documentation ranges | ✅ |
| Live DNS (A/AAAA/MX/NS/TXT, NXDOMAIN) with source and timestamp | ✅ (toggle in Settings) |
| Approximate geolocation, ASN, ISP, proxy/hosting flags (ip-api.com) with source and timestamp | ✅ (toggle in Settings) |
| AbuseIPDB reputation | ✅* (*needs key; otherwise "not configured") |
| URL structural analysis: punycode, homoglyphs, look-alikes, TLDs, shorteners, `@` trick | ✅ |
| URL reputation (Safe Browsing / VirusTotal URL) | ⛔ |

## Endpoint, correlation, response
| Feature | Status |
|---|---|
| Device inventory | ✅ (seeded devices are 🧪) |
| Endpoint event ingestion API (device-token auth) | ✅ |
| Event scoring: Office→script-host chains, encoded PowerShell, temp-path exec, C2 ports, blocked destinations | ✅ |
| Demo endpoint events | 🧪 |
| Consent-based agent (`agent/wolve_agent.py`): enrolment, heartbeat, system info | ✅ (no process or network monitoring yet) |
| Correlation: shared hash/filename/domain/IP (observed) and device owner = email recipient (inferred) | ✅ |
| Incident auto-creation, escalation on correlation | ✅ |
| Threat graph (React Flow), observed vs inferred edges | ✅ |
| Incident management: filter, assign, status, notes, resolve (note required), escalate | ✅ |
| Blocklist (domain/url/ip/hash), enforced in WOLVE analyses and endpoint scoring | ✅ (not pushed to a firewall or proxy, labelled "demo env") |
| IOC review (malicious/benign) | ✅ |
| Recommend endpoint isolation | ✅ recommendation only (no EDR/NAC control) |
| Escalation notifications (email/SMS/paging) | ⛔ (recorded in WOLVE only) |
| Dynamic malware sandbox | ⛔ (static analysis only; files are never executed) |
