# Three Bees — Feature status

Legend: ✅ working · 🧪 simulated (flagged in the system; UI labels via Settings → Display) · ⛔ not implemented (UI says so)

## Core
| Feature | Status | Notes |
|---|---|---|
| Command Center dashboard | ✅ | Real backend data, 10 s refresh, dynamic recommendations, demo-data badge |
| Risk engine | ✅ | Noisy-OR over weighted findings, capped at 99; AI contribution capped at 30 points; severity/confidence/classification |
| Evidence-source separation | ✅ | Every finding tagged verified / heuristic / intel / AI |
| Claude AI assessment | ✅* | *Needs `ANTHROPIC_API_KEY`. Structured output, prompt-injection-hardened, server-side refusal fallback. Without a key, reports say AI is unavailable |
| Sign-in & roles | ✅ | Username + password (scrypt), 12 h bearer sessions, sign-out, password change; employee / analyst / admin enforced server-side. No SSO yet |
| Audit log | ✅ | All analyses, actions, settings, demo operations |
| Rate limiting | ✅ | In-memory, per client IP, on analysis endpoints |
| English / Arabic + RTL | ✅ | Arabic is the default; UI and report bodies (findings, reasons, advice) are translated server-side |

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
| Quarantine / release / mark safe / mark suspicious / report to IT / delete / export | ✅ on 3B records |
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
| Speech-to-text | ✅ offline faster-whisper (`small`), used by Call Guard |
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
| Consent-based agent (`agent/threeb_agent.py`): pairing code, heartbeat, live outbound connections with owning process, firewall/Defender posture, reversible 3B-named firewall blocks | ✅ (real firewall changes not yet tested on a spare machine; dry-run and rollback are tested) |
| Correlation: shared hash/filename/domain/IP (observed) and device owner = email recipient (inferred) | ✅ |
| Incident auto-creation, escalation on correlation | ✅ |
| Threat graph (React Flow), observed vs inferred edges | ✅ |
| Incident management: filter, assign, status, notes, resolve (note required), escalate | ✅ |
| Blocklist (domain/url/ip/hash), enforced in 3B analyses and endpoint scoring | ✅ (not pushed to a firewall or proxy, labelled "demo env") |
| IOC review (malicious/benign) | ✅ |
| Recommend endpoint isolation | ✅ recommendation only (no EDR/NAC control) |
| Escalation notifications (email/SMS/paging) | ⛔ (recorded in 3B only) |
| Dynamic malware sandbox | ⛔ (static analysis only; files are never executed) |

## Call Guard (voice scams)
| Feature | Status |
|---|---|
| Live call on speaker → laptop microphone, 8 s chunks, consent required, audio never stored | ✅ (tested with recordings; test live with your own microphone before a demo) |
| Recorded call upload (wav/mp3/m4a/webm…) | ✅ |
| Fact-check of caller claims: UAE time (±30 min), weekday, organisation in the local UAE directory, local authority calling from a foreign number | ✅ deterministic, Arabic and English speech |
| Tone measurements (speech rate, pitch movement, loudness, pauses) | ✅ weak signals only |
| Separating the caller's voice from the user's | ⛔ (user should stay quiet while the caller answers) |
| Online lookup of company names | ⛔ (local directory only; unknown names are "unverified", never "fake") |

## Phone protection
| Feature | Status |
|---|---|
| Server APIs: SMS classify, caller check, call-directory list, device pairing | ✅ tested |
| iPhone app with SMS filter + Call Directory extensions | ✅ written, ⚠️ not yet compiled (needs Xcode on a Mac) |
| Phone simulator page in the web app | ✅ |

## Call Guard additions (November 2026)
| Feature | Status |
|---|---|
| Red alarms with sound: code read out after a code request · request approved after an "approve the notification" request · any critical call | ✅ codes are masked in the stored transcript and on screen |
| Scammer's next step and "Ask the caller" questions | ✅ rule-based, shown as predictions |
| Call language choice (English / Arabic / auto) | ✅ a chosen language skips detection (≈2.5 s per 8 s chunk on a laptop CPU) |

## Scam reports and investigators
| Feature | Status | Notes |
|---|---|---|
| Report a Scam form (category, channel, number, link, message, description, date, amount, emirate, screenshot, contact) | ✅ | Reference `3B-UAE-YYYY-NNNNNN`; privacy acknowledgement required; says clearly it is **not** an official police complaint |
| Screenshot evidence | ✅ | PNG/JPG/WEBP checked by content (not extension), 5 MB max, stored inert, served only to investigators, SHA-256 recorded; OCR runs locally |
| Investigator dashboard `/reports` | ✅ | Totals, reports over time, by type, most-reported numbers and domains, filters and search; analyst/admin only (server-enforced) |
| Review: status changes, notes, timeline | ✅ | Every view, status change, note, evidence view and print is in the audit log |
| Potentially related reports | ✅ | Same phone number, same link host name, or ≥45 % word overlap; each link shows its method, score and explanation; worded as leads, never "confirmed network" |
| Printable incident summary | ✅ | Browser Print → Save as PDF (no server-side PDF library) |
| Demo data | 🧪 | **Load / Reset demo data** buttons: 24 fictional reports labelled `DEMO DATA — FICTIONAL — NOT REAL INCIDENTS`, example.com/.net/.org links, 00-prefix numbers; kept in a separate data mode and never mixed with submitted reports |
| Learn About Scams | ✅ | 12 scam types (English + Arabic) with warning signs, safety tips, what to do, fictional examples; 5 quiz questions |
| "Senior investigator" role | ⛔ | Roles are employee / analyst / admin |
| URLhaus / PhishTank lookups | ⛔ | Not wired yet; VirusTotal hash lookup exists when a key is configured |

## Measured accuracy (real run, not an estimate)
`backend/benchmarks/run_sms_benchmark.py` runs the SMS text rules on the public UCI SMS Spam Collection (5,574 messages,
SHA-256 checked). Latest run: at score ≥ 30, **precision 1.000, recall 0.048, false-positive rate 0.000** (36 of 747 spam
flagged, 0 of 4,827 legitimate messages flagged). Spam ≠ scam: most of that dataset's spam is advertising, which 3B is
not built to flag, and the data is English from 2012. Full table, confusion matrix and errors:
[`backend/benchmarks/results/SMS_BENCHMARK.md`](../backend/benchmarks/results/SMS_BENCHMARK.md).
