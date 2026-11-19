# WOLVE AI — Architecture

```
 Next.js 15 (TypeScript, Tailwind v4, Recharts, React Flow)        consent-based agent (agent/)
            │  REST + X-WOLVE-User                                        │ X-Device-Token
            ▼                                                             ▼
 FastAPI ─ routers: analyze · emails · endpoints/agent · incidents · response · dashboard · system
            │
            ├─ services/pipeline.py      orchestration per input type (email, message, url, ip, phone, file, media)
            │    ├─ email_analyzer       MIME parse, headers, sender consistency, SPF/DKIM/DMARC, HTML links
            │    ├─ text_analyzer        EN/AR social-engineering patterns + combination rules
            │    ├─ url_analyzer         structure, look-alikes, punycode, TLD/shortener, DNS (intel)
            │    ├─ file_analyzer        magic bytes, MIME/ext mismatch, ZIP/OOXML/PDF/OLE, EXIF, polyglots
            │    ├─ ocr                  Tesseract → RapidOCR → unavailable; OpenCV QR decoding
            │    ├─ network_intel        IP facts, ip-api geolocation, AbuseIPDB, phone calling codes
            │    └─ ai                   Claude structured assessment (optional, untrusted-content guarded)
            ├─ services/risk.py          Finding model, noisy-OR score, severity/confidence/classification
            ├─ services/store.py         persistence, auto-incidents, audit
            └─ services/endpoint_engine  event scoring + cross-source correlation
            │
 SQLAlchemy → SQLite (default) / PostgreSQL via WOLVE_DATABASE_URL
 storage/quarantine/*.quarantined   suspicious uploads stored inert, never executed or served
```

## Security design
* **No execution of uploads.** Files are read as bytes. Archives are listed in memory with entry and size caps, and are never extracted to disk. Media goes through ffprobe/ffmpeg in a temporary directory that is deleted afterwards.
* **Upload limits:** extension allowlist, size cap (`WOLVE_MAX_UPLOAD_MB`), sanitised filenames, real-type detection independent of the declared MIME type.
* **Prompt injection:** submitted content is wrapped in `<submitted_content>` and the system prompt tells the model it is data. AI weight in the score is capped.
* **Secrets** come from the environment or `backend/.env` only and are never sent to the browser.
* **Honest outputs:** missing providers are reported as "not configured"; every external result carries its source and timestamp; simulated data is flagged in the DB (`simulated`, `source='simulated'`, `demo`) and badged in the UI.

## Data model
`organizations, users, devices, endpoint_events, analyses (kind-discriminated; JSON report), indicators, blocklist, incidents, incident_events, response_actions, audit_logs, app_settings`.
Indicators are the join key for correlation. They come from analyses (sender, reply_to, recipient, link, attachment, attachment_inner) and from endpoint events (sha256, dest_ip, dest_domain, file_name, device_owner).

## Correlation rules
* **Observed:** an endpoint event shares an indicator value (hash, filename, domain, IP) with a prior analysis. The event joins that analysis's incident, and the incident escalates (to Critical when execution evidence exists).
* **Inferred:** the device owner is the recipient of a high-risk email, with no shared artefact. Shown as a dashed edge.
* An event with no prior evidence and a score of 60 or more opens its own endpoint incident.

## Roadmap after the hackathon
1. **Microsoft 365:** an Entra ID app registration with `Mail.Read` / `Mail.ReadWrite` (application permissions, admin consent). Graph change notifications (webhooks) on new mail feed `run_email`. Quarantine becomes a Graph `move` to a quarantine folder, and every action is logged.
2. **Google Workspace:** the Gmail API with domain-wide delegation, Pub/Sub `watch`, and label-based quarantine.
3. **Windows agent:** a signed Windows service that collects ETW/Sysmon process-creation and network-connect events, uses an offline queue, has tamper protection, and runs a local policy (e.g. block a script host spawned by Office). Enrolment uses per-device certificates instead of tokens. It stays scoped to security telemetry: no content capture.
4. **Sandbox:** an isolated detonation service (separate VM/container network, no host mounts, egress through a sinkhole) that WOLVE calls over a queue. Results become `verified` findings.
5. **Auth:** OIDC SSO (Entra ID) and per-organisation tenancy, replacing the demo identity header.
6. **Intel:** VirusTotal URL/hash, Google Safe Browsing, URLhaus, plus a WHOIS domain-age provider.
7. **Speech:** Whisper-class speech-to-text for call recordings; synthetic-speech detection only with a validated model.
