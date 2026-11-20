# 3B — post-implementation security audit (after commit d6848c2)

Only what was actually executed is marked "tested". No firewall rule was created and no startup task was installed on the primary computer.

## 1. Security issues found
| # | Area | Issue | Severity |
|---|---|---|---|
| A1 | Agent firewall | `netsh` success was judged by the English text "Ok." — it fails on Arabic/other-language Windows, and real failures could be misread | High |
| A2 | Agent firewall | Blocking twice created duplicate rules | Medium |
| A3 | Agent firewall | If the outbound rule succeeded and the inbound failed, a half-applied block was left behind | Medium |
| A4 | Agent firewall | No check for administrator rights, no refusal of private/loopback/special addresses (could cut a device off its LAN or from 3B) | High |
| A5 | API | Block commands needed no explicit confirmation flag; duplicate commands could pile up; no way to inspect 3B-created rules | Medium |
| A6 | Agent posture | Firewall state was parsed from localised `netsh` text, so it returned "could not read" on non-English Windows | Medium |
| A7 | Agent | A permission failure while reading connections would crash the cycle silently instead of being reported | Medium |
| A8 | Detection accuracy | Every inbound connection to a non-standard port was rated "medium" (false positives for normal apps), while inbound connections to RDP/SSH/SMB were *not* flagged | Medium |
| A9 | Privacy | ip-api.com lookups were **on by default**, with no consent; provider failures were silent | High |
| A10 | Installer | Assigned to PowerShell's reserved `$args`; ignored failures of Python/pip/enrolment (could register a broken task); no admin check for `-AllowResponse`; did not list its changes before asking | Medium |
| A11 | Auth (not fixed — MVP design) | Web identity is a user name sent in a header (`X-3B-User`), so anyone who can reach the API can claim to be the admin; agent enrolment relies on it | **Critical for production** |
| A12 | Transport (not fixed) | HTTP only, no TLS; device token is stored in plain text in `agent/.threeb_agent.json` | High for production |
| A13 | Rate limiting (partial) | In-memory and only on analysis endpoints; agent endpoints are not limited | Low |

Reviewed and found safe: every command the agent runs is a fixed argument list (no shell, no string concatenation). IP values are validated with `ipaddress` before they reach `netsh`. Rule names always use the `3B-block-` prefix, so unrelated firewall rules cannot be touched. Uploaded files are never executed. Logs contain no command lines, tokens or message contents.

## 2. Issues fixed (this commit)
A1–A10 are fixed:
- `_exec` judges success by the exit code.
- Firewall status and rule listing use `Get-NetFirewallProfile` / `Get-NetFirewallRule` JSON, which works in any Windows language.
- Duplicate rules are detected before creating, and a half-applied block is rolled back.
- Administrator rights are checked.
- Private, loopback, link-local, multicast, reserved and documentation addresses are refused (both on the server and in the agent).
- Block commands require `confirm: true`, duplicates are ignored, and a read-only `list_rules` command exists.
- Permission errors are reported to the UI.
- Inbound connections to remote-access services are high; other inbound connections are informational.
- External lookups are off by default and need recorded consent; provider failures are labelled.
- The installer was rewritten with a change list, `-DryRun`, an admin check, exit-code checks, `-Uninstall -Purge`, and no duplicate tasks.

A11–A13 are documented as next priorities.

## 3. Arabic pages reviewed (in the browser, Arabic mode, with demo data)
Command Center, Scam Analyzer, Call Guard, Phone Protection, Email Security, File & Image Forensics, Endpoint Protection (including live connections), Network Intelligence, Threat Graph, Incidents list, Incident detail, Prevention Center (all tabs), Settings, Analysis report. Every page was scanned for remaining English text, and the report and phone pages were also checked visually. Fixed during review:
- the "Show technical details" button
- capability notes on the Forensics page
- simulated event titles
- the confidence wording (عالية/متوسطة/منخفضة)
- the file-size and file-drop messages
- the demo event titles

## 4. Remaining translation issues
- React Flow's built-in screen-reader instructions on the graph page are English (not visible on screen).
- User data stays in its original language: email subjects, sample messages, program names, ISP names.
- AI explanations (when a key is set) come back in English.
- Charts keep a left-to-right time axis, a deliberate choice.

## 5. Privacy improvements
See `docs/PRIVACY.md`. In summary: lookups are opt-in with recorded consent, only public IPs are ever sent, failures are explicit, Settings explains exactly what is transmitted, legitimate SMS messages are not stored, and call audio is never saved or uploaded.

## 6. Endpoint monitoring accuracy (tested on this Windows 11 laptop, read-only)
- **Connections:** 23 live connections, all attributed to a process, without administrator rights. Remote and local addresses are separate fields, and LAN addresses are labelled "Local network" without any lookup.
- **Listening ports:** 14, shown only as "open ports", never as intrusions.
- **Firewall status:** read via `Get-NetFirewallProfile` — domain, private and public all on. This matches the system.
- **Defender status:** service, antivirus and real-time protection on; signature age 0 days; last quick scan 2 days ago.
- **3B firewall rules:** none exist.
- **Location:** geography is labelled "approximate … not of a person" everywhere it appears.
- **Suspicious events:** each one carries its findings, with evidence and reasons. Ordinary process starts (score below 25) are not stored.

## 7. Tests executed
- `pytest`: **29 passed**. They cover:
  - the demo scenario end to end
  - live agent monitoring
  - posture events
  - command safety (unconfirmed, private and duplicate commands)
  - external-lookup consent
  - Arabic coverage, with zero untranslated report strings
  - the Arabic HTML export
  - Call Guard (real speech-to-text on the sample recording, consent required, live sessions, blocked numbers)
  - mobile SMS and caller checks using the user's real examples
  - agent firewall logic with the system mocked: refusals, admin check, idempotency, rollback, only 3B rules touched, unknown commands rejected
- `tsc --noEmit`: passes. ESLint: 0 errors.
- The installer was syntax-checked with the PowerShell parser, and `-DryRun` was run (it changed nothing and created no task).
- **Not tested:** real firewall blocking (by design — needs an isolated Windows VM), the installer's real install, and live microphone capture in Call Guard.

## 8. Simulated features
Seeded inventory devices, demo endpoint events, the demo email scenario, and the Phone Protection page (it simulates the phone apps; the analysis behind it is real).

## 9. Fully functional
- Email/message/URL/IP/phone/file analysis.
- OCR and QR reading.
- Risk engine, incidents and correlation.
- Threat graph and blocklist.
- Live connection monitoring.
- Posture checks.
- Firewall command pipeline (logic tested; real execution needs an administrator agent).
- Call Guard: offline speech-to-text, tone measurement, number checks.
- Mobile API.
- Arabic interface and reports.
- Opt-in geolocation.

## 10. Recommended next priority
1. **Real authentication** (A11): login with passwords or SSO, signed sessions, per-device enrolment codes. This blocks any deployment beyond a demo.
2. TLS for the API and agent.
3. The native Android app (CallScreeningService + SMS), or the iOS app if a Mac is available.
