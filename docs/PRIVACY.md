# 3B — Privacy and external data

## External lookups (off by default)
External lookups are **disabled by default**. They run only when an **administrator switches them on in Settings and confirms a consent dialog**. That consent is recorded with the person and time, and switching the feature off clears it. A database that had lookups switched on before consent was introduced counts as off until someone consents.

| Provider | Used for | What is sent | Never sent | Notes |
|---|---|---|---|---|
| ip-api.com (free tier) | Approximate country/city, network owner (ISP/ASN), proxy and hosting flags | **Public** IP addresses from monitored connections and analyses | Private/LAN/loopback addresses (labelled "Local network" locally), message contents, files, user names | Plain HTTP (the free tier has no HTTPS), so queried IPs are visible on the network path. Limit: 15 batch requests/minute. Location describes the network operator, not a person. |
| System DNS resolver | Checking that domains in analysed links exist | Domain names from submitted links | Everything else | Uses whatever DNS server the computer is configured with |
| AbuseIPDB / VirusTotal | Reputation (optional) | IP / file hash | Files are never uploaded | Only when an API key is configured |
| Claude API | AI opinion (optional) | Text of the item being analysed | — | Only when `ANTHROPIC_API_KEY` is set and AI is enabled |

**Failures are reported openly.** If the provider is unreachable or rate-limits 3B, each affected connection shows "Origin lookup failed", with the reason, instead of an empty or invented location. Results are cached for 24 hours, and every result shows its source and lookup time.

## Endpoint agent
The agent collects connection metadata (program, process ID, local and remote address, port, direction and state), the starts of suspicious processes, and Firewall/Defender status. Full command lines are collected **only** for script hosts and LOLBins (PowerShell, cmd, wscript, mshta…), because other programs' command lines can contain personal data. It never captures traffic contents, screens, keystrokes, files, browsing, passwords or calls. The device token is stored in `agent/.threeb_agent.json`; anyone who can read that file can impersonate the device.

## Calls and phone protection
- **Call Guard:** call audio is transcribed **on this computer** (faster-whisper) and is **never saved or uploaded**. Only the transcript and analysis are stored. It requires the user to confirm they are part of the call. It cannot intercept phone calls; it only hears what the microphone picks up, or a recording the user uploads.
- **Phone protection (SMS):** legitimate messages are **not stored**. Only messages classified as scams are kept as evidence.
