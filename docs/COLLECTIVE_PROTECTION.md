# Caller ID, phone intelligence and the collective protection network

## Status at a glance
| Feature | Status | Tested |
|---|---|---|
| Number lookup: E.164 format, country + flag, dialling code, line type, original network (libphonenumber, offline, free) | Done | `test_collective.py` |
| Caller name | **Not available.** No licensed caller-name source; 3B never guesses. | — |
| Verified business name | Only when an admin records it **with a source** | API test |
| Community number reports (10 categories), one per person per 24 h, 10/day limit, Turnstile, moderation, hidden reporters | Done | yes |
| Shared indicators: phone, email, email domain, domain, URL, payment ID (IBAN) | Done | yes |
| Status ladder reported → suspicious → verified, revoke, allow-list, review expiry (30 / 90 days) | Done | yes |
| Appeals / false-positive reports, paused warnings while under appeal | Done | yes |
| Incremental sync (`/api/network/sync?since=`), hashes only, removals, audit trail | Done | yes |
| Cross-identifier correlation: same identifier, near-identical template, similar domain, nearby number | Done | yes |
| Campaign graph with explained edges (`/threat-network`) | Done | API test + browser |
| Message fingerprints vs. reported campaigns (in every analysis) | Done | yes |
| Protection settings, personal blocked / trusted lists, protection events | Done | yes |
| iOS Call Directory receives verified (block) / suspicious (label) numbers | Server side done (`/api/mobile/call-directory`) | Server test only; **not run on an iPhone** |
| Android call screening app | **Not built.** Architecture below | — |
| Gmail / mailbox scanning via OAuth | **Not built.** Needs Google OAuth app verification for a restricted Gmail scope | — |
| External caller-ID / reputation phone APIs | **Not integrated.** Pricing and terms not checked by us | — |
| Firestore for phone intelligence | Not used: the existing 3B database already holds it (no duplicate database) | — |

## Rules that protect innocent people
* A single report **never** shares or blocks anything. 3 independent reporters (or 2 + a high-risk analysis) → *suspicious*
  (warning only). Only an analyst, or a listing by a trusted reputation provider, makes it *verified* (block-eligible).
* Verifying, revoking or allow-listing requires a written reason; every change is in the audit trail (`indicator_events`).
* An appeal pauses an unverified warning for everyone until an analyst decides. Upheld → allow-listed and removed from devices.
* Review dates: suspicious 30 days, verified 90 days. When they pass without re-review, the indicator drops back to *reported*
  and is removed from devices.
* Trusted contacts are never warned about for that user.
* Devices receive only `sha256("<type>:<normalised value>")`, a category and a level — never reporters, report text or evidence.
* "Similar template" and "nearby number" are shown as leads. 3B never claims two identifiers belong to the same person.
* Demo data (`data_mode = demo`) is fictional, labelled DEMO everywhere and uses numbers that are invalid in the UAE plan
  (`+971 00 000 0XXX`), so no real subscriber can be affected.

## Phones — what a website can and cannot do
A website **cannot see or block incoming cellular calls**. Automatic protection needs a native app:

* **iOS** — The repo's `mobile/ios` app has a **Call Directory extension**. iOS asks the extension for a list of numbers to
  label or block *in advance*; there is **no live lookup during a call**. The server endpoint `/api/mobile/call-directory` now
  includes verified (block) and suspicious (label) shared numbers. The app must be built with Xcode on a Mac and enabled by the
  user in Settings → Phone → Call Blocking & Identification. Not tested on a device.
* **Android** (to build) — a `CallScreeningService` (Android 10+, user must make the app the call-screening app) that checks
  the incoming number against the locally synced hash list (offline) and optionally `/api/mobile/caller-check`, then shows a
  warning or rejects the call **only if the user enabled auto-block and the number is verified**. Sync with
  `/api/network/sync?since=<version>` using the device token (`X-Device-Token`) from pairing. No contacts or call-log access is
  needed for this design.

## Email scanning (not built)
Design: Gmail API with the read-only scope via OAuth, never a password; analyse new messages with the existing email pipeline;
warn only, no delete/forward/modify without an explicit per-action choice. Requires Google's OAuth verification for a
restricted scope before real users can connect, so it is switched off in Protection Settings and the server refuses to enable it.

## Phone data providers (not integrated)
Possible sources for carrier / line type / reputation include commercial lookup APIs (for example Twilio Lookup, Numverify,
Telesign). **We did not check their current prices, free limits, UAE coverage or terms**, and nothing paid was enabled. Check
those before integrating; caller-name data must come only from a provider licensed to supply it. 3B does not scrape Truecaller
or any unauthorised database.

## API
* `GET /api/phone/lookup?number=` · `POST /api/phone/report` · `GET/PATCH /api/phone/reports` (analyst) · `PATCH /api/phone/numbers/{n}` (admin)
* `GET /api/network/sync?since=` · `POST /api/network/check` · `GET/POST/PATCH /api/network/indicators` (analyst)
* `POST /api/network/appeals` · `GET/PATCH /api/network/appeals` (analyst) · `GET/PUT /api/network/prefs` · `/api/network/lists` · `/api/network/events`
* `GET /api/network/campaigns?mode=` (analyst) · `GET /api/network/stats`
