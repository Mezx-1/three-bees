# WOLVE phone protection — architecture

The server side is built and tested (`/api/mobile/*`). The **iPhone app** source is in `mobile/ios` (SwiftUI app + SMS Filter + Call Directory extensions, XcodeGen project). It was written on Windows and has **not been compiled yet** — build it on a Mac following `mobile/ios/README.md`. The Android app is not built. The web page **Phone Protection** simulates the phone apps using the real API.

## What each platform allows
| Goal | iPhone (iOS) | Android |
|---|---|---|
| Move scam SMS to spam automatically | ✅ **SMS Filter Extension** (IdentityLookup). iOS passes each message from an **unknown sender** to the extension, which can ask the WOLVE server (`POST /api/mobile/sms/classify`) and answer *junk / promotion / transaction*. iOS then files it in the Junk folder. The user enables it once in Settings → Messages → Unknown & Spam. | ✅ SMS broadcast receiver (`RECEIVE_SMS`) or the default-SMS-app role; the app classifies and moves or flags the message. |
| Read all messages / messages from contacts | ❌ Not allowed by Apple | ✅ With permission |
| Warn before answering an unknown number | ✅ **Call Directory Extension**: labels such as "⚠️ WOLVE: likely scam" appear on the incoming-call screen, or the number is blocked. The list is synced from `GET /api/mobile/call-directory`. iOS 18 also has **Live Caller ID Lookup** for real-time server checks (needs a privacy-preserving PIR server). | ✅ **CallScreeningService** (Android 10+): calls `GET /api/mobile/caller-check` before the phone rings, then shows a warning or rejects the call. |
| Analyse the caller's voice during a normal call | ❌ No app can access cellular call audio | ❌ Not for normal apps |
| Analyse the voice with the call on speaker | ✅ Use **Call Guard** on a computer or tablet next to the phone | ✅ Same |

The warning before answering is based **on the number only**: registration country, satellite/premium ranges, the WOLVE blocklist and numbers seen in earlier scam reports. Caller ID can be spoofed.

## API
- `POST /api/mobile/sms/classify` `{sender, body}` → `{action: junk|allow, risk_score, classification, reasons[], advice[], stored}`
- `GET /api/mobile/caller-check?number=` → `{warn, level: none|caution|danger, label, reasons[], advice, note}`
- `GET /api/mobile/call-directory` → `{entries: [{number, label, block}], prefix_warnings: [...]}`

Authentication: the phone app's device token (`X-Device-Token`). Send `X-WOLVE-Lang: ar` for Arabic labels.

## What's needed to build the apps
- **iOS:** a Mac with Xcode, an Apple Developer account ($99/year) for the extensions, and a test iPhone.
- **Android:** Android Studio and an Android phone; no paid account is needed for testing.
