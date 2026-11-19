# WOLVE for iPhone

An Arabic iPhone app with two Apple extensions:
- **SMS filtering:** messages from unknown senders are checked **on the phone** and scams go to **Junk** automatically.
- **Call warning:** before you answer, iOS shows "⚠️ WOLVE: احتيال محتمل" under numbers reported as scams, or blocks them.

> Status: written on Windows and **not yet compiled**. Build it on the Mac with the steps below. The scam rules have unit tests built from real messages (⌘U).

## What you need
- A Mac with **Xcode 15 or newer**
- An Apple ID added in Xcode → Settings → Accounts. A free account can run the app on your own iPhone for 7 days; a paid Apple Developer account ($99/year) avoids that limit and is needed for TestFlight.
- An iPhone with iOS 17+, and a USB cable (or Wi-Fi pairing)
- [Homebrew](https://brew.sh), to install XcodeGen

## Build (about 10 minutes)
```bash
brew install xcodegen
cd mobile/ios
xcodegen                     # creates WolveShield.xcodeproj from project.yml
open WolveShield.xcodeproj
```
1. In Xcode, for each of the three targets (**WolveShield**, **MessageFilter**, **CallDirectory**) open *Signing & Capabilities*, choose your **Team**, and if Xcode complains, change the bundle IDs to something unique such as `com.yourname.wolve…`. If you change them, also update `appGroup` and `callDirectoryExtensionID` in `Shared/SharedStore.swift` and the App Group in all three targets.
2. Run the tests: Product → Test (⌘U). All of `ScamRulesTests` should pass.
3. Plug in the iPhone, select it as the run destination, and press Run (⌘R). On the phone, trust the developer in Settings → General → VPN & Device Management.

## Connect it to WOLVE
For the event use the **public HTTPS server** (see `docs/APP_STORE.md`); set `Shared/AppConfig.swift` → `defaultServer`.
For rehearsals on your Wi-Fi you can use the PC directly (plain HTTP is allowed only for local-network hosts):
`backend\.venv\Scripts\python -m uvicorn --app-dir backend app.main:app --host 0.0.0.0 --port 8000`, then server `http://<PC-IP>:8000`.
1. Web app → Settings → **Pair a device** → **Code for an iPhone** (8 letters, 15 minutes, single use).
2. iPhone app → **الإعدادات**: server address, the code, tick consent → **ربط الجوال**.
3. **الحماية** → **مزامنة قوائم الحماية**.

## Turn the protection on (on the iPhone)
- **Messages:** Settings → Apps → Messages → *Unknown & Spam* → *SMS Filtering* → **WOLVE**
- **Calls:** Settings → Apps → Phone → *Call Blocking & Identification* → turn on **WOLVE** (or the button in the app)

## Demo
1. In the WOLVE web app, Prevention Center → Blocklist → add the phone number you'll call from (type *phone*), or analyse a scam call from it in Call Guard.
2. In the iPhone app, press **مزامنة**. Call the iPhone from that number: the warning appears **before you answer**.
3. Send the iPhone the fake Salik text from a number **not in your contacts**: it lands in **Junk**.

## Limits (Apple's rules, not choices)
- Only messages from **unknown senders** are filtered; WOLVE never sees messages from your contacts.
- The extension has no internet access, so the phone uses rules synced from the server.
- Call warnings work for **exact numbers** synced from WOLVE (no prefix ranges, no real-time lookup). No app can hear the voice of a normal phone call — for that, use **Call Guard** with the call on speaker.
- Plain HTTP is allowed only to local-network hosts (`NSAllowsLocalNetworking`); everything else must be HTTPS.
- Publishing: see `docs/APP_STORE.md`. Live demo: `docs/LIVE_DEMO.md`.
