# Publishing 3B on iPhone (TestFlight → App Store)

## Timeline to the competition (24 Nov)
| When | Step | Who |
|---|---|---|
| **Today** | Enrol in the Apple Developer Program (developer.apple.com/programs → individual, $99). Approval is usually 24–48 h. | You (payment) |
| Today | Rent a server + domain and deploy 3B with HTTPS (below) | You (accounts), then follow the steps |
| When approved | Build on the Mac, upload to App Store Connect, **TestFlight internal testing** (your team, no review, works within minutes) | You |
| Same day | **TestFlight external testing** with a **public link / QR code** for the audience. Needs a short beta review (usually within ~1 day). | You |
| In parallel | Submit to the **App Store** (review usually 1–3 days, may ask for changes). Don't make the demo depend on it. | You |

## 1. Server (must be public HTTPS — App Review and the audience can't reach your laptop)
Any small Linux VPS works (e.g. 2 vCPU / 4 GB RAM, Ubuntu) plus a domain name.
```bash
# on the server
git clone <your repo> threebees && cd threebees
cp deploy/.env.example deploy/.env      # set THREEB_DOMAIN=your.domain
docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d --build
docker compose -f deploy/docker-compose.yml exec backend cat /data/demo-credentials.txt   # sign-in passwords
```
Caddy obtains the HTTPS certificate automatically once the domain's DNS points at the server. Check `https://your.domain/privacy` and sign in. Change the generated passwords in Settings → My account.
> These deployment files have **not been run yet** (Docker isn't available on the development PC). Test them on the server before the event.

## 2. App configuration
- `mobile/ios/Shared/AppConfig.swift` → `defaultServer = "https://your.domain"`
- In Xcode, set your Team on all three targets. If `ae.threebees.app` is taken, change the bundle IDs (and the App Group) consistently.
- Version: `MARKETING_VERSION` / `CURRENT_PROJECT_VERSION` in `project.yml` (increase the build number for each upload).

## 3. Upload
Xcode → select *Any iOS Device* → Product → **Archive** → Distribute App → **App Store Connect** → Upload.
Then, in App Store Connect → your app → **TestFlight**: add internal testers. For the audience, create an **External** group, enable the **Public Link** and show it as a QR code.

## 4. App Store listing (copy-ready)
- **Name:** 3B – حماية من الاحتيال (if the name is taken: "Three Bees")
- **Subtitle:** فلترة رسائل ومكالمات الاحتيال
- **Category:** Utilities. **Age rating:** 4+
- **Description (AR):** يحميك 3B من رسائل ومكالمات الاحتيال. يفحص رسائل المرسلين المجهولين على جوالك نفسه وينقل رسائل الاحتيال — مثل رسوم سالك المزيّفة وطرود الجمارك وطلبات رمز التحقق — إلى مجلد غير المرغوب تلقائياً. ويُظهر تحذيراً قبل الرد على الأرقام المُبلّغ عنها. لا يقرأ رسائل جهات الاتصال ولا يستمع إلى المكالمات.
- **Description (EN):** 3B protects you from scam texts and calls. It checks messages from unknown senders on your iPhone and files scams — fake toll fines, parcel fees, OTP requests — in Junk automatically, and warns you about reported numbers before you answer. It never reads messages from your contacts and cannot listen to calls.
- **Privacy Policy URL:** `https://your.domain/privacy`
- **App Privacy:** Data collected: *Other User Content* (only text the user checks manually), not linked to identity, not used for tracking. No tracking.
- **Screenshots:** 6.7" and 6.1" iPhone screenshots of the Protection, Check and Settings tabs (take them in the Simulator: ⌘S).

## 5. Notes for the App Review team (paste into "App Review Information")
> 3B is an SMS filter (IdentityLookup message filter extension) and Call Directory extension.
> To test filtering: Settings → Apps → Messages → Unknown & Spam → SMS Filtering → 3B, then send an SMS from a number that is not in Contacts, e.g. "Your parcel is on hold, pay the customs fee within 24 hours: http://parcel-fee.top". It appears under Junk.
> The app works offline without pairing. Optional pairing: open Settings and enter code **XXXXXXXX** (valid 7 days).

Create that 7-day code in the 3B web app's API docs (`https://your.domain/docs` → `POST /api/pairing-codes` with `{"purpose":"phone","minutes":10080}`) while signed in as an analyst. Reviewers may also reject the submission if the server is down, so keep it running during review.

## Known App Review risks
- **The extension must work:** Apple tests SMS filtering. The rules are in `Shared/ScamRules.swift` and tested by `ScamRulesTests`.
- **Login walls:** the app must not *require* an account to be useful. It doesn't: filtering works without pairing.
- **Data deletion:** "فك الربط وحذف بيانات هذا الجوال" in Settings deletes the device on the server (required).
- **iMessage:** Apple's filter only receives **SMS/MMS from unknown senders**. iMessages (like scams sent from an email address) are not passed to filter apps.
