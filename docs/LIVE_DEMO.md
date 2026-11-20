# Live demo on stage — script, rehearsal and backup plan

## Equipment
- **Presenter iPhone** with 3B installed (TestFlight), paired and synced, SMS Filtering + Call Blocking enabled.
- **"Scammer" phone** (a second SIM): its number must **not** be in the presenter's contacts, and **iMessage must be OFF** on it (Settings → Apps → Messages → iMessage off), so it sends a real **SMS**. An Android phone is ideal.
- A laptop with the 3B web app open (signed in as the analyst) on the public HTTPS server.
- Screen mirroring for the iPhone (QuickTime on the Mac via cable, or AirPlay).
- **Your own mobile hotspot**: conference Wi-Fi is unreliable.

## Before going on stage (T-30 min)
1. In the web app, Prevention Center → Blocklist → add the scammer phone's number as type **phone** (reason "demo scam number").
2. On the iPhone, open 3B → الحماية → **مزامنة**, and confirm "تحذير المكالمات: مُفعَّل".
3. Do one complete dry run (SMS + call) with the exact phones you'll use, then delete the test messages.
4. Charge both phones, enable Do Not Disturb exceptions for the scammer's number, and keep the phones' volume on.
5. Open the backup video (below) in a second tab.

## On stage (≈4 minutes)
| # | What you do | What the audience sees |
|---|---|---|
| 1 | Scammer phone sends: *"[Salik] تنبيه عاجل: رسوم مرور مستحقة 4 درهم. ادفع قبل الساعة 11:59 لتجنب غرامة 50 درهم: https://salik.ae.ticka.top"* | The message does **not** appear in the inbox — it lands in **غير مرغوب / Junk** with no network needed (checked on the phone) |
| 2 | Show the same text in 3B → افحص | Score, "احتيال محتمل" and the reasons (fake Salik link, payment pressure, fine threat) |
| 3 | Scammer phone **calls** the iPhone | Incoming-call screen shows **"⚠️ 3B: رقم احتيال مُبلّغ عنه"** — before answering (or the call is silently blocked, if you blocked it) |
| 4 | Laptop: Call Guard → upload `sample_scam_call.wav` (or play it next to the laptop mic in live mode) | Transcript appears and scores ~92 "تصيّد صوتي" with reasons (OTP request, police impersonation, threats) |
| 5 | Laptop: Command Center | New incidents and the threat graph linking everything |

## If something fails
- **SMS goes to the inbox:** the sender used iMessage (blue bubble), or the number is in Contacts. Show step 2 (manual check) and the backup video.
- **No call label:** sync again (الحماية → مزامنة); labels require iOS to reload the list (a few seconds). Otherwise show the web Phone Protection simulator.
- **Server unreachable:** SMS filtering still works (offline). Use the backup video for the rest.
- **Record a backup video** of a successful full run on the day before; it's standard practice and judges accept it.

## What to say (honest claims)
- "The SMS check runs **on the phone**; the message is not uploaded."
- "Before you answer, iPhone shows 3B's warning for numbers reported as scams. A phone number can't tell us where the caller physically is, and caller ID can be faked."
- "No app can listen to a normal phone call. For voice analysis, put the call on speaker next to 3B Call Guard."
