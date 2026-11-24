# Detection engine: intent, not vocabulary

## What it was before
The scam check in `backend/app/services/text_analyzer.py` was **keyword and phrase patterns** (urgency, OTP, payment,
authority…) plus a few hand-made combinations, scored with a noisy-OR. An optional AI layer (Claude or Gemini) could add up to
30 points. Without an AI key, a well-written scam with no "scam words" scored low, and a legitimate message with words like
"urgent", "OTP" or "congratulations" could score medium.

## What it is now (layers)
| Layer | Where | What it does |
|---|---|---|
| 1 Semantic AI | `services/ai.py` | Reads the whole message when an AI key is set (Claude or Gemini). Capped at 30 points; never decides alone. **Not active without a key.** |
| 2 Behaviour / intent | `services/intent_engine.py` | Reads **what the message asks you to do** (pay, reveal a code, give ID, open a link, install, approve, move chat, keep quiet), **who it claims to be** (bank, authority, courier, employer, family on a new number…), **which pressure** it uses (fear, urgency, reward, sympathy, secrecy) and **contradictions** (a bank asking for your code, an authority collecting a fine by message, paying to receive money, a "safe account"…). English, Arabic, Gulf/Levantine dialect and common Arabizi. |
| 2b Keyword check | `services/text_analyzer.py` | Unchanged patterns, but **weighted down** when the message asks for nothing risky or is protective advice ("never share this code"). |
| 3 Threat intelligence | `services/threat_intel.py`, `services/collective.py` | URLhaus / VirusTotal / Safe Browsing when keys + consent exist; the **shared 3B network** (reported / suspicious / verified indicators). "Not listed" never lowers the score. |
| 4 Technical | `url_analyzer`, `email_analyzer`, `network_intel`, `phone_intel` | Links, look-alike domains, headers (SPF/DKIM/DMARC), numbers. |
| 5 Scoring | `services/risk.py` | Noisy-OR of all evidence. Every finding says where it came from (verified / intel / heuristic / ai). |
| 6 Warning | `services/risk.py` `verdict()` | MEDIUM → *"WARNING: This message contains suspicious characteristics. We recommend verifying the sender independently…"*; HIGH / CRITICAL stronger. `assessment_status` says **"Suspected — not confirmed"** unless a verified source confirms it. |

Every report now also contains: `risk_level`, `warning`, `verdict_basis` (AI / threat intel / verified checks / heuristic),
`assessment_status`, `confirmed`, `intent` (what was read), `similar_methods` (closest entries in the Scam Methods Library, with
the reason) and `campaign_matches` (reports with a near-identical message, even with changed numbers or links).

## Honest limits
* Without an AI key, layer 2 is a **rule-based model of intent** built on multilingual concept lists. It generalises well
  beyond fixed templates (see the keyword-free test below) but it is not language understanding. Unusual phrasing it has no
  concept for can still be missed.
* The test set below was written by the team. It is not an independent benchmark. The SMS benchmark in
  `backend/benchmarks/` remains the only external dataset measured.

## Tests (`backend/tests/test_detection.py`, run with AI off and no shared data)
* 10 obvious scams (7 EN, 3 AR) → all **≥ 60 (HIGH/CRITICAL)**.
* 10 sophisticated scams without typical scam words (safe-account, government, "hi mum", job top-up, indirect investment,
  professional payroll phishing, ID harvesting, Arabic safe-account, "sent by mistake" refund, Arabizi family + secrecy) →
  all **≥ 30 with a warning** (7 of 10 HIGH), each explained by a behaviour finding, none marked "confirmed".
* 11 legitimate messages with suspicious-looking words (real OTP SMS, salary credit, "urgent" meeting, courier ETA, police
  awareness message, Arabic OTP / bill reminder…) → all **< 30, no warning**.
* With **all keyword patterns switched off**, ≥ 9 of 10 sophisticated scams still get a warning.
* Results at the time of writing: obvious 61–91, sophisticated 44–76, legitimate 0–21.

Run: `cd backend; .venv\Scripts\python -m pytest tests/test_detection.py -q`

## Scam Methods Library (`/scam-methods`, API `/api/knowledge`)
* **126 methods in 20 categories**, 94 UAE-focused, each with: id, name (EN + AR), category/subcategory, description, attack
  sequence, psychological techniques, objectives, targets, channels, behavioural indicators, fictional EN + AR examples,
  variations, detection strategies, protection steps, severity, impact, related methods, sources, last-reviewed date.
* **All seeded methods are `needs_review` with no source attached.** They were written from general fraud-awareness knowledge;
  no statistics or references were invented. A reviewer must add a traceable source, and only an **administrator** can mark a
  method **Verified** (the API refuses Verified without a source).
* Admin: add / edit / disable, JSON + CSV import/export, duplicate detection (name or example similarity), full version history.
* High-risk analyses with no close match are saved as **candidate patterns** (redacted excerpt). They are never added
  automatically; a reviewer can save one as a Draft method.
* Matching = character n-gram similarity (works across Arabic/English spelling) + overlap of behaviour. A match adds at most
  12 points and is shown as "a pointer, not proof".
