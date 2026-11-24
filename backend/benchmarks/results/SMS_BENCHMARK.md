# 3B text rules on the UCI SMS Spam Collection

- Run: 2026-11-24 08:09 UTC · Python 3.14.3 · dataset SHA-256 `1587ea43e58e82b14ff1f5425c88e17f8496bfcdb67a583dbff9eefaf9963ce3`
- Messages: 5574 (747 spam, 4827 ham)
- Method: the app's SMS text rules only (no URL reputation, no AI, no network). A message counts as
  flagged when its risk score reaches the threshold. Rules were **not** tuned on this dataset.
- Latency per message: median 0.33 ms, p95 0.60 ms

| Threshold | Precision | Recall | F1 | FPR | FNR | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|---|
| score ≥ 30 | 1.000 | 0.048 | 0.092 | 0.000 | 0.952 | 36 | 0 | 711 | 4827 |
| score ≥ 60 | 0.000 | 0.000 | 0.000 | 0.000 | 1.000 | 0 | 0 | 747 | 4827 |

## Confusion matrix (score ≥ 30)

| | Flagged | Not flagged |
|---|---|---|
| **Spam** | 36 | 711 |
| **Ham** | 0 | 4827 |

## How to read this

- **Spam is not scam.** Many spam messages are adverts or ringtone offers with no fraud tactic; 3B is
  built to flag fraud tactics (codes, payments, threats, impersonation), so missing plain adverts is expected.
- The data is from 2012, English only, UK/Singapore. It says nothing about Arabic or Gulf-dialect messages.
- These numbers are a baseline, not a claim of real-world accuracy. A fair test needs current, labelled
  UAE scam and legitimate messages collected with consent.

## Ham messages flagged at score ≥ 30 (false positives)


## Spam messages not flagged (sample of 10)

- 0 · “Free entry in 2 a wkly comp to win FA Cup final tkts 21st May 2005. Text FA to 87121 to receive entry question”
- 0 · “FreeMsg Hey there darling it's been 3 week's now and no word back! I'd like some fun you up for it still? Tb o”
- 24 · “WINNER!! As a valued network customer you have been selected to receivea £900 prize reward! To claim call 0906”
- 0 · “Had your mobile 11 months or more? U R entitled to Update to the latest colour mobiles with camera for Free! C”
- 0 · “SIX chances to win CASH! From 100 to 20,000 pounds txt> CSH11 and send to 87575. Cost 150p/day, 6days, 16+ Tsa”
- 0 · “XXXMobileMovieClub: To use your credit, click the WAP link in the next txt message or click here>> http://wap.”
- 0 · “England v Macedonia - dont miss the goals/team news. Txt ur national team to 87077 eg ENGLAND to 87077 Try:WAL”
- 0 · “Thanks for your subscription to Ringtone UK your mobile will be charged £5/month Please confirm by replying YE”
- 0 · “07732584351 - Rodger Burns - MSG = We tried to call you re your reply to our sms for a free nokia mobile + fre”
- 0 · “SMS. ac Sptv: The New Jersey Devils and the Detroit Red Wings play Ice Hockey. Correct or Incorrect? End? Repl”
