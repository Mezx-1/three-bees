# Three Bees (3B) — pitch talking points

The 5-minute slot is 3 minutes of demo (the first minute explains the solution) and 2 minutes of questions.
Slides: [`presentation/ThreeBees_pitch.pptx`](presentation/ThreeBees_pitch.pptx) (13 slides, speaker notes in English and Arabic).
The full deck for the submission is [`presentation/ThreeBees_3B.pptx`](presentation/ThreeBees_3B.pptx).

## 1. The problem · المشكلة
- Calls from strange numbers, annoying messages and links — even when you rest or sleep.
  مكالمات من أرقام غريبة ورسائل وروابط مزعجة، حتى وقت الراحة والنوم.
- The targets are the people we love: parents, the elderly, even children.
  المستهدفون هم أهلنا: كبار السن وحتى الأطفال.
- "It happened to my father. I was there and knew their tricks, so I stopped it. Not everyone has someone there — 3B is that someone."
  «هذا حصل مع أبوي، كنت موجود ووقفتهم. مش كل واحد عنده حدا جنبه — و3B هو هالشخص.»
- Why bees: the guard bees catch the thief at the door of the hive, before he gets in.
  ليش النحل: الحارس يكشف اللص على باب الخلية قبل ما يدخل.

## 2. How 3B works · فكرة السستم
- Three guards: it listens to the call, checks messages / links / email, and prepares the evidence for the police.
  ثلاث حراس: يسمع المكالمة، يفحص الرسائل والروابط والإيميل، ويجهز الدليل للشرطة.
- It reads the **intent**, not the words: does it ask you to send money, give a code, approve a notification?
  يقرأ نية الرسالة مش الكلمات: بدها منك تحوّل مصاري؟ تعطي رمز؟ توافق على إشعار؟
- Every result: a risk score, the reasons, and where each fact came from (technical check, reports, AI).
  كل نتيجة فيها درجة خطر والسبب ومن وين جاي كل دليل.

## 3. Call Guard (our strongest point) · أقوى نقطة
- Listens on the laptop with consent; speech-to-text offline; the audio is not stored.
  يسمع بموافقتك، يحوّل لنص بدون إنترنت، وما يخزّن الصوت.
- Catches the tricks: "give me the code", "approve the notification", "don't hang up".
- Checks facts: ask "what time is it there?" — a wrong answer means the caller isn't in the UAE.
  اسأله كم الساعة عندك؟ إذا جاوب غلط معناه مش بالإمارات.
- Strong alarm — "This is a scam, hang up!" — and ready questions to ask the caller.

## 4. Links (most of the marks) · الروابط
- Follows shorteners and redirects to the real page without opening it in a browser.
- Spots the fake: brand on the wrong domain (`tamm-abudhabi.vercel.app`), free hosting, a domain registered days ago.
- Knows the official UAE sites (.gov.ae, TAMM, UAE PASS, banks): **0 false alarms on 43 real UAE sites**.
  يعرف المواقع الرسمية، فما يعطي إنذار غلط عليها.
- In the app: a fake TAMM fine link scores 81/100 Critical; the real salik.ae scores 0 ("Official domain").

## 5. Similar scams and protecting everyone · التشابه والحماية الجماعية
- One person reports — everyone is warned. شخص واحد يبلّغ والكل يتحذّر.
- If the scammer changes his number, link or wording, 3B compares with what was reported and links them as one campaign. It says "similar", never "the same person".
  يقول «مشابه» مش «نفس الشخص».
- Early detection: new look-alike domains of UAE banks, TAMM, UAE PASS from public certificate logs — before the first victim.
- Fair: one report never blocks anything; blocking needs an analyst; owners can appeal.
  بلاغ واحد ما يحظر شي، والحظر يحتاج محلل، وصاحب الرقم يقدر يعترض.

## 6. For the police · للشرطة
- One click: evidence pack (timestamps, redirect chain, domain data, registrar and abuse contact) + a takedown request + a police-report draft.
- Simple mode for parents: one big word, bigger text, read aloud.

## 7. Numbers · الأرقام
- Public data (OpenPhish vs. 1,000 popular sites + 43 UAE sites): precision **0.86**, false alarms **1.7 %**, **0** on UAE official sites, recall 0.68 (offline engine only).
- 126 scam methods in Arabic and English · 124 automated tests passing.
- Details: [`backend/benchmarks/results/URL_BENCHMARK.md`](../backend/benchmarks/results/URL_BENCHMARK.md), [`DETECTION_ENGINE.md`](DETECTION_ENGINE.md).

## 8. Honest about what's next · الصراحة
- Not covered yet: search-engine ads and Google Maps listings, screenshots of scam pages, Android app, automatic Gmail scanning.
- We refused to: use Truecaller data without permission, guess a caller's name, block a number on one report, store call audio.
  ما استخدمنا بيانات Truecaller لأنها غير مصرّح فيها.

## 9. Closing · الختام
"We can't stop every scam, but we can stop it from spreading. Scammed once — never again."
«ما نقدر نوقف كل احتيال، بس نقدر نمنعه ينتشر. انضحك مرة، ما تنضحك مرة ثانية.»

## Demo video (about 90 seconds)
1. Call Guard catches a live scam call ("approve the notification" + the wrong-time question).
2. A fake TAMM link next to the real salik.ae, then More → Evidence pack / Takedown request.
3. Caller ID on a reported (DEMO) number, then the Threat Network campaign graph and look-alike watch.
