"""Arabic translation of backend-generated text (reports, alerts, messages).

Applied to JSON responses when the client sends `X-3B-Lang: ar` (see main.py), and to the
exported HTML report. Only display fields are translated — identifiers and enum values are not.
EXACT holds fixed sentences; TEMPLATES hold sentences with values, written with {0}, {1}…
"""
from __future__ import annotations

import re

EXACT: dict[str, str] = {
    # --- classification / categories
    "No significant threat detected": "لم يُرصد تهديد كبير",
    "Phishing": "تصيّد احتيالي",
    "Smishing (SMS phishing)": "تصيّد عبر الرسائل النصية",
    "Vishing (voice phishing)": "تصيّد صوتي (عبر المكالمات)",
    "Business Email Compromise": "اختراق البريد الإلكتروني للأعمال (BEC)",
    "Impersonation": "انتحال صفة",
    "Credential theft": "سرقة بيانات الدخول",
    "OTP theft": "سرقة رمز التحقق (OTP)",
    "Payment fraud": "احتيال مالي",
    "Malware delivery": "نشر برمجيات خبيثة",
    "Malicious link": "رابط خبيث",
    "Social engineering": "هندسة اجتماعية",
    "Possible deepfake-assisted fraud": "احتيال محتمل بمساعدة التزييف العميق",
    "Suspicious infrastructure": "بنية تحتية مشبوهة",
    "Risk score is an indicator built from the listed evidence, not a calibrated probability of fraud.":
        "درجة الخطورة مؤشر مبني على الأدلة المذكورة، وليست احتمالاً دقيقاً لوقوع الاحتيال.",
    # --- recommendations
    "Do not click links, open attachments, scan QR codes or reply until IT security reviews this item.":
        "لا تضغط على الروابط ولا تفتح المرفقات ولا تمسح رموز QR ولا تردّ حتى يراجع فريق أمن المعلومات هذا العنصر.",
    "If credentials were entered, reset the password immediately and revoke active sessions.":
        "إذا أُدخلت بيانات الدخول، غيّر كلمة المرور فوراً وأنهِ الجلسات النشطة.",
    "Never share one-time passwords. Legitimate banks and authorities never ask for an OTP by phone or message.":
        "لا تشارك رموز التحقق أبداً. البنوك والجهات الرسمية لا تطلب رمز OTP عبر الهاتف أو الرسائل.",
    "Verify any payment or bank-detail change through a known phone number — not contact details in the message.":
        "تحقّق من أي دفعة أو تغيير في البيانات البنكية عبر رقم هاتف معروف لديك — وليس من بيانات التواصل في الرسالة.",
    "Keep the attachment quarantined. If it was opened, recommend isolating the endpoint and running a full scan.":
        "أبقِ المرفق في الحجر. إذا فُتح، يُنصح بعزل الجهاز وإجراء فحص كامل.",
    "Contact the impersonated person or organisation through an independently verified channel.":
        "تواصل مع الشخص أو الجهة المنتحَل صفتها عبر قناة موثوقة تتحقق منها بنفسك.",
    "Hang up and call back on an official number. Agree on a verbal code word for urgent payment requests.":
        "أنهِ المكالمة واتصل على الرقم الرسمي. اتفقوا على كلمة سر شفهية لطلبات الدفع العاجلة.",
    "Add the domain/URL to the blocklist and check proxy logs for other users who visited it.":
        "أضف النطاق/الرابط إلى قائمة الحظر وراجع سجلات البروكسي لمعرفة المستخدمين الآخرين الذين زاروه.",
    "Report to IT security. For fraud against individuals in the UAE, report via official police channels (e.g. Aman service, 8002626).":
        "أبلغ فريق أمن المعلومات. وللاحتيال على الأفراد في الإمارات، أبلغ عبر القنوات الرسمية للشرطة (مثل خدمة أمان 8002626).",
    "No strong threat indicators found. Stay cautious with unexpected requests for money, credentials or codes.":
        "لم تُرصد مؤشرات تهديد قوية. ابقَ حذراً من الطلبات غير المتوقعة للمال أو بيانات الدخول أو الرموز.",
    "Recommend isolating the endpoint from the network for investigation.": "يُوصى بعزل الجهاز عن الشبكة للتحقيق.",
    "Collect process tree and memory image before remediation.": "اجمع شجرة العمليات وصورة الذاكرة قبل المعالجة.",
    "Reset credentials of the device owner.": "أعد تعيين بيانات دخول مالك الجهاز.",
    "Check other recipients of the same email and devices contacting the same destinations.":
        "تحقّق من باقي مستلمي البريد نفسه ومن الأجهزة التي تتصل بالوجهات نفسها.",
    "Triage the evidence and assign an owner.": "افرز الأدلة وعيّن مسؤولاً.",
    # --- limitations
    "Static analysis only — the file was never executed. Malware that is obfuscated or only acts at runtime may not be detected.":
        "تحليل ثابت فقط — لم يُشغَّل الملف أبداً. قد لا تُكتشف البرمجيات الخبيثة المموّهة أو التي تعمل فقط أثناء التشغيل.",
    "OCR unavailable: text inside the image was not extracted.": "قراءة النص غير متاحة: لم يُستخرج النص من الصورة.",
    "Legacy OLE documents were inspected for macro markers only; full OLE stream parsing is not implemented.":
        "فُحصت مستندات Office القديمة بحثاً عن علامات الماكرو فقط؛ التحليل الكامل لبنيتها غير متوفر.",
    "PE executables are not detonated. Dynamic behaviour requires the isolated sandbox (planned).":
        "لا تُشغَّل الملفات التنفيذية. تحليل السلوك يتطلب بيئة معزولة (مخطّط لها).",
    "Structural URL analysis only — the page was not visited or rendered.": "تحليل لبنية الرابط فقط — لم تتم زيارة الصفحة.",
    "External lookups disabled: DNS was not queried.": "البحث الخارجي متوقف: لم يتم الاستعلام عن DNS.",
    "No URL reputation provider configured (e.g. Google Safe Browsing, VirusTotal); 3B does not claim reputation results.":
        "لا يوجد مزوّد لسمعة الروابط (مثل Google Safe Browsing أو VirusTotal)؛ لذلك لا يقدّم 3B نتائج سمعة.",
    "External lookups disabled: no geolocation/ASN was queried.": "البحث الخارجي متوقف: لم يتم الاستعلام عن الموقع أو الشبكة.",
    "No IP reputation provider configured (AbuseIPDB key not set) — reputation is unknown, not clean.":
        "لا يوجد مزوّد لسمعة عناوين IP (مفتاح AbuseIPDB غير مضبوط) — السمعة غير معروفة، وليست نظيفة.",
    "IP geolocation is approximate (city/region level at best) and reflects the network operator, not a person or device.":
        "الموقع الجغرافي لعنوان IP تقريبي (على مستوى المدينة/المنطقة في أحسن الأحوال) ويعكس مشغّل الشبكة، لا شخصاً أو جهازاً.",
    "VPNs, proxies, Tor and cloud hosting hide the true origin of traffic.": "شبكات VPN والبروكسي وTor والاستضافة السحابية تُخفي المصدر الحقيقي.",
    "A country calling code shows where the number range is registered — NOT where the caller physically is.":
        "رمز الدولة يوضح أين سُجّل نطاق الرقم — وليس مكان وجود المتصل فعلياً.",
    "Caller ID can be spoofed: a call showing a local or official number may originate anywhere.":
        "يمكن تزييف هوية المتصل: مكالمة تُظهر رقماً محلياً أو رسمياً قد تأتي من أي مكان.",
    "No carrier/HLR or reputation lookup is configured; 3B cannot confirm the number's owner.":
        "لا يوجد استعلام عن مشغّل الرقم أو سمعته؛ لا يستطيع 3B تأكيد مالك الرقم.",
    "Text heuristics detect common scam techniques; novel or well-written scams may score low.":
        "فحص النص يكشف أساليب الاحتيال الشائعة؛ قد تحصل الأساليب الجديدة أو المكتوبة بإتقان على درجة منخفضة.",
    "Sender identity of SMS/WhatsApp/chat messages cannot be verified from text alone.":
        "لا يمكن التحقق من هوية مرسل الرسائل النصية أو واتساب أو الدردشة من النص وحده.",
    "Video: only sampled frames (1 every 3 s, max 4) were inspected; audio track was not transcribed.":
        "الفيديو: فُحصت إطارات مختارة فقط (إطار كل 3 ثوانٍ، 4 كحد أقصى)؛ ولم يُحوَّل الصوت إلى نص.",
    "Speech-to-text is not installed in this deployment; provide a transcript to analyse spoken content.":
        "تحويل الكلام إلى نص غير مثبّت؛ أرفق نص المحادثة لتحليل ما قيل.",
    "Synthetic-voice / deepfake detection is not implemented. 3B never labels media as fake based on impressions.":
        "كشف الصوت المُصطنع / التزييف العميق غير متوفر. لا يصف 3B أي وسائط بأنها مزيّفة بناءً على الانطباع.",
    "ffprobe not installed: media metadata unavailable.": "أداة ffprobe غير مثبّتة: البيانات الوصفية للوسائط غير متاحة.",
    "Email was analysed from submitted content; 3B is not connected to a live mailbox, so actions apply to the 3B record only.":
        "حُلّل البريد من المحتوى المُرسل؛ 3B غير متصل بصندوق بريد حقيقي، لذا تُطبَّق الإجراءات على سجل 3B فقط.",
    "No Authentication-Results header: SPF/DKIM/DMARC outcome unknown. Paste full headers or upload the .eml for this check.":
        "لا توجد ترويسة Authentication-Results: نتيجة SPF/DKIM/DMARC غير معروفة. الصق الترويسات كاملة أو ارفع ملف ‎.eml لإجراء هذا الفحص.",
    "No From header found — sender checks were skipped (pasted body only?).": "لم تُوجد ترويسة المرسل — تم تخطي فحص المرسل (هل لُصق النص فقط؟).",
    "No Received headers: the delivery path could not be traced.": "لا توجد ترويسات Received: تعذّر تتبّع مسار التسليم.",
    "not configured (no API key). Results come from 3B's built-in checks.": "غير مُفعَّل (لا يوجد مفتاح API). النتائج من فحوصات 3B المدمجة.",
    "AI analysis disabled in Settings.": "التحليل بالذكاء الاصطناعي متوقف من الإعدادات.",
    "AI not used for single-URL structural checks.": "لا يُستخدم الذكاء الاصطناعي لفحص بنية رابط منفرد.",
    "The AI model declined to assess this content.": "رفض نموذج الذكاء الاصطناعي تقييم هذا المحتوى.",
    "AI returned no structured result.": "لم يُرجع الذكاء الاصطناعي نتيجة منظّمة.",
    "AI provider rejected the API key.": "رفض مزوّد الذكاء الاصطناعي مفتاح API.",
    "AI provider rate limit reached — deterministic results shown.": "تم بلوغ حد الاستخدام لدى مزوّد الذكاء الاصطناعي — تُعرض نتائج الفحوصات المدمجة.",
    "Could not reach the AI provider — deterministic results shown.": "تعذّر الاتصال بمزوّد الذكاء الاصطناعي — تُعرض نتائج الفحوصات المدمجة.",
    "No OCR engine installed (install Tesseract or `pip install rapidocr onnxruntime`).": "لا يوجد محرك لقراءة النص من الصور.",
    # --- text social-engineering patterns
    "Urgency / time pressure": "استعجال / ضغط الوقت",
    "Message pressures the reader to act immediately, a classic tactic to prevent careful verification.":
        "الرسالة تضغط على القارئ للتصرف فوراً، وهو أسلوب معروف لمنع التحقق المتأنّي.",
    "Threat of negative consequences": "تهديد بعواقب سلبية",
    "Threatens account suspension, legal action, fines or arrest to scare the reader into complying.":
        "تهدّد بإيقاف الحساب أو اتخاذ إجراء قانوني أو غرامات أو اعتقال لتخويف القارئ ودفعه للاستجابة.",
    "Request for one-time password (OTP) / verification code": "طلب رمز التحقق لمرة واحدة (OTP)",
    "Asks the reader to share an OTP, PIN or verification code. Legitimate organisations never ask for these.":
        "تطلب من القارئ مشاركة رمز OTP أو الرقم السري أو رمز التحقق. الجهات الموثوقة لا تطلب ذلك أبداً.",
    "Request for credentials / login": "طلب بيانات الدخول / تسجيل الدخول",
    "Directs the reader to enter or confirm a password or log in through a link.": "توجّه القارئ لإدخال كلمة المرور أو تأكيدها أو تسجيل الدخول عبر رابط.",
    "Payment / money transfer request": "طلب دفع / تحويل أموال",
    "Requests a payment, wire transfer, gift cards, crypto, or a change of bank details.": "تطلب دفعة أو تحويلاً بنكياً أو بطاقات هدايا أو عملات رقمية أو تغيير البيانات البنكية.",
    "Secrecy / bypass of normal process": "سرّية / تجاوز الإجراءات المعتادة",
    "Asks the reader to keep the request confidential or skip normal approvals — common in CEO fraud (BEC).":
        "تطلب إبقاء الطلب سرياً أو تجاوز الموافقات المعتادة — وهذا شائع في احتيال انتحال صفة المدير.",
    "Authority impersonation cues": "علامات انتحال صفة جهة ذات سلطة",
    "Invokes authority (CEO, police, government, bank, IT department) to make the request seem legitimate.":
        "تستخدم اسم جهة ذات سلطة (مدير تنفيذي، شرطة، حكومة، بنك، قسم تقنية) لجعل الطلب يبدو مشروعاً.",
    "Too-good-to-be-true reward": "مكافأة مغرية بشكل مبالغ فيه",
    "Offers a prize, refund, lottery win or investment return to lure the reader.": "تعرض جائزة أو استرداداً أو ربح يانصيب أو عائد استثمار لاستدراج القارئ.",
    "Request to install software / remote access": "طلب تثبيت برنامج / وصول عن بُعد",
    "Asks the reader to install an app or grant remote access (AnyDesk, TeamViewer…), often used for fraud or malware.":
        "تطلب تثبيت تطبيق أو منح وصول عن بُعد (AnyDesk وTeamViewer…)، وهذا يُستخدم كثيراً في الاحتيال أو نشر البرمجيات الخبيثة.",
    "Parcel / delivery lure": "خدعة الطرود / التوصيل",
    "Uses a fake delivery problem or customs fee — very common smishing pretext in the UAE.": "تستخدم مشكلة توصيل وهمية أو رسوم جمركية — ذريعة احتيال شائعة جداً في الإمارات.",
    "Generic greeting": "تحية عامة",
    "Uses a generic greeting instead of your name — common in mass phishing.": "تستخدم تحية عامة بدلاً من اسمك — شائع في التصيّد الجماعي.",
    "Call-based pretext": "ذريعة عبر المكالمات",
    "Tells the reader to call a number or expect a call to 'resolve' an issue — a vishing setup.": "تطلب الاتصال برقم أو انتظار مكالمة «لحل» مشكلة — تمهيد للتصيّد الصوتي.",
    "Authority + payment + pressure combination": "جمع بين السلطة والدفع والضغط",
    "The message combines an authority figure, a payment request and pressure/secrecy — the core pattern of CEO fraud / BEC.":
        "تجمع الرسالة بين شخص ذي سلطة وطلب دفع وضغط/سرّية — وهو النمط الأساسي لاحتيال انتحال صفة المدير.",
    "Authority figure asking for a code": "جهة رسمية تطلب رمز التحقق",
    "Someone claiming to be the police, a bank or an official department asks for a one-time code. Real officials never do this.":
        "شخص يدّعي أنه من الشرطة أو البنك أو جهة رسمية يطلب رمز تحقق لمرة واحدة. الجهات الحقيقية لا تطلب ذلك أبداً.",
    "A code may have been said during the call": "يبدو أن رمزاً قيل خلال المكالمة",
    "After the caller asked for a code, a number that looks like a one-time code was heard. If it was your code, the caller can now use it — call your bank immediately.":
        "بعد أن طلب المتصل رمزاً، سُمع رقم يشبه رمز التحقق. إذا كان رمزك، فبإمكان المتصل استخدامه الآن — اتصل ببنكك فوراً.",
    # --- questions that expose a scam caller
    "What time is it where you are right now?": "كم الساعة عندك الآن؟",
    "Someone really in the UAE answers at once. 3B checks the answer against the real UAE time.":
        "من يتصل فعلاً من الإمارات يجيب فوراً. يقارن 3B الجواب بالوقت الحقيقي في الإمارات.",
    "Which company are you from, and what is its official number?": "من أي جهة أنت، وما رقمها الرسمي؟",
    "3B checks the name against known UAE organisations. Look the number up yourself — never use one they give.":
        "يقارن 3B الاسم بالجهات الإماراتية المعروفة. ابحث عن الرقم بنفسك — لا تستخدم رقماً يعطيك إياه.",
    "Can I hang up and call you back on the number printed on my card?": "هل أستطيع إنهاء المكالمة والاتصال بكم على الرقم المطبوع على بطاقتي؟",
    "A real bank always says yes. A scammer says it is urgent or that the line will be lost.":
        "البنك الحقيقي يوافق دائماً. المحتال يقول إن الأمر عاجل أو إن الفرصة ستضيع.",
    "What are the last four digits of my card?": "ما آخر أربعة أرقام من بطاقتي؟",
    "Your bank can see this. A scammer usually can't — and never read your own digits to them.":
        "بنكك يعرفها. المحتال غالباً لا يعرفها — ولا تقرأ أرقامك له أبداً.",
    "Why do you need a code that the bank itself sent to me?": "لماذا تحتاج رمزاً أرسله البنك نفسه إليّ؟",
    "Banks never ask for the code they send. Any answer here is a reason to hang up.":
        "البنوك لا تطلب أبداً الرمز الذي ترسله. أي جواب هنا سبب كافٍ لإنهاء المكالمة.",
    "What is your full name and badge number? I will call the station to confirm.": "ما اسمك الكامل ورقمك العسكري؟ سأتصل بالمركز للتأكد.",
    "Real officers give these and let you call back. Scammers threaten or hurry you.":
        "الموظف الحقيقي يعطيك ذلك ويسمح لك بالتحقق. المحتال يهدد أو يستعجلك.",
    "Can I pay this through the official app instead?": "هل أستطيع الدفع عبر التطبيق الرسمي بدلاً من ذلك؟",
    "Real fines can always be paid in the official app or website. Scammers insist on a transfer or gift cards.":
        "الغرامات الحقيقية تُدفع دائماً عبر التطبيق أو الموقع الرسمي. المحتال يصرّ على التحويل أو بطاقات الهدايا.",
    "What is the tracking number? I will check it in the courier's app.": "ما رقم التتبع؟ سأتحقق منه في تطبيق شركة التوصيل.",
    "A real courier gives it and the app shows the parcel. A scammer pushes a link or a fee.":
        "شركة التوصيل الحقيقية تعطيك الرقم ويظهر في التطبيق. المحتال يرسل رابطاً أو يطلب رسوماً.",
    "Why do I have to pay anything to receive a prize?": "لماذا عليّ أن أدفع أي شيء لأستلم جائزة؟",
    "Real prizes never cost money to collect.": "الجوائز الحقيقية لا تتطلب دفع أي مبلغ لاستلامها.",
    "Why would a company need control of my phone?": "لماذا تحتاج أي جهة إلى التحكم بهاتفي؟",
    "No bank or official body asks you to install remote-access apps.": "لا يطلب أي بنك أو جهة رسمية تثبيت تطبيقات التحكم عن بُعد.",
    "What day is it today?": "ما هو اليوم؟",
    "Another fact 3B can check against the real UAE date.": "معلومة أخرى يتحقق منها 3B بمقارنتها بتاريخ اليوم في الإمارات.",
    # --- scammer's next step
    "Predicted from the scam pattern, not a certainty.": "توقّع مبني على نمط الاحتيال، وليس أمراً مؤكداً.",
    "They will use the code straight away to log in or approve a payment — then may call back asking for “one more code to cancel it”.":
        "سيستخدم الرمز فوراً للدخول أو لاعتماد دفعة — وقد يعاود الاتصال طالباً «رمزاً آخر لإلغاء العملية».",
    "A one-time code is all they need to take over the card or account.": "رمز التحقق هو كل ما يحتاجه للاستيلاء على البطاقة أو الحساب.",
    "Call your bank now on the number printed on your card and block the card. Never give a second code.":
        "اتصل ببنكك الآن على الرقم المطبوع على بطاقتك وأوقف البطاقة. لا تعطِ رمزاً ثانياً أبداً.",
    "They will ask for the code sent to you by SMS, or your card number and CVV, “to verify” or “to stop the transaction”.":
        "سيطلب الرمز الذي يصلك برسالة نصية، أو رقم بطاقتك ورمز CVV، بحجة «التحقق» أو «إيقاف العملية».",
    "An account “problem” from a bank or official caller is the usual set-up before asking for a code.":
        "ادعاء وجود «مشكلة» في الحساب من بنك أو جهة رسمية هو التمهيد المعتاد قبل طلب الرمز.",
    "No bank or government body asks for a code by phone or message. Hang up and call the official number yourself.":
        "لا يطلب أي بنك أو جهة حكومية رمزاً عبر الهاتف أو الرسائل. أنهِ المكالمة واتصل بالرقم الرسمي بنفسك.",
    "Once they have the code they will log in or approve a payment immediately, often while keeping you on the line.":
        "بمجرد حصوله على الرمز سيدخل إلى حسابك أو يعتمد دفعة فوراً، وغالباً وهو يُبقيك على الخط.",
    "They asked for a code — the code is the key to your account.": "طلب رمزاً — والرمز هو مفتاح حسابك.",
    "Do not read out any code. If you already did, call your bank at once and block the card.":
        "لا تقرأ أي رمز. إذا قرأته، اتصل ببنكك فوراً وأوقف البطاقة.",
    "They will ask for a small “processing”, “customs” or “delivery” fee — or your card details — to release the prize.":
        "سيطلب رسوماً صغيرة «للمعالجة» أو «للجمارك» أو «للتوصيل» — أو بيانات بطاقتك — لتسليم الجائزة.",
    "Fake prizes are always followed by a fee or a request for card details.": "الجوائز الوهمية يتبعها دائماً طلب رسوم أو بيانات البطاقة.",
    "A real prize never costs money to collect. Do not pay or share card details.": "الجائزة الحقيقية لا تتطلب دفع مال لاستلامها. لا تدفع ولا تشارك بيانات بطاقتك.",
    "A link to pay a small redelivery fee; the page then asks for your card details and the code from your bank.":
        "رابط لدفع رسوم إعادة توصيل صغيرة؛ ثم تطلب الصفحة بيانات بطاقتك والرمز من بنكك.",
    "Delivery problems are the most common pretext for card-stealing pages in the UAE.": "مشاكل التوصيل هي الذريعة الأكثر شيوعاً لصفحات سرقة البطاقات في الإمارات.",
    "Check the parcel only in the courier's official app or website, typed in yourself.": "تحقق من الشحنة فقط عبر التطبيق أو الموقع الرسمي لشركة التوصيل، بكتابة العنوان بنفسك.",
    "They will demand immediate payment of a “fine” — by transfer, gift cards or crypto — and tell you not to hang up or tell anyone.":
        "سيطالب بدفع «غرامة» فوراً — بتحويل أو بطاقات هدايا أو عملات رقمية — ويطلب منك ألا تنهي المكالمة أو تخبر أحداً.",
    "Threats from someone claiming authority are meant to rush you into paying.": "التهديد من شخص يدّعي صفة رسمية هدفه دفعك للدفع بسرعة.",
    "Police and courts never collect fines by phone. End the call and check through the official app or 8002626 (Aman).":
        "الشرطة والمحاكم لا تحصّل الغرامات عبر الهاتف. أنهِ المكالمة وتحقق عبر التطبيق الرسمي أو 8002626 (أمان).",
    "The page or caller will ask for your username and password, then the code from your phone — after that they take over the account.":
        "ستطلب الصفحة أو المتصل اسم المستخدم وكلمة المرور، ثم الرمز من هاتفك — وبعدها يستولي على الحساب.",
    "Asking you to “verify” or “update” your account leads to a fake login page.": "طلب «التحقق» أو «تحديث» حسابك يقود إلى صفحة دخول مزيفة.",
    "Open the official app or website yourself. Never sign in from a link or attachment.": "افتح التطبيق أو الموقع الرسمي بنفسك. لا تسجّل الدخول أبداً من رابط أو مرفق.",
    "After you install the app they will control your phone or computer and open your banking app while you watch.":
        "بعد تثبيت التطبيق سيتحكم بهاتفك أو حاسوبك ويفتح تطبيق البنك أمام عينيك.",
    "Remote-access apps give the caller full control of the device.": "تطبيقات التحكم عن بُعد تمنح المتصل سيطرة كاملة على الجهاز.",
    "Do not install anything a caller asks for. If you did, disconnect from the internet and uninstall it.":
        "لا تثبّت أي شيء يطلبه المتصل. إذا ثبّته، افصل الإنترنت واحذفه.",
    "If the attachment is opened it may run code that steals saved passwords or lets the attacker in remotely.":
        "إذا فُتح المرفق فقد يشغّل كوداً يسرق كلمات المرور المحفوظة أو يُدخل المهاجم عن بُعد.",
    "The file is built to run code, not to be read.": "الملف مصمم لتشغيل كود، لا للقراءة.",
    "Do not open it. If it was opened, disconnect the device and report it to IT.": "لا تفتحه. إذا فُتح، افصل الجهاز عن الشبكة وأبلغ قسم تقنية المعلومات.",
    "They will push for the transfer to be made today, ask you to keep it confidential and to use new bank details.":
        "سيضغط لإتمام التحويل اليوم، ويطلب منك إبقاء الأمر سرياً واستخدام بيانات بنكية جديدة.",
    "Payment requests with urgency or secrecy are how invoice and CEO fraud work.": "طلبات الدفع المستعجلة أو السرية هي أسلوب احتيال الفواتير وانتحال صفة المدير.",
    "Confirm any payment or new bank details by calling a number you already know.": "تأكد من أي دفعة أو بيانات بنكية جديدة بالاتصال على رقم تعرفه مسبقاً.",
    "Card or account 'problem' pretext": "ذريعة «مشكلة» في البطاقة أو الحساب",
    "Claims your card or account needs an update, verification or has suspicious activity — the usual opening of a bank-impersonation call.":
        "يدّعي أن بطاقتك أو حسابك يحتاج تحديثاً أو تحققاً أو أن فيه نشاطاً مشبوهاً — وهي البداية المعتادة لمكالمات انتحال صفة البنك.",
    "Card or account 'problem' used to ask for a code": "«مشكلة» في البطاقة لطلب رمز التحقق",
    "Bank or official says your account has a problem": "بنك أو جهة رسمية تدّعي وجود مشكلة في حسابك",
    "Someone claiming to be a bank or an official body says your card or account needs action. This is how most bank-impersonation scams open.":
        "شخص يدّعي أنه من بنك أو جهة رسمية يقول إن بطاقتك أو حسابك يحتاج إجراء. هكذا تبدأ معظم عمليات انتحال صفة البنوك.",
    "The caller says your card or account needs attention and then asks for the code sent by SMS. That code would let them take over the card.":
        "المتصل يقول إن بطاقتك أو حسابك يحتاج إجراء، ثم يطلب الرمز الذي يصلك برسالة نصية. هذا الرمز يمكّنه من الاستيلاء على البطاقة.",
    "Pressure combined with credential request": "ضغط مقترن بطلب بيانات الدخول",
    "Urgency or threats paired with a login/password request strongly matches credential-phishing kits.":
        "الاستعجال أو التهديد مع طلب تسجيل الدخول/كلمة المرور يطابق بقوة أدوات تصيّد بيانات الدخول.",
    # --- email / sender
    "Reply-To differs from sender": "عنوان الرد مختلف عن المرسل",
    "Return-Path domain differs from From domain": "نطاق مسار الإرجاع مختلف عن نطاق المرسل",
    "Display name contains a different email address": "اسم العرض يحتوي عنوان بريد مختلفاً",
    "Executive/authority name from a free email account": "اسم مدير/جهة رسمية من بريد مجاني",
    "Sender domain imitates your organisation": "نطاق المرسل يقلّد نطاق مؤسستك",
    "Look-alike of your organisation's domain": "نطاق شبيه بنطاق مؤسستك",
    "Claims to be internal but comes from outside": "يدّعي أنه داخلي لكنه من خارج المؤسسة",
    "Message-ID domain mismatch": "عدم تطابق نطاق معرّف الرسالة",
    "Link text disguises the real destination": "نص الرابط يُخفي الوجهة الحقيقية",
    "Email body contains a password field": "نص البريد يحتوي حقلاً لكلمة المرور",
    "HTML emails should never ask for passwords inline.": "يجب ألا يطلب البريد كلمة المرور داخل الرسالة أبداً.",
    # --- URL
    "Dangerous URL scheme": "بروتوكول رابط خطير",
    "Unparseable URL": "رابط غير قابل للتحليل",
    "No valid host could be extracted from the URL.": "تعذّر استخراج مضيف صالح من الرابط.",
    "Link points to a raw IP address": "الرابط يشير إلى عنوان IP مباشرة",
    "Legitimate services almost always use domain names; raw-IP links are common in phishing and malware delivery.":
        "الخدمات الموثوقة تستخدم أسماء نطاقات غالباً؛ الروابط بعناوين IP مباشرة شائعة في التصيّد ونشر البرمجيات الخبيثة.",
    "Link targets a private/internal IP": "الرابط يستهدف عنوان IP داخلياً",
    "The URL points at a private network address.": "الرابط يشير إلى عنوان في شبكة خاصة.",
    "Domain is on the 3B blocklist": "النطاق موجود في قائمة حظر 3B",
    "An analyst previously blocked this domain in the local 3B environment.": "قام محلل سابقاً بحظر هذا النطاق في بيئة 3B.",
    "Unencrypted HTTP link": "رابط HTTP غير مشفّر",
    "The link does not use HTTPS. Credentials sent here could be intercepted.": "الرابط لا يستخدم HTTPS. يمكن اعتراض أي بيانات دخول تُرسل عبره.",
    "Credentials/@ trick in URL": "خدعة الرمز @ في الرابط",
    "The URL contains an '@' in the host part. Browsers ignore everything before '@', a trick to disguise the real destination.":
        "يحتوي الرابط على «@» في جزء المضيف. المتصفح يتجاهل كل ما قبله، وهذه خدعة لإخفاء الوجهة الحقيقية.",
    "Non-standard port": "منفذ غير معتاد",
    "Internationalised (punycode) domain": "نطاق بأحرف دولية (Punycode)",
    "Non-ASCII characters in domain": "أحرف غير لاتينية في النطاق",
    "High-abuse top-level domain": "امتداد نطاق كثير الاستغلال",
    "URL shortener": "رابط مختصر",
    "Shortened links hide the true destination.": "الروابط المختصرة تُخفي الوجهة الحقيقية.",
    "Excessive subdomains": "نطاقات فرعية كثيرة",
    "Hyphen-heavy domain": "نطاق مليء بالشرطات",
    "Domains like 'secure-login-verify' are typical of phishing kits.": "نطاقات مثل «secure-login-verify» نموذجية في أدوات التصيّد.",
    "Imitates your organisation's domain": "يقلّد نطاق مؤسستك",
    "Sensitive keywords in link path": "كلمات حساسة في مسار الرابط",
    "Very long URL": "رابط طويل جداً",
    "Link downloads an executable file": "الرابط يُنزّل ملفاً تنفيذياً",
    "The URL points directly at an executable/script file type.": "الرابط يشير مباشرة إلى ملف تنفيذي أو سكربت.",
    "Embedded redirect": "إعادة توجيه مضمّنة",
    "The URL embeds another URL, a pattern used for open-redirect abuse.": "الرابط يتضمن رابطاً آخر، وهو نمط يُستغل لإعادة التوجيه.",
    "URL is on the 3B blocklist": "الرابط موجود في قائمة حظر 3B",
    "An analyst blocked this exact URL.": "قام محلل بحظر هذا الرابط تحديداً.",
    "Domain does not exist (NXDOMAIN)": "النطاق غير موجود (NXDOMAIN)",
    "DNS reports the domain is not registered/resolvable. It may be taken down, not yet live, or fabricated.":
        "يفيد DNS بأن النطاق غير مسجّل أو لا يُستدل عليه. ربما أُزيل أو لم يُفعَّل بعد أو أنه مختلق.",
    "No mail (MX) records": "لا توجد سجلات بريد (MX)",
    "The domain resolves but has no mail servers — unusual for a domain sending business email.": "النطاق موجود لكن بلا خوادم بريد — غير معتاد لنطاق يرسل بريد أعمال.",
    # --- files
    "Hash matches a known-malicious file": "البصمة تطابق ملفاً خبيثاً معروفاً",
    "File extension does not match real file type": "امتداد الملف لا يطابق نوعه الحقيقي",
    "Declared MIME type differs from content": "نوع الملف المُعلن يختلف عن محتواه",
    "Double file extension": "امتداد ملف مزدوج",
    "Document name hides a web page": "اسم مستند يُخفي صفحة ويب",
    "Right-to-left override in filename": "حرف عكس الاتجاه في اسم الملف",
    "The filename uses the RLO character to visually reverse its extension.": "يستخدم اسم الملف حرف RLO لعكس امتداده بصرياً.",
    "Executable or script file type": "ملف تنفيذي أو سكربت",
    "Very high entropy": "عشوائية مرتفعة جداً",
    "Archive contains executable or script": "الأرشيف يحتوي ملفاً تنفيذياً أو سكربت",
    "Double extension inside archive": "امتداد مزدوج داخل الأرشيف",
    "Password-protected archive": "أرشيف محمي بكلمة مرور",
    "Encrypted archives prevent security scanning and are often used to smuggle malware past email filters.":
        "الأرشيفات المشفّرة تمنع الفحص الأمني وتُستخدم كثيراً لتمرير البرمجيات الخبيثة عبر فلاتر البريد.",
    "Corrupted ZIP structure": "بنية ZIP تالفة",
    "File has a ZIP signature but could not be parsed.": "الملف يحمل توقيع ZIP لكن تعذّر تحليله.",
    "Office document contains VBA macros": "مستند Office يحتوي وحدات ماكرو VBA",
    "Macro-enabled documents can run code when the user clicks 'Enable Content'.": "المستندات التي تحتوي ماكرو يمكنها تشغيل أوامر عند الضغط على «تمكين المحتوى».",
    "Remote template / external OLE reference": "قالب خارجي / مرجع OLE خارجي",
    "Document loads content from an external location when opened (template injection).": "المستند يحمّل محتوى من مكان خارجي عند فتحه (حقن القالب).",
    "Possible zip bomb": "قنبلة ZIP محتملة",
    "Extremely high compression ratio.": "نسبة ضغط مرتفعة جداً.",
    "PDF contains JavaScript": "ملف PDF يحتوي JavaScript",
    "Embedded JavaScript can exploit PDF readers or redirect users.": "يمكن لـ JavaScript المضمّن استغلال برامج قراءة PDF أو إعادة توجيه المستخدم.",
    "PDF auto-action on open": "ملف PDF ينفّذ إجراءً تلقائياً عند فتحه",
    "The PDF triggers an action automatically when opened.": "ينفّذ ملف PDF إجراءً تلقائياً عند فتحه.",
    "PDF /Launch action": "أمر تشغيل برنامج داخل PDF",
    "Can launch external programs.": "يمكنه تشغيل برامج خارجية.",
    "PDF has embedded files": "ملف PDF يحتوي ملفات مضمّنة",
    "Files hidden inside the PDF.": "ملفات مخفية داخل PDF.",
    "PDF contains a submittable form": "ملف PDF يحتوي نموذجاً قابلاً للإرسال",
    "Forms inside PDFs are used to harvest credentials.": "النماذج داخل PDF تُستخدم لجمع بيانات الدخول.",
    "Legacy Office file with macro streams": "ملف Office قديم يحتوي ماكرو",
    "OLE document appears to contain VBA macro storage.": "يبدو أن المستند يحتوي تخزيناً لماكرو VBA.",
    "Container formats are commonly used to deliver malware past filters. Contents were not extracted.": "صيغ الحاويات تُستخدم كثيراً لتمرير البرمجيات الخبيثة. لم تُستخرج المحتويات.",
    "HTML attachment contains a login form": "مرفق HTML يحتوي نموذج تسجيل دخول",
    "Local HTML files with password fields are a common credential-phishing technique.": "ملفات HTML التي تحتوي حقول كلمة مرور أسلوب شائع لتصيّد بيانات الدخول.",
    "Active script in HTML/SVG": "سكربت نشط في HTML/SVG",
    "The file contains <script> tags that run when opened in a browser.": "يحتوي الملف أوسمة <script> تعمل عند فتحه في المتصفح.",
    "QR code found in image": "رمز QR في الصورة",
    "Image contains GPS location metadata": "الصورة تحتوي بيانات موقع GPS",
    "EXIF GPS data is embedded — a privacy concern, and useful for forensics.": "بيانات GPS مضمّنة — مصدر قلق للخصوصية ومفيدة للتحقيق.",
    "Script-like content in image metadata": "محتوى يشبه السكربت في بيانات الصورة",
    "Metadata contains code-like strings, which can indicate steganographic payload staging.": "تحتوي البيانات الوصفية نصوصاً تشبه الأوامر، وقد يدل ذلك على إخفاء حمولة داخل الصورة.",
    "Image could not be decoded": "تعذّر فك ترميز الصورة",
    "Hidden data appended after image end": "بيانات مخفية بعد نهاية الصورة",
    "Metadata references a synthetic-media tool": "البيانات الوصفية تذكر أداة لإنشاء وسائط مصطنعة",
    "PowerShell encoded/IEX execution": "تشغيل PowerShell مُرمَّز / IEX",
    "WScript.Shell object (runs commands)": "كائن WScript.Shell (ينفّذ أوامر)",
    "cmd.exe /c command execution": "تنفيذ أوامر cmd.exe /c",
    "Base64 payload decoding": "فك حمولة مرمّزة بـ Base64",
    "Downloads content from the internet": "يُنزّل محتوى من الإنترنت",
    "Auto-executing macro entry point": "ماكرو يعمل تلقائياً",
    "Obfuscated eval()": "دالة eval() مموّهة",
    "Living-off-the-land binary (LOLBin) invocation": "استدعاء أداة نظام تُستغل في الهجمات (LOLBin)",
    "file content": "محتوى الملف",
    "Windows executable (PE)": "ملف تنفيذي لـ Windows",
    "Linux executable (ELF)": "ملف تنفيذي لـ Linux",
    "PDF document": "مستند PDF",
    "PNG image": "صورة PNG",
    "JPEG image": "صورة JPEG",
    "GIF image": "صورة GIF",
    "ZIP archive / Office Open XML": "أرشيف ZIP / مستند Office",
    "RAR archive": "أرشيف RAR",
    "7-Zip archive": "أرشيف 7-Zip",
    "GZIP archive": "أرشيف GZIP",
    "ISO disk image": "صورة قرص ISO",
    "Windows shortcut (LNK)": "اختصار Windows (LNK)",
    "HTML document": "مستند HTML",
    "Plain text": "نص عادي",
    "Unknown binary": "ملف ثنائي غير معروف",
    # --- network / IP / phone
    "Documentation/test IP range": "نطاق IP مخصّص للتوثيق/الاختبار",
    "This address is reserved for documentation (RFC 5737/3849) and is not routable on the internet. Used in 3B demo scenarios.":
        "هذا العنوان مخصّص للتوثيق (RFC 5737/3849) ولا يعمل على الإنترنت. يُستخدم في سيناريوهات عرض 3B.",
    "Private / internal address": "عنوان خاص / داخلي",
    "This is not a public internet address; it belongs to a local network. External geolocation does not apply.":
        "ليس عنواناً عاماً على الإنترنت؛ بل ينتمي لشبكة محلية. لا ينطبق عليه تحديد الموقع الخارجي.",
    "Reserved / special-purpose address": "عنوان محجوز / لاستخدام خاص",
    "Address is in a special-purpose range.": "العنوان ضمن نطاق مخصّص لاستخدام خاص.",
    "IP is on the 3B blocklist": "عنوان IP موجود في قائمة حظر 3B",
    "An analyst blocked this IP in the local environment.": "قام محلل بحظر هذا العنوان.",
    "Provider flags IP as proxy/VPN/Tor": "المزوّد يصنّف العنوان كبروكسي/VPN/Tor",
    "The geolocation provider marks this IP as an anonymising proxy.": "يصنّف مزوّد الموقع هذا العنوان كخدمة لإخفاء الهوية.",
    "Hosting / data-centre IP": "عنوان استضافة / مركز بيانات",
    "IP belongs to a hosting provider rather than a residential or corporate network — typical for phishing servers, also for legitimate services.":
        "العنوان يتبع مزوّد استضافة لا شبكة منزلية أو شركة — شائع في خوادم التصيّد وفي الخدمات السليمة أيضاً.",
    "IP reported for abuse": "عنوان IP مُبلّغ عنه بسبب إساءة",
    "IP has some abuse reports": "يوجد بعض البلاغات عن هذا العنوان",
    "International number": "رقم دولي",
    "Satellite / international-network number": "رقم شبكة فضائية / دولية",
    "These ranges are frequently used for premium-rate and wangiri fraud.": "هذه النطاقات تُستخدم كثيراً في احتيال الأرقام مرتفعة التكلفة والمكالمات الفائتة.",
    "UAE mobile number format": "صيغة رقم هاتف متحرك إماراتي",
    "UAE toll-free / shared-cost number format": "صيغة رقم إماراتي مجاني / مشترك التكلفة",
    "Unknown (no country code)": "غير معروف (بدون رمز دولة)",
    "United Arab Emirates": "الإمارات العربية المتحدة",
    "Saudi Arabia": "السعودية",
    "Local network": "شبكة محلية",
    "Special-purpose address": "عنوان لاستخدام خاص",
    "Origin unknown": "المصدر غير معروف",
    "Origin unknown (external lookups off)": "المصدر غير معروف (البحث الخارجي متوقف)",
    # --- endpoint
    "Document/email app spawned a script host": "برنامج مستندات/بريد شغّل مشغّل سكربتات",
    "Script interpreter executed": "تم تشغيل مُفسِّر سكربتات",
    "Obfuscated / download command line": "أمر مموّه / أمر تنزيل",
    "Command line contains encoded or download-cradle patterns.": "سطر الأوامر يحتوي ترميزاً أو أنماط تنزيل.",
    "Executed from a temporary/download folder": "شُغّل من مجلد مؤقت/تنزيلات",
    "Process ran from a location used for email attachments and downloads.": "العملية شُغّلت من مكان تُحفظ فيه مرفقات البريد والتنزيلات.",
    "Double-extension file executed": "تشغيل ملف بامتداد مزدوج",
    "A file disguised as a document was executed.": "تم تشغيل ملف متنكّر كمستند.",
    "Connection to a blocklisted destination": "اتصال بوجهة محظورة",
    "Connection on a port associated with C2/backdoors": "اتصال عبر منفذ مرتبط بالأبواب الخلفية",
    "Script host made an outbound connection": "مشغّل سكربت أجرى اتصالاً صادراً",
    "Executable file written": "تمت كتابة ملف تنفيذي",
    "Repeated failed logins": "محاولات دخول فاشلة متكررة",
    "Connection to a blocked IP": "اتصال بعنوان IP محظور",
    "Connection to an IP flagged in an investigation": "اتصال بعنوان IP مُعلَّم في تحقيق",
    "Script interpreter connecting to the internet": "مُفسِّر سكربتات يتصل بالإنترنت",
    "Program from Temp/Downloads using the network": "برنامج من مجلد Temp/التنزيلات يستخدم الشبكة",
    "Programs running from temporary or download folders are often freshly delivered malware.": "البرامج التي تعمل من المجلدات المؤقتة أو التنزيلات تكون غالباً برمجيات خبيثة وصلت حديثاً.",
    "Port often used by backdoors": "منفذ تستخدمه الأبواب الخلفية غالباً",
    "Remote side is a proxy/VPN/Tor exit": "الطرف الآخر بروكسي/VPN/Tor",
    "The network owner is flagged as an anonymising service.": "مالك الشبكة مصنّف كخدمة لإخفاء الهوية.",
    "Inbound connection from the internet": "اتصال وارد من الإنترنت",
    "Defender real-time protection is off": "الحماية الفورية في Defender متوقفة",
    "Malware will not be blocked when files are opened.": "لن تُمنع البرمجيات الخبيثة عند فتح الملفات.",
    "Antivirus is disabled": "مكافحة الفيروسات معطّلة",
    "Microsoft Defender antivirus reports as disabled.": "يُبلغ Microsoft Defender أن مكافحة الفيروسات معطّلة.",
    "Antivirus signatures are out of date": "تعريفات مكافحة الفيروسات قديمة",
    "The firewall is disabled for this network profile, so inbound attacks are not filtered.": "جدار الحماية متوقف لملف الشبكة هذا، لذلك لا تتم تصفية الهجمات الواردة.",
    "Security posture weakness": "ضعف في وضع الحماية",
    "Unknown program": "برنامج غير معروف",
    "live agent telemetry": "بيانات مباشرة من الوكيل",
    "agent posture check": "فحص حالة الحماية من الوكيل",
    # --- incidents, actions & messages
    "Recommend isolation for": "التوصية بعزل",
    "Incident marked false positive after email was reviewed as safe.": "تم تصنيف الحادثة كإنذار كاذب بعد مراجعة البريد واعتباره آمناً.",
    "Email moved to 3B quarantine (local record). Not removed from any external mailbox — no mail integration is connected.":
        "نُقل البريد إلى حجر 3B (سجل محلي). لم يُحذف من أي صندوق بريد خارجي — لا يوجد ربط بالبريد.",
    "Email released from 3B quarantine.": "أُخرج البريد من حجر 3B.",
    "Email marked safe after analyst review.": "تم تعليم البريد كآمن بعد مراجعة المحلل.",
    "Email marked as suspicious.": "تم تعليم البريد كمشبوه.",
    "Reported to IT security: an incident was opened/updated in 3B.": "تم الإبلاغ لفريق أمن المعلومات: فُتحت/حُدّثت حادثة في 3B.",
    "Escalated to SOC lead / CISO queue (3B notification centre). No external email/SMS/paging integration is configured.":
        "صُعّدت إلى قائد مركز العمليات الأمنية / مسؤول أمن المعلومات (مركز إشعارات 3B). لا يوجد ربط بإرسال بريد أو رسائل خارجية.",
    "Local 3B record deleted. No external mailbox was modified.": "حُذف السجل من 3B. لم يُعدَّل أي صندوق بريد خارجي.",
    "Demo environment reset.": "تمت إعادة ضبط بيئة العرض.",
    "These endpoint events are SIMULATED for the demo.": "أحداث الأجهزة هذه محاكاة لأغراض العرض.",
    "Marking a critical-risk email as safe requires a review note.": "تعليم بريد عالي الخطورة كآمن يتطلب ملاحظة مراجعة.",
    "A resolution note is required to resolve or close an incident.": "ملاحظة الحل مطلوبة لحل الحادثة أو إغلاقها.",
    "No changes supplied": "لم يتم تقديم أي تغييرات",
    "Analysis not found": "التحليل غير موجود",
    "Email analysis not found": "تحليل البريد غير موجود",
    "Incident not found": "الحادثة غير موجودة",
    "Device not found": "الجهاز غير موجود",
    "Linked analysis not found": "التحليل المرتبط غير موجود",
    "Indicator not found": "المؤشر غير موجود",
    "Command not found": "الأمر غير موجود",
    "Not found": "غير موجود",
    "Invalid IP address": "عنوان IP غير صحيح",
    "Invalid domain": "نطاق غير صحيح",
    "Hash must be a SHA-256 hex digest": "يجب أن تكون البصمة بصيغة SHA-256",
    "Missing X-3B-User header (select a user in Settings).": "لم يتم تحديد المستخدم (اختر مستخدماً من الإعدادات).",
    "Rate limit exceeded — please wait a minute.": "تم تجاوز عدد الطلبات المسموح — انتظر دقيقة.",
    "Provide an .eml file or paste the email source/body.": "أرفق ملف ‎.eml أو الصق مصدر البريد/نصه.",
    "Upload a .eml file (or paste the raw email).": "ارفع ملف ‎.eml (أو الصق البريد الخام).",
    "Outlook .msg files are not supported yet — in Outlook use 'Save as' → .eml, or paste the message source.": "ملفات Outlook ‎.msg غير مدعومة بعد — في Outlook استخدم «حفظ باسم» ← ‎.eml، أو الصق مصدر الرسالة.",
    "Pasted email too large.": "البريد الملصق كبير جداً.",
    "Uploaded file is empty.": "الملف المرفوع فارغ.",
    "Uploaded file is empty": "الملف المرفوع فارغ",
    "Message text is empty": "نص الرسالة فارغ",
    "Enter a valid URL or domain (e.g. https://example.com/login).": "أدخل رابطاً أو نطاقاً صحيحاً (مثل https://example.com/login).",
    "Enter a valid domain name (e.g. example.com).": "أدخل اسم نطاق صحيحاً (مثل example.com).",
    "Not a valid phone number (expected 6–15 digits, optionally with + country code)": "رقم هاتف غير صحيح (من 6 إلى 15 رقماً، مع رمز الدولة اختيارياً)",
    "Transcript too long (max 100k characters).": "نص المحادثة طويل جداً (100 ألف حرف كحد أقصى).",
    "Threshold must be between 30 and 95": "يجب أن يكون الحد بين 30 و95",
    "Device user consent is required before 3B monitoring can be enabled.": "موافقة مستخدم الجهاز مطلوبة قبل تفعيل مراقبة 3B.",
    "This device has no 3B agent installed, so it cannot receive commands.": "لا يوجد وكيل 3B مثبّت على هذا الجهاز، لذلك لا يمكنه استقبال أوامر.",
    "Invalid device token": "رمز الجهاز غير صحيح",
    "Missing X-Device-Token": "رمز الجهاز مفقود",
    "No active incidents": "لا توجد حوادث نشطة",
    "Relationship directly present in submitted evidence or endpoint telemetry": "علاقة موجودة مباشرة في الأدلة أو بيانات الأجهزة",
    "Relationship inferred by 3B (e.g. same person, no shared artefact)": "علاقة استنتجها 3B (مثل الشخص نفسه، دون دليل مشترك)",
    "observed link": "رابط مُلاحَظ",
    "inferred link": "رابط مُستنتَج",
    "owned by": "يملكه",
    "evidence": "دليل",
    "reported": "أبلغ عن",
    "sender": "المرسل",
    "reply to": "الرد إلى",
    "recipient": "المستلم",
    "link": "رابط",
    "attachment": "مرفق",
    "attachment inner": "داخل المرفق",
    "sender domain": "نطاق المرسل",
    "dest domain": "نطاق الوجهة",
    "dest ip": "عنوان الوجهة",
    "file name": "اسم الملف",
    "process target": "ملف العملية",
    "Correlated": "تم الربط",
    "3B correlation engine": "محرّك الربط في 3B",
    "Matched": "تطابق",
    "Email Security": "أمن البريد الإلكتروني",
    "Scam Analyzer": "محلل الاحتيال",
    "Network Intelligence": "استخبارات الشبكة",
    "File Forensics": "فحص الملفات",
    "Multimedia Forensics": "فحص الوسائط",
    "Endpoint Protection": "حماية الأجهزة",
    "Manual": "يدوي",
    "SMS": "رسالة نصية",
    "WhatsApp": "واتساب",
    "Chat": "دردشة",
    "Call transcript": "نص مكالمة",
    "Email text": "نص بريد",
    "Message": "رسالة",
    "(no subject)": "(بدون موضوع)",
    "[verified]": "[مؤكَّد]",
    "[heuristic]": "[نمط]",
    "[intel]": "[مصدر خارجي]",
    "[ai]": "[ذكاء اصطناعي]",
    "Isolation is recommended, not enforced, in the MVP": "يُوصى بالعزل ولا يُفرض في هذا الإصدار",
    "Dynamic detonation sandbox is a planned isolated service; uploads are analysed statically.": "البيئة المعزولة للتشغيل خدمة مخطّط لها؛ تُحلَّل الملفات المرفوعة بشكل ثابت.",
    "Planned: Microsoft Graph API (Mail.Read, Mail.ReadWrite) with admin consent": "مخطّط: Microsoft Graph API (Mail.Read وMail.ReadWrite) بموافقة المسؤول",
    "Planned: Gmail API with domain-wide delegation": "مخطّط: Gmail API بتفويض على مستوى النطاق",
    "Hash lookups only; files are never uploaded": "بحث بالبصمات فقط؛ لا تُرفع الملفات أبداً",
    "System resolver via dnspython (when external lookups are on)": "استعلام DNS من النظام (عند تفعيل البحث الخارجي)",
    "ip-api.com free tier (when external lookups are on)": "خدمة ip-api.com المجانية (عند تفعيل البحث الخارجي)",
    "All samples are harmless test data generated by 3B.": "جميع الأمثلة بيانات اختبار غير ضارة أنشأها 3B.",
    "Simulated inventory device for the demo": "جهاز محاكاة في الجرد لأغراض العرض",
    # --- call guard
    "Call Guard": "حارس المكالمات",
    "Caller gave the wrong UAE time": "المتصل ذكر وقتاً خاطئاً للإمارات",
    "Caller gave the wrong day": "المتصل ذكر يوماً خاطئاً",
    "Organisation could not be verified": "تعذّر التحقق من الجهة",
    "Known UAE organisation": "جهة إماراتية معروفة",
    "Not found among known UAE organisations": "غير موجودة ضمن الجهات الإماراتية المعروفة",
    "Claim checks compare what was said with the real UAE time/date and a directory of known UAE organisations. 3B cannot tell the two voices apart: ask your question and let the caller answer.":
        "يقارن التحقق ما قيل بالوقت والتاريخ الفعليين في الإمارات وبدليل الجهات الإماراتية المعروفة. لا يميّز 3B بين الصوتين: اطرح سؤالك ودع المتصل يجيب.",
    "Wrong user name or password.": "اسم المستخدم أو كلمة المرور غير صحيحة.",
    "Too many sign-in attempts — wait a minute.": "محاولات دخول كثيرة — انتظر دقيقة.",
    "Please sign in.": "يرجى تسجيل الدخول.",
    "Current password is wrong.": "كلمة المرور الحالية غير صحيحة.",
    "Pairing code is wrong, already used or expired.": "رمز الربط غير صحيح أو مستخدم أو منتهي الصلاحية.",
    "Consent is required to protect this phone.": "الموافقة مطلوبة لحماية هذا الجوال.",
    "This phone was unlinked and its data deleted from 3B.": "تم فك ربط هذا الجوال وحذف بياناته من 3B.",
    "Repeated failed logins for local account": "محاولات دخول فاشلة متكررة لحساب محلي",
    "powershell.exe launched by WINWORD.EXE": "WINWORD.EXE شغّل powershell.exe",
    "Teams.exe updated": "تم تحديث Teams.exe",
    "Text message sent from an email address": "رسالة نصية مُرسلة من عنوان بريد إلكتروني",
    "Banks, government services and delivery companies send SMS from short names or numbers. Messages from email addresses (iMessage) are a common way scammers bypass SMS filters.":
        "البنوك والجهات الحكومية وشركات التوصيل ترسل الرسائل من أسماء مختصرة أو أرقام. الرسائل من عناوين بريد (iMessage) طريقة شائعة لتجاوز فلاتر الرسائل.",
    "Sender number is on the 3B blocklist": "رقم المرسل موجود في قائمة حظر 3B",
    "This number was reported as a scam number.": "تم الإبلاغ عن هذا الرقم كرقم احتيال.",
    "Number is on the 3B scam blocklist": "الرقم موجود في قائمة احتيال 3B",
    "Reported as a scam number by an analyst.": "أبلغ محلل أنه رقم احتيال.",
    "Number appeared in scam reports": "ظهر الرقم في بلاغات احتيال",
    "⚠️ 3B: likely scam": "⚠️ 3B: احتيال محتمل",
    "⚠️ 3B: be careful": "⚠️ 3B: كن حذراً",
    "⚠️ 3B: reported scam": "⚠️ 3B: رقم احتيال مُبلّغ عنه",
    "⚠️ 3B: satellite number": "⚠️ 3B: رقم فضائي",
    "Do not share codes, passwords or card numbers. If they claim to be a bank or the police, hang up and call the official number.":
        "لا تشارك أي رموز أو كلمات مرور أو أرقام بطاقات. إذا ادّعى أنه من البنك أو الشرطة، أنهِ المكالمة واتصل بالرقم الرسمي.",
    "Based on the number only. Caller ID can be spoofed.": "مبني على الرقم فقط. يمكن تزييف هوية المتصل.",
    "Missed-call / call-back lure": "خدعة المكالمة الفائتة / معاودة الاتصال",
    "A 'you missed a call' notice from an unknown sender is a common trick to make you call back a premium-rate or scam number (wangiri).":
        "إشعار «لديك مكالمة فائتة» من مرسل مجهول حيلة شائعة لدفعك لمعاودة الاتصال برقم مرتفع التكلفة أو رقم احتيال (Wangiri).",
    "Unknown international number wants a call-back": "رقم دولي مجهول يريد أن تعاود الاتصال به",
    "A missed-call notice pointing to a foreign number is the classic set-up for call-back (wangiri) fraud. Do not call back.":
        "إشعار مكالمة فائتة يشير إلى رقم أجنبي هو التمهيد المعتاد لاحتيال معاودة الاتصال (Wangiri). لا تعاود الاتصال.",
    "Payment request with a link that imitates a known brand": "طلب دفع مع رابط ينتحل اسم جهة معروفة",
    "The message asks you to pay and sends you to a website pretending to be an official service — the pattern of fake toll, fine and parcel-fee scams.":
        "الرسالة تطلب الدفع وتوجّهك إلى موقع ينتحل صفة جهة رسمية — وهو نمط احتيال رسوم الطرق والمخالفات والطرود المزيّفة.",
    "Call (unknown number)": "مكالمة (رقم غير معروف)",
    "Caller number is on the 3B blocklist": "رقم المتصل موجود في قائمة حظر 3B",
    "An analyst previously blocked this number as a scam number.": "قام محلل سابقاً بحظر هذا الرقم كرقم احتيال.",
    "3B cannot intercept phone calls. It only analyses audio captured by this computer's microphone with consent, or recordings you upload.":
        "لا يستطيع 3B اعتراض المكالمات الهاتفية. يحلّل فقط الصوت الذي يلتقطه ميكروفون هذا الجهاز بموافقتك، أو التسجيلات التي ترفعها.",
    "A number's country code shows where the number range is registered — not where the caller physically is. Caller ID can be spoofed.":
        "رمز الدولة في الرقم يبيّن أين سُجّل نطاق الرقم — لا مكان وجود المتصل فعلياً. ويمكن تزييف هوية المتصل.",
    "No caller number provided (hidden/unknown caller).": "لم يُدخل رقم المتصل (متصل مخفي أو مجهول).",
    "No speech was transcribed yet, so the conversation content was not analysed.": "لم يُحوَّل أي كلام إلى نص بعد، لذلك لم يُحلَّل محتوى المحادثة.",
    "Speech-to-text is not installed; type what the caller said into the transcript box.": "تحويل الكلام إلى نص غير مثبّت؛ اكتب ما قاله المتصل في خانة النص.",
    "Tone measurements are weak signals: accents, emotions, phone-line quality and normal stress all affect them. They never prove fraud.":
        "قياسات نبرة الصوت مؤشرات ضعيفة: تتأثر باللهجة والمشاعر وجودة الخط والتوتر العادي. ولا تُثبت الاحتيال أبداً.",
    "Not enough speech in the audio to measure tone.": "لا يوجد كلام كافٍ في التسجيل لقياس النبرة.",
    "Fast, pressured speech": "كلام سريع وضاغط",
    "Raised, agitated voice": "صوت مرتفع ومتوتر",
    "Very flat intonation": "نبرة رتيبة جداً",
    "Almost no pauses": "شبه انعدام للتوقفات",
    "The caller leaves very little room to respond, a pressure tactic.": "المتصل لا يترك مجالاً تقريباً للرد، وهذا أسلوب ضغط.",
    "Consent is required: confirm you are a participant in this call and that analysing it is allowed.": "الموافقة مطلوبة: أكّد أنك طرف في هذه المكالمة وأن تحليلها مسموح.",
    "Caller number is too long.": "رقم المتصل طويل جداً.",
    "Remote-access service reached from the internet": "خدمة وصول عن بُعد يتم الوصول إليها من الإنترنت",
    "Inbound connection from a public address": "اتصال وارد من عنوان عام",
    "Origin lookup failed": "فشل تحديد المصدر",
    "Firewall changes must be explicitly confirmed.": "تغييرات جدار الحماية تتطلب تأكيداً صريحاً.",
    "Refusing to block a private, local or special-purpose address: it could cut the device off from its network or from 3B.":
        "رُفض حظر عنوان خاص أو محلي أو مخصّص: قد يفصل الجهاز عن شبكته أو عن 3B.",
    "The same command is already waiting for the agent.": "الأمر نفسه بانتظار التنفيذ لدى الوكيل.",
    "Turning on external lookups requires explicit consent: public IP addresses and domains will be sent to ip-api.com and your DNS resolver.":
        "تفعيل البحث الخارجي يتطلب موافقة صريحة: سيتم إرسال عناوين IP العامة والنطاقات إلى ip-api.com وخادم DNS لديك.",
}

TEMPLATES: dict[str, str] = {
    "AI review not used: {0}": "لم تُستخدم مراجعة الذكاء الاصطناعي: {0}",
    "AI analysis failed: {0}": "فشل التحليل بالذكاء الاصطناعي: {0}",
    "AI provider error ({0}).": "خطأ لدى مزوّد الذكاء الاصطناعي ({0}).",
    "AI assessment: {0}": "تقييم الذكاء الاصطناعي: {0}",
    "Model {0} · confidence {1}": "النموذج {0} · الثقة {1}",
    "'.{0}' is a low-cost TLD heavily abused for phishing. Not proof of malice.": "الامتداد «‎.{0}» منخفض التكلفة ويُستغل كثيراً في التصيّد. هذا ليس دليلاً على الخبث.",
    "'{0}' disguises an executable as a document.": "«{0}» يُخفي ملفاً تنفيذياً على هيئة مستند.",
    "'{0}' hides an executable extension behind a document extension.": "«{0}» يُخفي امتداداً تنفيذياً خلف امتداد مستند.",
    "'{0}' looks like a document but opens in the browser as a web page.": "«{0}» يبدو كمستند لكنه يُفتح في المتصفح كصفحة ويب.",
    "'{0}' inside the archive is an executable/script type.": "الملف «{0}» داخل الأرشيف ملف تنفيذي أو سكربت.",
    "'{0}' is not a valid IPv4 or IPv6 address": "«{0}» ليس عنوان IPv4 أو IPv6 صحيحاً",
    "'{0}' is sending from a free webmail address ({1}).": "«{0}» يرسل من بريد مجاني ({1}).",
    "'{0}' is visually close to the official '{1}' domain (typosquatting/homoglyph).": "«{0}» يشبه بصرياً النطاق الرسمي «{1}» (انتحال بأخطاء إملائية أو أحرف متشابهة).",
    "'{0}' requires the {1} role.": "الإجراء «{0}» يتطلب صلاحية {1}.",
    "AbuseIPDB confidence score {0}/100 from {1} reports.": "درجة الثقة في AbuseIPDB هي {0}/100 من {1} بلاغ.",
    "AbuseIPDB score {0}/100.": "درجة AbuseIPDB هي {0}/100.",
    "Assign an analyst to critical incident {0}.": "عيّن محللاً للحادثة الحرجة {0}.",
    "Assigned to {0}": "أُسندت إلى {0}",
    "Blocked {0} {1} in the 3B demo environment. Future analyses and endpoint events matching it are flagged. Not pushed to any firewall, proxy or mail gateway.":
        "تم حظر {1} في بيئة 3B. أي تحليلات أو أحداث أجهزة مستقبلية تطابقه ستُعلَّم. لم يُرسل إلى أي جدار حماية أو بروكسي أو بوابة بريد.",
    "Brand name '{0}' used on an unrelated domain": "اسم العلامة «{0}» مستخدم على نطاق لا علاقة له بها",
    "Calling code +{0} is assigned to {1}. Scam calls claiming to be local authorities or banks often come from abroad.":
        "رمز الاتصال ‎+{0} مخصّص لـ {1}. مكالمات الاحتيال التي تدّعي أنها من جهات محلية أو بنوك تأتي غالباً من الخارج.",
    "Command queued. The agent on {0} will run it on its next check-in (only if it was started with --allow-response).":
        "تمت جدولة الأمر. سينفّذه الوكيل على {0} عند اتصاله التالي (فقط إذا شُغّل مع ‎--allow-response).",
    "Decoded {0} QR code(s). QR codes hide destinations from the reader ('quishing').": "تمت قراءة {0} رمز QR. رموز QR تُخفي الوجهة عن القارئ (تصيّد عبر QR).",
    "Destination port {0}.": "منفذ الوجهة {0}.",
    "Device owner {0} received high-risk email {1}": "مالك الجهاز {0} استلم البريد عالي الخطورة {1}",
    "Display name claims '{0}' but domain is unrelated": "اسم العرض يدّعي «{0}» لكن النطاق لا علاقة له",
    "Display name shows '{0}' but the real address is {1}.": "اسم العرض يُظهر «{0}» لكن العنوان الحقيقي هو {1}.",
    "Display name suggests {0} staff, but the address is external.": "اسم العرض يوحي بأنه من موظفي {0}، لكن العنوان خارجي.",
    "Domain contains non-Latin characters ({0}) that can visually imitate Latin letters.": "النطاق يحتوي أحرفاً غير لاتينية ({0}) يمكنها تقليد الأحرف اللاتينية بصرياً.",
    "Domain decodes to '{0}'. Punycode is used in homograph attacks that imitate real brands.": "يُفك النطاق إلى «{0}». يُستخدم Punycode في هجمات تقليد العلامات التجارية.",
    "Encoder/software metadata mentions '{0}'. This suggests (but does not prove) synthetic or edited media.": "البيانات الوصفية تذكر «{0}». هذا يوحي (دون إثبات) بأن الوسائط مُصطنعة أو معدّلة.",
    "Endpoint contacted {0}, which is on the 3B blocklist.": "اتصل الجهاز بـ {0}، وهو في قائمة حظر 3B.",
    "Endpoint threat on {0}: {1}": "تهديد على الجهاز {0}: {1}",
    "Endpoint {0} matches {1} '{2}' from {3} analysis {4}": "بيانات الجهاز ({0}) تطابق ({1}) «{2}» من تحليل {3} رقم {4}",
    "Endpoint {0} shows compromise indicators — recommend isolation.": "الجهاز {0} تظهر عليه مؤشرات اختراق — يُوصى بالعزل.",
    "Endpoint {0}: {1} (risk {2}){3}": "الجهاز {0}: {1} (الخطورة {2}){3}",
    "Entropy {0}/8 suggests packed or encrypted content.": "العشوائية {0}/8 توحي بمحتوى مضغوط أو مشفّر.",
    "Envelope sender is {0}. Common for mailing services, but also for spoofing.": "المرسل الفعلي هو {0}. شائع في خدمات البريد الجماعي، وفي التزييف أيضاً.",
    "File exceeds the {0} MB limit.": "الملف يتجاوز حد {0} ميغابايت.",
    "File type '.{0}' is not accepted. Allowed: documents, archives, images, audio/video, email, executables/scripts (static analysis only).":
        "نوع الملف «‎.{0}» غير مقبول. المسموح: مستندات، أرشيفات، صور، صوت/فيديو، بريد، ملفات تنفيذية/سكربتات (تحليل ثابت فقط).",
    "From {0} → Reply-To {1}": "من {0} ← الرد إلى {1}",
    "Incident created automatically from {0} analysis {1} (risk {2}/100, {3}).": "أُنشئت الحادثة تلقائياً من تحليل {0} رقم {1} (الخطورة {2}/100، {3}).",
    "Incident created from endpoint event #{0} on {1}.": "أُنشئت الحادثة من حدث الجهاز رقم {0} على {1}.",
    "Incident created manually by {0}.": "أنشأ {0} الحادثة يدوياً.",
    "Internal error: {0}. See server log.": "خطأ داخلي: {0}. راجع سجل الخادم.",
    "Isolation recommended for {0}. 3B does not control the network in this MVP — IT must isolate the device via EDR/NAC or by disconnecting it.":
        "يُوصى بعزل {0}. لا يتحكم 3B بالشبكة في هذا الإصدار — على فريق التقنية عزل الجهاز عبر EDR/NAC أو فصله عن الشبكة.",
    "Linked analysis {0}: {1}": "التحليل المرتبط {0}: {1}",
    "Look-alike of '{0}'": "نطاق شبيه بـ «{0}»",
    "Message-ID was generated by '{0}', not the sender's domain.": "معرّف الرسالة أُنشئ بواسطة «{0}»، وليس نطاق المرسل.",
    "Named '.{0}' but the file signature identifies it as: {1}.": "اسمه بامتداد «‎.{0}» لكن توقيع الملف يبيّن أنه: {1}.",
    "Path/query contains: {0}.": "المسار يحتوي: {0}.",
    "Provider unreachable: {0}": "تعذّر الوصول إلى المزوّد: {0}",
    "Remote port {0} is commonly used by remote-access tools and malware.": "المنفذ {0} تستخدمه أدوات الوصول عن بُعد والبرمجيات الخبيثة غالباً.",
    "Replies go to {0}, not the sender {1}. Attackers use this to receive replies on a mailbox they control.":
        "الردود تذهب إلى {0} وليس إلى المرسل {1}. يستخدم المهاجمون ذلك لاستلام الردود على بريد يتحكمون به.",
    "SHA-256 is on the 3B blocklist: {0}": "البصمة SHA-256 موجودة في قائمة حظر 3B: {0}",
    "Sender declared '{0}', content is '{1}'.": "المرسل أعلن «{0}»، والمحتوى الفعلي «{1}».",
    "Sender name references {0} while sending from {1}.": "اسم المرسل يذكر {0} بينما يرسل من {1}.",
    "Severity escalated {0} → {1}: attack progressed from email to endpoint.": "رُفع مستوى الخطورة {0} ← {1}: انتقل الهجوم من البريد إلى الجهاز.",
    "Signatures are {0} days old.": "عمر التعريفات {0} يوم.",
    "Static pattern found in {0}. The file was not executed.": "عُثر على النمط في {0}. لم يُشغَّل الملف.",
    "Suspicious code pattern: {0}": "نمط أوامر مشبوه: {0}",
    "The file claims to be an image but failed to decode: {0}": "يدّعي الملف أنه صورة لكن تعذّر فك ترميزه: {0}",
    "The host contains '{0}' but is not your domain ({1}).": "المضيف يحتوي «{0}» لكنه ليس نطاقك ({1}).",
    "The host contains '{0}' but the registered domain is '{1}', not an official domain ({2}).": "المضيف يحتوي «{0}» لكن النطاق المسجّل هو «{1}»، وليس نطاقاً رسمياً ({2}).",
    "The host has {0} subdomain levels, often used to push the real domain out of view.": "للمضيف {0} مستويات من النطاقات الفرعية، وتُستخدم غالباً لإخفاء النطاق الحقيقي.",
    "The link shows '{0}' but actually opens '{1}'.": "الرابط يُظهر «{0}» لكنه يفتح فعلياً «{1}».",
    "The link uses port {0}.": "الرابط يستخدم المنفذ {0}.",
    "The link uses the '{0}:' scheme, which can execute code or load local content.": "الرابط يستخدم البروتوكول «{0}:» الذي يمكنه تشغيل أوامر أو تحميل محتوى محلي.",
    "The receiving server reported {0}={1}. The message was not authorised by the domain it claims to come from.":
        "أفاد خادم الاستلام بأن {0}={1}. الرسالة غير مُصرَّح بها من النطاق الذي تدّعي أنها منه.",
    "This action requires the '{0}' role (you are '{1}').": "هذا الإجراء يتطلب صلاحية «{0}» (صلاحيتك «{1}»).",
    "Type '{0}' can run code on the recipient's computer.": "النوع «{0}» يمكنه تشغيل أوامر على جهاز المستلم.",
    "URL is {0} characters, which can hide its real destination.": "طول الرابط {0} حرفاً، وقد يُخفي وجهته الحقيقية.",
    "Unknown user '{0}'.": "مستخدم غير معروف «{0}».",
    "Windows Firewall is off ({0} profile)": "جدار حماية Windows متوقف (ملف الشبكة {0})",
    "archive entry '{0}'": "الملف «{0}» داخل الأرشيف",
    "shown {0} → real {1}": "الظاهر {0} ← الحقيقي {1}",
    "{0} '{1}' is already blocked": "«{1}» محظور مسبقاً",
    "{0} (text in image)": "{0} (نص داخل الصورة)",
    "{0} (text on screen)": "{0} (نص على الشاشة)",
    "{0} bytes follow the end-of-image marker (detected as: {1}). This is a known way to hide payloads in images.": "يوجد {0} بايت بعد نهاية الصورة (نوعها: {1}). هذه طريقة معروفة لإخفاء حمولة داخل الصور.",
    "{0} check failed": "فشل فحص {0}",
    "{0} connected in to local port {1} ({2}).": "اتصل {0} بالمنفذ المحلي {1} ({2}).",
    "{0} contains '{1}' but is not {2}.": "{0} يحتوي «{1}» لكنه ليس {2}.",
    "{0} contents were not extracted (only ZIP listing is supported in the MVP).": "لم تُستخرج محتويات {0} (يُدعم عرض ملفات ZIP فقط حالياً).",
    "{0} critical incident(s) need immediate response": "{0} حادثة حرجة تحتاج استجابة فورية",
    "{0} failed login attempts.": "{0} محاولة دخول فاشلة.",
    "{0} high-severity incident(s) under investigation": "{0} حادثة عالية الخطورة قيد التحقيق",
    "{0} is one or two characters away from {1} (typosquatting).": "{0} يختلف بحرف أو حرفين فقط عن {1} (انتحال بأخطاء إملائية).",
    "{0} is talking to {1}, which is on the 3B blocklist.": "{0} يتصل بـ {1}، وهو في قائمة حظر 3B.",
    "{0} launched {1} — a typical malicious-attachment execution chain.": "{0} شغّل {1} — سلسلة تشغيل نموذجية لمرفق خبيث.",
    "{0} lower-severity incident(s) open": "{0} حادثة منخفضة الخطورة مفتوحة",
    "{0} malicious domain/IP indicator(s) are not on the blocklist.": "{0} مؤشر خبيث (نطاق/IP) غير موجود في قائمة الحظر.",
    "{0} not passing ({1})": "{0} لم ينجح ({1})",
    "{0} opened a connection to {1}:{2}. Scripts downloading code is a common malware step.": "{0} فتح اتصالاً بـ {1}:{2}. تنزيل السكربتات لأوامر خطوة شائعة في البرمجيات الخبيثة.",
    "{0} opened a network connection — possible payload download or C2.": "{0} فتح اتصالاً شبكياً — احتمال تنزيل حمولة أو اتصال بخادم تحكم.",
    "{0} passed for the sending domain. Note: attackers can pass these checks on domains they own.": "نجح {0} لنطاق المرسل. ملاحظة: يمكن للمهاجمين اجتياز هذا الفحص على نطاقات يملكونها.",
    "{0} passed": "نجح {0}",
    "{0} quarantined email(s) awaiting analyst review.": "{0} رسالة في الحجر بانتظار مراجعة المحلل.",
    "{0} ran on the endpoint.": "تم تشغيل {0} على الجهاز.",
    "{0} result was '{1}', so the sender's domain could not be confirmed.": "نتيجة {0} كانت «{1}»، لذلك تعذّر تأكيد نطاق المرسل.",
    "{0} suspicious email(s) not yet quarantined or reviewed.": "{0} رسالة مشبوهة لم تُحجز أو تُراجع بعد.",
    "{0} trailing bytes": "{0} بايت إضافي",
    "{0} was created on disk.": "أُنشئ {0} على القرص.",
    "{0} was flagged malicious in a 3B analysis or incident.": "عُلّم {0} كخبيث في تحليل أو حادثة على 3B.",
    "Status {0} → {1}": "الحالة {0} ← {1}",
    "Severity {0} → {1}": "الخطورة {0} ← {1}",
    "Process started: {0} (parent {1})": "بدأت عملية: {0} (العملية الأم {1})",
    "Process started: {0}": "بدأت عملية: {0}",
    "Windows Firewall is off ({0})": "جدار حماية Windows متوقف ({0})",
    "{0} → {1}": "{0} ← {1}",
    "{0} vs {1}": "{0} مقابل {1}",
    "Linked to {0} high-risk message(s) or call(s) analysed by 3B.": "مرتبط بـ {0} رسالة أو مكالمة عالية الخطورة حلّلها 3B.",
    "SMS from {0}: {1}": "رسالة من {0}: {1}",
    "Call from {0}": "مكالمة من {0}",
    "The caller said “{0}”, but the time in the UAE is {1}, about {2} hour(s) different. Someone really calling from the UAE would know the local time — this suggests the caller is abroad.":
        "قال المتصل «{0}»، لكن الوقت في الإمارات {1}، بفارق نحو {2} ساعة. من يتصل فعلاً من الإمارات يعرف الوقت المحلي — وهذا يشير إلى أن المتصل خارج الدولة.",
    "The caller said today is {0}, but in the UAE today is {1}.": "قال المتصل إن اليوم {0}، لكن اليوم في الإمارات {1}.",
    "Claims to be {0} but calls from a foreign number": "يدّعي أنه من {0} لكنه يتصل من رقم أجنبي",
    "{0} is a UAE organisation, but the call comes from a number registered to {1}. UAE government bodies, banks and telecoms call from UAE numbers.":
        "{0} جهة إماراتية، لكن المكالمة من رقم مسجّل لدى {1}. الجهات الحكومية والبنوك وشركات الاتصالات في الإمارات تتصل من أرقام إماراتية.",
    "The caller says they are from “{0}”, which is not in 3B's directory of known UAE organisations. It may be a small company, a mishearing, or an invented name — ask for the official number and call back yourself.":
        "يقول المتصل إنه من «{0}»، وهي غير موجودة في دليل 3B للجهات الإماراتية المعروفة. قد تكون شركة صغيرة أو خطأ في السماع أو اسماً مختلقاً — اطلب الرقم الرسمي واتصل بنفسك.",
    "said {0} · actual {1} GST": "قال {0} · الفعلي {1} بتوقيت الإمارات",
    "said {0} · actual {1}": "قال {0} · الفعلي {1}",
    "{0} (UAE, UTC+4)": "{0} (الإمارات، UTC+4)",
    "Outbound HTTP connection to {0}": "اتصال HTTP صادر إلى {0}",
    "wscript.exe outbound to {0}": "wscript.exe يتصل للخارج بـ {0}",
    "wscript.exe executed {0}": "wscript.exe شغّل الملف {0}",
    "SIMULATED: {0}": "محاكاة: {0}",
    "Caller number not analysed: {0}": "لم يُحلَّل رقم المتصل: {0}",
    "The caller speaks at about {0} words per minute, faster than typical conversation (~120–160). Scammers often talk fast to prevent the listener from thinking.":
        "يتحدث المتصل بنحو {0} كلمة في الدقيقة، أسرع من المحادثة المعتادة (~120–160). المحتالون يتحدثون بسرعة غالباً لمنع المستمع من التفكير.",
    "Large pitch movement ({0} semitones) and loudness swings ({1} dB) suggest an agitated or insistent tone — a common pressure tactic, but also normal in heated conversations.":
        "تغيّر كبير في طبقة الصوت ({0} نصف نغمة) وفي ارتفاعه ({1} ديسيبل) يوحي بنبرة متوترة أو ملحّة — أسلوب ضغط شائع، وطبيعي أيضاً في النقاشات الحادة.",
    "Pitch barely changes ({0} semitones). This can happen with scripted reading, recorded messages or synthetic voices — and with some normal speakers. Not evidence on its own.":
        "طبقة الصوت شبه ثابتة ({0} نصف نغمة). قد يحدث هذا عند القراءة من نص أو في الرسائل المسجلة أو الأصوات المصطنعة — ولدى بعض المتحدثين العاديين. ليس دليلاً بمفرده.",
    "A public address ({0}) has an open connection to {1} on port {2}. This is not proof of an intrusion, but these services should not be exposed to the internet.":
        "يوجد اتصال مفتوح من عنوان عام ({0}) إلى {1} على المنفذ {2}. هذا ليس دليلاً على اختراق، لكن لا ينبغي كشف هذه الخدمات على الإنترنت.",
    "{0} is connected to local port {1} ({2}). Normal for servers, games and P2P apps; review if unexpected.":
        "{0} متصل بالمنفذ المحلي {1} ({2}). هذا طبيعي للخوادم والألعاب وتطبيقات المشاركة؛ راجعه إن كان غير متوقع.",
    "Asked the agent on {0} to list 3B firewall rules (read-only).": "طُلب من الوكيل على {0} عرض قواعد جدار الحماية الخاصة بـ 3B (قراءة فقط).",
    "Audio exceeds the {0} MB limit.": "الملف الصوتي يتجاوز حد {0} ميغابايت.",
    "Could not decode the audio: {0}": "تعذّر فك ترميز الصوت: {0}",
    "{0} ≈ {1}": "{0} ≈ {1}",
}

# classification-style prefixes "X: rest" and evidence prefixes
_SEP_RX = re.compile(r"^(.{2,60}?): (.+)$", re.S)
_SOURCE_RX = re.compile(r"^\[(verified|heuristic|intel|ai)\] (.+?)(?: — (.+))?$", re.S)
_CORR_RX = re.compile(r"^Correlated: (.+)$", re.S)

_compiled: list[tuple[re.Pattern, str]] = []
for en, ar in sorted(TEMPLATES.items(), key=lambda kv: -len(kv[0])):
    parts = re.split(r"(\{\d+\})", en)
    rx = "".join("(.+?)" if re.fullmatch(r"\{\d+\}", p) else re.escape(p) for p in parts)
    _compiled.append((re.compile("^" + rx + "$", re.S), ar))

SEV_AR = {"critical": "حرج", "high": "مرتفع", "medium": "متوسط", "low": "منخفض", "info": "معلومة",
          "open": "مفتوحة", "investigating": "قيد التحقيق", "contained": "تم احتواؤها", "resolved": "تم حلّها",
          "false_positive": "إنذار كاذب", "admin": "مسؤول", "analyst": "محلل", "employee": "موظف"}


def _group(g: str, depth: int) -> str:
    if g in SEV_AR:
        return SEV_AR[g]
    if g in EXACT:
        return EXACT[g]
    return translate(g, depth + 1) if depth < 2 else g


def translate(s: str, depth: int = 0) -> str:
    if not s or not isinstance(s, str):
        return s
    if s in EXACT:
        return EXACT[s]
    for rx, ar in _compiled:
        m = rx.match(s)
        if m:
            out = ar
            for i, g in enumerate(m.groups()):
                out = out.replace("{" + str(i) + "}", _group(g, depth))
            return out
    if depth > 2:
        return s
    m = _SOURCE_RX.match(s)
    if m:
        src = EXACT.get(f"[{m.group(1)}]", m.group(1))
        tail = f" — {translate(m.group(3), depth + 1)}" if m.group(3) else ""
        return f"{src} {translate(m.group(2), depth + 1)}{tail}"
    m = _CORR_RX.match(s)
    if m:
        return EXACT["Correlated"] + ": " + " | ".join(translate(p.strip(), depth + 1) for p in m.group(1).split(" | "))
    if "; " in s:
        parts = s.split("; ")
        tr_parts = [translate(p, depth + 1) for p in parts]
        if any(a != b for a, b in zip(parts, tr_parts)):
            return "؛ ".join(tr_parts)
    m = _SEP_RX.match(s)
    if m:
        left, right = m.group(1), m.group(2)
        l2 = EXACT.get(left, left)
        r2 = translate(right, depth + 1)
        if l2 != left or r2 != right:
            return f"{l2}: {r2}"
    if s.startswith("Matched: "):
        return EXACT["Matched"] + ": " + s[len("Matched: "):]
    return s


DISPLAY_KEYS = {"title", "detail", "summary", "message", "result", "classification", "threat_categories", "recommended_actions",
                "limitations", "score_note", "social_engineering_techniques", "recommended_response", "text", "security_status_text",
                "reason", "error", "label", "note", "evidence", "reasons", "advice", "step", "why", "question", "listen_for", "actual", "said", "observed", "inferred", "label_text"}


def translate_obj(obj, key: str | None = None):
    if isinstance(obj, dict):
        return {k: translate_obj(v, k) for k, v in obj.items()}
    if isinstance(obj, list):
        return [translate_obj(v, key) for v in obj]
    if isinstance(obj, str) and key in DISPLAY_KEYS:
        return translate(obj)
    return obj


# Organisation names from the claim-check directory (first Arabic alias) and calling-code regions.
def _extend() -> None:
    from .services.claims import ORGANISATIONS
    from .services.network_intel import CALLING_CODES

    for canon, aliases in ORGANISATIONS:
        ar = next((a for a in aliases if any("؀" <= ch <= "ۿ" for ch in a)), None)
        if ar and canon not in EXACT:
            EXACT[canon] = ar
    regions = {
        "United Arab Emirates": "الإمارات العربية المتحدة", "Saudi Arabia": "السعودية", "Qatar": "قطر", "Kuwait": "الكويت", "Bahrain": "البحرين",
        "Oman": "عُمان", "Egypt": "مصر", "Jordan": "الأردن", "Lebanon": "لبنان", "Syria": "سوريا", "Iraq": "العراق", "Iran": "إيران", "Turkey": "تركيا",
        "Pakistan": "باكستان", "India": "الهند", "Bangladesh": "بنغلاديش", "Sri Lanka": "سريلانكا", "Nepal": "نيبال", "Philippines": "الفلبين",
        "Indonesia": "إندونيسيا", "Malaysia": "ماليزيا", "China": "الصين", "Hong Kong": "هونغ كونغ", "Russia/Kazakhstan": "روسيا/كازاخستان",
        "United Kingdom": "المملكة المتحدة", "USA/Canada (NANP)": "أمريكا/كندا", "France": "فرنسا", "Germany": "ألمانيا", "Nigeria": "نيجيريا",
        "Ghana": "غانا", "Kenya": "كينيا", "South Africa": "جنوب أفريقيا", "Morocco": "المغرب", "Algeria": "الجزائر", "Tunisia": "تونس",
        "Sudan": "السودان", "Somalia": "الصومال", "Ethiopia": "إثيوبيا", "Vietnam": "فيتنام", "Cambodia": "كمبوديا", "Myanmar": "ميانمار",
        "Laos": "لاوس", "International Networks (satellite/IoT)": "شبكات دولية (أقمار صناعية/إنترنت الأشياء)",
        "International Networks": "شبكات دولية", "Global Mobile Satellite": "شبكة اتصالات فضائية عالمية", "another country": "دولة أخرى",
    }
    for v in CALLING_CODES.values():
        if v in regions:
            EXACT.setdefault(v, regions[v])
    EXACT.setdefault("another country", "دولة أخرى")


_extend()
