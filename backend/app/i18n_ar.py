"""Arabic translation of backend-generated text (reports, alerts, messages).

Applied to JSON responses when the client sends `X-3B-Lang: ar` (see main.py), and to the
exported HTML report. Only display fields are translated — identifiers and enum values are not.
EXACT holds fixed sentences; TEMPLATES hold sentences with values, written with {0}, {1}…
"""
from __future__ import annotations

import re

EXACT: dict[str, str] = {
    "Thank you. Your report is counted once and reviewed by a moderator. A single report never blocks a number for others.": "شكراً. بلاغك يُحسب مرة واحدة ويراجعه مشرف. بلاغ واحد لا يحظر الرقم عن الآخرين أبداً.",
    "This is not on the shared list, so nothing is being blocked or warned about.": "هذا غير مدرج في القائمة المشتركة، لذلك لا يوجد حظر أو تحذير بشأنه.",
    "Thank you. An analyst will review it. While an unverified warning is under appeal it is paused for everyone.": "شكراً. سيراجعه محلل. أثناء الاعتراض يتوقف التحذير غير الموثق للجميع.",
    "The library is a reference for the engine, not a complete list of every scam. Seeded methods need a reviewer and a source before they are marked Verified.": "المكتبة مرجع للمحرك وليست قائمة كاملة بكل الاحتيالات. الأساليب الأولية تحتاج مراجعاً ومصدراً قبل توثيقها.",
    "Not listed doesn't mean safe. A report is not proof.": "عدم الإدراج لا يعني الأمان. والبلاغ ليس دليلاً.",
    "Possible duplicate of an existing method.": "قد يكون مكرراً لأسلوب موجود.",
    "Counts come from the 3B database. 'user' is real submitted data; 'demo' is fictional and labelled DEMO.": "الأعداد من قاعدة بيانات 3B. «user» بيانات حقيقية مُرسلة؛ و«demo» بيانات خيالية مُعلّمة كتجريبية.",
    "You already reported this number in the last 24 hours. Thank you — one report per person counts.": "سبق أن أبلغت عن هذا الرقم خلال 24 ساعة. شكراً — يُحسب بلاغ واحد لكل شخص.",
    "Daily report limit reached. Please try again tomorrow.": "وصلت للحد اليومي للبلاغات. حاول غداً.",
    "That doesn't look like a phone number. Use international format, e.g. +971 50 123 4567.": "هذا لا يبدو رقم هاتف. استخدم الصيغة الدولية، مثل ‎+971 50 123 4567.",
    "Only an administrator can mark a method Verified.": "فقط المسؤول يستطيع توثيق الأسلوب.",
    "A method can be marked Verified only with at least one source (title + URL or document reference).": "لا يُوثّق الأسلوب إلا بمصدر واحد على الأقل (عنوان + رابط أو مرجع وثيقة).",
    "Explain the evidence (at least a sentence) when verifying or allow-listing.": "اشرح الدليل (جملة على الأقل) عند التوثيق أو التصنيف كسليم.",
    "Explain the evidence or reason (at least a sentence).": "اشرح الدليل أو السبب (جملة على الأقل).",
    "Please explain why this is a mistake (at least a sentence).": "يرجى شرح سبب الخطأ (جملة على الأقل).",
    "Add a short decision note.": "أضف ملاحظة قرار قصيرة.",
    "Not reported": "لم يُبلّغ عنه",
    "Unknown report category.": "فئة بلاغ غير معروفة.",
    "Shared behaviour": "سلوك مشترك",
    "The wording is close to this method's examples.": "الصياغة قريبة من أمثلة هذا الأسلوب.",
    "move or pay money": "نقل أو دفع مال",
    "reveal a code or password": "كشف رمز أو كلمة مرور",
    "hand over personal or ID details": "تسليم بيانات شخصية أو هوية",
    "act through a link": "التصرف عبر رابط",
    "install an app or give remote access": "تثبيت تطبيق أو منح وصول عن بُعد",
    "approve a request in an app": "الموافقة على طلب في تطبيق",
    "move to a private chat": "الانتقال لمحادثة خاصة",
    "claim to be a bank": "ادعاء أنه بنك",
    "claim to be an authority": "ادعاء أنه جهة رسمية",
    "claim to be a courier": "ادعاء أنه شركة توصيل",
    "offer a job": "عرض وظيفة",
    "claim to be family or a friend": "ادعاء أنه قريب أو صديق",
    "pitch an investment": "عرض استثمار",
    "claim to be tech support": "ادعاء أنه دعم فني",
    "claim to be a telecom provider": "ادعاء أنه شركة اتصالات",
    "use fear": "استخدام الخوف",
    "rush you": "الاستعجال",
    "promise money or rewards": "الوعد بالمال أو المكافآت",
    "appeal to sympathy": "استدرار التعاطف",
    "ask for secrecy": "طلب الكتمان",
    "send money to an unusual account or wallet": "إرسال المال لحساب أو محفظة غير معتادة",
    "ask a fee before you receive something": "طلب رسوم قبل استلام شيء",
    "a bank": "بنك",
    "a government body or the police": "جهة حكومية أو الشرطة",
    "a delivery company": "شركة توصيل",
    "technical support": "الدعم الفني",
    "a telecom provider": "شركة اتصالات",
    "an organisation": "جهة ما",
    "A bank": "بنك",
    "A government body or the police": "جهة حكومية أو الشرطة",
    "A delivery company": "شركة توصيل",
    "Technical support": "الدعم الفني",
    "A telecom provider": "شركة اتصالات",
    "An organisation": "جهة ما",
    "Supporting phrases": "عبارات داعمة",
    "Asks you to reveal a code, PIN or password": "يطلب منك كشف رمز أو رقم سري أو كلمة مرور",
    "Whoever holds this code can use your account. A genuine person or company has no reason to ask for it.": "من يملك هذا الرمز يستطيع استخدام حسابك. لا يوجد سبب يجعل شخصاً أو جهة حقيقية تطلبه.",
    "Asks you to move money to an account they choose": "يطلب نقل أموالك إلى حساب يختاره هو",
    "The sender wants your money moved to a 'safe', new or personal account, wallet or gift cards. Banks and authorities never move customers' money this way — this is the core of 'safe-account' fraud.": "المرسل يريد نقل أموالك إلى حساب «آمن» أو جديد أو شخصي أو محفظة أو بطاقات هدايا. البنوك والجهات الرسمية لا تنقل أموال العملاء بهذه الطريقة — وهذا جوهر احتيال «الحساب الآمن».",
    "An authority demands payment by message or phone, under threat": "جهة رسمية تطلب الدفع عبر رسالة أو مكالمة مع التهديد",
    "Fines, visa or residency fees are paid through official government apps and websites, not by instructions in a call or message that threatens you.": "المخالفات ورسوم التأشيرة والإقامة تُدفع عبر التطبيقات والمواقع الحكومية الرسمية، وليس بتعليمات في مكالمة أو رسالة تهددك.",
    "A 'relative or friend' on an unusual number asks for money": "«قريب أو صديق» من رقم غير معتاد يطلب مالاً",
    "Someone says they are family or a friend (often 'my new number' or 'my phone broke') and then asks for money. Call them on the number you already have before paying anything.": "شخص يقول إنه من العائلة أو صديق (غالباً «هذا رقمي الجديد» أو «خرب تلفوني») ثم يطلب مالاً. اتصل به على الرقم الذي لديك قبل أن تدفع أي شيء.",
    "You must pay first to receive something": "يجب أن تدفع أولاً لتحصل على شيء",
    "The message asks for a fee, deposit or 'top-up' before you can receive a job, prize, refund, loan, parcel or profit. Paying to receive money is the signature of advance-fee fraud.": "الرسالة تطلب رسوماً أو عربوناً أو «شحن رصيد» قبل أن تحصل على وظيفة أو جائزة أو استرداد أو قرض أو طرد أو أرباح. الدفع مقابل استلام المال هو علامة احتيال الرسوم المسبقة.",
    "Investment offer built on promised returns": "عرض استثمار مبني على أرباح موعودة",
    "The sender promises steady or guaranteed returns and invites you to put money in. Real investments carry risk and come from licensed firms you contact yourself.": "المرسل يعد بأرباح ثابتة أو مضمونة ويدعوك لوضع أموالك. الاستثمارات الحقيقية فيها مخاطرة وتأتي من شركات مرخصة تتواصل معها بنفسك.",
    "Unexpected money request built on a story": "طلب مال غير متوقع مبني على قصة",
    "The request comes with an emotional or 'by mistake' story (an accident, a wrong transfer, family need). Check the story independently — e.g. in your own banking app — before sending anything.": "الطلب يأتي مع قصة عاطفية أو «بالغلط» (حادث، تحويل خاطئ، حاجة عائلية). تحقق من القصة بنفسك — مثلاً في تطبيق بنكك — قبل إرسال أي شيء.",
    "Payment to an unusual destination": "دفع إلى وجهة غير معتادة",
    "You're asked to pay into a personal account, wallet, phone number or with gift cards/crypto instead of an official payment channel.": "يُطلب منك الدفع إلى حساب شخصي أو محفظة أو رقم هاتف أو ببطاقات هدايا أو عملات رقمية بدلاً من قناة دفع رسمية.",
    "A payment request that arrives with a deadline, a threat or a link is how fake fine, toll, bill and parcel-fee scams work. Pay only inside the official app or website you open yourself.": "طلب دفع يأتي مع مهلة أو تهديد أو رابط هو أسلوب احتيال المخالفات والبوابات والفواتير ورسوم الطرود المزيفة. ادفع فقط داخل التطبيق أو الموقع الرسمي الذي تفتحه بنفسك.",
    "Money request under pressure": "طلب مال تحت الضغط",
    "You're asked to pay or transfer money while being rushed or kept quiet.": "يُطلب منك الدفع أو التحويل مع الاستعجال أو الكتمان.",
    "Asks for money": "يطلب مالاً",
    "The message asks you to send or pay money. On its own this is normal; it matters only with other warning signs.": "الرسالة تطلب منك إرسال أو دفع مال. هذا وحده أمر عادي؛ يصبح مهماً فقط مع علامات تحذير أخرى.",
    "Collects identity or account details": "يجمع بيانات الهوية أو الحساب",
    "You're asked for ID, passport, date of birth, account or payroll details — enough to open accounts or take over yours. Organisations that already know you don't collect this by message or link.": "يُطلب منك الهوية أو الجواز أو تاريخ الميلاد أو بيانات الحساب أو الراتب — وهذا يكفي لفتح حسابات باسمك أو الاستيلاء على حسابك. الجهات التي تعرفك لا تجمع هذه البيانات عبر رسالة أو رابط.",
    "Asks for personal details": "يطلب بيانات شخصية",
    "Personal information is requested. Confirm who is asking through a channel you trust.": "تُطلب معلومات شخصية. تأكد من هوية الطالب عبر قناة تثق بها.",
    "Asks you to install an app or share your screen": "يطلب منك تثبيت تطبيق أو مشاركة الشاشة",
    "Remote-access and 'support' apps give the other person control of your phone or computer, including your banking app.": "تطبيقات التحكم عن بُعد و«الدعم» تعطي الطرف الآخر سيطرة على هاتفك أو حاسوبك، بما في ذلك تطبيق البنك.",
    "Asks you to approve a request in your app": "يطلب منك الموافقة على طلب في تطبيقك",
    "Approving the notification is what authorises the payment or login. A genuine bank never asks you to approve something to 'stop' a transaction.": "الموافقة على الإشعار هي ما يعتمد الدفع أو الدخول. البنك الحقيقي لا يطلب منك الموافقة على شيء «لإيقاف» عملية.",
    "Job offer that costs you money": "عرض عمل يكلّفك مالاً",
    "Genuine employers don't charge for jobs, training, visas or 'activating' a work account, and don't pay for liking or rating things.": "أصحاب العمل الحقيقيون لا يأخذون رسوماً مقابل الوظيفة أو التدريب أو التأشيرة أو «تفعيل» حساب عمل، ولا يدفعون مقابل الإعجابات أو التقييمات.",
    "Moves you to a private chat or group": "ينقلك إلى محادثة خاصة أو مجموعة",
    "Moving the conversation to WhatsApp/Telegram groups keeps it away from moderation and is common in investment and job scams.": "نقل المحادثة إلى مجموعات واتساب أو تيليجرام يبعدها عن الرقابة، وهو شائع في احتيال الاستثمار والوظائف.",
    "Tells you to keep it secret": "يطلب منك الكتمان",
    "Being told not to involve the bank, family or colleagues removes the people most likely to stop the scam.": "عندما يُطلب منك ألا تُشرك البنك أو العائلة أو الزملاء، فهذا يبعد أكثر الناس قدرة على إيقاف الاحتيال.",
    "Risky request combined with pressure": "طلب خطِر مع ضغط",
    "The message asks you to act (pay, log in, share details) and pushes you to do it fast or under threat.": "الرسالة تطلب منك التصرف (الدفع، تسجيل الدخول، مشاركة البيانات) وتدفعك لفعل ذلك بسرعة أو تحت التهديد.",
    "Link presented as the way to avoid a problem": "رابط يُقدَّم كطريقة لتجنب مشكلة",
    "You're told something bad will happen unless you act through the link — the standard set-up of a phishing page.": "يُقال لك إن شيئاً سيئاً سيحدث ما لم تتصرف عبر الرابط — وهذا الإعداد المعتاد لصفحة تصيّد.",
    "Scam-related words appear, but the message is protective advice (e.g. 'do not share this code') and asks you for nothing risky, so they were weighted down.": "تظهر كلمات مرتبطة بالاحتيال، لكن الرسالة نصيحة وقائية (مثل «لا تشارك هذا الرمز») ولا تطلب منك شيئاً خطراً، لذلك خُفّض وزنها.",
    "Scam-related words appear, but the message doesn't ask you to pay, share secrets or personal data, install anything or open a link, so they were weighted down.": "تظهر كلمات مرتبطة بالاحتيال، لكن الرسالة لا تطلب منك الدفع أو مشاركة الرموز أو البيانات الشخصية أو تثبيت شيء أو فتح رابط، لذلك خُفّض وزنها.",
    "Keyword checks only flag common scam wording; the intent layer reads what the message asks you to do, who it claims to be and how it pressures you.": "فحص الكلمات يرصد فقط الصياغات الشائعة؛ أما طبقة النية فتقرأ ما تطلبه الرسالة منك، ومن تدّعي أنها، وكيف تضغط عليك.",
    "No close match in the scam-methods library. That doesn't make it safe: new techniques have no match yet.": "لا يوجد تطابق قريب في مكتبة أساليب الاحتيال. هذا لا يعني أنها آمنة: الأساليب الجديدة ليس لها تطابق بعد.",
    "This content behaves like a method in 3B's scam-methods library (see the similar methods list). Similarity is a pointer, not proof.": "هذا المحتوى يتصرف مثل أسلوب في مكتبة أساليب الاحتيال في 3B (انظر قائمة الأساليب المشابهة). التشابه مؤشر وليس دليلاً.",
    "Known legitimate identifier": "معرّف معروف بأنه سليم",
    "WARNING: This message contains suspicious characteristics. We recommend verifying the sender independently before taking any action.": "تحذير: هذه الرسالة فيها خصائص مشبوهة. ننصح بالتحقق من المرسل بنفسك قبل اتخاذ أي إجراء.",
    "HIGH RISK: Several signs of a scam. Don't pay, share codes or personal details, or use the links until you have verified the sender through an official channel.": "خطورة مرتفعة: عدة علامات احتيال. لا تدفع ولا تشارك الرموز أو البيانات الشخصية ولا تستخدم الروابط حتى تتحقق من المرسل عبر قناة رسمية.",
    "DANGER: This matches how scams work. Stop: don't pay, share codes or approve anything. Contact the organisation through its official number.": "خطر: هذا يطابق طريقة عمل الاحتيال. توقف: لا تدفع ولا تشارك الرموز ولا توافق على أي شيء. تواصل مع الجهة عبر رقمها الرسمي.",
    "Verified technical checks": "فحوص تقنية مؤكدة",
    "Threat intelligence": "استخبارات التهديدات",
    "Heuristic and behaviour analysis": "تحليل الأنماط والسلوك",
    "AI analysis": "تحليل الذكاء الاصطناعي",
    "No signals": "لا توجد إشارات",
    "No strong indicators found": "لم تُرصد مؤشرات قوية",
    "Malicious indicator confirmed by a verified source": "مؤشر خبيث مؤكد من مصدر موثوق",
    "Suspected — not confirmed": "مشتبه به — غير مؤكد",
    "toll_fine": "مخالفة بوابات",
    "delivery": "توصيل",
    "bank_impersonation": "انتحال صفة بنك",
    "job": "وظيفة",
    "investment": "استثمار",
    "government_impersonation": "انتحال صفة جهة حكومية",
    "shopping": "تسوق",
    "qr": "رمز QR",
    "romance": "احتيال عاطفي",
    "account_takeover": "الاستيلاء على حساب",
    "phishing": "تصيّد",
    "malware": "برمجية خبيثة",
    "other": "أخرى",
    "banking": "احتيال بنكي",
    "government": "انتحال صفة حكومية",
    "harassment": "إزعاج",
    "support": "دعم فني مزيف",
    "payment": "طلب دفع مشبوه",
    "Number is not valid in its country's numbering plan": "الرقم غير صالح في خطة الترقيم لبلده",
    "This number can't be a real line in that country's plan. Spoofed or placeholder numbers often look like this.": "لا يمكن أن يكون هذا الرقم خطاً حقيقياً في خطة ذلك البلد. الأرقام المزورة أو الوهمية غالباً تبدو هكذا.",
    "Internet (VoIP) number": "رقم إنترنت (VoIP)",
    "VoIP numbers are easy to obtain anonymously. Many are legitimate; combined with other signs they matter more.": "أرقام VoIP سهلة الحصول دون هوية. كثير منها سليم؛ لكنها تصبح أهم مع علامات أخرى.",
    "Premium-rate number": "رقم بتعرفة مرتفعة",
    "Calling back may cost money per minute.": "معاودة الاتصال قد تكلّف مالاً عن كل دقيقة.",
    "Reviewed as legitimate": "تمت مراجعته كرقم سليم",
    "Reviewed as legitimate (DEMO data)": "تمت مراجعته كرقم سليم (بيانات تجريبية)",
    "Confirmed scam number": "رقم احتيال مؤكد",
    "Confirmed scam number (DEMO data)": "رقم احتيال مؤكد (بيانات تجريبية)",
    "An analyst reviewed the reports and evidence and confirmed this number was used for scams.": "راجع محلل البلاغات والأدلة وأكد أن هذا الرقم استُخدم في الاحتيال.",
    "On the 3B verified threat list": "مدرج في قائمة التهديدات المؤكدة في 3B",
    "On the 3B verified threat list (DEMO data)": "مدرج في قائمة التهديدات المؤكدة في 3B (بيانات تجريبية)",
    "Verified by an analyst or a trusted source. Opted-in devices warn about or block this number.": "تم التحقق منه من محلل أو مصدر موثوق. الأجهزة المشتركة تحذّر من هذا الرقم أو تحظره.",
    "On the 3B suspicious list (not verified)": "مدرج في قائمة الاشتباه في 3B (غير مؤكد)",
    "On the 3B suspicious list (not verified) (DEMO data)": "مدرج في قائمة الاشتباه في 3B (غير مؤكد) (بيانات تجريبية)",
    "Several independent signals, awaiting analyst review. Devices show a warning only.": "عدة إشارات مستقلة بانتظار مراجعة محلل. الأجهزة تعرض تحذيراً فقط.",
    "Verified business number": "رقم جهة تجارية موثّق",
    "No reports for this number": "لا توجد بلاغات عن هذا الرقم",
    "The country is where the number range is assigned, not where the caller is.": "البلد هو مكان تخصيص نطاق الرقم، وليس مكان المتصل.",
    "Caller ID can be spoofed: a call can show any number.": "يمكن تزوير هوية المتصل: قد تُظهر المكالمة أي رقم.",
    "'Original network' comes from the number range; the number may have moved to another operator.": "«الشبكة الأصلية» مأخوذة من نطاق الرقم؛ وقد يكون الرقم انتقل إلى مشغّل آخر.",
    "No reports or warnings for this number. Unknown does not mean dangerous — and it does not mean safe.": "لا بلاغات أو تحذيرات عن هذا الرقم. المجهول لا يعني خطراً — ولا يعني آمناً.",
    "Not available — 3B has no licensed caller-name source and never guesses names.": "غير متاح — لا يملك 3B مصدراً مرخصاً لأسماء المتصلين ولا يخمّن الأسماء أبداً.",
    "Linked through shared links or near-identical messages — not proof of the same people.": "مرتبط عبر روابط مشتركة أو رسائل شبه متطابقة — وليس دليلاً على أنهم نفس الأشخاص.",
    "Same exact identifier": "نفس المعرّف تماماً",
    "Strongly related campaign": "حملة مرتبطة بقوة",
    "Potentially related activity": "نشاط قد يكون مرتبطاً",
    "Similar scam technique": "أسلوب احتيال مشابه",
    "Both reports name the same phone number.": "البلاغان يذكران نفس رقم الهاتف.",
    "Both reports contain a link to the same domain.": "البلاغان يحتويان رابطاً لنفس النطاق.",
    "Both reports mention the same email address.": "البلاغان يذكران نفس البريد الإلكتروني.",
    "The numbers differ only in the last two digits (possibly one block of numbers). Weak on its own.": "الرقمان يختلفان في آخر خانتين فقط (ربما من نفس مجموعة الأرقام). مؤشر ضعيف وحده.",
    "The two domains are built from the same words or look almost the same — typical when a campaign registers new look-alike sites.": "النطاقان مبنيان من نفس الكلمات أو متشابهان جداً — وهذا معتاد عندما تسجل حملة مواقع جديدة مشابهة.",
    "The messages are near-copies of one template (numbers, links or a few words changed). This shows the same script, not the same person.": "الرسالتان نسختان شبه متطابقتين من قالب واحد (تغيّرت الأرقام أو الروابط أو كلمات قليلة). هذا يدل على نفس النص، وليس نفس الشخص.",
    "The messages share much of their wording and structure.": "الرسالتان تتشاركان كثيراً من الصياغة والبنية.",
    "Same type of scam, but no shared identifier or wording.": "نفس نوع الاحتيال، لكن دون معرّف أو صياغة مشتركة.",
    "Reports share an identifier or a near-identical message template.": "البلاغات تتشارك معرّفاً أو قالب رسالة شبه متطابق.",
    "Linked by the evidence listed on each edge. Not proof that the same people are behind every report.": "مرتبطة بالأدلة المذكورة على كل رابط. وليس دليلاً على أن نفس الأشخاص وراء كل بلاغ.",
    "Verified scam indicator": "مؤشر احتيال مؤكد",
    "Reported by several 3B users — not verified": "أبلغ عنه عدة مستخدمين في 3B — غير مؤكد",
    "Only hashes, categories and levels are distributed. Reporter identities and report texts never leave the server.": "تُوزَّع فقط البصمات والتصنيفات والمستويات. هويات المبلّغين ونصوص البلاغات لا تغادر الخادم أبداً.",
    "Reported by several 3B users": "أبلغ عنه عدة مستخدمين في 3B",
    "Reported by several 3B users (DEMO data)": "أبلغ عنه عدة مستخدمين في 3B (بيانات تجريبية)",
    "Reported once to 3B": "أُبلغ عنه مرة واحدة في 3B",
    "Reported once to 3B (DEMO data)": "أُبلغ عنه مرة واحدة في 3B (بيانات تجريبية)",
    "Matches a scam template already reported to 3B": "يطابق قالب احتيال سبق الإبلاغ عنه في 3B",
    "Matches a scam template already reported to 3B (DEMO data)": "يطابق قالب احتيال سبق الإبلاغ عنه في 3B (بيانات تجريبية)",
    "phone": "رقم هاتف",
    "email": "بريد إلكتروني",
    "email domain": "نطاق بريد",
    "domain": "نطاق",
    "url": "رابط",
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
    "Asks you to approve a notification or request": "يطلب منك الموافقة على إشعار أو طلب",
    "Tells you to confirm or approve a notification, prompt or request — approving it in your banking app is what sends the money.":
        "يطلب منك تأكيد أو الموافقة على إشعار أو طلب — والموافقة عليه في تطبيق البنك هي ما يحوّل المال.",
    "Account 'problem' used to make you approve a request": "«مشكلة» في الحساب لدفعك إلى الموافقة على طلب",
    "The caller says your account is at risk and asks you to approve a notification. Real banks never ask you to approve a payment to stop one.":
        "يقول المتصل إن حسابك في خطر ويطلب منك الموافقة على إشعار. البنوك الحقيقية لا تطلب أبداً الموافقة على دفعة لإيقاف دفعة.",
    "The request may have been approved": "يبدو أن الطلب تمت الموافقة عليه",
    "After the caller asked for a notification to be approved, someone on the call said they approved it. If that was a payment, call your bank now — it can sometimes still be stopped.":
        "بعد أن طلب المتصل الموافقة على إشعار، قال أحد طرفي المكالمة إنه وافق عليه. إذا كان ذلك دفعة، اتصل ببنكك الآن — فقد يمكن إيقافها أحياناً.",
    "The payment you approved may already be on its way — they may call back to “reverse” it and ask you to approve more.":
        "قد تكون الدفعة التي وافقت عليها في طريقها الآن — وقد يعاود الاتصال بحجة «إلغائها» ويطلب منك الموافقة على المزيد.",
    "Approving the notification is what sends the money.": "الموافقة على الإشعار هي ما يحوّل المال.",
    "Call your bank now on the number printed on your card and ask them to stop the transaction. Approve nothing else.":
        "اتصل ببنكك الآن على الرقم المطبوع على بطاقتك واطلب إيقاف العملية. لا توافق على أي شيء آخر.",
    "They will ask you to approve the notification in your banking app — that approval is what sends the money to them.":
        "سيطلب منك الموافقة على الإشعار في تطبيق البنك — وهذه الموافقة هي ما يحوّل المال إليه.",
    "A real bank blocks a suspicious payment itself; it never asks you to approve one.": "البنك الحقيقي يوقف الدفعة المشبوهة بنفسه، ولا يطلب منك الموافقة عليها أبداً.",
    "Never approve a notification you did not start yourself. Hang up and call your bank.": "لا توافق أبداً على إشعار لم تبدأه بنفسك. أنهِ المكالمة واتصل ببنكك.",
    "Why would approving a payment stop a payment?": "كيف توقف الموافقةُ على دفعةٍ دفعةً أخرى؟",
    "A real bank blocks a suspicious payment itself. It never asks you to approve one.": "البنك الحقيقي يوقف الدفعة المشبوهة بنفسه، ولا يطلب منك الموافقة عليها أبداً.",
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
    "Claims to be {0} but asks for a secret code or password": "يدّعي أنه {0} لكنه يطلب رمزاً سرياً أو كلمة مرور",
    "The sender presents as {0} and asks you to reveal a code, PIN, password or card security number. The real organisation already has what it needs and never asks for these.": "المرسل يقدّم نفسه على أنه {0} ويطلب منك كشف رمز أو رقم سري أو كلمة مرور أو رمز أمان البطاقة. الجهة الحقيقية لديها ما تحتاجه ولا تطلب هذه أبداً.",
    "The sender presents as {0} and wants your money moved to a 'safe', new or personal account, wallet or gift cards. Banks and authorities never move customers' money this way — this is the core of 'safe-account' fraud.": "المرسل يقدّم نفسه على أنه {0} ويريد نقل أموالك إلى حساب «آمن» أو جديد أو شخصي أو محفظة أو بطاقات هدايا. البنوك والجهات الرسمية لا تنقل أموال العملاء بهذه الطريقة — وهذا جوهر احتيال «الحساب الآمن».",
    "{0} asks for payment with pressure or a link": "{0} يطلب الدفع مع ضغط أو رابط",
    "Resembles a known scam method: {0}": "يشبه أسلوب احتيال معروفاً: {0}",
    "{0} was verified as malicious by an analyst or a trusted reputation provider ({1}). Other users reported it before you.": "{0} تم التحقق من أنه خبيث من محلل أو مزوّد سمعة موثوق ({1}). مستخدمون آخرون أبلغوا عنه قبلك.",
    "{0} was reported by {1} different users ({2}). Not yet verified, so treat it as a warning, not proof.": "{0} أبلغ عنه {1} مستخدمين مختلفين ({2}). لم يُتحقق منه بعد، لذا اعتبره تحذيراً وليس دليلاً.",
    "{0} appears in a user report that has not been verified. On its own this proves nothing.": "{0} يظهر في بلاغ مستخدم لم يُتحقق منه. هذا وحده لا يثبت شيئاً.",
    "{0} was reviewed and marked legitimate.": "{0} تمت مراجعته وتصنيفه كسليم.",
    "This message is {0}% similar to report {1} ({2}), even if numbers, links or some words differ. It shows the same script is in use, not that the same person sent it.": "هذه الرسالة مشابهة بنسبة {0}% للبلاغ {1} ({2})، حتى لو اختلفت الأرقام أو الروابط أو بعض الكلمات. هذا يدل على استخدام نفس النص، وليس أن نفس الشخص أرسلها.",
    "Known scam {0} on the 3B shared list": "{0} احتيال معروف في القائمة المشتركة في 3B",
    "{0} community report": "بلاغ مجتمعي واحد",
    "{0} community reports": "{0} بلاغات من المجتمع",
    "Reported by {0} different user as: {1}. Reports are claims by users, not proof.": "أبلغ عنه مستخدم واحد كـ: {1}. البلاغات ادعاءات من المستخدمين وليست دليلاً.",
    "Reported by {0} different users as: {1}. Reports are claims by users, not proof.": "أبلغ عنه {0} مستخدمين مختلفين كـ: {1}. البلاغات ادعاءات من المستخدمين وليست دليلاً.",
    "Named in {0} scam report": "مذكور في بلاغ احتيال واحد",
    "Named in {0} scam reports": "مذكور في {0} بلاغات احتيال",
    "People who reported scams to 3B gave this number ({0}).": "أشخاص أبلغوا 3B عن احتيال ذكروا هذا الرقم ({0}).",
    "An analyst reviewed this number and marked it legitimate{0}.": "راجع محلل هذا الرقم وصنّفه سليماً{0}.",
    "Recorded as {0} by an administrator from a verified source.": "مسجل باسم {0} من قِبل مسؤول بناءً على مصدر موثق.",
    "Known scam {0} on the 3B shared list (DEMO data)": "{0} احتيال معروف في القائمة المشتركة في 3B (بيانات تجريبية)",
    "{0} community report (DEMO data)": "بلاغ مجتمعي واحد (بيانات تجريبية)",
    "{0} community reports (DEMO data)": "{0} بلاغات من المجتمع (بيانات تجريبية)",
    "Named in {0} scam report (DEMO data)": "مذكور في بلاغ احتيال واحد (بيانات تجريبية)",
    "Named in {0} scam reports (DEMO data)": "مذكور في {0} بلاغات احتيال (بيانات تجريبية)",
    "AI review not used: {0}": "لم تُستخدم مراجعة الذكاء الاصطناعي: {0}",
    "No URL reputation provider was queried (no key configured, or external lookups are off); 3B does not claim reputation results.": "لم يُستعلم من أي مزوّد لسمعة الروابط (لا يوجد مفتاح، أو الاستعلامات الخارجية مطفأة)؛ لا يدّعي 3B أي نتيجة سمعة.",
    "Listed as phishing by {0}": "مُدرج كتصيّد لدى {0}",
    "Listed as malware by {0}": "مُدرج كبرمجية خبيثة لدى {0}",
    "Flagged as suspicious by {0}": "مُصنّف كمشبوه لدى {0}",
    "{0}: no record — not being listed is not proof that a link is safe.": "{0}: لا يوجد سجل — عدم إدراج الرابط ليس دليلاً على أنه آمن.",
    "{0}: {1} — reputation unknown, not clean.": "{0}: {1} — السمعة غير معروفة، وليست نظيفة.",
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
                "reason", "error", "label", "note", "evidence", "reasons", "advice", "step", "why", "question", "listen_for", "actual", "said", "observed", "inferred", "label_text", "warning", "assessment_status", "verdict_basis", "explanation", "level_text", "relationship", "confidence_note", "caller_name_note", "notes"}


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


def _extend_methods() -> None:
    """Scam-method names (English -> Arabic) so 'Resembles a known scam method: X' reads fully in Arabic."""
    from .knowledge.methods_seed import ROWS
    from .knowledge.names_ar import NAMES_AR

    for row in ROWS:
        if NAMES_AR.get(row[0]):
            EXACT.setdefault(row[1], NAMES_AR[row[0]])


_extend_methods()
