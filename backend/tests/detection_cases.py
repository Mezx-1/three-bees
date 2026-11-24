"""Detection evaluation set: 10 obvious scams, 10 sophisticated scams without the usual scam words, 10+ legitimate messages.

All messages were written by the 3B team for testing. They are fictional: names, numbers, domains and amounts
are placeholders. This is a self-made test set, not an independent benchmark.
"""

OBVIOUS = [
    ("en", "Dear customer, your ADCB card has been blocked due to suspicious activity. Share the OTP sent to your mobile immediately to unblock it."),
    ("en", "URGENT: Your parcel is on hold. Pay 7 AED redelivery fee now at http://aramex-redeliver.example.com/pay or it will be returned."),
    ("en", "Congratulations! You have won 500,000 AED in the Etisalat anniversary draw. To claim your prize, pay the 1,000 AED processing fee today."),
    ("en", "Abu Dhabi Police: an arrest warrant has been issued in your name. Pay the fine immediately via this link to cancel the case: http://adpolice-fines.example.net"),
    ("en", "Hi, it's the CEO. I need you to make an urgent wire transfer of 85,000 AED to a new supplier account today. Keep this confidential and don't call me, I'm in a meeting."),
    ("en", "Guaranteed 30% monthly profit with our bitcoin trading platform! Deposit today, only 5 places left: https://crypto-gold.example.org"),
    ("en", "We are hiring! Earn 800 AED per day liking videos from home. Pay 300 AED registration fee to start your job."),
    ("ar", "عزيزي العميل، سيتم إيقاف حسابك البنكي خلال 24 ساعة. يرجى تحديث بياناتك عبر الرابط: http://bank-update.example.com"),
    ("ar", "معك البنك، بطاقتك موقوفة. عطني الرمز اللي وصلك على جوالك عشان نفعلها الحين."),
    ("ar", "مبروك! ربحت جائزة 100,000 درهم. ادفع رسوم 500 درهم لاستلام الجائزة."),
]

SOPHISTICATED = [
    # 1 fake bank rep moving money, no "urgent/OTP/password" words
    ("en", "Hello Mr. Khalid, this is Omar from the fraud prevention unit at your bank. To protect your savings we will move them temporarily to a protected account while we look into this. "
           "Please send the balance to the account I share with you now, and don't discuss it with branch staff as the case is internal."),
    # 2 government impersonation
    ("en", "Good morning, I am calling from the Federal Authority for Identity. There is a mismatch in your residency file. To avoid your visa being cancelled, settle the correction amount of 1,250 through the link we will text you."),
    # 3 family impersonation
    ("en", "Hi mum it's me, I dropped my phone in the sink so this is my new number. Can you help me with something? I need to settle a bill today and my app isn't working, I'll pay you back tomorrow x"),
    # 4 job with unusual financial requirement
    ("en", "We came across your profile and would like to offer you a remote position as an online assistant. Daily earnings 300-900 AED. To activate your workstation you only need to top up your task account with 200 AED, which is returned with your first commission."),
    # 5 investment, indirect promise
    ("en", "My cousin works at a trading firm in DIFC, they've been giving members a steady 4% every week. A few seats are left this month. If you want in I can add you to the WhatsApp group and you start with any amount you like."),
    # 6 professional phishing
    ("en", "Dear Ms. Rahman, as part of our annual compliance review, please re-validate your payroll account details through the secure portal below by Thursday to ensure uninterrupted salary processing. "
           "https://payroll-hr-portal.example-secure.net/validate  Kind regards, People Operations"),
    # 7 personal information harvest
    ("en", "Hi! We're updating the residents' directory for your building. Could you reply with your full name, Emirates ID number and a photo of the front of your card so we can issue the new parking access?"),
    # 8 Arabic safe-account, no classic words
    ("ar", "مساء الخير، معك قسم المتابعة في البنك. حتى نحمي رصيدك لازم ننقله مؤقتاً لحساب آمن باسمك، راح أرسل لك رقم الحساب الحين، ولا تقول لأحد في الفرع لأن الموضوع داخلي."),
    # 9 unfamiliar technique: accidental transfer "return"
    ("en", "Hello, I sent you 750 dirhams by mistake while paying my landlord, it was meant for another number. Please can you send it back to 0501234567? My family really needs it this week."),
    # 10 mixed Arabizi / new technique, family + secrecy
    ("mix", "Habibi ana Hamad, hada rqmi el jdeed. 3indi mshkle bil bank, momken t7awel li 2000 drhm w barj3hom bokra? la t2ool la7ad please"),
]

LEGITIMATE = [
    ("en", "Your OTP for ADCB online banking is 482913. Do not share this code with anyone, including bank staff."),
    ("en", "Congratulations! Your salary of AED 12,500 has been credited to your account ending 4411."),
    ("en", "Urgent: the team meeting has moved to 3pm today in room 4B. Please bring the Q3 report."),
    ("en", "Your Aramex shipment 3392011 will be delivered tomorrow between 9am and 1pm. Track it in the Aramex app."),
    ("en", "We noticed a sign-in to your account from a new device. If this wasn't you, please call us on the number on the back of your card."),
    ("en", "Hey, are we still on for dinner Friday? I'll book the table, you can pay me back your share later :)"),
    ("en", "Abu Dhabi Police warn: never share your bank card details or OTP with callers claiming to be bank employees."),
    ("ar", "مبروك! تم قبول طلبك لبطاقة الائتمان. ستصلك البطاقة خلال 5 أيام عمل."),
    ("ar", "رمز التحقق الخاص بك هو 5521. لا تشارك هذا الرمز مع أي شخص."),
    ("ar", "تذكير: فاتورة الكهرباء بقيمة 320 درهم مستحقة بتاريخ 15. يمكنك الدفع عبر التطبيق الرسمي."),
    ("en", "Hi Sara, please review the attached invoice from our usual supplier and process it in the normal approval flow by Thursday."),
]
