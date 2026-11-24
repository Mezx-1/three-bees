# URL detection benchmark (offline structural engine)

Run: 2026-11-24 11:12 UTC. Method: `pipeline.run_url` with AI off, external lookups off (no page visits, no redirects followed, no domain age, no reputation APIs). This measures the floor: with lookups on, 3B also follows redirects, reads domain age (RDAP) and asks URLhaus/VirusTotal/Safe Browsing when keys are configured.

Data: OpenPhish community feed (300 phishing URLs, downloaded 2026-11-24), Tranco top sites (500 from ranks 1-1,000 + 500 random from ranks 10,001-100,000, homepages), and 43 real UAE government/bank/service URLs written by the team.

Rules were tuned while looking at the **dev** half of the phishing URLs. Quote the **test** half.

| Phishing split | Threshold | Precision | Recall | F1 | False-positive rate | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|---|
| test | ≥30 | 0.860 | 0.677 | 0.758 | 0.017 | 111 | 18 | 53 | 1025 |
| test | ≥60 | 1.000 | 0.049 | 0.093 | 0.000 | 8 | 0 | 156 | 1043 |
| dev | ≥30 | 0.855 | 0.779 | 0.815 | 0.017 | 106 | 18 | 30 | 1025 |
| dev | ≥60 | 1.000 | 0.037 | 0.071 | 0.000 | 5 | 0 | 131 | 1043 |

False positives on legitimate sets (score ≥ 30):

* tranco_top1k: 16 of 500 — https://apple-dns.net/ (34, Brand name 'apple' used on an unrelated domain); https://google-analytics.com/ (34, Brand name 'google' used on an unrelated domain); https://amazon-adsystem.com/ (34, Brand name 'amazon' used on an unrelated domain); https://withgoogle.com/ (34, Brand name 'google' used on an unrelated domain); https://cdn-apple.com/ (34, Brand name 'apple' used on an unrelated domain); https://telegram.me/ (40, Brand name 'telegram' on a different country or domain ending); https://tiktokcdn-us.com/ (34, Brand name 'tiktok' used on an unrelated domain); https://media-amazon.com/ (34, Brand name 'amazon' used on an unrelated domain)
* tranco_10k_100k: 2 of 500 — https://go0gles.cc/ (38, Look-alike of 'google'); https://xn--2-5wf2bba1ap9j6b6d2dwa0dm6b.com/ (35, Internationalised (punycode) domain)
* uae_official: 0 of 43

Limits: homepages of popular sites are easier than real inner pages; OpenPhish is mostly global brands, not UAE; live phishing pages change quickly. This is not the judges' hidden test set.
