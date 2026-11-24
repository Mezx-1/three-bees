"""URL detection benchmark on public data (offline: no page visits, no DNS, no AI, no reputation APIs).

Data (download into backend/benchmarks/data/urls/, gitignored):
  * openphish_feed.txt  - OpenPhish community feed, https://openphish.com/feed.txt   (phishing)
  * tranco.zip          - Tranco top-1M list, https://tranco-list.eu/              (legitimate domains)
  * uae_official.txt    - hand-written list of real UAE government/bank/service URLs (legitimate; self-made)

Split: each phishing URL goes to "dev" or "test" by a hash of the URL. Rules were tuned while looking at the
dev half only; the numbers to quote are the TEST half. Legitimate URLs: 500 domains from Tranco ranks 1-1000,
500 random domains from ranks 10,001-100,000 (seed 42), plus the UAE list.

Run:  .venv\\Scripts\\python benchmarks\\run_url_benchmark.py
"""
from __future__ import annotations

import csv
import hashlib
import io
import random
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))
DATA = ROOT / "data" / "urls"
OUT = ROOT / "results"


def load():
    phish = [l.strip() for l in (DATA / "openphish_feed.txt").read_text(encoding="utf-8").splitlines() if l.strip().startswith("http")]
    with zipfile.ZipFile(DATA / "tranco.zip") as z:
        name = z.namelist()[0]
        rows = list(csv.reader(io.TextIOWrapper(z.open(name), encoding="utf-8")))
    ranked = [(int(r[0]), r[1]) for r in rows if len(r) == 2 and r[0].isdigit()]
    top = [d for rank, d in ranked if rank <= 1000][:500]
    rng = random.Random(42)
    deep = rng.sample([d for rank, d in ranked if 10_001 <= rank <= 100_000], 500)
    uae = [l.strip() for l in (ROOT / "uae_official.txt").read_text(encoding="utf-8").splitlines() if l.strip() and not l.startswith("#")]
    return phish, top, deep, uae


def split(url: str) -> str:
    return "test" if int(hashlib.sha256(url.encode()).hexdigest(), 16) % 2 else "dev"


def main() -> None:
    from app.services import pipeline

    ctx = pipeline.Context(ai_enabled=False, external_lookups=False)
    phish, top, deep, uae = load()
    sets = {"phishing": [(u, 1) for u in phish], "tranco_top1k": [(f"https://{d}/", 0) for d in top],
            "tranco_10k_100k": [(f"https://{d}/", 0) for d in deep], "uae_official": [(u, 0) for u in uae]}
    rows = []
    for name, items in sets.items():
        for url, label in items:
            r = pipeline.run_url(url, ctx).report
            rows.append({"set": name, "split": split(url) if label else "all", "url": url, "label": label, "score": r["risk_score"],
                         "top_reason": next((f["title"] for f in r["findings"] if f["weight"] > 0), "")})

    def metrics(rs, thr):
        tp = sum(1 for r in rs if r["label"] == 1 and r["score"] >= thr)
        fn = sum(1 for r in rs if r["label"] == 1 and r["score"] < thr)
        fp = sum(1 for r in rs if r["label"] == 0 and r["score"] >= thr)
        tn = sum(1 for r in rs if r["label"] == 0 and r["score"] < thr)
        p = tp / (tp + fp) if tp + fp else 0.0
        rc = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * p * rc / (p + rc) if p + rc else 0.0
        fpr = fp / (fp + tn) if fp + tn else 0.0
        return tp, fp, fn, tn, p, rc, f1, fpr

    legit = [r for r in rows if r["label"] == 0]
    lines = [
        "# URL detection benchmark (offline structural engine)", "",
        f"Run: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}. Method: `pipeline.run_url` with AI off, external lookups off "
        "(no page visits, no redirects followed, no domain age, no reputation APIs). This measures the floor: with lookups on, 3B also "
        "follows redirects, reads domain age (RDAP) and asks URLhaus/VirusTotal/Safe Browsing when keys are configured.", "",
        f"Data: OpenPhish community feed ({len(phish)} phishing URLs, downloaded {datetime.now(timezone.utc).date()}), Tranco top sites "
        f"({len(top)} from ranks 1-1,000 + {len(deep)} random from ranks 10,001-100,000, homepages), and {len(uae)} real UAE "
        "government/bank/service URLs written by the team.", "",
        "Rules were tuned while looking at the **dev** half of the phishing URLs. Quote the **test** half.", "",
        "| Phishing split | Threshold | Precision | Recall | F1 | False-positive rate | TP | FP | FN | TN |", "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for sp in ("test", "dev"):
        rs = [r for r in rows if r["label"] == 1 and r["split"] == sp] + legit
        for thr in (30, 60):
            tp, fp, fn, tn, p, rc, f1, fpr = metrics(rs, thr)
            lines.append(f"| {sp} | ≥{thr} | {p:.3f} | {rc:.3f} | {f1:.3f} | {fpr:.3f} | {tp} | {fp} | {fn} | {tn} |")
    lines += ["", "False positives on legitimate sets (score ≥ 30):", ""]
    for name in ("tranco_top1k", "tranco_10k_100k", "uae_official"):
        rs = [r for r in rows if r["set"] == name]
        fps = [r for r in rs if r["score"] >= 30]
        lines.append(f"* {name}: {len(fps)} of {len(rs)}" + (" — " + "; ".join(f"{r['url']} ({r['score']}, {r['top_reason']})" for r in fps[:8]) if fps else ""))
    lines += ["", "Limits: homepages of popular sites are easier than real inner pages; OpenPhish is mostly global brands, not UAE; "
              "live phishing pages change quickly. This is not the judges' hidden test set."]
    OUT.mkdir(exist_ok=True)
    (OUT / "URL_BENCHMARK.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    with open(OUT / "url_predictions.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    sys.stdout.reconfigure(encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
