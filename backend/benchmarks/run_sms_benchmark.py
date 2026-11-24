"""Benchmark 3B's text rules on the public UCI SMS Spam Collection.

Reproducible:  python benchmarks/run_sms_benchmark.py
  * downloads the dataset once into benchmarks/data/ (CC BY 4.0, Almeida & Hidalgo, UCI ML Repository)
  * checks the zip's SHA-256 so results always refer to the same data
  * scores every message with the same rules the app uses for SMS (text rules only, no network, no AI)
  * writes per-message predictions (CSV) and a Markdown report with the real numbers

Important: the dataset labels SPAM vs HAM (2012, English, UK/Singapore). Spam is not the same as scam —
much spam is plain advertising that 3B is not designed to flag. Read the numbers with that in mind.
"""
from __future__ import annotations

import csv
import hashlib
import io
import platform
import statistics
import sys
import time
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))

from app.services import risk, text_analyzer  # noqa: E402

URL = "https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip"
SHA256 = "1587ea43e58e82b14ff1f5425c88e17f8496bfcdb67a583dbff9eefaf9963ce3"
ZIP = ROOT / "data" / "sms_spam_collection.zip"
OUT = ROOT / "results"
THRESHOLDS = (30, 60)  # "medium or higher" and "high or higher", the app's own severity cut-offs


def load() -> list[tuple[str, str]]:
    if not ZIP.exists():
        ZIP.parent.mkdir(parents=True, exist_ok=True)
        urllib.request.urlretrieve(URL, ZIP)
    digest = hashlib.sha256(ZIP.read_bytes()).hexdigest()
    if digest != SHA256:
        sys.exit(f"Dataset hash mismatch: {digest} (expected {SHA256}). Refusing to report numbers on different data.")
    raw = zipfile.ZipFile(ZIP).read("SMSSpamCollection").decode("utf-8", "replace")
    rows = []
    for line in raw.splitlines():
        label, _, text = line.partition("\t")
        if label in ("spam", "ham") and text:
            rows.append((label, text))
    return rows


def metrics(y_true: list[int], y_pred: list[int]) -> dict:
    tp = sum(1 for t, p in zip(y_true, y_pred) if t and p)
    fp = sum(1 for t, p in zip(y_true, y_pred) if not t and p)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t and not p)
    tn = sum(1 for t, p in zip(y_true, y_pred) if not t and not p)
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": prec, "recall": rec, "f1": f1,
            "fpr": fp / (fp + tn) if fp + tn else 0.0, "fnr": fn / (fn + tp) if fn + tp else 0.0}


def main() -> None:
    rows = load()
    OUT.mkdir(exist_ok=True)
    preds, lat = [], []
    for label, text in rows:
        t = time.perf_counter()
        findings, art = text_analyzer.analyze_text(text, "sms")
        score = risk.combine(findings)
        lat.append((time.perf_counter() - t) * 1000)
        preds.append((label, score, sorted(art["matched_patterns"]), text))
    y_true = [1 if lab == "spam" else 0 for lab, *_ in preds]
    run_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    with open(OUT / "sms_predictions.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["label", "score", "flagged_at_30", "patterns", "text"])
        for lab, score, pats, text in preds:
            w.writerow([lab, score, int(score >= 30), "|".join(pats), text])

    lines = [
        "# 3B text rules on the UCI SMS Spam Collection",
        "",
        f"- Run: {run_at} · Python {platform.python_version()} · dataset SHA-256 `{SHA256}`",
        f"- Messages: {len(rows)} ({sum(y_true)} spam, {len(rows) - sum(y_true)} ham)",
        "- Method: the app's SMS text rules only (no URL reputation, no AI, no network). A message counts as",
        "  flagged when its risk score reaches the threshold. Rules were **not** tuned on this dataset.",
        f"- Latency per message: median {statistics.median(lat):.2f} ms, p95 {sorted(lat)[int(len(lat) * 0.95)]:.2f} ms",
        "",
        "| Threshold | Precision | Recall | F1 | FPR | FNR | TP | FP | FN | TN |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for th in THRESHOLDS:
        m = metrics(y_true, [1 if s >= th else 0 for _, s, _, _ in preds])
        lines.append(f"| score ≥ {th} | {m['precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f} | {m['fpr']:.3f} | {m['fnr']:.3f} "
                     f"| {m['tp']} | {m['fp']} | {m['fn']} | {m['tn']} |")
    m30 = metrics(y_true, [1 if s >= 30 else 0 for _, s, _, _ in preds])
    lines += [
        "",
        "## Confusion matrix (score ≥ 30)",
        "",
        "| | Flagged | Not flagged |",
        "|---|---|---|",
        f"| **Spam** | {m30['tp']} | {m30['fn']} |",
        f"| **Ham** | {m30['fp']} | {m30['tn']} |",
        "",
        "## How to read this",
        "",
        "- **Spam is not scam.** Many spam messages are adverts or ringtone offers with no fraud tactic; 3B is",
        "  built to flag fraud tactics (codes, payments, threats, impersonation), so missing plain adverts is expected.",
        "- The data is from 2012, English only, UK/Singapore. It says nothing about Arabic or Gulf-dialect messages.",
        "- These numbers are a baseline, not a claim of real-world accuracy. A fair test needs current, labelled",
        "  UAE scam and legitimate messages collected with consent.",
        "",
        "## Ham messages flagged at score ≥ 30 (false positives)",
        "",
    ]
    fps = [(s, p, t) for lab, s, p, t in preds if lab == "ham" and s >= 30]
    for s, p, t in sorted(fps, reverse=True)[:15]:
        lines.append(f"- {s} · {', '.join(p)} · “{t[:110]}”")
    lines += ["", "## Spam messages not flagged (sample of 10)", ""]
    for _, s, p, t in [x for x in preds if x[0] == "spam" and x[1] < 30][:10]:
        lines.append(f"- {s} · “{t[:110]}”")
    (OUT / "SMS_BENCHMARK.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines[:16]))


if __name__ == "__main__":
    main()
