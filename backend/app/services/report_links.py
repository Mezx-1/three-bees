"""Explainable links between scam reports ("potentially related", never "confirmed").

Methods, each with its own score and plain explanation:
  * same phone number  (digits only)                         0.90
  * same domain        (registered domain of the link)       0.90
  * similar message    (word-set overlap of the texts)       the overlap itself, when >= 0.45
A phone number or domain can be spoofed, shared, reassigned or mistyped by the reporter, so a link is a
lead for a person to review, not evidence that the same people are behind both reports.
Reports are only compared within the same data mode: demo records never link to real submissions.
"""
from __future__ import annotations

import re
from collections import defaultdict

TEXT_MIN = 0.45
_WORD = re.compile(r"[a-zء-ي]{3,}", re.I)
STOP = {"the", "and", "your", "you", "for", "this", "that", "with", "from", "are", "have", "has", "our", "will", "not",
        "من", "على", "الى", "إلى", "في", "هذا", "هذه", "عن", "مع"}


def phone_key(phone: str | None) -> str | None:
    digits = re.sub(r"\D", "", phone or "")
    return digits[-9:] if len(digits) >= 7 else None


def words(text: str | None) -> set[str]:
    return {w.lower() for w in _WORD.findall(text or "") if w.lower() not in STOP}


def jaccard(a: set[str], b: set[str]) -> float:
    return len(a & b) / len(a | b) if a and b else 0.0


def links_between(a, b) -> list[dict]:
    """Why two reports may be related (empty list = no link)."""
    out = []
    pa, pb = phone_key(a.phone), phone_key(b.phone)
    if pa and pa == pb:
        out.append({"method": "same_phone", "score": 0.9, "indicator": b.phone,
                    "explanation": "Both reports name the same phone number."})
    if a.domain and a.domain == b.domain:
        out.append({"method": "same_domain", "score": 0.9, "indicator": b.domain,
                    "explanation": "Both reports contain a link to the same domain."})
    sim = jaccard(words(a.message), words(b.message))
    if sim >= TEXT_MIN:
        out.append({"method": "similar_text", "score": round(sim, 2), "indicator": f"{round(sim * 100)}% word overlap",
                    "explanation": "The two messages use largely the same wording, as in a copied template."})
    return out


def related(report, others) -> list[dict]:
    rows = []
    for o in others:
        if o.id == report.id or o.data_mode != report.data_mode:
            continue
        ls = links_between(report, o)
        if ls:
            rows.append({"reference": o.reference, "category": o.category, "status": o.status, "created_at": o.created_at,
                         "score": max(x["score"] for x in ls), "links": ls})
    return sorted(rows, key=lambda r: -r["score"])


def groups(reports) -> list[dict]:
    """Clusters of reports joined by any link (union-find), largest first; only groups of 2+."""
    parent = {r.id: r.id for r in reports}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    by_id = {r.id: r for r in reports}
    shared: dict[tuple[int, int], list[dict]] = {}
    rs = list(reports)
    for i, a in enumerate(rs):
        for b in rs[i + 1:]:
            if a.data_mode != b.data_mode:
                continue
            ls = links_between(a, b)
            if ls:
                parent[find(a.id)] = find(b.id)
                shared[(a.id, b.id)] = ls
    members = defaultdict(list)
    for r in rs:
        members[find(r.id)].append(r)
    out = []
    for root, ms in members.items():
        if len(ms) < 2:
            continue
        ids = {m.id for m in ms}
        methods = defaultdict(set)
        for (x, y), ls in shared.items():
            if x in ids:
                for l in ls:
                    methods[l["method"]].add(l["indicator"])
        out.append({"size": len(ms), "references": sorted(m.reference for m in ms),
                    "categories": sorted({m.category for m in ms}),
                    "shared": {k: sorted(v)[:5] for k, v in methods.items()},
                    "total_lost": sum(m.amount_lost or 0 for m in ms),
                    "first_seen": min(m.created_at for m in ms), "last_seen": max(m.created_at for m in ms)})
    return sorted(out, key=lambda g: -g["size"])
