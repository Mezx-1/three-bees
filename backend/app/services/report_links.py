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


LEVELS = ("same_identifier", "strongly_related", "potentially_related", "similar_technique")
LEVEL_TEXT = {"same_identifier": "Same exact identifier", "strongly_related": "Strongly related campaign",
              "potentially_related": "Potentially related activity", "similar_technique": "Similar scam technique"}
GROUPING = {"same_identifier", "strongly_related"}  # only these join reports into one campaign


def _cgram(text: str | None) -> dict:
    from .knowledge import _grams
    from .intent_engine import normalize
    c = _grams(normalize(text or ""))
    n = sum(v * v for v in c.values()) ** 0.5 or 1.0
    return {g: v / n for g, v in c.items()}


def text_similarity(a: str | None, b: str | None) -> float:
    """Character n-gram cosine: survives changed numbers, links, spelling and small rewording."""
    va, vb = _cgram(a), _cgram(b)
    if len(va) > len(vb):
        va, vb = vb, va
    return sum(x * vb.get(g, 0.0) for g, x in va.items())


def _labels(host: str) -> list[str]:
    parts = host.split(".")
    core = parts[:-1] if len(parts) > 1 else parts
    return [t for p in core for t in re.split(r"[-_]", p) if len(t) >= 3 and t not in ("www", "com", "net", "org")]


def domain_similarity(a: str | None, b: str | None) -> float:
    if not a or not b or a == b:
        return 0.0
    ta, tb = set(_labels(a)), set(_labels(b))
    tok = len(ta & tb) / len(ta | tb) if ta and tb else 0.0
    from difflib import SequenceMatcher
    return max(tok, SequenceMatcher(None, a, b).ratio() if a.rsplit(".", 1)[-1] == b.rsplit(".", 1)[-1] else 0.0)


def _emails(r) -> set[str]:
    return {e.lower() for e in re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", f"{r.message or ''} {r.description or ''}")}


def links_between(a, b) -> list[dict]:
    """Why two reports may be related (empty list = no link). Each link has a level and a plain explanation."""
    out = []
    pa, pb = phone_key(a.phone), phone_key(b.phone)
    if pa and pa == pb:
        out.append({"method": "same_phone", "level": "same_identifier", "score": 0.9, "indicator": b.phone,
                    "explanation": "Both reports name the same phone number."})
    elif pa and pb and pa[:-2] == pb[:-2]:
        out.append({"method": "nearby_phone", "level": "potentially_related", "score": 0.4, "indicator": f"{a.phone} ~ {b.phone}",
                    "explanation": "The numbers differ only in the last two digits (possibly one block of numbers). Weak on its own."})
    if a.domain and a.domain == b.domain:
        out.append({"method": "same_domain", "level": "same_identifier", "score": 0.9, "indicator": b.domain,
                    "explanation": "Both reports contain a link to the same domain."})
    else:
        ds = domain_similarity(a.domain, b.domain)
        if ds >= 0.6:
            out.append({"method": "similar_domain", "level": "potentially_related", "score": round(0.5 * ds, 2), "indicator": f"{a.domain} ~ {b.domain}",
                        "explanation": "The two domains are built from the same words or look almost the same — typical when a campaign registers new look-alike sites."})
    shared_mail = _emails(a) & _emails(b)
    if shared_mail:
        out.append({"method": "same_email", "level": "same_identifier", "score": 0.9, "indicator": sorted(shared_mail)[0],
                    "explanation": "Both reports mention the same email address."})
    sim = text_similarity(a.message, b.message) if (a.message and b.message) else 0.0
    jac = jaccard(words(a.message), words(b.message))
    if sim >= 0.8 or jac >= 0.7:
        out.append({"method": "similar_text", "level": "strongly_related", "score": round(max(sim, jac), 2), "indicator": f"{round(max(sim, jac) * 100)}% similar",
                    "explanation": "The messages are near-copies of one template (numbers, links or a few words changed). This shows the same script, not the same person."})
    elif sim >= 0.55 or jac >= TEXT_MIN:
        out.append({"method": "similar_text", "level": "potentially_related", "score": round(max(sim, jac), 2), "indicator": f"{round(max(sim, jac) * 100)}% similar",
                    "explanation": "The messages share much of their wording and structure."})
    if not out and a.category == b.category and a.category not in ("other",):
        out.append({"method": "same_technique", "level": "similar_technique", "score": 0.2, "indicator": a.category,
                    "explanation": "Same type of scam, but no shared identifier or wording."})
    return out


def strongest(links: list[dict]) -> str | None:
    for lv in LEVELS:
        if any(l.get("level") == lv for l in links):
            return lv
    return None


def related(report, others) -> list[dict]:
    rows = []
    for o in others:
        if o.id == report.id or o.data_mode != report.data_mode:
            continue
        ls = [l for l in links_between(report, o) if l["level"] != "similar_technique"]
        if ls:
            lv = strongest(ls)
            rows.append({"reference": o.reference, "category": o.category, "status": o.status, "created_at": o.created_at,
                         "score": max(x["score"] for x in ls), "level": lv, "level_text": LEVEL_TEXT[lv], "links": ls})
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
            ls = [l for l in links_between(a, b) if l["level"] in GROUPING]
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


def campaign_id(references: list[str]) -> str:
    import hashlib
    return "CAMP-" + hashlib.sha1(sorted(references)[0].encode()).hexdigest()[:6].upper()


def graph(reports) -> dict:
    """Campaign graph: reports, the identifiers they contain, and explained links between reports.

    Campaigns join reports only through the same identifier or a near-identical template. Weaker links
    (similar domains, nearby numbers, similar wording) are drawn as dashed 'possible' edges."""
    rs = list(reports)
    nodes: dict[str, dict] = {}
    edges: list[dict] = []

    def node(nid, kind, label, **kw):
        nodes.setdefault(nid, {"id": nid, "kind": kind, "label": label, **kw})

    for r in rs:
        node(r.reference, "report", r.reference, category=r.category, created_at=r.created_at, amount_lost=r.amount_lost)
        if r.phone:
            node("phone:" + (phone_key(r.phone) or r.phone), "phone", r.phone)
            edges.append({"source": r.reference, "target": "phone:" + (phone_key(r.phone) or r.phone), "level": "contains", "explanation": "Number given in the report"})
        if r.domain:
            node("domain:" + r.domain, "domain", r.domain)
            edges.append({"source": r.reference, "target": "domain:" + r.domain, "level": "contains", "explanation": "Link in the report"})
        for e in sorted(_emails(r)):
            node("email:" + e, "email", e)
            edges.append({"source": r.reference, "target": "email:" + e, "level": "contains", "explanation": "Email address in the report"})
    for i, a in enumerate(rs):
        for b in rs[i + 1:]:
            if a.data_mode != b.data_mode:
                continue
            ls = [l for l in links_between(a, b) if l["method"] in ("similar_text", "similar_domain", "nearby_phone")]
            for l in ls:
                edges.append({"source": a.reference, "target": b.reference, "level": l["level"], "method": l["method"],
                              "score": l["score"], "explanation": l["explanation"]})
    camps = []
    for g in groups(rs):
        refs = g["references"]
        ids = set(refs)
        ind = {n for e in edges if e["level"] == "contains" and e["source"] in ids for n in [e["target"]]}
        camps.append({**g, "campaign_id": campaign_id(refs),
                      "indicators": {k: sum(1 for x in ind if x.startswith(k + ":")) for k in ("phone", "email", "domain")},
                      "relationship": "Reports share an identifier or a near-identical message template.",
                      "confidence_note": "Linked by the evidence listed on each edge. Not proof that the same people are behind every report."})
    return {"nodes": list(nodes.values()), "edges": edges, "campaigns": camps}
