"""Scam Methods Knowledge Base: storage helpers + similarity search used during analysis.

The knowledge base is a *reference*, not a rule engine:
  * a match never adds much to the risk score by itself (similarity alone is not evidence);
  * a message with no match can still be high risk (the intent layer decides that);
  * every match is explained ("both ask you to move money to an account they choose…").

Similarity = 0.55 × text similarity (TF-IDF over character 3–5-grams of normalised text, so it works across
Arabic, English, dialect spelling and typos) + 0.45 × behaviour overlap (what the message asks you to do,
who it claims to be, which pressure it uses — read by the intent engine from the method's own examples).
"""
from __future__ import annotations

import csv
import io
import math
import re
from collections import Counter
from difflib import SequenceMatcher

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import ScamMethod, ScamMethodVersion, utcnow
from . import intent_engine as ie

REVIEW_STATUSES = ("draft", "needs_review", "verified")
MATCH_MIN = 0.30

_INDEX: dict = {"sig": None, "docs": [], "idf": {}, "vecs": [], "behav": []}


def _grams(t: str) -> Counter:
    t = re.sub(r"https?://\S+|\S+@\S+", " link ", t)
    t = re.sub(r"\d+", "0", t)
    t = re.sub(r"[^\w\s]", " ", t)
    t = " " + re.sub(r"\s+", " ", t).strip() + " "
    c: Counter = Counter()
    for n in (3, 4, 5):
        for i in range(len(t) - n + 1):
            g = t[i:i + n]
            if g.strip():
                c[g] += 1
    return c


def _vec(c: Counter, idf: dict) -> dict:
    v = {g: (1 + math.log(n)) * idf.get(g, 0.0) for g, n in c.items() if g in idf}
    norm = math.sqrt(sum(x * x for x in v.values())) or 1.0
    return {g: x / norm for g, x in v.items()}


def _cos(a: dict, b: dict) -> float:
    if len(a) > len(b):
        a, b = b, a
    return sum(x * b.get(g, 0.0) for g, x in a.items())


def behaviour_keys(it: ie.Intent) -> set[str]:
    keys = {f"ask:{k}" for k in it.asks} | {f"claim:{k}" for k in it.claims} | {f"lever:{k}" for k in it.levers}
    if it.unusual_destination:
        keys.add("unusual_destination")
    if it.advance_fee:
        keys.add("advance_fee")
    return keys


def method_text(d: dict) -> str:
    ex = d.get("examples") or {}
    return " \n ".join([d.get("name", ""), d.get("description", ""), *(ex.get("en") or []), *(ex.get("ar") or [])])


def _rebuild(methods: list[ScamMethod]) -> None:
    docs = [{"id": m.id, "name": m.name, "category": m.category, "status": m.review_status, "data": m.data} for m in methods]
    grams = [_grams(ie.normalize(method_text(d["data"]))) for d in docs]
    df: Counter = Counter()
    for g in grams:
        df.update(set(g))
    n = max(1, len(docs))
    idf = {g: math.log((n + 1) / (c + 1)) + 1 for g, c in df.items()}
    _INDEX.update(docs=docs, idf=idf, vecs=[_vec(g, idf) for g in grams],
                  behav=[behaviour_keys(ie.read_intent(" \n ".join((d["data"].get("examples") or {}).get("en", []) + (d["data"].get("examples") or {}).get("ar", []))))
                         for d in docs])


def ensure_index(db: Session) -> int:
    sig = db.execute(select(func.count(ScamMethod.id), func.max(ScamMethod.updated_at)).where(ScamMethod.enabled.is_(True))).one()
    sig = (sig[0], str(sig[1]))
    if sig != _INDEX["sig"]:
        _rebuild(db.scalars(select(ScamMethod).where(ScamMethod.enabled.is_(True))).all())
        _INDEX["sig"] = sig
    return len(_INDEX["docs"])


ASK_WORDS = {"ask:move_money": "move or pay money", "ask:share_secret": "reveal a code or password", "ask:share_personal": "hand over personal or ID details",
             "ask:open_link": "act through a link", "ask:install": "install an app or give remote access", "ask:approve": "approve a request in an app",
             "ask:switch_channel": "move to a private chat", "claim:bank": "claim to be a bank", "claim:government": "claim to be an authority",
             "claim:delivery": "claim to be a courier", "claim:employer": "offer a job", "claim:familiar": "claim to be family or a friend",
             "claim:investment": "pitch an investment", "claim:tech_support": "claim to be tech support", "claim:telecom": "claim to be a telecom provider",
             "lever:fear": "use fear", "lever:urgency": "rush you", "lever:greed": "promise money or rewards", "lever:sympathy": "appeal to sympathy",
             "lever:secrecy": "ask for secrecy", "unusual_destination": "send money to an unusual account or wallet", "advance_fee": "ask a fee before you receive something"}


def match(text: str, it: ie.Intent | None = None, *, limit: int = 3) -> list[dict]:
    """Known methods that resemble this content, with the reasons. Empty when nothing is reasonably close."""
    if not _INDEX["docs"] or not text.strip():
        return []
    it = it or ie.read_intent(text)
    q = _vec(_grams(ie.normalize(text)), _INDEX["idf"])
    mine = behaviour_keys(it)
    rows = []
    for d, v, b in zip(_INDEX["docs"], _INDEX["vecs"], _INDEX["behav"]):
        ts = _cos(q, v)
        shared = mine & b
        bs = len(shared) / len(mine | b) if (mine | b) else 0.0
        score = 0.55 * ts + 0.45 * bs
        risky_shared = {x for x in shared if (x.startswith("ask:") and x != "ask:call_back") or x in ("unusual_destination", "advance_fee")}
        if score >= MATCH_MIN and (risky_shared or ts >= 0.5):
            why = [ASK_WORDS[k] for k in sorted(shared) if k in ASK_WORDS][:4]
            rows.append({"id": d["id"], "name": d["name"], "category": d["category"], "review_status": d["status"],
                         "similarity": round(score, 2), "text_similarity": round(ts, 2), "behaviour_overlap": round(bs, 2),
                         "shared_behaviours": why,
                         "explanation": ("Shared behaviour: " + "; ".join(why)) if why else "The wording is close to this method's examples."})
    rows.sort(key=lambda r: -r["similarity"])
    return rows[:limit]


# ----------------------------------------------------------------- storage

def seed(db: Session) -> int:
    if db.scalar(select(func.count(ScamMethod.id))):
        _backfill_names(db)
        return 0
    from ..knowledge.methods_seed import build_methods

    n = 0
    for d in build_methods():
        db.add(ScamMethod(id=d["id"], name=d["name"], category=d["category"], data=d, review_status=d["review_status"], origin="seed"))
        db.add(ScamMethodVersion(method_id=d["id"], version=1, data=d, review_status=d["review_status"], changed_by="system", note="Initial seed"))
        n += 1
    db.commit()
    return n


def _backfill_names(db: Session) -> None:
    """Add Arabic names to seeded methods created before names_ar existed (no version bump: display only)."""
    from ..knowledge.names_ar import NAMES_AR

    changed = False
    for m in db.scalars(select(ScamMethod).where(ScamMethod.origin == "seed")).all():
        if not (m.data or {}).get("name_ar") and NAMES_AR.get(m.id[3:]):
            m.data = {**m.data, "name_ar": NAMES_AR[m.id[3:]]}
            changed = True
    if changed:
        db.commit()


REQUIRED = ("name", "category", "description")


def validate(d: dict) -> dict:
    d = dict(d or {})
    for k in REQUIRED:
        if not str(d.get(k) or "").strip():
            raise ValueError(f"'{k}' is required")
    st = d.get("review_status", "draft")
    if st not in REVIEW_STATUSES:
        raise ValueError(f"review_status must be one of {', '.join(REVIEW_STATUSES)}")
    if st == "verified" and not d.get("sources"):
        raise ValueError("A method can be marked Verified only with at least one source (title + URL or document reference).")
    for k in ("attack_sequence", "psychological_techniques", "attacker_objectives", "typical_targets", "channels", "behavioral_indicators",
              "technical_indicators", "variations", "detection_strategies", "protection_steps", "related_methods", "sources"):
        v = d.get(k)
        if isinstance(v, str):
            d[k] = [x.strip() for x in re.split(r"[;\n]", v) if x.strip()]
        elif v is None:
            d[k] = []
    ex = d.get("examples") or {}
    d["examples"] = {"en": [x for x in (ex.get("en") or []) if x], "ar": [x for x in (ex.get("ar") or []) if x]}
    d["examples_are_fictional"] = True
    return d


def duplicates(db: Session, d: dict, exclude: str | None = None) -> list[dict]:
    """Likely duplicates: very similar name, or nearly identical examples."""
    out = []
    name = ie.normalize(d.get("name", ""))
    probe = " ".join((d.get("examples") or {}).get("en", []) + (d.get("examples") or {}).get("ar", []))
    for m in db.scalars(select(ScamMethod)).all():
        if m.id == exclude:
            continue
        ns = SequenceMatcher(None, name, ie.normalize(m.name)).ratio()
        es = 0.0
        if probe:
            other = " ".join((m.data.get("examples") or {}).get("en", []) + (m.data.get("examples") or {}).get("ar", []))
            es = _cos(_vec(_grams(ie.normalize(probe)), _INDEX["idf"] or {}), _vec(_grams(ie.normalize(other)), _INDEX["idf"] or {})) if _INDEX["idf"] else 0.0
        if ns >= 0.85 or es >= 0.8:
            out.append({"id": m.id, "name": m.name, "name_similarity": round(ns, 2), "example_similarity": round(es, 2)})
    return out


def next_id(db: Session, category: str) -> str:
    prefix = f"SM-{category.upper()[:6]}-"
    ids = [i for (i,) in db.execute(select(ScamMethod.id).where(ScamMethod.id.like(prefix + "%"))).all()]
    nums = [int(x.rsplit("-", 1)[1]) for x in ids if x.rsplit("-", 1)[1].isdigit()]
    return f"{prefix}{(max(nums) + 1) if nums else 1:03d}"


def save(db: Session, d: dict, actor: str, *, method_id: str | None = None, note: str = "", origin: str = "admin") -> ScamMethod:
    d = validate(d)
    m = db.get(ScamMethod, method_id) if method_id else None
    if m is None:
        mid = d.get("id") or next_id(db, d["category"])
        if db.get(ScamMethod, mid):
            raise ValueError(f"Method {mid} already exists")
        d["id"] = mid
        d.setdefault("last_reviewed", None)
        m = ScamMethod(id=mid, name=d["name"], category=d["category"], data=d, review_status=d.get("review_status", "draft"),
                       origin=origin, created_by=actor, version=1)
        db.add(m)
        ver = 1
    else:
        d["id"] = m.id
        if d.get("review_status") != m.review_status and d.get("review_status") == "verified":
            d["last_reviewed"] = utcnow().date().isoformat()
        m.name, m.category, m.data, m.review_status = d["name"], d["category"], d, d.get("review_status", m.review_status)
        m.version += 1
        m.updated_at = utcnow()
        ver = m.version
    db.add(ScamMethodVersion(method_id=m.id, version=ver, data=d, review_status=m.review_status, enabled=m.enabled, changed_by=actor, note=note[:500]))
    db.commit()
    return m


EXPORT_FIELDS = ["id", "name", "category", "subcategory", "description", "attack_sequence", "psychological_techniques", "channels",
                 "behavioral_indicators", "detection_strategies", "protection_steps", "severity", "uae_focus", "review_status", "sources",
                 "example_en", "example_ar", "last_reviewed"]


def to_csv(methods: list[ScamMethod]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=EXPORT_FIELDS)
    w.writeheader()
    for m in methods:
        d = m.data
        row = {k: d.get(k, "") for k in EXPORT_FIELDS}
        for k, v in row.items():
            if isinstance(v, list):
                row[k] = "; ".join(str(x) if not isinstance(x, dict) else (x.get("title") or x.get("url") or "") for x in v)
        row["example_en"] = " | ".join((d.get("examples") or {}).get("en", []))
        row["example_ar"] = " | ".join((d.get("examples") or {}).get("ar", []))
        row["review_status"] = m.review_status
        w.writerow(row)
    return buf.getvalue()


def from_csv(text: str) -> list[dict]:
    rows = []
    for r in csv.DictReader(io.StringIO(text)):
        d = {k: (v or "").strip() for k, v in r.items() if k}
        d["examples"] = {"en": [x.strip() for x in d.pop("example_en", "").split("|") if x.strip()],
                         "ar": [x.strip() for x in d.pop("example_ar", "").split("|") if x.strip()]}
        d["uae_focus"] = d.get("uae_focus", "").lower() in ("1", "true", "yes")
        d["sources"] = [{"title": s.strip()} for s in d.get("sources", "").split(";") if s.strip()]
        rows.append(d)
    return rows
