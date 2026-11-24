"""Scam Methods Knowledge Base API.

Read: any signed-in user. Add / edit / disable / import / export / candidates: analysts.
Marking a method Verified needs an administrator and at least one source.
"""
from __future__ import annotations

import json
from collections import Counter

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import ROLE_RANK, current_user, iso, require
from ..models import Analysis, CandidatePattern, ScamMethod, ScamMethodVersion, User, utcnow
from ..knowledge.methods_seed import CATEGORIES
from ..services import knowledge as kb
from ..services.store import audit

router = APIRouter(prefix="/api/knowledge", tags=["knowledge"])


def summary(m: ScamMethod) -> dict:
    d = m.data or {}
    return {"id": m.id, "name": m.name, "name_ar": d.get("name_ar"), "category": m.category, "category_name": CATEGORIES.get(m.category, {}).get("name", m.category),
            "subcategory": d.get("subcategory"), "severity": d.get("severity"), "uae_focus": bool(d.get("uae_focus")), "review_status": m.review_status,
            "enabled": m.enabled, "version": m.version, "origin": m.origin, "sources": len(d.get("sources") or []),
            "description": d.get("description"), "created_at": iso(m.created_at), "updated_at": iso(m.updated_at)}


@router.get("/categories")
def categories(user: User = Depends(current_user)):
    return [{"key": k, "name": v["name"]} for k, v in CATEGORIES.items()]


@router.get("/methods")
def list_methods(q: str | None = None, category: str | None = None, status: str | None = None, uae: bool | None = None,
                 include_disabled: bool = False, db: Session = Depends(get_db), user: User = Depends(current_user)):
    stmt = select(ScamMethod).order_by(ScamMethod.category, ScamMethod.id)
    if category:
        stmt = stmt.where(ScamMethod.category == category)
    if status:
        stmt = stmt.where(ScamMethod.review_status == status)
    if not (include_disabled and ROLE_RANK.get(user.role, 0) >= ROLE_RANK["analyst"]):
        stmt = stmt.where(ScamMethod.enabled.is_(True))
    rows = db.scalars(stmt).all()
    if uae is not None:
        rows = [m for m in rows if bool((m.data or {}).get("uae_focus")) == uae]
    if q:
        ql = q.lower()
        rows = [m for m in rows if ql in json.dumps(m.data, ensure_ascii=False).lower() or ql in m.id.lower()]
    return [summary(m) for m in rows]


@router.get("/methods/{mid}")
def get_method(mid: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    m = db.get(ScamMethod, mid)
    if not m:
        raise HTTPException(404, "Method not found")
    out = {**summary(m), "data": m.data}
    if ROLE_RANK.get(user.role, 0) >= ROLE_RANK["analyst"]:
        out["versions"] = [{"version": v.version, "review_status": v.review_status, "enabled": v.enabled, "changed_by": v.changed_by,
                            "note": v.note, "changed_at": iso(v.changed_at)}
                           for v in db.scalars(select(ScamMethodVersion).where(ScamMethodVersion.method_id == mid).order_by(ScamMethodVersion.version.desc())).all()]
    return out


def _check_verify(d: dict, user: User) -> None:
    if d.get("review_status") == "verified" and ROLE_RANK.get(user.role, 0) < ROLE_RANK["admin"]:
        raise HTTPException(403, "Only an administrator can mark a method Verified.")


@router.post("/methods")
def create_method(body: dict = Body(...), force: bool = False, db: Session = Depends(get_db), user: User = Depends(require("analyst"))):
    _check_verify(body, user)
    try:
        d = kb.validate(body)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    dups = kb.duplicates(db, d)
    if dups and not force:
        raise HTTPException(409, {"message": "Possible duplicate of an existing method.", "duplicates": dups})
    try:
        m = kb.save(db, d, user.username, note=body.get("_note", "Created"))
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    audit(db, user.username, "knowledge.create", m.id)
    db.commit()
    return summary(m)


@router.put("/methods/{mid}")
def update_method(mid: str, body: dict = Body(...), db: Session = Depends(get_db), user: User = Depends(require("analyst"))):
    if not db.get(ScamMethod, mid):
        raise HTTPException(404, "Method not found")
    _check_verify(body, user)
    try:
        m = kb.save(db, body, user.username, method_id=mid, note=body.get("_note", "Edited"))
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    audit(db, user.username, "knowledge.update", mid, {"status": m.review_status})
    db.commit()
    return summary(m)


@router.post("/methods/{mid}/{action}")
def toggle_method(mid: str, action: str, db: Session = Depends(get_db), user: User = Depends(require("analyst"))):
    m = db.get(ScamMethod, mid)
    if not m or action not in ("enable", "disable"):
        raise HTTPException(404, "Not found")
    m.enabled = action == "enable"
    m.version += 1
    m.updated_at = utcnow()
    db.add(ScamMethodVersion(method_id=mid, version=m.version, data=m.data, review_status=m.review_status, enabled=m.enabled,
                             changed_by=user.username, note=action.capitalize() + "d"))
    audit(db, user.username, f"knowledge.{action}", mid)
    db.commit()
    return summary(m)


@router.get("/export")
def export(format: str = Query("json", pattern="^(json|csv)$"), db: Session = Depends(get_db), user: User = Depends(require("analyst"))):
    ms = db.scalars(select(ScamMethod).order_by(ScamMethod.id)).all()
    if format == "csv":
        return Response(kb.to_csv(ms), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=3b-scam-methods.csv"})
    data = [{**m.data, "review_status": m.review_status, "enabled": m.enabled, "version": m.version} for m in ms]
    return Response(json.dumps(data, ensure_ascii=False, indent=1), media_type="application/json",
                    headers={"Content-Disposition": "attachment; filename=3b-scam-methods.json"})


@router.post("/import")
def import_methods(body: dict = Body(...), db: Session = Depends(get_db), user: User = Depends(require("analyst"))):
    """body: {"format": "json"|"csv", "content": "..."}. Imported methods become Draft unless they carry sources and an admin imports them."""
    fmt, content = body.get("format", "json"), body.get("content", "")
    try:
        rows = json.loads(content) if fmt == "json" else kb.from_csv(content)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(422, f"Could not read the {fmt.upper()} file: {exc.__class__.__name__}")
    if not isinstance(rows, list):
        raise HTTPException(422, "Expected a list of methods.")
    created, skipped, errors = [], [], []
    for i, r in enumerate(rows[:1000]):
        if not isinstance(r, dict):
            errors.append({"row": i + 1, "error": "not an object"})
            continue
        r = dict(r)
        if r.get("review_status") == "verified" and (ROLE_RANK.get(user.role, 0) < ROLE_RANK["admin"] or not r.get("sources")):
            r["review_status"] = "needs_review"
        r.setdefault("review_status", "draft")
        r.pop("id", None) if (r.get("id") and db.get(ScamMethod, r["id"])) else None
        try:
            d = kb.validate(r)
        except ValueError as exc:
            errors.append({"row": i + 1, "error": str(exc)})
            continue
        dups = kb.duplicates(db, d)
        if dups:
            skipped.append({"row": i + 1, "name": d["name"], "duplicate_of": dups[0]["id"]})
            continue
        try:
            created.append(kb.save(db, d, user.username, note="Imported", origin="import").id)
        except ValueError as exc:
            errors.append({"row": i + 1, "error": str(exc)})
    audit(db, user.username, "knowledge.import", "", {"created": len(created), "skipped": len(skipped)})
    db.commit()
    return {"created": created, "skipped_duplicates": skipped, "errors": errors}


@router.get("/stats")
def stats(db: Session = Depends(get_db), user: User = Depends(current_user)):
    ms = db.scalars(select(ScamMethod)).all()
    enabled = [m for m in ms if m.enabled]
    by_cat = Counter(m.category for m in enabled)
    by_status = Counter(m.review_status for m in enabled)
    recent = sorted(ms, key=lambda m: m.created_at, reverse=True)[:6]
    seen = Counter()
    for (rep,) in db.execute(select(Analysis.report).order_by(Analysis.created_at.desc()).limit(300)).all():
        for s in ((rep or {}).get("similar_methods") or [])[:1]:
            seen[(s["id"], s["name"])] += 1
    open_candidates = db.scalar(select(CandidatePattern.id).where(CandidatePattern.status == "open").limit(1))
    return {
        "total": len(enabled), "disabled": len(ms) - len(enabled), "uae_focus": sum(1 for m in enabled if (m.data or {}).get("uae_focus")),
        "by_category": [{"key": k, "name": CATEGORIES.get(k, {}).get("name", k), "count": n} for k, n in sorted(by_cat.items(), key=lambda kv: -kv[1])],
        "by_status": dict(by_status), "verified": by_status.get("verified", 0), "unverified": len(enabled) - by_status.get("verified", 0),
        "recent": [summary(m) for m in recent],
        "seen_in_investigations": [{"id": i, "name": n, "analyses": c} for (i, n), c in seen.most_common(8)],
        "open_candidates": bool(open_candidates),
        "note": "The library is a reference for the engine, not a complete list of every scam. Seeded methods need a reviewer and a source before they are marked Verified.",
    }


@router.get("/candidates")
def candidates(db: Session = Depends(get_db), user: User = Depends(require("analyst"))):
    rows = db.scalars(select(CandidatePattern).where(CandidatePattern.status == "open").order_by(CandidatePattern.created_at.desc()).limit(100)).all()
    return [{"id": c.id, "analysis_id": c.analysis_id, "excerpt": c.excerpt, "risk_score": c.risk_score, "intent": c.intent, "created_at": iso(c.created_at)} for c in rows]


@router.post("/candidates/{cid}/{action}")
def candidate_action(cid: int, action: str, body: dict = Body(default={}), db: Session = Depends(get_db), user: User = Depends(require("analyst"))):
    c = db.get(CandidatePattern, cid)
    if not c or c.status != "open" or action not in ("promote", "dismiss"):
        raise HTTPException(404, "Not found")
    if action == "dismiss":
        c.status = "dismissed"
        db.commit()
        return {"status": "dismissed"}
    d = {"name": body.get("name") or "New technique (from an investigation)", "category": body.get("category") or "emerging",
         "description": body.get("description") or "Seen in a high-risk analysis with no close match in the library. Needs review.",
         "examples": {"en": [c.excerpt] if c.excerpt.isascii() else [], "ar": [] if c.excerpt.isascii() else [c.excerpt]},
         "review_status": "draft", "subcategory": "candidate", "severity": "medium"}
    m = kb.save(db, d, user.username, note=f"Promoted from candidate #{cid}", origin="candidate")
    c.status, c.method_id = "promoted", m.id
    audit(db, user.username, "knowledge.promote_candidate", m.id)
    db.commit()
    return summary(m)
