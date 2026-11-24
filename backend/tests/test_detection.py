"""Intent-based detection: 10 obvious scams, 10 sophisticated scams without the usual words, 11 legitimate messages.

Runs the real pipeline with AI off, no external lookups and no shared data, so only the local engine is measured.
The messages are a self-written test set (see detection_cases.py), not an independent benchmark.
"""
import pytest

from app.seed import seed
from app.services import pipeline, text_analyzer
from app.services.store import build_context
from app.db import SessionLocal

from .detection_cases import LEGITIMATE, OBVIOUS, SOPHISTICATED


@pytest.fixture(scope="module")
def ctx():
    seed()
    with SessionLocal() as db:
        c = build_context(db)
    c.ai_enabled, c.external_lookups = False, False
    c.shared, c.report_templates, c.blocked_domains, c.blocked_urls, c.blocked_phones = {}, [], set(), set(), set()
    return c


def run(ctx, text):
    return pipeline.run_message(text, ctx).report


@pytest.mark.parametrize("lang,text", OBVIOUS)
def test_obvious_scams_are_high_risk(ctx, lang, text):
    r = run(ctx, text)
    assert r["risk_score"] >= 60, (r["risk_score"], text)
    assert r["risk_level"] in ("HIGH", "CRITICAL") and r["warning"]


@pytest.mark.parametrize("lang,text", SOPHISTICATED)
def test_sophisticated_scams_get_a_warning(ctx, lang, text):
    r = run(ctx, text)
    assert r["risk_score"] >= 30, (r["risk_score"], text)
    assert r["warning"], "a suspicious message must carry a warning even when fraud isn't confirmed"
    assert any(f["category"] == "behavior" and f["weight"] >= 30 for f in r["findings"]), "the intent layer should explain why"
    assert r["confirmed"] is False and r["assessment_status"].startswith("Suspected")


@pytest.mark.parametrize("lang,text", LEGITIMATE)
def test_legitimate_messages_stay_low(ctx, lang, text):
    r = run(ctx, text)
    assert r["risk_score"] < 30, (r["risk_score"], text, [f["title"] for f in r["findings"] if f["weight"] >= 10])
    assert r["warning"] is None and r["risk_level"] == "LOW"


def test_sophisticated_scams_are_caught_without_any_keyword_list(ctx, monkeypatch):
    """Switch off every keyword pattern: the intent layer alone must still warn on most sophisticated scams."""
    monkeypatch.setattr(text_analyzer, "PATTERNS", [])
    scores = [run(ctx, t)["risk_score"] for _, t in SOPHISTICATED]
    assert sum(s >= 30 for s in scores) >= 9, scores


def test_report_has_required_fields(ctx):
    r = run(ctx, SOPHISTICATED[0][1])
    for k in ("risk_score", "risk_level", "classification", "findings", "warning", "recommended_actions", "confidence", "verdict_basis",
              "assessment_status", "intent", "similar_methods"):
        assert k in r, k
    f = next(f for f in r["findings"] if f["category"] == "behavior")
    assert f["detail"] and f["evidence"].startswith("Supporting phrases")
    assert r["similar_methods"] and r["similar_methods"][0]["id"] == "SM-BANK-002"
    assert "Heuristic and behaviour analysis" in r["verdict_basis"]


def test_protective_advice_is_not_flagged(ctx):
    r = run(ctx, "Reminder from your bank: we will never ask for your OTP, PIN or password. Do not share them with anyone.")
    assert r["risk_score"] < 30
