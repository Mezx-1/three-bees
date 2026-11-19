"""WOLVE risk engine.

Every analyzer emits `Finding`s. Each finding records *where its evidence came from*:

  verified   – deterministic technical fact (file signature mismatch, SPF=fail header, IP is private…)
  heuristic  – rule-based pattern match (urgency wording, look-alike domain…). Can be wrong.
  intel      – result returned by an external provider (DNS, geolocation, reputation), with source+timestamp
  ai         – model-generated assessment. Never treated as proof.

The score is an *indicator* (0–100), not a calibrated probability. Findings combine with a
noisy-OR so several independent weak signals add up, while no single heuristic reaches 100.
AI findings are capped so the model alone cannot push a submission to Critical.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass, field
from typing import Iterable

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

CLASSIFICATION_LABELS = {
    "phishing": "Phishing",
    "smishing": "Smishing (SMS phishing)",
    "vishing": "Vishing (voice phishing)",
    "bec": "Business Email Compromise",
    "impersonation": "Impersonation",
    "credential_theft": "Credential theft",
    "otp_theft": "OTP theft",
    "payment_fraud": "Payment fraud",
    "malware_delivery": "Malware delivery",
    "malicious_link": "Malicious link",
    "social_engineering": "Social engineering",
    "deepfake_possible": "Possible deepfake-assisted fraud",
    "suspicious_infrastructure": "Suspicious infrastructure",
}

AI_MAX_CONTRIBUTION = 30  # an AI-only finding can add at most this many weight points


@dataclass
class Finding:
    title: str
    detail: str
    category: str  # authentication|sender|url|attachment|content|image|network|endpoint|phone|metadata|ai|intel
    severity: str = "low"
    weight: int = 10  # 0..100 — contribution strength for the noisy-OR
    source: str = "heuristic"  # verified|heuristic|intel|ai
    tags: list[str] = field(default_factory=list)  # threat categories this supports
    evidence: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Limitation:
    text: str


def severity_for(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def combine(findings: Iterable[Finding]) -> int:
    remaining = 1.0
    for f in findings:
        w = max(0, min(f.weight, 95))
        if f.source == "ai":
            w = min(w, AI_MAX_CONTRIBUTION)
        remaining *= 1 - w / 100
    # Capped at 99: the score expresses strength of evidence, never certainty.
    return min(99, int(round((1 - remaining) * 100)))


def classify(findings: list[Finding], score: int, default: str = "No significant threat detected") -> tuple[str, list[str]]:
    tag_weight: dict[str, int] = defaultdict(int)
    for f in findings:
        for t in f.tags:
            tag_weight[t] += f.weight
    ranked = sorted(tag_weight.items(), key=lambda kv: kv[1], reverse=True)
    categories = [CLASSIFICATION_LABELS.get(t, t) for t, _ in ranked]
    if score < 30 or not ranked:
        return default, categories
    return CLASSIFICATION_LABELS.get(ranked[0][0], ranked[0][0]), categories


def confidence_for(findings: list[Finding], limitations: list[str]) -> str:
    """How much the evidence supports the verdict — not a probability."""
    cats = {f.category for f in findings if f.weight >= 10}
    verified_count = sum(1 for f in findings if f.source in ("verified", "intel") and f.weight >= 15)
    if len(cats) >= 3 and verified_count >= 1:
        level = "high"
    elif len(cats) >= 2 or verified_count >= 1:
        level = "medium"
    else:
        level = "low"
    if level == "high" and verified_count < 3 and len(limitations) >= 4:
        level = "medium"
    return level


def build_report(
    findings: list[Finding],
    limitations: list[str],
    *,
    default_classification: str = "No significant threat detected",
    extra: dict | None = None,
    recommendations: list[str] | None = None,
) -> dict:
    score = combine(findings)
    severity = severity_for(score)
    classification, categories = classify(findings, score, default_classification)
    ordered = sorted(findings, key=lambda f: (SEVERITY_ORDER.index(f.severity), f.weight), reverse=True)
    tags = sorted({t for f in findings for t in f.tags})
    report = {
        "risk_score": score,
        "severity": severity,
        "classification": classification,
        "threat_categories": categories,
        "confidence": confidence_for(findings, limitations),
        "findings": [f.to_dict() for f in ordered],
        "verified_findings": [f.to_dict() for f in ordered if f.source in ("verified", "intel")],
        "heuristic_findings": [f.to_dict() for f in ordered if f.source == "heuristic"],
        "ai_findings": [f.to_dict() for f in ordered if f.source == "ai"],
        "social_engineering_techniques": sorted({f.title for f in findings if f.category == "content"}),
        "recommended_actions": recommendations or recommend(tags, severity),
        "limitations": limitations,
        "score_note": "Risk score is an indicator built from the listed evidence, not a calibrated probability of fraud.",
    }
    if extra:
        report.update(extra)
    return report


def recommend(tags: list[str] | set[str], severity: str) -> list[str]:
    tags = set(tags)
    recs: list[str] = []
    if severity in ("high", "critical"):
        recs.append("Do not click links, open attachments, scan QR codes or reply until IT security reviews this item.")
    if "credential_theft" in tags or "phishing" in tags:
        recs.append("If credentials were entered, reset the password immediately and revoke active sessions.")
    if "otp_theft" in tags:
        recs.append("Never share one-time passwords. Legitimate banks and authorities never ask for an OTP by phone or message.")
    if "payment_fraud" in tags or "bec" in tags:
        recs.append("Verify any payment or bank-detail change through a known phone number — not contact details in the message.")
    if "malware_delivery" in tags:
        recs.append("Keep the attachment quarantined. If it was opened, recommend isolating the endpoint and running a full scan.")
    if "impersonation" in tags:
        recs.append("Contact the impersonated person or organisation through an independently verified channel.")
    if "vishing" in tags or "deepfake_possible" in tags:
        recs.append("Hang up and call back on an official number. Agree on a verbal code word for urgent payment requests.")
    if "malicious_link" in tags or "suspicious_infrastructure" in tags:
        recs.append("Add the domain/URL to the blocklist and check proxy logs for other users who visited it.")
    if severity in ("high", "critical"):
        recs.append("Report to IT security. For fraud against individuals in the UAE, report via official police channels (e.g. Aman service, 8002626).")
    if not recs:
        recs.append("No strong threat indicators found. Stay cautious with unexpected requests for money, credentials or codes.")
    return recs
