"""Verdict computation.

The model is intentionally a transparent weighted sum rather than anything
learned. This is a triage tool whose output ends up in an incident ticket, and
an analyst has to be able to answer "why did it say that?" in one sentence. A
gradient-boosted classifier would score better on a benchmark and be far worse
in an escalation meeting.

Two adjustments sit on top of the raw sum:

**Corroboration bonus.** Indicators that fire in several independent categories
are worth more than the same total weight concentrated in one. Three categories
of evidence is the difference between "aggressive marketing" and "attack".

**Authentication gate.** Content and URL heuristics produce most of the false
positives in any phishing tool, because legitimate marketing mail looks like
phishing. When a message passes DMARC from a domain that genuinely owns the
brand it claims, soft evidence is discounted -- the sender is who they say they
are, so urgency wording is just bad copywriting.
"""

from __future__ import annotations

from .models import Finding, Severity, Verdict

# Score thresholds. A single critical indicator is lifted to LIKELY_PHISHING by
# the severity floor below rather than by its weight; two or three together
# clear 75 on weight alone.
THRESHOLDS: tuple[tuple[int, Verdict], ...] = (
    (75, Verdict.MALICIOUS),
    (45, Verdict.LIKELY_PHISHING),
    (20, Verdict.SUSPICIOUS),
    (0, Verdict.BENIGN),
)

CORROBORATION_BONUS: dict[int, int] = {0: 0, 1: 0, 2: 3, 3: 8, 4: 14, 5: 20}

_VERDICT_RANK: dict[Verdict, int] = {
    Verdict.BENIGN: 0,
    Verdict.SUSPICIOUS: 1,
    Verdict.LIKELY_PHISHING: 2,
    Verdict.MALICIOUS: 3,
}

# Categories whose findings are discounted when the sender authenticated cleanly.
SOFT_CATEGORIES: frozenset[str] = frozenset({"content"})
SOFT_DISCOUNT = 0.4


def _authentication_clean(findings: list[Finding]) -> bool:
    """True when nothing in the authentication category raised a real concern."""
    for f in findings:
        if f.indicator.category != "authentication":
            continue
        if f.id in ("AUTH-004", "AUTH-008"):
            continue  # advisory only, not a failure
        return False
    return True


def compute(findings: list[Finding]) -> tuple[int, Verdict, dict]:
    """Return ``(score, verdict, breakdown)`` for a set of findings.

    The empty-findings case is handled by the general path rather than by an
    early return. A separate return built its own breakdown dict, which drifted
    out of sync the moment a key was added and crashed the renderer on exactly
    the messages that were fine.
    """
    auth_clean = _authentication_clean(findings)
    raw_weight = 0
    discounted = 0
    for f in findings:
        weight = f.indicator.weight
        if auth_clean and f.indicator.category in SOFT_CATEGORIES:
            reduced = int(round(weight * SOFT_DISCOUNT))
            discounted += weight - reduced
            weight = reduced
        raw_weight += weight

    categories = sorted({f.indicator.category for f in findings})
    bonus = CORROBORATION_BONUS.get(len(categories), 20)

    score = min(100, raw_weight + bonus)
    verdict = next(v for threshold, v in THRESHOLDS if score >= threshold)

    # Severity floor. The catalogue defines "critical" as near-conclusive on its
    # own, so a lone critical indicator -- a bare .exe attachment, an RTLO
    # filename -- must not be filed as merely Suspicious just because nothing
    # else corroborated it. Weight alone cannot express this without inflating
    # the number past what the evidence supports.
    floored = False
    if any(f.indicator.severity is Severity.CRITICAL for f in findings):
        if _VERDICT_RANK[verdict] < _VERDICT_RANK[Verdict.LIKELY_PHISHING]:
            verdict = Verdict.LIKELY_PHISHING
            floored = True

    breakdown = {
        "raw_weight": raw_weight,
        "discount": discounted,
        "corroboration_bonus": bonus,
        "categories": categories,
        "authentication_clean": auth_clean,
        "finding_count": len(findings),
        "critical_floor_applied": floored,
    }
    return score, verdict, breakdown


def explain(score: int, verdict: Verdict, breakdown: dict) -> str:
    """A one-line rationale, for the top of the report."""
    parts = [
        f"{breakdown['finding_count']} indicator(s) across "
        f"{len(breakdown['categories'])} category(ies)",
        f"weight {breakdown['raw_weight']}",
    ]
    if breakdown["corroboration_bonus"]:
        parts.append(f"+{breakdown['corroboration_bonus']} corroboration")
    if breakdown["discount"]:
        parts.append(
            f"-{breakdown['discount']} discounted (sender authenticated cleanly)"
        )
    if breakdown.get("critical_floor_applied"):
        parts.append("floored by a critical indicator")
    return f"{verdict.value} - score {score}/100 ({'; '.join(parts)})"
