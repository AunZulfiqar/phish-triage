"""Analyzer registry and the top-level ``analyze`` entry point."""

from __future__ import annotations

from ..models import Finding, ParsedEmail, Report
from ..parser import now_utc, parse_bytes, parse_file
from ..scoring import compute
from .attachments import AttachmentAnalyzer
from .auth import AuthAnalyzer
from .base import Analyzer, Context
from .content import ContentAnalyzer
from .headers import HeaderAnalyzer
from .urls import URLAnalyzer

# Order matters only for readability of the report; analyzers are independent
# except that AuthAnalyzer publishes its parsed results into the shared context
# for anything that wants them later.
ANALYZERS: tuple[Analyzer, ...] = (
    AuthAnalyzer(),
    HeaderAnalyzer(),
    URLAnalyzer(),
    AttachmentAnalyzer(),
    ContentAnalyzer(),
)


def run_analyzers(email: ParsedEmail, ctx: Context) -> list[Finding]:
    findings: list[Finding] = []
    for analyzer in ANALYZERS:
        try:
            findings.extend(analyzer.run(email, ctx))
        except Exception as exc:  # pragma: no cover - defensive
            # One broken analyzer must not lose the rest of the triage. Real
            # phishing is malformed often enough that this matters.
            import warnings
            warnings.warn(f"{analyzer.name} analyzer failed: {exc!r}", stacklevel=2)
    findings.sort(key=lambda f: (-f.indicator.severity.rank, -f.indicator.weight, f.id))
    return findings


def analyze(email: ParsedEmail, ctx: Context | None = None) -> Report:
    ctx = ctx or Context()
    findings = run_analyzers(email, ctx)
    score, verdict, breakdown = compute(findings)
    return Report(
        email=email,
        findings=findings,
        score=score,
        verdict=verdict,
        generated_at=now_utc(),
        online_checks=ctx.online,
        breakdown=breakdown,
    )


def analyze_file(path, ctx: Context | None = None) -> Report:
    return analyze(parse_file(path), ctx)


def analyze_bytes(raw: bytes, source: str = "<memory>", ctx: Context | None = None) -> Report:
    return analyze(parse_bytes(raw, source), ctx)


__all__ = [
    "ANALYZERS", "Analyzer", "Context",
    "analyze", "analyze_bytes", "analyze_file", "run_analyzers",
]
