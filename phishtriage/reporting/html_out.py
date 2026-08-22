"""Standalone HTML report.

Self-contained by design: no external stylesheet, no font CDN, no script. The
file can be attached to a ticket, opened on an air-gapped analysis host, or
archived as evidence, and it will render identically years later. Autoescaping
is on, which matters more than usual here -- every string in the report
originates from an attacker-controlled message.
"""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..catalog import CATEGORY_TITLES
from ..models import Report
from ..scoring import explain
from ..utils import defang
from .json_out import to_iocs

_TEMPLATE_DIR = Path(__file__).parent / "templates"

_VERDICT_VAR = {
    "Benign": "benign",
    "Suspicious": "suspicious",
    "Likely Phishing": "likely",
    "Malicious": "malicious",
}


def _environment() -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(default_for_string=True, default=True),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    return env


class _Defang:
    """Template-facing defang helpers."""

    url = staticmethod(defang.defang_url)
    domain = staticmethod(defang.defang_domain)
    ip = staticmethod(defang.defang_ip)
    email = staticmethod(defang.defang_email)
    text = staticmethod(defang.defang_text)


def render(report: Report) -> str:
    template = _environment().get_template("report.html.j2")
    return template.render(
        report=report,
        grouped=report.by_category(),
        category_titles=CATEGORY_TITLES,
        iocs=to_iocs(report, defanged=True),
        rationale=explain(report.score, report.verdict, report.breakdown),
        verdict_var=_VERDICT_VAR.get(report.verdict.value, "info"),
        d=_Defang,
    )


def write(report: Report, path: str | Path) -> Path:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render(report), encoding="utf-8")
    return out
