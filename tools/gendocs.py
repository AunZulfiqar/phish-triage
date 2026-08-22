#!/usr/bin/env python3
"""Regenerate the derived documentation.

``docs/indicators.md`` is generated from ``phishtriage/catalog.py`` rather than
maintained alongside it. Hand-written detection documentation drifts from the
code within about two commits, and a detection reference that lies is worse than
no reference at all -- an analyst reads it to decide whether a finding matters.

    python tools/gendocs.py
"""

from __future__ import annotations

import io
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from phishtriage import catalog  # noqa: E402
from phishtriage.analyzers import Context, analyze_bytes  # noqa: E402
from phishtriage.reporting import html_out, terminal  # noqa: E402

DOCS = ROOT / "docs"

WEIGHT_KEY = (
    ("1-3", "contextual noise; meaningful only alongside other findings"),
    ("4-7", "a real oddity, common in marketing mail as well as phishing"),
    ("8-14", "strong signal, unusual in legitimate mail"),
    ("15-25", "near-conclusive on its own"),
)


def render_indicators() -> str:
    out = io.StringIO()
    out.write("# Indicator catalogue\n\n")
    out.write("Generated from `phishtriage/catalog.py` by `make docs`. Do not edit by hand.\n\n")
    out.write(f"**{len(catalog.all_indicators())} indicators** across "
              f"{len(catalog.CATEGORIES)} categories.\n\n")
    out.write("Weight is the contribution to the 0-100 risk score. See the "
              "[scoring section](../README.md#how-the-score-is-built) of the README for how "
              "weights combine into a verdict.\n\n")
    out.write("| Weight range | Meaning |\n|---|---|\n")
    for rng, meaning in WEIGHT_KEY:
        out.write(f"| {rng} | {meaning} |\n")
    out.write("\n")

    for category in catalog.CATEGORIES:
        rows = [i for i in catalog.all_indicators() if i.category == category]
        out.write(f"## {category.capitalize()} ({len(rows)})\n\n")
        out.write("| ID | Indicator | Severity | Weight | ATT&CK | What it means |\n")
        out.write("|---|---|---|---|---|---|\n")
        for i in rows:
            attack = ", ".join(f"`{t}`" for t in i.attack) or "-"
            out.write(f"| `{i.id}` | {i.name} | {i.severity.value} | {i.weight} | "
                      f"{attack} | {i.description} |\n")
        out.write("\n")
    return out.getvalue()


DEMO_CTX = Context(org_domains=("example-corp.com",))
DEMO_SAMPLE = "credential-phish.eml"

# Committed artifacts must be byte-identical on every machine, so the two
# things that vary between runs are pinned: the source label (which would
# otherwise embed the generating machine's absolute filesystem path into a
# public file) and the generation timestamp.
DEMO_SOURCE_LABEL = f"samples/{DEMO_SAMPLE}"
DEMO_TIMESTAMP = datetime(2026, 3, 14, 9, 12, 4, tzinfo=timezone.utc)


def _demo_report():
    raw = (ROOT / "samples" / DEMO_SAMPLE).read_bytes()
    report = analyze_bytes(raw, DEMO_SOURCE_LABEL, DEMO_CTX)
    report.generated_at = DEMO_TIMESTAMP
    return report


def render_demo() -> str:
    from rich.console import Console

    buffer = io.StringIO()
    console = Console(file=buffer, width=96, force_terminal=False, legacy_windows=False)
    terminal.render(_demo_report(), console)
    return buffer.getvalue()


def render_sample_html() -> str:
    return html_out.render(_demo_report())


def main() -> None:
    DOCS.mkdir(exist_ok=True)
    for name, content in (("indicators.md", render_indicators()),
                          ("demo-output.txt", render_demo()),
                          ("sample-report.html", render_sample_html())):
        path = DOCS / name
        # newline="" stops Python's text layer rewriting line endings to the
        # platform default. Without it a file generated on Windows and
        # regenerated on Linux differs byte-for-byte, and the reproducibility
        # check can never pass on both.
        path.write_text(content, encoding="utf-8", newline="")
        print(f"wrote {path.relative_to(ROOT)} ({len(content):,} chars)")


if __name__ == "__main__":
    main()
