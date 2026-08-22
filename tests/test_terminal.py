"""Terminal rendering.

Rendering is where a triage tool fails most visibly: it either prints the report
or it dies halfway through one. The encoding fallback below exists because the
Windows legacy console cannot encode block-drawing characters, and rendering
into it raised UnicodeEncodeError mid-report.
"""

from __future__ import annotations

import io

import pytest
from rich.console import Console

from phishtriage.analyzers import Context, analyze_bytes, analyze_file
from phishtriage.reporting import terminal

from .conftest import SAMPLES, build_eml


def render_to_string(report, **console_kwargs) -> str:
    buffer = io.StringIO()
    console = Console(file=buffer, width=100, force_terminal=False, **console_kwargs)
    terminal.render(report, console)
    return buffer.getvalue()


@pytest.fixture(scope="module")
def malicious():
    return analyze_file(SAMPLES / "credential-phish.eml",
                        Context(org_domains=("example-corp.com",)))


class TestRendering:
    def test_report_contains_the_verdict_and_score(self, malicious):
        out = render_to_string(malicious)
        assert "MALICIOUS" in out
        assert "100/100" in out

    def test_every_finding_id_appears(self, malicious):
        out = render_to_string(malicious)
        for finding in malicious.findings:
            assert finding.id in out

    def test_attack_techniques_are_shown(self, malicious):
        out = render_to_string(malicious)
        for technique in malicious.attack_techniques:
            assert technique in out

    def test_no_live_url_is_printed(self, malicious):
        out = render_to_string(malicious)
        assert "http://" not in out
        assert "https://" not in out

    def test_benign_report_renders_without_findings(self):
        report = analyze_file(SAMPLES / "benign-newsletter.eml", Context())
        out = render_to_string(report)
        assert "BENIGN" in out
        assert "No indicators fired." in out

    def test_message_with_no_urls_or_attachments_renders(self):
        raw = build_eml({"From": "a@example.com", "Subject": "Hi"}, "Short note.")
        out = render_to_string(analyze_bytes(raw, "<test>"))
        assert "MESSAGE" in out


class TestEncodingFallback:
    """A console that cannot encode block glyphs must still get a report."""

    def test_ascii_glyphs_chosen_for_a_cp1252_console(self):
        buffer = io.StringIO()
        console = Console(file=buffer, width=100)
        # Simulate the Windows legacy console.
        object.__setattr__(console, "_legacy_windows", True)
        glyphs = terminal._glyphs(console)
        assert glyphs == {"full": "#", "empty": ".", "dash": "-"}

    def test_unicode_glyphs_chosen_for_a_utf8_console(self):
        console = Console(file=io.StringIO(), width=100)
        glyphs = terminal._glyphs(console)
        assert glyphs["full"] in ("█", "#")

    def test_rendering_into_a_cp1252_stream_does_not_raise(self, malicious):
        """The regression test for the original crash.

        A cp1252-backed stream raises UnicodeEncodeError on any character it
        cannot map, so this fails loudly if a non-encodable glyph creeps back in.
        """
        raw = io.BytesIO()
        stream = io.TextIOWrapper(raw, encoding="cp1252", errors="strict", newline="")
        console = Console(file=stream, width=100, force_terminal=False)
        terminal.render(malicious, console)
        stream.flush()
        assert raw.getvalue()
