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


class TestMarkupIsNotInterpreted:
    """Rich parses square-bracket markup in bare strings.

    Defanged output is made of square brackets, and every string in a report
    originates from an attacker-controlled message. Both facts point the same
    way: nothing may reach the console as a plain string.
    """

    def test_defanged_at_sign_survives_rendering(self, malicious):
        """`[@]` matches Rich's tag syntax and was silently swallowed, printing
        a sender address with no @ in it at all."""
        out = render_to_string(malicious)
        assert "[@]" in out
        assert "alerts[@]micros0ft-security[.]tk" in out.replace("\n", "")

    def test_markup_in_a_subject_is_not_executed(self):
        raw = build_eml(
            {"From": "a@example.com", "Subject": "[bold red]URGENT[/bold red] [blink]now"},
            "Short note.",
        )
        out = render_to_string(analyze_bytes(raw, "<test>"))
        assert "[bold red]URGENT[/bold red]" in out.replace("\n", "")

    def test_unclosed_markup_tag_does_not_raise(self):
        """An unclosed tag makes Rich raise MarkupError and lose the report."""
        raw = build_eml({"From": "a@example.com", "Subject": "[/not-a-real-tag"}, "body")
        out = render_to_string(analyze_bytes(raw, "<test>"))
        assert "MESSAGE" in out


class TestEncodingFallback:
    """A console that cannot encode block glyphs must still get a report."""

    def test_ascii_glyphs_chosen_for_a_legacy_windows_console(self):
        # `legacy_windows` is a real Console constructor argument. An earlier
        # version of this test forced the private `_legacy_windows` attribute
        # instead, which Rich does not promise to honour -- it happened to work
        # on Windows and did nothing on Linux.
        console = Console(file=io.StringIO(), width=100, legacy_windows=True)
        assert console.legacy_windows is True
        assert terminal._glyphs(console) == {"full": "#", "empty": ".", "dash": "-"}

    def test_unicode_glyphs_chosen_for_a_modern_utf8_console(self):
        buffer = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
        console = Console(file=buffer, width=100, legacy_windows=False)
        assert terminal._glyphs(console) == {"full": "█", "empty": "░", "dash": "—"}

    def test_ascii_glyphs_chosen_for_a_cp1252_stream(self):
        buffer = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
        console = Console(file=buffer, width=100, legacy_windows=False)
        assert terminal._glyphs(console) == {"full": "#", "empty": ".", "dash": "-"}

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
