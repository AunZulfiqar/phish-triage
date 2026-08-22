"""Scoring model, catalogue integrity, report rendering and the CLI contract."""

from __future__ import annotations

import json

import pytest

from phishtriage import catalog
from phishtriage.analyzers import Context, analyze_file
from phishtriage.models import Finding, Severity, Verdict
from phishtriage.reporting import html_out, json_out
from phishtriage.scoring import compute

from .conftest import SAMPLES


def fake(indicator_id: str) -> Finding:
    return Finding(catalog.get(indicator_id), "synthetic evidence")


class TestCatalogue:
    def test_ids_are_unique(self):
        all_ids = [i.id for i in catalog.all_indicators()]
        assert len(all_ids) == len(set(all_ids))

    def test_every_indicator_has_a_known_category(self):
        for indicator in catalog.all_indicators():
            assert indicator.category in catalog.CATEGORIES

    def test_weights_are_within_range(self):
        for indicator in catalog.all_indicators():
            assert 0 <= indicator.weight <= 40

    def test_attack_ids_look_like_technique_ids(self):
        import re
        for indicator in catalog.all_indicators():
            for technique in indicator.attack:
                assert re.fullmatch(r"T\d{4}(\.\d{3})?", technique), technique

    def test_severity_and_weight_agree_in_direction(self):
        """A critical indicator must not weigh less than a low one."""
        criticals = [i.weight for i in catalog.all_indicators()
                     if i.severity is Severity.CRITICAL]
        lows = [i.weight for i in catalog.all_indicators() if i.severity is Severity.LOW]
        assert min(criticals) > max(lows)


class TestScoring:
    def test_no_findings_is_benign(self):
        score, verdict, breakdown = compute([])
        assert score == 0 and verdict is Verdict.BENIGN
        assert breakdown["authentication_clean"] is True

    def test_single_critical_indicator_reaches_likely_phishing(self):
        score, verdict, _ = compute([fake("ATT-001")])
        assert verdict is Verdict.LIKELY_PHISHING, score

    def test_two_critical_indicators_reach_malicious(self):
        score, verdict, _ = compute([fake("ATT-001"), fake("AUTH-005"), fake("URL-001")])
        assert verdict is Verdict.MALICIOUS, score

    def test_corroboration_bonus_grows_with_category_spread(self):
        one = compute([fake("URL-006"), fake("URL-007")])[0]
        three = compute([fake("URL-006"), fake("HDR-005"), fake("CNT-009")])[0]
        assert three > 0
        # Same-category evidence earns no bonus.
        assert compute([fake("URL-006"), fake("URL-007")])[2]["corroboration_bonus"] == 0
        assert compute([fake("URL-006"), fake("HDR-005"),
                        fake("CNT-009")])[2]["corroboration_bonus"] > 0
        assert one >= 0

    def test_content_findings_are_discounted_when_auth_is_clean(self):
        content_only = [fake("CNT-001"), fake("CNT-003"), fake("CNT-010")]
        clean_score, _, breakdown = compute(content_only)
        assert breakdown["authentication_clean"] is True
        assert breakdown["discount"] > 0

        with_auth_failure = [*content_only, fake("AUTH-005")]
        failing_score, _, failing_breakdown = compute(with_auth_failure)
        assert failing_breakdown["discount"] == 0
        assert failing_score > clean_score

    def test_score_is_capped_at_one_hundred(self):
        every = [fake(i.id) for i in catalog.all_indicators()]
        score, verdict, _ = compute(every)
        assert score == 100 and verdict is Verdict.MALICIOUS


class TestEndToEnd:
    """Regression bands for the sample corpus.

    Asserted as bands rather than exact scores so that tuning an individual
    weight does not break the suite, while a change that flips a verdict does.
    """

    EXPECTED = {
        "benign-newsletter.eml": (Verdict.BENIGN, 0, 15),
        "benign-receipt.eml": (Verdict.BENIGN, 0, 19),
        "bec-wire-fraud.eml": (Verdict.LIKELY_PHISHING, 45, 74),
        "credential-phish.eml": (Verdict.MALICIOUS, 75, 100),
        "malware-attachment.eml": (Verdict.MALICIOUS, 75, 100),
    }

    @pytest.mark.parametrize("filename", sorted(EXPECTED))
    def test_sample_lands_in_the_expected_band(self, filename):
        expected_verdict, low, high = self.EXPECTED[filename]
        report = analyze_file(SAMPLES / filename, Context(org_domains=("example-corp.com",)))
        assert report.verdict is expected_verdict, (
            f"{filename}: {report.verdict.value} at {report.score} — "
            f"{[f.id for f in report.findings]}"
        )
        assert low <= report.score <= high

    def test_benign_messages_trigger_no_high_severity_findings(self):
        for filename in ("benign-newsletter.eml", "benign-receipt.eml"):
            report = analyze_file(SAMPLES / filename, Context())
            severe = [f.id for f in report.findings
                      if f.indicator.severity.rank >= Severity.HIGH.rank]
            assert not severe, f"{filename} raised {severe}"

    def test_no_network_access_in_offline_mode(self, monkeypatch):
        """Offline is the default and must be enforced, not merely intended."""
        import socket

        def blocked(*args, **kwargs):
            raise AssertionError("analysis attempted a network connection")

        monkeypatch.setattr(socket, "socket", blocked)
        monkeypatch.setattr(socket, "create_connection", blocked)
        for path in sorted(SAMPLES.glob("*.eml")):
            analyze_file(path, Context(online=False))


@pytest.fixture(scope="module")
def report():
    """Module-scoped rather than class-scoped-on-a-method.

    A class-scoped fixture defined as an instance method is deprecated in
    pytest and becomes an error in 10.x, because each test gets a fresh
    instance while the fixture runs once.
    """
    return analyze_file(SAMPLES / "credential-phish.eml",
                        Context(org_domains=("example-corp.com",)))


class TestReporting:
    def test_json_is_serialisable_and_defanged(self, report):
        payload = json.loads(json_out.dumps(report))
        assert payload["verdict"]["label"] == "Malicious"
        assert payload["findings"]
        blob = json.dumps(payload)
        assert "http://" not in blob and "https://" not in blob

    def test_no_defang_keeps_live_urls(self, report):
        payload = json.loads(json_out.dumps(report, defanged=False))
        assert any(u["url"].startswith("http") for u in payload["urls"])

    def test_iocs_are_typed_and_unique(self, report):
        iocs = json_out.to_iocs(report)
        assert iocs
        assert len({(i["type"], i["value"]) for i in iocs}) == len(iocs)
        assert {i["type"] for i in iocs} <= {"url", "domain", "sender-domain", "ip-src", "sha256"}

    def test_html_report_is_self_contained(self, report):
        html = html_out.render(report)
        assert "<style>" in html
        assert "Malicious" in html
        # No external resource may be referenced from the report.
        for marker in ("src=\"http", "href=\"http", "@import", "cdn."):
            assert marker not in html

    def test_html_escapes_attacker_controlled_text(self):
        from phishtriage.analyzers import analyze_bytes

        from .conftest import build_eml

        raw = build_eml(
            {"From": "a@example.com", "Subject": "<script>alert(1)</script>"},
            "body",
        )
        html = html_out.render(analyze_bytes(raw, "<test>"))
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html


class TestCLI:
    def test_indicators_json_lists_the_catalogue(self, capsys):
        from phishtriage.cli import main

        assert main(["indicators", "--format", "json"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert len(payload) == len(catalog.all_indicators())

    def test_analyze_exit_code_is_zero_for_benign(self, capsys):
        from phishtriage.cli import main

        code = main(["analyze", str(SAMPLES / "benign-newsletter.eml"),
                     "--format", "summary"])
        capsys.readouterr()
        assert code == 0

    def test_analyze_exit_code_is_one_for_malicious(self, capsys):
        from phishtriage.cli import main

        code = main(["analyze", str(SAMPLES / "credential-phish.eml"),
                     "--format", "summary"])
        capsys.readouterr()
        assert code == 1

    def test_fail_on_never_always_exits_zero(self, capsys):
        from phishtriage.cli import main

        code = main(["analyze", str(SAMPLES / "credential-phish.eml"),
                     "--format", "summary", "--fail-on", "never"])
        capsys.readouterr()
        assert code == 0

    def test_batch_mode_scans_a_directory(self, capsys):
        from phishtriage.cli import main

        main(["analyze", str(SAMPLES), "--format", "summary", "--fail-on", "never"])
        payload = json.loads(capsys.readouterr().out)
        assert len(payload) == len(list(SAMPLES.glob("*.eml")))

    def test_missing_input_is_a_usage_error(self, capsys):
        from phishtriage.cli import main

        assert main(["analyze", str(SAMPLES / "does-not-exist.eml")]) == 2
        capsys.readouterr()
