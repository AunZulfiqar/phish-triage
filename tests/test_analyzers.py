"""Per-indicator analyzer behaviour.

Each test drives one indicator to fire, and where a false positive is plausible
there is a paired test proving it stays silent. That pairing is the point: a
phishing detector that only has positive tests will quietly become unusable in
production while its suite stays green.
"""

from __future__ import annotations

from .conftest import build_eml


def ids(report) -> set[str]:
    return {f.id for f in report.findings}


AUTH_PASS = ("mx.example-corp.com; spf=pass smtp.mailfrom=news@example.com; "
             "dkim=pass header.d=example.com; dmarc=pass header.from=example.com")


class TestAuthentication:
    def test_spf_hard_fail(self, analyze_raw):
        raw = build_eml({
            "From": "a@example.com",
            "Authentication-Results": "mx.corp.com; spf=fail smtp.mailfrom=a@example.com",
        }, "body")
        assert "AUTH-001" in ids(analyze_raw(raw))

    def test_spf_softfail_is_weaker(self, analyze_raw):
        raw = build_eml({
            "From": "a@example.com",
            "Authentication-Results": "mx.corp.com; spf=softfail smtp.mailfrom=a@example.com",
        }, "body")
        found = ids(analyze_raw(raw))
        assert "AUTH-002" in found and "AUTH-001" not in found

    def test_dmarc_failure(self, analyze_raw):
        raw = build_eml({
            "From": "a@example.com",
            "Authentication-Results": "mx.corp.com; dmarc=fail header.from=example.com",
        }, "body")
        assert "AUTH-005" in ids(analyze_raw(raw))

    def test_missing_authentication_results(self, analyze_raw):
        raw = build_eml({"From": "a@example.com"}, "body")
        assert "AUTH-006" in ids(analyze_raw(raw))

    def test_alignment_mismatch_when_auth_passes_for_another_domain(self, analyze_raw):
        raw = build_eml({
            "From": "security@microsoft.com",
            "Authentication-Results": "mx.corp.com; spf=pass smtp.mailfrom=bounce@sender.tk; "
                                      "dkim=pass header.d=sender.tk",
        }, "body")
        assert "AUTH-007" in ids(analyze_raw(raw))

    def test_aligned_pass_produces_no_alignment_finding(self, analyze_raw):
        raw = build_eml({"From": "news@example.com", "Authentication-Results": AUTH_PASS}, "body")
        assert "AUTH-007" not in ids(analyze_raw(raw))


class TestHeaders:
    def test_reply_to_mismatch(self, analyze_raw):
        raw = build_eml({
            "From": "billing@example.com",
            "Reply-To": "collector@other.tk",
            "Authentication-Results": AUTH_PASS,
        }, "body")
        assert "HDR-001" in ids(analyze_raw(raw))

    def test_brand_impersonation_in_display_name(self, analyze_raw):
        raw = build_eml({
            "From": "Microsoft Account Team <alerts@not-microsoft.tk>",
            "Authentication-Results": AUTH_PASS,
        }, "body")
        assert "HDR-004" in ids(analyze_raw(raw))

    def test_real_brand_domain_is_not_impersonation(self, analyze_raw):
        raw = build_eml({
            "From": "Microsoft Account Team <alerts@microsoft.com>",
            "Authentication-Results": AUTH_PASS,
        }, "body")
        assert "HDR-004" not in ids(analyze_raw(raw))

    def test_address_hidden_inside_display_name(self, analyze_raw):
        raw = build_eml({
            "From": '"support@paypal.com" <attacker@evil.tk>',
            "Authentication-Results": AUTH_PASS,
        }, "body")
        assert "HDR-003" in ids(analyze_raw(raw))

    def test_freemail_claiming_a_corporate_role(self, analyze_raw):
        raw = build_eml({
            "From": "Sarah Ahmed CFO <s.ahmed.finance@gmail.com>",
            "Authentication-Results": AUTH_PASS,
        }, "body")
        assert "HDR-012" in ids(analyze_raw(raw))

    def test_reply_prefix_without_a_thread(self, analyze_raw):
        raw = build_eml({"From": "a@example.com", "Subject": "Re: Invoice"}, "body")
        assert "HDR-013" in ids(analyze_raw(raw))

    def test_reply_prefix_with_a_real_thread_is_fine(self, analyze_raw):
        raw = build_eml({
            "From": "a@example.com", "Subject": "Re: Invoice",
            "In-Reply-To": "<original@example.com>",
        }, "body")
        assert "HDR-013" not in ids(analyze_raw(raw))


class TestURLs:
    def test_anchor_text_href_mismatch(self, analyze_raw):
        html = '<a href="https://evil.example.tk/x">https://www.paypal.com/signin</a>'
        raw = build_eml({"From": "a@example.com"}, html, content_type="text/html")
        assert "URL-001" in ids(analyze_raw(raw))

    def test_non_domain_anchor_text_is_not_a_mismatch(self, analyze_raw):
        html = '<a href="https://tracking.example.net/x">Read more</a>'
        raw = build_eml({"From": "a@example.com"}, html, content_type="text/html")
        assert "URL-001" not in ids(analyze_raw(raw))

    def test_userinfo_obfuscation(self, analyze_raw):
        html = '<a href="https://www.paypal.com@evil.example.tk/login">Sign in</a>'
        raw = build_eml({"From": "a@example.com"}, html, content_type="text/html")
        assert "URL-013" in ids(analyze_raw(raw))

    def test_bare_ip_target(self, analyze_raw):
        raw = build_eml({"From": "a@example.com"}, "Visit http://198.51.100.7/login now")
        assert "URL-005" in ids(analyze_raw(raw))

    def test_punycode_host(self, analyze_raw):
        raw = build_eml({"From": "a@example.com"}, "Go to https://xn--80ak6aa92e.com/verify")
        assert "URL-002" in ids(analyze_raw(raw))

    def test_lookalike_brand_domain(self, analyze_raw):
        raw = build_eml({"From": "a@example.com"}, "Go to https://micros0ft.com/account")
        assert "URL-004" in ids(analyze_raw(raw))

    def test_brand_in_subdomain_of_attacker_domain(self, analyze_raw):
        raw = build_eml({"From": "a@example.com"},
                        "https://login.microsoft.com.account-verify.evil.tk/auth")
        assert "URL-010" in ids(analyze_raw(raw))

    def test_legitimate_brand_url_is_clean(self, analyze_raw):
        html = '<a href="https://login.microsoftonline.com/common/oauth2">Sign in</a>'
        raw = build_eml({"From": "a@example.com", "Authentication-Results": AUTH_PASS},
                        html, content_type="text/html")
        found = ids(analyze_raw(raw))
        assert not {"URL-001", "URL-004", "URL-008", "URL-010"} & found

    def test_url_shortener(self, analyze_raw):
        raw = build_eml({"From": "a@example.com"}, "Click https://bit.ly/3xAbCd")
        assert "URL-006" in ids(analyze_raw(raw))

    def test_open_redirect_parameter(self, analyze_raw):
        raw = build_eml({"From": "a@example.com"},
                        "https://redir.example.net/go?url=https://evil.tk/harvest")
        assert "URL-009" in ids(analyze_raw(raw))


class TestAttachments:
    def _with_attachment(self, filename: str, content_type: str, body_text: str = "See attached."):
        boundary = "B"
        body = (
            f"--{boundary}\n"
            'Content-Type: text/plain; charset="utf-8"\n\n'
            f"{body_text}\n"
            f"--{boundary}\n"
            f'Content-Type: {content_type}; name="{filename}"\n'
            f'Content-Disposition: attachment; filename="{filename}"\n\n'
            "TVqQAAMAAAAEAAAA\n"
            f"--{boundary}--\n"
        )
        return build_eml({"From": "a@example.com"}, body,
                         content_type=f'multipart/mixed; boundary="{boundary}"')

    def test_executable_attachment(self, analyze_raw):
        raw = self._with_attachment("update.exe", "application/octet-stream")
        assert "ATT-001" in ids(analyze_raw(raw))

    def test_double_extension(self, analyze_raw):
        raw = self._with_attachment("invoice.pdf.scr", "application/octet-stream")
        assert "ATT-002" in ids(analyze_raw(raw))

    def test_macro_document(self, analyze_raw):
        raw = self._with_attachment(
            "report.docm", "application/vnd.ms-word.document.macroEnabled.12")
        assert "ATT-003" in ids(analyze_raw(raw))

    def test_rtlo_filename(self, analyze_raw):
        raw = self._with_attachment("invoice‮gnp.exe", "application/octet-stream")
        assert "ATT-008" in ids(analyze_raw(raw))

    def test_encrypted_archive_with_password_in_body(self, analyze_raw):
        raw = self._with_attachment(
            "docs.zip", "application/zip",
            body_text="Please open the archive. The password is Secret2026.",
        )
        found = ids(analyze_raw(raw))
        assert "ATT-006" in found and "ATT-004" in found

    def test_plain_pdf_is_not_flagged(self, analyze_raw):
        raw = self._with_attachment("report.pdf", "application/pdf")
        found = ids(analyze_raw(raw))
        assert not {"ATT-001", "ATT-002", "ATT-003", "ATT-005", "ATT-007"} & found


class TestContent:
    def test_credential_form_in_body(self, analyze_raw):
        html = ('<form action="https://evil.tk/x" method="post">'
                '<input type="password" name="password"></form>')
        raw = build_eml({"From": "a@example.com"}, html, content_type="text/html")
        assert "CNT-006" in ids(analyze_raw(raw))

    def test_hidden_text(self, analyze_raw):
        html = ('<div style="display:none">' + "filter poison text " * 5 + "</div>"
                "<p>Hello there, this is the visible part of the message.</p>")
        raw = build_eml({"From": "a@example.com"}, html, content_type="text/html")
        assert "CNT-004" in ids(analyze_raw(raw))

    def test_invisible_characters(self, analyze_raw):
        body = "Please ver​ify your acc​ount imm​edia​tely no​w"
        raw = build_eml({"From": "a@example.com"}, body)
        assert "CNT-005" in ids(analyze_raw(raw))

    def test_invisible_matching_still_finds_the_keyword(self, analyze_raw):
        body = "Please ver​ify your acc​ount imm​edia​tely no​w"
        raw = build_eml({"From": "a@example.com"}, body)
        # The zero-width joiners must not hide "verify your account".
        assert "CNT-002" in ids(analyze_raw(raw))

    def test_bec_shape_requires_no_payload(self, analyze_raw):
        raw = build_eml({"From": "ceo@example.com"},
                        "Are you available? I need you to handle a quick task. Reply back.")
        assert "CNT-011" in ids(analyze_raw(raw))

    def test_bec_shape_silent_when_links_present(self, analyze_raw):
        raw = build_eml({"From": "ceo@example.com"},
                        "Are you available? See https://example.com/doc")
        assert "CNT-011" not in ids(analyze_raw(raw))
