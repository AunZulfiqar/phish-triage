"""Defang, domain and homoglyph helpers."""

from __future__ import annotations

import pytest

from phishtriage.utils import defang, domains, homoglyph


class TestDefang:
    @pytest.mark.parametrize("live,dead", [
        ("http://evil.example.tk/a", "hxxp[://]evil[.]example[.]tk/a"),
        ("https://evil.example.tk/a", "hxxps[://]evil[.]example[.]tk/a"),
    ])
    def test_urls_are_neutralised(self, live, dead):
        assert defang.defang_url(live) == dead

    @pytest.mark.parametrize("url", [
        "https://a.example.com/x?y=1",
        "http://198.51.100.4/p",
        "ftp://files.example.net/pub",
        "https://paypal.com@evil.example.tk/",
        # An open-redirect link carries a second live URL in its query string.
        "https://redir.example.net/go?url=https://evil.tk/harvest",
    ])
    def test_round_trip_restores_the_original(self, url):
        assert defang.refang(defang.defang_url(url)) == url

    def test_nested_scheme_is_also_neutralised(self):
        out = defang.defang_url("https://redir.example.net/go?url=https://evil.tk/harvest")
        assert "https://" not in out
        assert out.count("hxxps[://]") == 2

    def test_userinfo_at_sign_is_bracketed(self):
        out = defang.defang_url("https://paypal.com@evil.example.tk/")
        assert out == "hxxps[://]paypal[.]com[@]evil[.]example[.]tk/"

    def test_defang_text_neutralises_indicators_inside_prose(self):
        out = defang.defang_text(
            "carries a redirect parameter redirect=https://login.microsoftonline.com"
        )
        assert "https://" not in out
        assert "hxxps[://]login[.]microsoftonline[.]com" in out

    def test_defang_text_leaves_version_numbers_alone(self):
        assert defang.defang_text("PHPMailer 6.8.0") == "PHPMailer 6.8.0"

    def test_defang_structure_recurses(self):
        out = defang.defang_structure(
            {"a": "http://evil.tk/x", "b": ["mail.evil.tk", {"c": "1.2.3.4"}], "d": 7}
        )
        assert out["a"] == "hxxp[://]evil[.]tk/x"
        assert out["b"][0] == "mail[.]evil[.]tk"
        assert out["b"][1]["c"] == "1[.]2[.]3[.]4"
        assert out["d"] == 7

    def test_email_and_ip(self):
        assert defang.defang_email("a@example.com") == "a[@]example[.]com"
        assert defang.defang_ip("198.51.100.4") == "198[.]51[.]100[.]4"
        assert defang.defang_ip("2001:db8::1") == "2001[:]db8[:][:]1"


class TestDomains:
    @pytest.mark.parametrize("host,expected", [
        ("mail.corp.example.co.uk", "example.co.uk"),
        ("www.google.com", "google.com"),
        ("login.microsoft.com.attacker.tk", "attacker.tk"),
        ("example.com", "example.com"),
    ])
    def test_registered_domain_respects_the_public_suffix_list(self, host, expected):
        assert domains.registered_domain(host) == expected

    def test_ip_hosts_have_no_registered_domain(self):
        assert domains.registered_domain("198.51.100.4") == ""
        assert domains.is_ip("198.51.100.4")
        assert not domains.is_ip("example.com")

    def test_same_org_uses_the_registrable_domain(self):
        assert domains.same_org("mail.example.co.uk", "smtp.example.co.uk")
        assert not domains.same_org("example.co.uk", "example.com")
        assert not domains.same_org("", "example.com")

    @pytest.mark.parametrize("a,b,expected", [
        ("paypal", "paypal", 0),
        ("paypa1", "paypal", 1),
        ("micros0ft", "microsoft", 1),
        ("completely", "different", 5),
    ])
    def test_levenshtein(self, a, b, expected):
        result = domains.levenshtein(a, b, cap=4)
        assert result == expected if expected <= 4 else result > 4

    def test_levenshtein_early_exit_is_bounded(self):
        assert domains.levenshtein("a" * 40, "b" * 2, cap=2) > 2

    def test_addresses_in_free_text(self):
        found = domains.addresses_in("contact Bob <bob@example.com> or admin@example.org")
        assert "bob@example.com" in found
        assert "admin@example.org" in found


class TestHomoglyph:
    def test_cyrillic_in_a_latin_word_is_mixed_script(self):
        # U+0430 CYRILLIC SMALL LETTER A renders identically to Latin 'a'.
        assert homoglyph.is_mixed_script("pаypal")
        assert not homoglyph.is_mixed_script("paypal")

    def test_confusable_characters_are_named(self):
        found = homoglyph.confusable_chars("pаypal")
        assert found
        char, name, script = found[0]
        assert script == "Cyrillic"
        assert "CYRILLIC" in name

    def test_invisible_characters_are_counted(self):
        text = "ur​ge​nt​ re​ply​"
        found = homoglyph.find_invisible(text)
        assert found
        assert sum(count for _, _, count in found) == 5

    def test_strip_invisible_restores_matchable_text(self):
        assert homoglyph.strip_invisible("u​r​g​e​nt") == "urgent"

    def test_rtlo_detection(self):
        assert homoglyph.has_rtlo("invoice‮gnp.exe")
        assert not homoglyph.has_rtlo("invoice.png")

    def test_punycode_decoding(self):
        # xn--80ak6aa92e is the punycode for a Cyrillic-homoglyph "apple".
        assert homoglyph.decode_punycode("xn--80ak6aa92e.com") is not None
        assert homoglyph.decode_punycode("example.com") is None
