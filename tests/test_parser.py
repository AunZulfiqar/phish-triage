"""Parser behaviour, including the malformed shapes phishing actually uses."""

from __future__ import annotations

from phishtriage.parser import parse_bytes

from .conftest import build_eml


def test_basic_headers_are_extracted():
    raw = build_eml({
        "From": "Alice Example <alice@example.com>",
        "To": "bob@example.org",
        "Subject": "Quarterly report",
        "Message-ID": "<abc123@example.com>",
        "Date": "Sat, 14 Mar 2026 09:12:04 +0000",
    }, "Hello Bob.")
    msg = parse_bytes(raw)

    assert msg.from_display == "Alice Example"
    assert msg.from_address == "alice@example.com"
    assert msg.from_domain == "example.com"
    assert msg.to == ["bob@example.org"]
    assert msg.subject == "Quarterly report"
    assert msg.message_id == "<abc123@example.com>"


def test_unquoted_comma_in_display_name_keeps_the_address():
    """An unquoted comma splits the header into two entries, the first of which
    has no address. Taking pairs[0] blindly would lose the sender entirely."""
    raw = build_eml({"From": "Rehan Mahmood | CFO, Example Corp <r@gmail.com>"}, "x")
    msg = parse_bytes(raw)

    assert msg.from_address == "r@gmail.com"
    assert msg.from_domain == "gmail.com"
    assert "CFO" in msg.from_display
    assert "Example Corp" in msg.from_display


def test_display_name_only_header_does_not_crash():
    raw = build_eml({"From": "No Address Here"}, "x")
    msg = parse_bytes(raw)
    assert msg.from_address == ""
    assert msg.from_domain == ""


def test_received_chain_is_ordered_newest_first_with_delays():
    raw = build_eml({
        "Received": "from b.example.net (b.example.net [198.51.100.9]) "
                    "by mx.example.com with ESMTPS id 2; "
                    "Sat, 14 Mar 2026 09:12:10 +0000",
        "From": "a@example.net",
    }, "x")
    # A second Received must be appended manually to preserve duplicate keys.
    raw = raw.replace(
        b"From: a@example.net",
        b"Received: from a.example.net (a.example.net [198.51.100.8]) "
        b"by b.example.net with ESMTP id 1; Sat, 14 Mar 2026 09:12:04 +0000\r\n"
        b"From: a@example.net",
    )
    msg = parse_bytes(raw)

    assert len(msg.hops) == 2
    assert msg.hops[0].by_host == "mx.example.com"
    assert msg.hops[0].from_ip == "198.51.100.9"
    assert msg.hops[1].from_host == "a.example.net"
    assert msg.hops[0].delay_seconds == 6.0


def test_html_anchor_text_and_href_are_kept_separate():
    html = '<a href="https://evil.example.tk/go">https://www.paypal.com/login</a>'
    raw = build_eml({"From": "a@example.net"}, html, content_type="text/html")
    msg = parse_bytes(raw)

    anchors = [u for u in msg.urls if u.source == "html-anchor"]
    assert len(anchors) == 1
    assert anchors[0].host == "evil.example.tk"
    assert "paypal.com" in anchors[0].anchor_text


def test_hidden_text_is_recorded_but_not_counted_as_visible():
    html = ('<div style="font-size:0px">poison keywords here</div>'
            "<p>Visible paragraph text that a human can actually read.</p>")
    raw = build_eml({"From": "a@example.net"}, html, content_type="text/html")
    msg = parse_bytes(raw)

    assert msg.html_facts.hidden_text
    assert "poison" in msg.html_facts.hidden_text[0]
    assert msg.html_facts.visible_text_len > 20


def test_script_and_style_content_is_not_treated_as_body_text():
    html = "<style>.a{color:red}</style><script>var x=1;</script><p>Real text.</p>"
    raw = build_eml({"From": "a@example.net"}, html, content_type="text/html")
    msg = parse_bytes(raw)
    assert msg.html_facts.visible_text_len == len("Real text.")


def test_attachment_is_hashed_without_being_opened():
    from .conftest import build_eml as _b  # noqa: F401

    boundary = "BOUND"
    body = (
        f"--{boundary}\n"
        'Content-Type: text/plain; charset="utf-8"\n\n'
        "See attached.\n"
        f"--{boundary}\n"
        'Content-Type: application/octet-stream; name="invoice.pdf.exe"\n'
        'Content-Disposition: attachment; filename="invoice.pdf.exe"\n\n'
        "TVqQAAMAAAAEAAAA\n"
        f"--{boundary}--\n"
    )
    raw = build_eml(
        {"From": "a@example.net"}, body,
        content_type=f'multipart/mixed; boundary="{boundary}"',
    )
    msg = parse_bytes(raw)

    assert len(msg.attachments) == 1
    att = msg.attachments[0]
    assert att.filename == "invoice.pdf.exe"
    assert len(att.sha256) == 64
    assert len(att.md5) == 32
    assert att.size > 0


def test_malformed_message_still_parses():
    """Broken Content-Type must not take the whole triage down."""
    raw = b"From: a@example.net\r\nContent-Type: !!!broken!!!\r\n\r\nbody text"
    msg = parse_bytes(raw)
    assert msg.from_address == "a@example.net"
