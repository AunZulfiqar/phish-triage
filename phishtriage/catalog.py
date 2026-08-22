"""The indicator catalogue.

Every detection rule in phish-triage is declared here, exactly once, with an
explicit weight and an ATT&CK mapping. Analyzers look rules up by ID rather than
inventing findings inline -- so ``docs/indicators.md`` can be generated straight
from this file and can never drift from the code.

Weight guidance
---------------
  1-3    contextual noise; meaningful only alongside other findings
  4-7    a real oddity, common in marketing mail as well as phishing
  8-14   strong signal, unusual in legitimate mail
  15-25  near-conclusive on its own
"""

from __future__ import annotations

from .models import Indicator, Severity

S = Severity

_ALL: tuple[Indicator, ...] = (
    # ---------------------------------------------------------------- auth ---
    Indicator("AUTH-001", "SPF hard fail", "authentication", S.HIGH, 18,
              "The sending IP is not authorised by the SPF record of the envelope domain. "
              "The sender is forging the envelope address.", ("T1566.002", "T1656")),
    Indicator("AUTH-002", "SPF soft fail or neutral", "authentication", S.MEDIUM, 8,
              "SPF did not pass but the domain owner declined to assert a hard failure.",
              ("T1656",)),
    Indicator("AUTH-003", "DKIM signature failed", "authentication", S.HIGH, 15,
              "A DKIM signature was present but did not verify. The message was altered in "
              "transit or the signature was forged.", ("T1656",)),
    Indicator("AUTH-004", "No DKIM signature", "authentication", S.LOW, 4,
              "The message carries no DKIM signature, so body integrity cannot be confirmed."),
    Indicator("AUTH-005", "DMARC evaluation failed", "authentication", S.CRITICAL, 22,
              "The message failed DMARC. The domain owner's published policy says mail like "
              "this is not legitimate.", ("T1566.002", "T1656")),
    Indicator("AUTH-006", "No authentication results present", "authentication", S.MEDIUM, 7,
              "No Authentication-Results or Received-SPF header. The message was not "
              "evaluated by a receiving MTA, or the headers were stripped."),
    Indicator("AUTH-007", "DMARC identifier alignment mismatch", "authentication", S.HIGH, 14,
              "The domain that passed SPF or DKIM is not aligned with the visible From domain. "
              "Authentication passed for a domain the recipient never sees.", ("T1656",)),
    Indicator("AUTH-008", "Sender domain publishes no DMARC record", "authentication", S.MEDIUM, 6,
              "Live DNS shows no _dmarc TXT record, so the domain cannot be protected from "
              "spoofing. Frequently true of throwaway phishing domains."),
    Indicator("AUTH-009", "SPF record ends in +all", "authentication", S.HIGH, 12,
              "The domain's SPF record authorises the entire internet to send as it."),

    # ------------------------------------------------------------- headers ---
    Indicator("HDR-001", "Reply-To points to a different domain", "headers", S.MEDIUM, 10,
              "Replies will be routed away from the apparent sender, the classic setup for "
              "conversation hijacking and BEC.", ("T1656",)),
    Indicator("HDR-002", "Return-Path does not match From", "headers", S.MEDIUM, 8,
              "The envelope sender and the header sender disagree. Normal for mailing lists, "
              "suspicious for one-to-one business mail.", ("T1656",)),
    Indicator("HDR-003", "Display name contains a conflicting address", "headers", S.HIGH, 14,
              "The display name embeds an email address different from the real sender, a "
              "direct attempt to make the wrong address the visible one.", ("T1656",)),
    Indicator("HDR-004", "Display name impersonates a known brand", "headers", S.HIGH, 15,
              "The display name claims a well-known brand while the sending domain is "
              "unrelated to it.", ("T1656",)),
    Indicator("HDR-005", "Message-ID domain does not match sender", "headers", S.LOW, 5,
              "The Message-ID was minted by infrastructure unrelated to the sending domain."),
    Indicator("HDR-006", "Message-ID missing or malformed", "headers", S.LOW, 4,
              "Well-behaved MTAs always emit a syntactically valid Message-ID."),
    Indicator("HDR-007", "Bulk or scripted mailer fingerprint", "headers", S.LOW, 4,
              "X-Mailer or User-Agent matches a mass-mailing or scripted sending tool."),
    Indicator("HDR-008", "Implausible delay in the Received chain", "headers", S.LOW, 3,
              "A hop-to-hop delay is negative or unusually long, suggesting forged or "
              "hand-crafted Received headers."),
    Indicator("HDR-009", "Date header disagrees with delivery time", "headers", S.LOW, 5,
              "The Date header is far from the timestamp of the earliest trusted hop."),
    Indicator("HDR-010", "Truncated or absent Received chain", "headers", S.MEDIUM, 7,
              "Fewer relay hops than a message crossing the public internet should show, "
              "consistent with direct-to-MX injection."),
    Indicator("HDR-011", "Recipient does not appear in To or Cc", "headers", S.LOW, 5,
              "The message was blind-copied, typical of bulk phishing runs."),
    Indicator("HDR-012", "Corporate identity claimed from a freemail account", "headers",
              S.MEDIUM, 9,
              "The sender writes with organisational authority from a consumer mailbox, the "
              "dominant BEC pattern.", ("T1656", "T1585.002")),
    Indicator("HDR-013", "Subject carries a spoofed reply or external marker", "headers",
              S.MEDIUM, 8,
              "The subject fakes RE: or FW: to imply an existing thread, or forges the "
              "[EXTERNAL] banner that an organisation appends itself.", ("T1656",)),

    # ---------------------------------------------------------------- urls ---
    Indicator("URL-001", "Link text displays a different domain than its target", "urls",
              S.CRITICAL, 20,
              "The anchor text shows one domain while the href points somewhere else. Rarely "
              "anything but deception.", ("T1566.002", "T1204.001")),
    Indicator("URL-002", "Internationalised (punycode) hostname", "urls", S.HIGH, 13,
              "The hostname uses an xn-- encoded label, which can render as a near-perfect "
              "copy of a Latin brand name.", ("T1566.002",)),
    Indicator("URL-003", "Mixed-script or homoglyph hostname", "urls", S.HIGH, 14,
              "The hostname mixes Unicode scripts, for example Cyrillic characters standing "
              "in for visually identical Latin ones.", ("T1566.002",)),
    Indicator("URL-004", "Hostname is a lookalike of a known brand", "urls", S.HIGH, 15,
              "The registered domain is within a short edit distance of a major brand domain.",
              ("T1566.002", "T1656")),
    Indicator("URL-005", "Link points at a bare IP address", "urls", S.HIGH, 13,
              "Legitimate services are reached by name. A raw IP avoids reputation lookups.",
              ("T1566.002",)),
    Indicator("URL-006", "URL shortener conceals the destination", "urls", S.MEDIUM, 8,
              "The true landing page cannot be assessed without resolving the redirect."),
    Indicator("URL-007", "High-abuse top-level domain", "urls", S.MEDIUM, 7,
              "The TLD is disproportionately represented in abuse feeds, usually because "
              "registration is free or unverified."),
    Indicator("URL-008", "Credential-harvest keywords in the URL path", "urls", S.MEDIUM, 9,
              "Path or query terms such as login, verify, secure, account or mfa on a domain "
              "unrelated to the brand being imitated.", ("T1598.003",)),
    Indicator("URL-009", "Open-redirect style parameter", "urls", S.MEDIUM, 9,
              "A query parameter carries another absolute URL, letting the attacker borrow a "
              "trusted domain's reputation as a first hop.", ("T1566.002",)),
    Indicator("URL-010", "Brand name buried in a long subdomain chain", "urls", S.MEDIUM, 10,
              "A trusted brand appears in the subdomain of a domain the attacker controls, "
              "for example login.microsoft.com.attacker.tld.", ("T1656",)),
    Indicator("URL-011", "Action link served over plain HTTP", "urls", S.LOW, 5,
              "A link asking the user to authenticate or pay is not TLS-protected."),
    Indicator("URL-012", "data: or javascript: URI in message body", "urls", S.HIGH, 16,
              "Inline script or an embedded document rather than a normal link, commonly used "
              "to build a credential form entirely client-side.", ("T1027.006",)),
    Indicator("URL-013", "Userinfo obfuscation in the URL authority", "urls", S.HIGH, 14,
              "An @ before the host makes everything to its left decorative, so the URL can "
              "be made to read like a trusted domain.", ("T1566.002",)),

    # --------------------------------------------------------- attachments ---
    Indicator("ATT-001", "Directly executable attachment", "attachments", S.CRITICAL, 25,
              "The attachment runs as a program on double-click.", ("T1566.001", "T1204.002")),
    Indicator("ATT-002", "Double file extension", "attachments", S.CRITICAL, 22,
              "The filename presents a benign extension in front of the real, executable one.",
              ("T1036.007", "T1204.002")),
    Indicator("ATT-003", "Macro-enabled Office document", "attachments", S.HIGH, 16,
              "The document format exists specifically to carry executable macros.",
              ("T1566.001", "T1204.002")),
    Indicator("ATT-004", "Archive attachment", "attachments", S.MEDIUM, 8,
              "Archives hide their contents from many scanners until extracted.",
              ("T1566.001",)),
    Indicator("ATT-005", "Declared content type contradicts the file extension", "attachments",
              S.MEDIUM, 10,
              "The MIME type and the filename disagree about what the file is."),
    Indicator("ATT-006", "Password-protected archive with the password in the body",
              "attachments", S.CRITICAL, 20,
              "Encrypting the payload and supplying the key in the message defeats gateway "
              "scanning by design.", ("T1566.001",)),
    Indicator("ATT-007", "Script attachment", "attachments", S.CRITICAL, 22,
              "A script file that executes through a Windows or shell interpreter.",
              ("T1566.001", "T1204.002")),
    Indicator("ATT-008", "Right-to-left override in the filename", "attachments", S.CRITICAL, 24,
              "A U+202E character reverses the displayed filename so an executable appears to "
              "be a document.", ("T1036.002",)),
    Indicator("ATT-009", "HTML attachment", "attachments", S.HIGH, 15,
              "HTML attachments are the standard vehicle for HTML smuggling and for offline "
              "credential-harvest forms.", ("T1027.006", "T1566.001")),
    Indicator("ATT-010", "Disk-image or container attachment", "attachments", S.HIGH, 17,
              "ISO, IMG and VHD containers strip Mark-of-the-Web from the files inside them.",
              ("T1553.005", "T1566.001")),
    Indicator("ATT-011", "Windows shortcut attachment", "attachments", S.CRITICAL, 21,
              "A .lnk file can invoke an arbitrary interpreter with arbitrary arguments.",
              ("T1204.002",)),

    # ------------------------------------------------------------- content ---
    Indicator("CNT-001", "Urgency and time pressure", "content", S.LOW, 6,
              "Language engineered to force action before verification."),
    Indicator("CNT-002", "Credential-harvest phrasing", "content", S.MEDIUM, 9,
              "The message asks the reader to sign in, confirm a password or re-validate an "
              "account.", ("T1598.003",)),
    Indicator("CNT-003", "Payment or wire-transfer request", "content", S.HIGH, 12,
              "Financial instruction language consistent with business email compromise.",
              ("T1656",)),
    Indicator("CNT-004", "Hidden text in the HTML body", "content", S.HIGH, 13,
              "Text rendered invisible with zero font size, display:none or background-matched "
              "colour, used to poison keyword-based filters."),
    Indicator("CNT-005", "Zero-width or invisible characters", "content", S.MEDIUM, 10,
              "Zero-width joiners and similar characters break up keywords that a content "
              "filter would otherwise match."),
    Indicator("CNT-006", "Credential form embedded in the message body", "content", S.CRITICAL, 20,
              "An HTML form with a password or login field posts straight from the reader's "
              "mail client.", ("T1598.003",)),
    Indicator("CNT-007", "Body is essentially a single image", "content", S.MEDIUM, 9,
              "Almost no machine-readable text. The message is a picture of text, which "
              "defeats content inspection."),
    Indicator("CNT-008", "Plain-text and HTML parts disagree", "content", S.MEDIUM, 11,
              "The text/plain alternative differs substantially from the HTML the user sees, "
              "a technique aimed at filters that only read one part."),
    Indicator("CNT-009", "Generic salutation", "content", S.INFO, 3,
              "Addressed to Dear Customer or similar rather than a name."),
    Indicator("CNT-010", "Threatened consequence", "content", S.MEDIUM, 8,
              "Account closure, legal action or loss of access used as leverage."),
    Indicator("CNT-011", "Reply solicitation with no links or attachments", "content", S.MEDIUM, 9,
              "A short, personal, payload-free message asking the reader to respond, the "
              "opening move of a BEC conversation.", ("T1656",)),
    Indicator("CNT-012", "Requests secrecy or bypassing normal process", "content", S.HIGH, 12,
              "Asks the reader to keep the request confidential or to skip an approval step.",
              ("T1656",)),
)

BY_ID: dict[str, Indicator] = {i.id: i for i in _ALL}

CATEGORIES: tuple[str, ...] = ("authentication", "headers", "urls", "attachments", "content")

# Display names, kept beside the categories they label so that every renderer --
# terminal, HTML and web -- names a section the same way.
CATEGORY_TITLES: dict[str, str] = {
    "authentication": "Authentication (SPF / DKIM / DMARC)",
    "headers": "Headers and routing",
    "urls": "URLs",
    "attachments": "Attachments",
    "content": "Body content",
}


def get(indicator_id: str) -> Indicator:
    try:
        return BY_ID[indicator_id]
    except KeyError:  # pragma: no cover - programmer error
        raise KeyError(f"unknown indicator id: {indicator_id}") from None


def all_indicators() -> tuple[Indicator, ...]:
    return _ALL
