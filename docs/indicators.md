# Indicator catalogue

Generated from `phishtriage/catalog.py` by `make docs`. Do not edit by hand.

**58 indicators** across 5 categories.

Weight is the contribution to the 0-100 risk score. See the [scoring section](../README.md#how-the-score-is-built) of the README for how weights combine into a verdict.

| Weight range | Meaning |
|---|---|
| 1-3 | contextual noise; meaningful only alongside other findings |
| 4-7 | a real oddity, common in marketing mail as well as phishing |
| 8-14 | strong signal, unusual in legitimate mail |
| 15-25 | near-conclusive on its own |

## Authentication (9)

| ID | Indicator | Severity | Weight | ATT&CK | What it means |
|---|---|---|---|---|---|
| `AUTH-001` | SPF hard fail | high | 18 | `T1566.002`, `T1656` | The sending IP is not authorised by the SPF record of the envelope domain. The sender is forging the envelope address. |
| `AUTH-002` | SPF soft fail or neutral | medium | 8 | `T1656` | SPF did not pass but the domain owner declined to assert a hard failure. |
| `AUTH-003` | DKIM signature failed | high | 15 | `T1656` | A DKIM signature was present but did not verify. The message was altered in transit or the signature was forged. |
| `AUTH-004` | No DKIM signature | low | 4 | - | The message carries no DKIM signature, so body integrity cannot be confirmed. |
| `AUTH-005` | DMARC evaluation failed | critical | 22 | `T1566.002`, `T1656` | The message failed DMARC. The domain owner's published policy says mail like this is not legitimate. |
| `AUTH-006` | No authentication results present | medium | 7 | - | No Authentication-Results or Received-SPF header. The message was not evaluated by a receiving MTA, or the headers were stripped. |
| `AUTH-007` | DMARC identifier alignment mismatch | high | 14 | `T1656` | The domain that passed SPF or DKIM is not aligned with the visible From domain. Authentication passed for a domain the recipient never sees. |
| `AUTH-008` | Sender domain publishes no DMARC record | medium | 6 | - | Live DNS shows no _dmarc TXT record, so the domain cannot be protected from spoofing. Frequently true of throwaway phishing domains. |
| `AUTH-009` | SPF record ends in +all | high | 12 | - | The domain's SPF record authorises the entire internet to send as it. |

## Headers (13)

| ID | Indicator | Severity | Weight | ATT&CK | What it means |
|---|---|---|---|---|---|
| `HDR-001` | Reply-To points to a different domain | medium | 10 | `T1656` | Replies will be routed away from the apparent sender, the classic setup for conversation hijacking and BEC. |
| `HDR-002` | Return-Path does not match From | medium | 8 | `T1656` | The envelope sender and the header sender disagree. Normal for mailing lists, suspicious for one-to-one business mail. |
| `HDR-003` | Display name contains a conflicting address | high | 14 | `T1656` | The display name embeds an email address different from the real sender, a direct attempt to make the wrong address the visible one. |
| `HDR-004` | Display name impersonates a known brand | high | 15 | `T1656` | The display name claims a well-known brand while the sending domain is unrelated to it. |
| `HDR-005` | Message-ID domain does not match sender | low | 5 | - | The Message-ID was minted by infrastructure unrelated to the sending domain. |
| `HDR-006` | Message-ID missing or malformed | low | 4 | - | Well-behaved MTAs always emit a syntactically valid Message-ID. |
| `HDR-007` | Bulk or scripted mailer fingerprint | low | 4 | - | X-Mailer or User-Agent matches a mass-mailing or scripted sending tool. |
| `HDR-008` | Implausible delay in the Received chain | low | 3 | - | A hop-to-hop delay is negative or unusually long, suggesting forged or hand-crafted Received headers. |
| `HDR-009` | Date header disagrees with delivery time | low | 5 | - | The Date header is far from the timestamp of the earliest trusted hop. |
| `HDR-010` | Truncated or absent Received chain | medium | 7 | - | Fewer relay hops than a message crossing the public internet should show, consistent with direct-to-MX injection. |
| `HDR-011` | Recipient does not appear in To or Cc | low | 5 | - | The message was blind-copied, typical of bulk phishing runs. |
| `HDR-012` | Corporate identity claimed from a freemail account | medium | 9 | `T1656`, `T1585.002` | The sender writes with organisational authority from a consumer mailbox, the dominant BEC pattern. |
| `HDR-013` | Subject carries a spoofed reply or external marker | medium | 8 | `T1656` | The subject fakes RE: or FW: to imply an existing thread, or forges the [EXTERNAL] banner that an organisation appends itself. |

## Urls (13)

| ID | Indicator | Severity | Weight | ATT&CK | What it means |
|---|---|---|---|---|---|
| `URL-001` | Link text displays a different domain than its target | critical | 20 | `T1566.002`, `T1204.001` | The anchor text shows one domain while the href points somewhere else. Rarely anything but deception. |
| `URL-002` | Internationalised (punycode) hostname | high | 13 | `T1566.002` | The hostname uses an xn-- encoded label, which can render as a near-perfect copy of a Latin brand name. |
| `URL-003` | Mixed-script or homoglyph hostname | high | 14 | `T1566.002` | The hostname mixes Unicode scripts, for example Cyrillic characters standing in for visually identical Latin ones. |
| `URL-004` | Hostname is a lookalike of a known brand | high | 15 | `T1566.002`, `T1656` | The registered domain is within a short edit distance of a major brand domain. |
| `URL-005` | Link points at a bare IP address | high | 13 | `T1566.002` | Legitimate services are reached by name. A raw IP avoids reputation lookups. |
| `URL-006` | URL shortener conceals the destination | medium | 8 | - | The true landing page cannot be assessed without resolving the redirect. |
| `URL-007` | High-abuse top-level domain | medium | 7 | - | The TLD is disproportionately represented in abuse feeds, usually because registration is free or unverified. |
| `URL-008` | Credential-harvest keywords in the URL path | medium | 9 | `T1598.003` | Path or query terms such as login, verify, secure, account or mfa on a domain unrelated to the brand being imitated. |
| `URL-009` | Open-redirect style parameter | medium | 9 | `T1566.002` | A query parameter carries another absolute URL, letting the attacker borrow a trusted domain's reputation as a first hop. |
| `URL-010` | Brand name buried in a long subdomain chain | medium | 10 | `T1656` | A trusted brand appears in the subdomain of a domain the attacker controls, for example login.microsoft.com.attacker.tld. |
| `URL-011` | Action link served over plain HTTP | low | 5 | - | A link asking the user to authenticate or pay is not TLS-protected. |
| `URL-012` | data: or javascript: URI in message body | high | 16 | `T1027.006` | Inline script or an embedded document rather than a normal link, commonly used to build a credential form entirely client-side. |
| `URL-013` | Userinfo obfuscation in the URL authority | high | 14 | `T1566.002` | An @ before the host makes everything to its left decorative, so the URL can be made to read like a trusted domain. |

## Attachments (11)

| ID | Indicator | Severity | Weight | ATT&CK | What it means |
|---|---|---|---|---|---|
| `ATT-001` | Directly executable attachment | critical | 25 | `T1566.001`, `T1204.002` | The attachment runs as a program on double-click. |
| `ATT-002` | Double file extension | critical | 22 | `T1036.007`, `T1204.002` | The filename presents a benign extension in front of the real, executable one. |
| `ATT-003` | Macro-enabled Office document | high | 16 | `T1566.001`, `T1204.002` | The document format exists specifically to carry executable macros. |
| `ATT-004` | Archive attachment | medium | 8 | `T1566.001` | Archives hide their contents from many scanners until extracted. |
| `ATT-005` | Declared content type contradicts the file extension | medium | 10 | - | The MIME type and the filename disagree about what the file is. |
| `ATT-006` | Password-protected archive with the password in the body | critical | 20 | `T1566.001` | Encrypting the payload and supplying the key in the message defeats gateway scanning by design. |
| `ATT-007` | Script attachment | critical | 22 | `T1566.001`, `T1204.002` | A script file that executes through a Windows or shell interpreter. |
| `ATT-008` | Right-to-left override in the filename | critical | 24 | `T1036.002` | A U+202E character reverses the displayed filename so an executable appears to be a document. |
| `ATT-009` | HTML attachment | high | 15 | `T1027.006`, `T1566.001` | HTML attachments are the standard vehicle for HTML smuggling and for offline credential-harvest forms. |
| `ATT-010` | Disk-image or container attachment | high | 17 | `T1553.005`, `T1566.001` | ISO, IMG and VHD containers strip Mark-of-the-Web from the files inside them. |
| `ATT-011` | Windows shortcut attachment | critical | 21 | `T1204.002` | A .lnk file can invoke an arbitrary interpreter with arbitrary arguments. |

## Content (12)

| ID | Indicator | Severity | Weight | ATT&CK | What it means |
|---|---|---|---|---|---|
| `CNT-001` | Urgency and time pressure | low | 6 | - | Language engineered to force action before verification. |
| `CNT-002` | Credential-harvest phrasing | medium | 9 | `T1598.003` | The message asks the reader to sign in, confirm a password or re-validate an account. |
| `CNT-003` | Payment or wire-transfer request | high | 12 | `T1656` | Financial instruction language consistent with business email compromise. |
| `CNT-004` | Hidden text in the HTML body | high | 13 | - | Text rendered invisible with zero font size, display:none or background-matched colour, used to poison keyword-based filters. |
| `CNT-005` | Zero-width or invisible characters | medium | 10 | - | Zero-width joiners and similar characters break up keywords that a content filter would otherwise match. |
| `CNT-006` | Credential form embedded in the message body | critical | 20 | `T1598.003` | An HTML form with a password or login field posts straight from the reader's mail client. |
| `CNT-007` | Body is essentially a single image | medium | 9 | - | Almost no machine-readable text. The message is a picture of text, which defeats content inspection. |
| `CNT-008` | Plain-text and HTML parts disagree | medium | 11 | - | The text/plain alternative differs substantially from the HTML the user sees, a technique aimed at filters that only read one part. |
| `CNT-009` | Generic salutation | info | 3 | - | Addressed to Dear Customer or similar rather than a name. |
| `CNT-010` | Threatened consequence | medium | 8 | - | Account closure, legal action or loss of access used as leverage. |
| `CNT-011` | Reply solicitation with no links or attachments | medium | 9 | `T1656` | A short, personal, payload-free message asking the reader to respond, the opening move of a BEC conversation. |
| `CNT-012` | Requests secrecy or bypassing normal process | high | 12 | `T1656` | Asks the reader to keep the request confidential or to skip an approval step. |

