<div align="center">

# phish-triage

**Offline-first phishing email triage for SOC analysts — CLI, web UI and JSON API.**

Drop in a `.eml`, get back a defanged, evidence-backed verdict you can paste straight into a ticket.

[![CI](https://github.com/AunZulfiqar/phish-triage/actions/workflows/ci.yml/badge.svg)](https://github.com/AunZulfiqar/phish-triage/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)
![Tests](https://img.shields.io/badge/tests-153%20passing-2ea44f)
![Coverage](https://img.shields.io/badge/coverage-86%25-2ea44f)
![Indicators](https://img.shields.io/badge/indicators-58-3B82F6)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

</div>

---

## The problem

Phishing report triage is the highest-volume, lowest-glamour job in a SOC. An analyst gets a
forwarded `.eml`, and then spends ten minutes doing the same eleven things by hand: read the
`Received` chain, check whether `Authentication-Results` actually says `dmarc=pass`, compare
`Reply-To` against `From`, hover every link without clicking it, hash the attachment, decide.

Ten minutes each, forty a day. The checks are mechanical, the judgement is not — but almost all
of the *time* goes on the mechanical part.

`phish-triage` does the mechanical part in about 30 milliseconds and leaves the judgement to the
analyst. It does not try to be the decision. It tries to be the ten minutes.

## What makes this different from a "phishing detector"

Most student phishing projects train a classifier on a URL feature set and report 97% accuracy.
That number does not survive contact with a SOC, for two reasons: the model cannot say *why*,
and a ticket that says "0.97 malicious" is not something an analyst can defend in an escalation.

This tool takes the opposite position:

- **The score is a transparent weighted sum**, not a model. Every point is traceable to a named
  indicator with a stated weight. `docs/indicators.md` is generated from the same source the
  code scores from, so the documentation cannot drift from the behaviour.
- **Evidence, not just labels.** Each finding quotes the exact header, URL or filename that
  fired it.
- **Nothing is resolved, fetched, or executed.** Analysis is entirely static. Fetching an
  attacker's link from an analyst's machine confirms delivery, leaks the environment, and can
  burn the investigation. Shorteners are reported as unresolved rather than followed.
- **Everything that leaves the tool is defanged**, including URLs nested inside open-redirect
  query strings — the ones an analyst most wants to keep un-clicked.

## Demo

```console
$ phish-triage analyze samples/credential-phish.eml --org-domain example-corp.com
```

```
┌──────────────────────────────── VERDICT ─────────────────────────────────┐
│  MALICIOUS   100/100                                                     │
│  ████████████████████████████████████████                                │
│  Malicious - score 100/100 (20 indicator(s) across 4 category(ies);      │
│  weight 204; +14 corroboration)                                          │
└──────────────────────────────────────────────────────────────────────────┘

──────────────────── Authentication (SPF / DKIM / DMARC) ────────────────────
 AUTH-005  CRITICAL  22  DMARC evaluation failed
                         Authentication-Results reports dmarc=fail
 AUTH-001  HIGH      18  SPF hard fail
                         Authentication-Results reports spf=fail

────────────────────────────── Headers and routing ──────────────────────────
 HDR-004   HIGH      15  Display name impersonates a known brand
                         Display name claims "Microsoft 365 Security" but the
                         message was sent from micros0ft-security.tk
 HDR-001   MEDIUM    10  Reply-To points to a different domain

──────────────────────────────────── URLs ───────────────────────────────────
 URL-001   CRITICAL  20  Link text displays a different domain than its target
                         Link text shows "login.microsoftonline.com" but the
                         href resolves to login.microsoftonline.com.account-
                         verify.micros0ft-security[.]tk

───────────────────────────────── Body content ──────────────────────────────
 CNT-006   CRITICAL  20  Credential form embedded in the message body
                         HTML form in the body collects name:password, password
 CNT-004   HIGH      13  Hidden text in the HTML body
                         86 characters of hidden text, e.g. 'newsletter update
                         quarterly report shipping confirmation inv'

MITRE ATT&CK   T1204.001  T1566.002  T1598.003  T1656
```

Full capture: [`docs/demo-output.txt`](docs/demo-output.txt).

## Install

```bash
git clone https://github.com/AunZulfiqar/phish-triage.git
cd phish-triage
pip install -e .
```

Python 3.10+. Three runtime dependencies (`rich`, `jinja2`, `tldextract`). `dnspython` is
optional and only used by `--online`.

## Usage

```bash
# Single message, human-readable report
phish-triage analyze suspicious.eml

# Tell it which domains are yours — improves impersonation and recipient checks
phish-triage analyze suspicious.eml --org-domain yourcompany.com

# A whole reported-phishing folder, ranked worst-first
phish-triage analyze ./reported-mail/ --format summary

# Standalone HTML report to attach to a ticket
phish-triage analyze suspicious.eml --format html -o report.html

# Just the observables, for a SIEM or MISP import
phish-triage analyze suspicious.eml --format iocs

# Allow DNS lookups of the sender's SPF/DMARC records
phish-triage analyze suspicious.eml --online

# Browse the detection catalogue
phish-triage indicators
```

## Web UI

A hardened Flask front end over the same engine — drop files in, get the report in a browser,
download JSON/HTML/IOCs. Optional; the CLI has no dependency on it.

```bash
pip install -e ".[web]"
phish-triage-web --org-domain yourcompany.com
# http://127.0.0.1:8000
```

| Route | Purpose |
|---|---|
| `GET /` | upload / paste form |
| `POST /analyze` | analyse, redirect to a report |
| `GET /report/<token>` | single report, or a ranked table for a batch |
| `GET /report/<token>/download/<n>.json` · `.html` · `iocs.json` | downloads |
| `GET /indicators` | the catalogue, rendered from the same source the scorer uses |
| `POST /api/analyze` | JSON API — multipart, or `{"raw": "..."}` |
| `GET /healthz` | liveness |

```bash
curl -s -X POST http://127.0.0.1:8000/api/analyze \
  -H 'Content-Type: application/json' \
  -d "$(jq -Rs '{raw: .}' < suspicious.eml)" | jq '.verdict'
```

### How it is hardened

This application is handed live phishing mail on purpose, which drives every design decision:

- **The message body is never rendered as HTML.** Not in a sandboxed iframe, not through a
  sanitiser. It is reported *about*, never reproduced. Phishing HTML is purpose-built to defeat
  sanitisers, and a sanitiser bug would execute the payload on the analyst's own origin.
- **CSP is `default-src 'none'` with no `unsafe-inline`.** There is not a single inline style or
  script — the score bar's width is carried in a `data-` attribute and applied from a static JS
  file. If a rendering bug ever did emit attacker markup, a tracking pixel still could not fire
  and confirm the message was opened.
- **Nothing touches disk.** Results live in a bounded, expiring in-memory store. Uploaded mail is
  evidence containing third-party personal data; persisting it would create a retention
  obligation and buy nothing. A restart loses everything, which is correct.
- **Offline unless explicitly enabled.** `PHISH_TRIAGE_ALLOW_ONLINE=1` is required before the
  server will resolve a single DNS record, and a request cannot force it on.
- CSRF tokens on every state-changing form, per-IP rate limiting, a 4 MB body cap, strict
  upload-extension checks, `X-Forwarded-For` ignored unless a proxy is declared trusted, and
  server errors that never echo the exception (it can contain message fragments).

Flask's dev server is for development. Behind anything shared, use a real WSGI server and put
authentication in front of it:

```bash
waitress-serve --listen 127.0.0.1:8000 "webapp:create_app()"
```

| Environment variable | Default | Purpose |
|---|---|---|
| `PHISH_TRIAGE_SECRET_KEY` | random per start | session signing |
| `PHISH_TRIAGE_ALLOW_ONLINE` | `0` | permit live SPF/DMARC lookups |
| `PHISH_TRIAGE_ORG_DOMAINS` | — | comma-separated domains you own |
| `PHISH_TRIAGE_MAX_UPLOAD` | `4194304` | request body cap in bytes |
| `PHISH_TRIAGE_RESULT_TTL` | `1800` | seconds before a result is dropped |
| `PHISH_TRIAGE_RATE_LIMIT` | `60` | requests per window per client |

### Exit codes

Chosen so the tool drops into a mail-gateway pipeline or a CI check:

| Code | Meaning |
|---|---|
| `0` | analysed; verdict Benign |
| `1` | analysed; verdict Suspicious or worse (tune with `--fail-on`) |
| `2` | usage error |
| `3` | the message could not be parsed |

## What it looks at

58 indicators across five categories. Full reference: **[`docs/indicators.md`](docs/indicators.md)**.

| Category | Count | The checks that carry the most weight |
|---|---|---|
| **Authentication** | 9 | SPF/DKIM/DMARC results, and *relaxed DMARC alignment* — whether the domain that actually authenticated is the one the recipient sees |
| **Headers** | 13 | Disagreement between `From`, `Reply-To`, `Return-Path`, `Message-ID` and the display name; forged `Received` chains; freemail senders claiming a corporate role |
| **URLs** | 13 | Anchor-text vs href mismatch, punycode and mixed-script hosts, brand lookalikes by edit distance, userinfo (`@`) obfuscation, open redirects |
| **Attachments** | 11 | Executables, double extensions, RTLO filenames, macro-capable formats, disk-image containers, encrypted archives whose password is in the body |
| **Content** | 12 | Credential forms in the body, hidden text, zero-width characters, text/HTML part divergence, and the payload-free shape of a BEC opener |

A note on what is *weak* evidence here: the keyword lexicons. They are weighted low deliberately,
and financial wording needs two independent hits before it fires at all — because a legitimate
receipt says "payment details" all day long, and a single-hit threshold was this tool's largest
source of false positives during development.

## How the score is built

```
score = Σ(weights of fired indicators)
      + corroboration bonus (evidence spread across independent categories)
      − soft-evidence discount (if the sender authenticated cleanly)
```

Two adjustments matter:

**Corroboration bonus.** Three categories of weak evidence beat one category of the same total
weight. Aggressive marketing trips content heuristics; an attack trips content *and* headers
*and* URLs.

**Authentication gate.** If a message passes DMARC from a domain that genuinely owns the brand
it claims, content findings are discounted by 60%. The sender is who they say they are, so
urgency wording is just bad copywriting.

**Severity floor.** A lone critical indicator — a bare `.exe`, an RTLO filename — is floored at
*Likely Phishing* regardless of score. The catalogue defines critical as near-conclusive, and
weight alone cannot express that without inflating the number past what the evidence supports.

| Score | Verdict |
|---|---|
| 0–19 | Benign |
| 20–44 | Suspicious |
| 45–74 | Likely Phishing |
| 75–100 | Malicious |

## Sample corpus

Five synthetic messages in [`samples/`](samples/), all generated by
[`samples/generate.py`](samples/generate.py) — no real mail, no real recipients, IPs from the
RFC 5737 documentation ranges.

| Sample | Verdict | Score | Why it is in the corpus |
|---|---|---|---|
| `benign-newsletter.eml` | Benign | 0 | Authenticated, aligned, link-heavy |
| `benign-receipt.eml` | Benign | 0 | **False-positive control** — a transactional receipt full of payment language |
| `bec-wire-fraud.eml` | Likely Phishing | 53 | No links, no attachments; detected on message *shape* |
| `credential-phish.eml` | Malicious | 100 | Brand impersonation, auth failure, credential form |
| `malware-attachment.eml` | Malicious | 100 | Double extension plus an encrypted archive |

The two benign samples exist because a phishing detector with only positive tests will quietly
become unusable in production while its suite stays green.

## Framework mapping

Findings carry MITRE ATT&CK technique IDs where a mapping is genuinely defensible:

`T1566.001` Spearphishing Attachment · `T1566.002` Spearphishing Link ·
`T1598.003` Phishing for Information · `T1656` Impersonation ·
`T1204.001`/`T1204.002` User Execution · `T1036.002` RTLO · `T1036.007` Double Extension ·
`T1027.006` HTML Smuggling · `T1553.005` Mark-of-the-Web Bypass

Operationally this sits in **NIST SP 800-61 Detection & Analysis** — it is a triage aid, not a
containment tool.

## Development

```bash
pip install -e ".[dev]"          # includes the web extra
pytest                           # 153 tests
pytest --cov=phishtriage --cov=webapp
ruff check .
python samples/generate.py       # regenerate the synthetic corpus
python tools/gendocs.py          # regenerate docs/ from the catalogue
python -m webapp --port 8000     # run the web UI
```

## Limitations

Stated plainly, because a security tool that oversells itself is worse than none:

- **`Authentication-Results` is trusted as written.** An attacker can forge that header outright.
  It is only meaningful if it was added by *your* mail infrastructure. Use `--org-domain` to
  declare what you trust; the tool reports what the header claims and says so.
- **No reputation, no sandbox, no detonation.** There is no VirusTotal lookup and no URL
  resolution. Hashes are produced so you can pivot elsewhere.
- **`.msg` files are not parsed.** Outlook's format is not MIME; export to `.eml` first.
- **The lookalike brand list is small and hand-curated.** It covers commonly impersonated
  brands, not the top million domains. Add your own organisation's domains — most phishing an
  organisation receives imitates that organisation.
- **The web UI has no authentication.** It is built to run on localhost or behind something
  that does authenticate. Do not expose it directly.
- **The weights are reasoned, not learned.** They were tuned against a five-message corpus and
  a reading of what each indicator means. They are a defensible starting point, not an
  empirically optimised one, and should be re-tuned against your own mail.

## License

MIT — see [LICENSE](LICENSE).
