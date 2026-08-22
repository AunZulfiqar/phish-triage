"""RFC 5322 message parsing.

Everything the analyzers need is extracted here in one pass, so that no analyzer
has to re-walk the MIME tree. The parser is deliberately forgiving: phishing mail
is frequently malformed, sometimes deliberately, and a triage tool that throws on
a broken Content-Type is useless exactly when it matters most.

Only the standard library is used for MIME handling. HTML is parsed with
``html.parser`` rather than a third-party library so that the tool has no
scraping dependency and cannot be tripped by an HTML parser that "fixes" the
markup before the analyzer sees the trick.
"""

from __future__ import annotations

import email
import email.policy
import email.utils
import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

from .models import Attachment, ExtractedURL, Hop, ParsedEmail
from .utils import domains

_RECEIVED_FROM = re.compile(r"\bfrom\s+([A-Za-z0-9._-]+)", re.IGNORECASE)
_RECEIVED_BY = re.compile(r"\bby\s+([A-Za-z0-9._-]+)", re.IGNORECASE)
_RECEIVED_WITH = re.compile(r"\bwith\s+([A-Za-z0-9._/-]+)", re.IGNORECASE)
_RECEIVED_IP = re.compile(r"\[(?:IPv6:)?([0-9A-Fa-f:.]+)\]")

_URL_RE = re.compile(
    r"""(?xi)
    \b
    (?:https?://|www\.)
    [^\s<>"'\)\]}​]+
    """
)
_SCHEME_URL_RE = re.compile(r"""(?i)\b(data|javascript|vbscript|file|ftp):[^\s<>"']+""")


@dataclass
class _HtmlFacts:
    """Structural observations that only exist at the HTML level."""

    anchors: list[tuple[str, str]] = field(default_factory=list)   # (href, anchor text)
    sources: list[str] = field(default_factory=list)               # img/script/iframe src
    form_actions: list[str] = field(default_factory=list)
    input_types: list[str] = field(default_factory=list)
    hidden_text: list[str] = field(default_factory=list)
    visible_text_len: int = 0
    image_count: int = 0
    has_form: bool = False


class _HtmlHarvester(HTMLParser):
    """Collect links, forms and hidden text in a single pass over the markup."""

    _HIDING_PATTERNS = (
        re.compile(r"display\s*:\s*none", re.IGNORECASE),
        re.compile(r"visibility\s*:\s*hidden", re.IGNORECASE),
        re.compile(r"font-size\s*:\s*0(?:\.0+)?(?:px|pt|em|%)?", re.IGNORECASE),
        re.compile(r"opacity\s*:\s*0(?:\.0+)?\b", re.IGNORECASE),
        re.compile(r"height\s*:\s*0(?:px)?\s*(?:;|$)", re.IGNORECASE),
    )

    _WHITE_TEXT_RE = re.compile(
        r"(?:^|;)\s*color\s*:\s*(?:#?(?:fff(?:fff)?)|white)\b", re.IGNORECASE
    )
    # Any background that is not itself white or transparent.
    _PAINTED_BACKGROUND_RE = re.compile(
        r"background(?:-color)?\s*:\s*(?!\s*(?:transparent|none|#?fff(?:fff)?|white)\b)[^;]+",
        re.IGNORECASE,
    )

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.facts = _HtmlFacts()
        self._anchor_href: str | None = None
        self._anchor_text: list[str] = []
        self._hidden_depth = 0
        self._skip_depth = 0

    # -- helpers ----------------------------------------------------------
    @classmethod
    def _is_hidden(cls, attrs: dict[str, str]) -> bool:
        style = attrs.get("style", "")
        if any(p.search(style) for p in cls._HIDING_PATTERNS):
            return True
        # White text only hides something when nothing is painted behind it.
        # White-on-blue is an ordinary call-to-action button, and treating it as
        # concealment flagged the most visible element of the message as the
        # most suspicious one.
        if cls._WHITE_TEXT_RE.search(style) and not cls._PAINTED_BACKGROUND_RE.search(style):
            return True
        if attrs.get("hidden") is not None:
            return True
        return attrs.get("width") == "0" or attrs.get("height") == "0"

    # -- HTMLParser API ---------------------------------------------------
    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {k.lower(): (v or "") for k, v in attrs}

        if tag in ("script", "style", "head"):
            self._skip_depth += 1
            return
        if self._is_hidden(attributes):
            self._hidden_depth += 1

        if tag == "a":
            self._anchor_href = attributes.get("href", "").strip()
            self._anchor_text = []
        elif tag in ("img", "iframe", "script", "embed", "source"):
            src = attributes.get("src", "").strip()
            if src:
                self.facts.sources.append(src)
            if tag == "img":
                self.facts.image_count += 1
        elif tag == "form":
            self.facts.has_form = True
            action = attributes.get("action", "").strip()
            if action:
                self.facts.form_actions.append(action)
        elif tag == "input":
            self.facts.input_types.append(attributes.get("type", "text").lower())
            if attributes.get("name"):
                self.facts.input_types.append(f"name:{attributes['name'].lower()}")

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style", "head"):
            self._skip_depth = max(0, self._skip_depth - 1)
            return
        if tag == "a" and self._anchor_href is not None:
            text = " ".join("".join(self._anchor_text).split())
            self.facts.anchors.append((self._anchor_href, text))
            self._anchor_href = None
            self._anchor_text = []
        if self._hidden_depth:
            self._hidden_depth = max(0, self._hidden_depth - 1)

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        stripped = data.strip()
        if not stripped:
            return
        if self._hidden_depth:
            self.facts.hidden_text.append(stripped[:200])
        else:
            self.facts.visible_text_len += len(stripped)
        if self._anchor_href is not None:
            self._anchor_text.append(data)


def _decode(value: object) -> str:
    """Header values under policy.default are already decoded; be defensive anyway."""
    if value is None:
        return ""
    try:
        return str(value).replace("\r", "").replace("\n", " ").strip()
    except Exception:
        return ""


def _split_address_header(raw: str) -> tuple[str, str]:
    """Return ``(display name, address)`` from a From/Reply-To header.

    ``getaddresses`` splits on commas, so an *unquoted* comma inside a display
    name -- ``Rehan Mahmood, CFO <r@example.com>`` -- is parsed as two entries,
    the first with no address at all. Naive callers take ``pairs[0]`` and end up
    with an empty sender domain, which silently disables every alignment and
    impersonation check.

    Attackers use exactly that shape, so the address-bearing entry is selected
    explicitly and the comma-split fragments are stitched back onto the display
    name.
    """
    pairs = email.utils.getaddresses([raw or ""])
    if not pairs:
        return "", ""
    index = next((i for i, (_, addr) in enumerate(pairs) if "@" in addr), None)
    if index is None:
        return pairs[0][0].strip(), ""
    display, address = pairs[index]
    fragments = [d or a for d, a in pairs[:index] if (d or a).strip()]
    if fragments:
        display = ", ".join([*fragments, display]) if display else ", ".join(fragments)
    return display.strip(), address.strip().lower()


def _parse_received(index: int, raw: str) -> Hop:
    hop = Hop(index=index, raw=" ".join(raw.split()))
    if match := _RECEIVED_FROM.search(raw):
        hop.from_host = match.group(1).lower()
    if match := _RECEIVED_BY.search(raw):
        hop.by_host = match.group(1).lower()
    if match := _RECEIVED_WITH.search(raw):
        hop.with_proto = match.group(1).upper()
    for candidate in _RECEIVED_IP.findall(raw):
        if domains.is_ip(candidate):
            hop.from_ip = candidate
            break
    if ";" in raw:
        stamp = raw.rsplit(";", 1)[-1].strip()
        try:
            parsed = email.utils.parsedate_to_datetime(stamp)
            if parsed is not None:
                hop.timestamp = parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError):
            hop.timestamp = None
    return hop


def _link_hop_delays(hops: list[Hop]) -> None:
    """Received headers are newest-first, so hop *i* happened after hop *i+1*."""
    for i in range(len(hops) - 1):
        later, earlier = hops[i].timestamp, hops[i + 1].timestamp
        if later and earlier:
            hops[i].delay_seconds = (later - earlier).total_seconds()


def _make_url(raw: str, source: str, anchor_text: str = "") -> ExtractedURL | None:
    raw = raw.strip().strip('"\'<>')
    if not raw or raw.startswith("#") or raw.lower().startswith("mailto:"):
        return None
    candidate = f"http://{raw}" if raw.lower().startswith("www.") else raw
    try:
        parts = urlsplit(candidate)
    except ValueError:
        return None
    scheme = (parts.scheme or "").lower()
    if scheme in ("data", "javascript", "vbscript", "file"):
        return ExtractedURL(raw, scheme, "", "", "", source, anchor_text)
    if scheme not in ("http", "https", "ftp"):
        return None
    host = (parts.hostname or "").lower()
    if not host:
        return None
    return ExtractedURL(
        url=candidate,
        scheme=scheme,
        host=host,
        registered_domain=domains.registered_domain(host),
        path=parts.path + (f"?{parts.query}" if parts.query else ""),
        source=source,
        anchor_text=anchor_text,
    )


def _harvest_urls(text: str, html: str, facts: _HtmlFacts) -> list[ExtractedURL]:
    found: list[ExtractedURL] = []
    seen: set[tuple[str, str, str]] = set()

    def add(url: ExtractedURL | None) -> None:
        if url is None:
            return
        key = (url.url, url.source, url.anchor_text)
        if key not in seen:
            seen.add(key)
            found.append(url)

    for href, anchor_text in facts.anchors:
        add(_make_url(href, "html-anchor", anchor_text))
    for src in facts.sources:
        add(_make_url(src, "html-src"))
    for action in facts.form_actions:
        add(_make_url(action, "html-form"))
    for match in _URL_RE.finditer(text or ""):
        add(_make_url(match.group(0).rstrip(".,;:!?"), "plain-text"))
    for match in _SCHEME_URL_RE.finditer(html or ""):
        add(_make_url(match.group(0), "html-src"))
    return found


def _hash_payload(payload: bytes) -> tuple[str, str, str]:
    return (
        hashlib.md5(payload, usedforsecurity=False).hexdigest(),
        hashlib.sha1(payload, usedforsecurity=False).hexdigest(),
        hashlib.sha256(payload).hexdigest(),
    )


def parse_bytes(raw: bytes, source_path: str = "<memory>") -> ParsedEmail:
    """Parse raw RFC 5322 bytes into a :class:`ParsedEmail`."""
    message = email.message_from_bytes(raw, policy=email.policy.default)
    parsed = ParsedEmail(source_path=source_path, raw_size=len(raw))

    for key, value in message.items():
        parsed.headers.setdefault(key.lower(), []).append(_decode(value))

    parsed.from_display, parsed.from_address = _split_address_header(parsed.header("from"))
    parsed.from_domain = domains.domain_of_address(parsed.from_address)
    _, parsed.reply_to = _split_address_header(parsed.header("reply-to"))
    parsed.return_path = domains.domain_of_address(
        parsed.header("return-path").strip("<> ").lower()
    )
    parsed.to = [a.lower() for _, a in
                 email.utils.getaddresses(parsed.header_all("to")) if a]
    parsed.cc = [a.lower() for _, a in
                 email.utils.getaddresses(parsed.header_all("cc")) if a]
    parsed.subject = parsed.header("subject")
    parsed.message_id = parsed.header("message-id").strip()
    parsed.date_header = parsed.header("date")

    received = parsed.header_all("received")
    parsed.hops = [_parse_received(i, raw_hop) for i, raw_hop in enumerate(received)]
    _link_hop_delays(parsed.hops)

    text_parts: list[str] = []
    html_parts: list[str] = []
    for part in message.walk():
        if part.get_content_maintype() == "multipart":
            continue
        filename = part.get_filename()
        disposition = (part.get_content_disposition() or "").lower()
        content_type = (part.get_content_type() or "").lower()

        if filename or disposition == "attachment":
            try:
                payload = part.get_payload(decode=True) or b""
            except Exception:
                payload = b""
            md5, sha1, sha256 = _hash_payload(payload)
            parsed.attachments.append(Attachment(
                filename=_decode(filename) or "(unnamed)",
                content_type=content_type,
                size=len(payload),
                md5=md5, sha1=sha1, sha256=sha256,
                is_inline=disposition == "inline",
            ))
            continue

        try:
            body = part.get_content()
        except Exception:
            payload = part.get_payload(decode=True) or b""
            body = payload.decode("utf-8", errors="replace")
        if content_type == "text/plain":
            text_parts.append(body)
        elif content_type == "text/html":
            html_parts.append(body)

    parsed.body_text = "\n".join(text_parts).strip()
    parsed.body_html = "\n".join(html_parts).strip()

    harvester = _HtmlHarvester()
    if parsed.body_html:
        try:
            harvester.feed(parsed.body_html)
            harvester.close()
        except Exception:
            pass
    parsed.urls = _harvest_urls(parsed.body_text, parsed.body_html, harvester.facts)

    parsed.html_facts = harvester.facts
    return parsed


def parse_file(path: str | Path) -> ParsedEmail:
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"no such message: {p}")
    return parse_bytes(p.read_bytes(), source_path=str(p))


def now_utc() -> datetime:
    return datetime.now(timezone.utc)
