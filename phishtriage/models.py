"""Core data structures shared by every analyzer.

The design goal is auditability: an analyst reading a report must be able to see
*which* indicator fired, *what evidence* fired it, and *how much* it moved the
score. Nothing here is a black box.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


class Verdict(str, Enum):
    BENIGN = "Benign"
    SUSPICIOUS = "Suspicious"
    LIKELY_PHISHING = "Likely Phishing"
    MALICIOUS = "Malicious"

    @property
    def colour(self) -> str:
        return {
            "Benign": "green",
            "Suspicious": "yellow",
            "Likely Phishing": "dark_orange",
            "Malicious": "red",
        }[self.value]


@dataclass(frozen=True)
class Indicator:
    """A single detection rule. Registered once, referenced by findings."""

    id: str
    name: str
    category: str
    severity: Severity
    weight: int
    description: str
    attack: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not 0 <= self.weight <= 40:
            raise ValueError(f"{self.id}: weight must be 0..40, got {self.weight}")


@dataclass
class Finding:
    """An indicator that actually fired, with the evidence that fired it."""

    indicator: Indicator
    evidence: str
    detail: dict[str, Any] = field(default_factory=dict)

    @property
    def id(self) -> str:
        return self.indicator.id

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.indicator.id,
            "name": self.indicator.name,
            "category": self.indicator.category,
            "severity": self.indicator.severity.value,
            "weight": self.indicator.weight,
            "description": self.indicator.description,
            "attack": list(self.indicator.attack),
            "evidence": self.evidence,
            "detail": self.detail,
        }


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    md5: str
    sha1: str
    sha256: str
    is_inline: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "filename": self.filename,
            "content_type": self.content_type,
            "size": self.size,
            "md5": self.md5,
            "sha1": self.sha1,
            "sha256": self.sha256,
            "is_inline": self.is_inline,
        }


@dataclass
class ExtractedURL:
    url: str
    scheme: str
    host: str
    registered_domain: str
    path: str
    source: str            # "html-anchor" | "html-src" | "plain-text"
    anchor_text: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "scheme": self.scheme,
            "host": self.host,
            "registered_domain": self.registered_domain,
            "path": self.path,
            "source": self.source,
            "anchor_text": self.anchor_text,
        }


@dataclass
class Hop:
    """One `Received:` header, parsed."""

    index: int
    raw: str
    from_host: str = ""
    from_ip: str = ""
    by_host: str = ""
    with_proto: str = ""
    timestamp: datetime | None = None
    delay_seconds: float | None = None


@dataclass
class ParsedEmail:
    """Everything extracted from the message before any scoring happens."""

    source_path: str
    headers: dict[str, list[str]] = field(default_factory=dict)
    from_display: str = ""
    from_address: str = ""
    from_domain: str = ""
    reply_to: str = ""
    return_path: str = ""
    to: list[str] = field(default_factory=list)
    cc: list[str] = field(default_factory=list)
    subject: str = ""
    message_id: str = ""
    date_header: str = ""
    hops: list[Hop] = field(default_factory=list)
    body_text: str = ""
    body_html: str = ""
    urls: list[ExtractedURL] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    raw_size: int = 0
    # Structural HTML observations (anchors, forms, hidden text). Populated by
    # the parser; typed as Any to keep HTML-only concerns out of this module.
    html_facts: Any = None

    def header(self, name: str, default: str = "") -> str:
        values = self.headers.get(name.lower(), [])
        return values[0] if values else default

    def header_all(self, name: str) -> list[str]:
        return self.headers.get(name.lower(), [])


@dataclass
class Report:
    """The finished triage result."""

    email: ParsedEmail
    findings: list[Finding]
    score: int
    verdict: Verdict
    generated_at: datetime
    online_checks: bool = False
    breakdown: dict[str, Any] = field(default_factory=dict)

    @property
    def attack_techniques(self) -> list[str]:
        seen: list[str] = []
        for f in self.findings:
            for t in f.indicator.attack:
                if t not in seen:
                    seen.append(t)
        return sorted(seen)

    def by_category(self) -> dict[str, list[Finding]]:
        buckets: dict[str, list[Finding]] = {}
        for f in self.findings:
            buckets.setdefault(f.indicator.category, []).append(f)
        for group in buckets.values():
            group.sort(key=lambda f: (-f.indicator.severity.rank, -f.indicator.weight))
        return buckets

    def iocs(self) -> dict[str, list[str]]:
        """Deduplicated observables, ready to pivot on in a SIEM."""
        domains = sorted({u.registered_domain for u in self.email.urls if u.registered_domain})
        return {
            "urls": sorted({u.url for u in self.email.urls}),
            "domains": domains,
            "sender_domain": [self.email.from_domain] if self.email.from_domain else [],
            "sender_ips": sorted({h.from_ip for h in self.email.hops if h.from_ip}),
            "attachment_sha256": sorted({a.sha256 for a in self.email.attachments}),
        }
