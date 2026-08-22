"""Analyzer contract.

An analyzer receives the fully parsed message and returns findings. It never
scores, never decides a verdict, and never mutates the message -- keeping that
separation is what makes the scoring model auditable and the analyzers testable
in isolation.
"""

from __future__ import annotations

from typing import Any, Protocol

from .. import catalog
from ..models import Finding, ParsedEmail


class Analyzer(Protocol):
    name: str
    category: str

    def run(self, email: ParsedEmail, ctx: Context) -> list[Finding]:
        ...


class Context:
    """Run-time options and cross-analyzer scratch space.

    ``online`` gates every check that would touch the network. It defaults to
    False so that the tool is safe to run on an isolated triage host, and so
    that analysing a message never signals the attacker that it was opened.
    """

    def __init__(self, online: bool = False, org_domains: tuple[str, ...] = ()) -> None:
        self.online = online
        self.org_domains = tuple(d.lower() for d in org_domains)
        self.shared: dict[str, Any] = {}


def finding(indicator_id: str, evidence: str, **detail: Any) -> Finding:
    """Build a finding from the catalogue, so weights live in exactly one place."""
    return Finding(catalog.get(indicator_id), evidence, detail)
