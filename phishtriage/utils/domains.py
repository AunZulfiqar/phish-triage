"""Domain parsing and comparison helpers.

``tldextract`` is used for registrable-domain extraction because a naive
"last two labels" split gets ``example.co.uk`` wrong, and getting that wrong
turns every UK sender into a false positive. It is configured to use its bundled
public-suffix snapshot so that the tool never reaches out to the network during
an analysis run -- offline-first is a hard requirement here, since analysts open
this on isolated triage boxes.
"""

from __future__ import annotations

import ipaddress
import re
from functools import lru_cache

try:  # pragma: no cover - exercised implicitly
    import tldextract

    _EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), fallback_to_snapshot=True)
except Exception:  # pragma: no cover - dependency missing
    _EXTRACT = None


_ADDR_RE = re.compile(r"[\w.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")


@lru_cache(maxsize=4096)
def split_host(host: str) -> tuple[str, str, str]:
    """Return ``(subdomain, domain, suffix)`` for a hostname."""
    host = (host or "").strip().strip(".").lower()
    if not host:
        return "", "", ""
    if _EXTRACT is not None:
        result = _EXTRACT(host)
        return result.subdomain, result.domain, result.suffix
    parts = host.split(".")
    if len(parts) < 2:
        return "", host, ""
    return ".".join(parts[:-2]), parts[-2], parts[-1]


def registered_domain(host: str) -> str:
    """The registrable domain, e.g. ``mail.corp.example.co.uk`` -> ``example.co.uk``."""
    if is_ip(host):
        return ""
    _, domain, suffix = split_host(host)
    if domain and suffix:
        return f"{domain}.{suffix}"
    return domain or ""


def subdomain_of(host: str) -> str:
    return split_host(host)[0]


def tld(host: str) -> str:
    suffix = split_host(host)[2]
    return suffix.rsplit(".", 1)[-1] if suffix else ""


def is_ip(host: str) -> bool:
    candidate = (host or "").strip("[]")
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False


def domain_of_address(address: str) -> str:
    """Extract the domain from an email address."""
    if not address or "@" not in address:
        return ""
    return address.rsplit("@", 1)[-1].strip().strip(">").lower()


def addresses_in(text: str) -> list[str]:
    """Every RFC-ish email address appearing in a string."""
    return [m.group(0).lower() for m in _ADDR_RE.finditer(text or "")]


def same_org(a: str, b: str) -> bool:
    """True if two domains share a registrable domain."""
    if not a or not b:
        return False
    return registered_domain(a) == registered_domain(b) != ""


def levenshtein(a: str, b: str, cap: int = 4) -> int:
    """Edit distance with early exit once it exceeds ``cap``.

    The cap matters: lookalike detection only cares about "close", and the
    early exit keeps the comparison cheap across the whole brand list.
    """
    if a == b:
        return 0
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            current.append(min(
                previous[j] + 1,
                current[j - 1] + 1,
                previous[j - 1] + (ca != cb),
            ))
        if min(current) > cap:
            return cap + 1
        previous = current
    return previous[-1]
