"""Defanging, so that a report can be pasted into a ticket without arming it.

Every URL, domain and IP that leaves this tool goes through here first. An
analyst copying an IOC into Jira, Slack or an email should not produce a live,
clickable link to the thing they are investigating -- and mail clients will
happily auto-link a raw URL sitting in a report.

The scheme is the widely used one: ``hxxp``, bracketed dots, bracketed ``@``.
"""

from __future__ import annotations

import re

# Matches every scheme occurrence, not just a leading one, so a URL nested
# inside an open-redirect query string is neutralised too.
_SCHEME_RE = re.compile(r"(?i)(https?|ftp)://")

# Used by defang_text to find live indicators embedded in prose.
_URL_IN_TEXT = re.compile(r"""(?i)\b(?:https?|ftp)://[^\s<>"'\]}]+""")
_IPV4_IN_TEXT = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HOST_IN_TEXT = re.compile(
    r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b"
)


_SCHEME_MAP = {"http": "hxxp", "https": "hxxps", "ftp": "fxp"}


def defang_url(url: str) -> str:
    """Neutralise a URL, including any URL nested inside its query string.

    Open-redirect links carry a second absolute URL as a parameter. Defanging
    only the leading scheme leaves that inner URL live and clickable, which is
    precisely the destination an analyst most wants to keep un-clicked, so every
    scheme occurrence is rewritten rather than just the first.
    """
    if not url:
        return ""
    out = _SCHEME_RE.sub(lambda m: f"{_SCHEME_MAP[m.group(1).lower()]}[://]", url)
    out = out.replace(".", "[.]")
    out = out.replace("@", "[@]")
    return out


def defang_domain(domain: str) -> str:
    return domain.replace(".", "[.]") if domain else ""


def defang_ip(ip: str) -> str:
    if not ip:
        return ""
    if ":" in ip:  # IPv6
        return ip.replace(":", "[:]")
    return ip.replace(".", "[.]")


def defang_email(address: str) -> str:
    if not address or "@" not in address:
        return defang_domain(address)
    local, _, domain = address.rpartition("@")
    return f"{local}[@]{defang_domain(domain)}"


def defang_text(text: str) -> str:
    """Neutralise every live indicator inside a free-text string.

    Evidence strings and finding details quote attacker infrastructure verbatim,
    so they need the same treatment as the IOC list. Order matters: URLs are
    defanged first, which strips their dots, so the bare-hostname pass cannot
    double-process what the URL pass already handled.

    Over-defanging ordinary prose is the acceptable failure direction here --
    a bracketed word is merely ugly, whereas a live link in an incident ticket
    is a click waiting to happen.
    """
    if not text:
        return ""
    out = _URL_IN_TEXT.sub(lambda m: defang_url(m.group(0)), text)
    out = _IPV4_IN_TEXT.sub(lambda m: defang_ip(m.group(0)), out)
    return _HOST_IN_TEXT.sub(lambda m: defang_domain(m.group(0)), out)


def defang_structure(value):
    """Recursively apply :func:`defang_text` to every string in a structure."""
    if isinstance(value, str):
        return defang_text(value)
    if isinstance(value, dict):
        return {k: defang_structure(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [defang_structure(v) for v in value]
    return value


def refang(text: str) -> str:
    """Reverse the transformation, for round-tripping IOCs back into tooling.

    Mirrors :func:`defang_url` exactly, including nested schemes -- an IOC that
    survives a defang/refang cycle unchanged is what lets the JSON output be fed
    back into a scanner or a SIEM lookup without hand-editing.
    """
    out = (
        text.replace("[://]", "://")
        .replace("[.]", ".")
        .replace("[@]", "@")
        .replace("[:]", ":")
    )
    out = re.sub(r"(?i)hxxp(s?)://", r"http\1://", out)
    return re.sub(r"(?i)fxp://", "ftp://", out)
