"""Web application configuration.

Defaults are chosen for the way this tool is actually used: an analyst running
it on their own machine, or a small team running it inside the perimeter. The
settings that matter most are the ones that keep attacker-controlled data from
lingering or escaping -- upload size, result retention, and the fact that
nothing is ever written to disk.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _bool_env(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


@dataclass
class Config:
    # A generated key means sessions do not survive a restart. That is the right
    # default for a triage tool -- it is not a service with logged-in users, and
    # a hardcoded fallback key would be a far worse failure mode.
    secret_key: str = field(default_factory=lambda: os.environ.get(
        "PHISH_TRIAGE_SECRET_KEY") or secrets.token_hex(32))

    # 4 MB. Real phishing mail with an attachment rarely exceeds 2 MB, and the
    # parser holds the whole message in memory.
    max_content_length: int = field(default_factory=lambda: _int_env(
        "PHISH_TRIAGE_MAX_UPLOAD", 4 * 1024 * 1024))

    max_files_per_request: int = field(default_factory=lambda: _int_env(
        "PHISH_TRIAGE_MAX_FILES", 25))

    # Results live in memory only, and expire. Uploaded mail is evidence and
    # frequently contains third-party personal data; keeping it around after the
    # analyst has read the report creates a liability and buys nothing.
    result_ttl_seconds: int = field(default_factory=lambda: _int_env(
        "PHISH_TRIAGE_RESULT_TTL", 1800))
    max_stored_results: int = field(default_factory=lambda: _int_env(
        "PHISH_TRIAGE_MAX_RESULTS", 200))

    # Requests per window, per client address.
    rate_limit_requests: int = field(default_factory=lambda: _int_env(
        "PHISH_TRIAGE_RATE_LIMIT", 60))
    rate_limit_window_seconds: int = field(default_factory=lambda: _int_env(
        "PHISH_TRIAGE_RATE_WINDOW", 60))

    # Off by default. Enabling it makes the server perform DNS lookups for the
    # sender domain of every message analysed, which is observable.
    allow_online_checks: bool = field(default_factory=lambda: _bool_env(
        "PHISH_TRIAGE_ALLOW_ONLINE", False))

    org_domains: tuple[str, ...] = field(default_factory=lambda: tuple(
        d.strip().lower()
        for d in os.environ.get("PHISH_TRIAGE_ORG_DOMAINS", "").split(",")
        if d.strip()
    ))

    session_cookie_secure: bool = field(default_factory=lambda: _bool_env(
        "PHISH_TRIAGE_COOKIE_SECURE", False))

    def as_flask(self) -> dict[str, object]:
        return {
            "SECRET_KEY": self.secret_key,
            "MAX_CONTENT_LENGTH": self.max_content_length,
            "SESSION_COOKIE_HTTPONLY": True,
            "SESSION_COOKIE_SAMESITE": "Lax",
            "SESSION_COOKIE_SECURE": self.session_cookie_secure,
            "JSON_SORT_KEYS": False,
            "TEMPLATES_AUTO_RELOAD": False,
        }
