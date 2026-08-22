"""Social-engineering language patterns.

Keyword matching is a blunt instrument and is treated as such: every lexicon
here carries a low-to-moderate weight in the catalogue and is designed to be
corroborating evidence, never a verdict on its own. A newsletter saying "act
now" is not phishing; a newsletter saying "act now" from a domain that just
failed DMARC is a different matter.

Patterns are matched case-insensitively on word boundaries so that "won" does
not match "wonder".
"""

from __future__ import annotations

import re

URGENCY: tuple[str, ...] = (
    "act now", "immediate action", "immediately", "urgent", "urgently",
    "as soon as possible", "right away", "within 24 hours", "within 48 hours",
    "expires today", "expires soon", "final notice", "last warning",
    "time sensitive", "do not delay", "prompt attention", "before it is too late",
)

CREDENTIALS: tuple[str, ...] = (
    "verify your account", "confirm your identity", "confirm your password",
    "update your password", "re-enter your password", "reset your password",
    "sign in to continue", "log in to verify", "validate your account",
    "unusual sign-in", "unusual activity", "suspicious login",
    "your account has been locked", "account suspended", "re-activate your account",
    "confirm your email", "verify your email address", "authenticate your account",
    "session has expired", "credentials have expired", "mfa", "two-factor",
)

FINANCIAL: tuple[str, ...] = (
    "wire transfer", "bank transfer", "wire the funds", "payment details",
    "update banking details", "change of bank", "new account details",
    "outstanding invoice", "overdue invoice", "remittance advice",
    "process this payment", "release the payment", "purchase order",
    "gift card", "gift cards", "bitcoin", "cryptocurrency wallet",
    "beneficiary details", "swift code", "iban",
)

THREAT: tuple[str, ...] = (
    "will be closed", "will be terminated", "will be suspended",
    "permanently deleted", "legal action", "law enforcement", "criminal charges",
    "lose access", "loss of access", "your service will be discontinued",
    "failure to comply", "avoid suspension", "avoid termination",
)

SECRECY: tuple[str, ...] = (
    "keep this confidential", "keep this between us", "do not tell anyone",
    "do not discuss this", "handle this discreetly", "discreet",
    "bypass the usual", "skip the approval", "without informing",
    "i am in a meeting", "i am currently unavailable", "cannot talk right now",
)

GENERIC_SALUTATION: tuple[str, ...] = (
    "dear customer", "dear user", "dear client", "dear member", "dear account holder",
    "dear sir/madam", "dear sir or madam", "dear valued customer", "dear email user",
    "hello user", "attention user", "dear friend",
)

# Wording that implies the payload was deliberately encrypted to evade scanning.
ARCHIVE_PASSWORD: tuple[str, ...] = (
    "password is", "password:", "passcode is", "passcode:", "zip password",
    "archive password", "unlock code", "extraction password", "the pass is",
)


def _compile(terms: tuple[str, ...]) -> re.Pattern[str]:
    escaped = sorted((re.escape(t) for t in terms), key=len, reverse=True)
    return re.compile(r"(?<!\w)(" + "|".join(escaped) + r")(?!\w)", re.IGNORECASE)


PATTERNS: dict[str, re.Pattern[str]] = {
    "urgency": _compile(URGENCY),
    "credentials": _compile(CREDENTIALS),
    "financial": _compile(FINANCIAL),
    "threat": _compile(THREAT),
    "secrecy": _compile(SECRECY),
    "salutation": _compile(GENERIC_SALUTATION),
    "archive_password": _compile(ARCHIVE_PASSWORD),
}


def matches(category: str, text: str, limit: int = 6) -> list[str]:
    """Return up to ``limit`` distinct hits for ``category`` within ``text``."""
    pattern = PATTERNS[category]
    seen: list[str] = []
    for match in pattern.finditer(text):
        hit = match.group(0).lower()
        if hit not in seen:
            seen.append(hit)
        if len(seen) >= limit:
            break
    return seen
