"""Request-level protections.

This application accepts hostile input by definition -- the whole point is that
users hand it live phishing mail. Three consequences shape everything here:

1. **The message body is never rendered as HTML.** Not in a sandboxed iframe,
   not with a sanitiser. It is displayed as escaped text or not at all. A
   sanitiser is a bug away from executing the payload in the analyst's browser
   on the analyst's origin, and phishing HTML is specifically built to defeat
   sanitisers.
2. **The Content-Security-Policy forbids external loads.** If a rendering bug
   ever does emit attacker markup, a remote image beacon still cannot fire and
   confirm to the sender that the message was opened.
3. **Nothing is executed, resolved, or fetched server-side** unless the operator
   explicitly enables online checks.
"""

from __future__ import annotations

import hmac
import secrets
from functools import wraps

from flask import abort, current_app, jsonify, request, session

CSRF_SESSION_KEY = "_csrf_token"
CSRF_FIELD = "csrf_token"
CSRF_HEADER = "X-CSRF-Token"

# No inline scripts, no external anything, no framing, no form posts off-origin.
CONTENT_SECURITY_POLICY = "; ".join((
    "default-src 'none'",
    "style-src 'self'",
    "script-src 'self'",
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "base-uri 'none'",
    "object-src 'none'",
))

SECURITY_HEADERS = {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=(), interest-cohort=()",
    # Reports quote attacker infrastructure; they must never be cached by an
    # intermediary or left in the browser's disk cache.
    "Cache-Control": "no-store, max-age=0",
}


def apply_security_headers(response):
    for header, value in SECURITY_HEADERS.items():
        response.headers.setdefault(header, value)
    return response


# ------------------------------------------------------------------- CSRF ---

def issue_csrf_token() -> str:
    token = session.get(CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[CSRF_SESSION_KEY] = token
    return token


def validate_csrf() -> bool:
    expected = session.get(CSRF_SESSION_KEY)
    if not expected:
        return False
    supplied = request.form.get(CSRF_FIELD) or request.headers.get(CSRF_HEADER, "")
    return bool(supplied) and hmac.compare_digest(str(expected), str(supplied))


def csrf_protect(view):
    """Reject unsafe methods that arrive without a valid token.

    The JSON API is exempt only when it is called without cookies -- a
    cookie-less request cannot be a cross-site forgery, because there is no
    ambient authority for an attacker's page to borrow.
    """

    @wraps(view)
    def wrapper(*args, **kwargs):
        if request.method in ("GET", "HEAD", "OPTIONS"):
            return view(*args, **kwargs)
        if request.path.startswith("/api/") and not request.cookies:
            return view(*args, **kwargs)
        if not validate_csrf():
            if request.path.startswith("/api/"):
                return jsonify(error="invalid or missing CSRF token"), 403
            abort(403, description="Invalid or missing CSRF token. Reload the page and retry.")
        return view(*args, **kwargs)

    return wrapper


# ------------------------------------------------------------- rate limit ---

def client_key() -> str:
    """Identify the caller for rate-limiting.

    ``X-Forwarded-For`` is only consulted when the operator has declared a
    trusted proxy, because it is trivially spoofed and honouring it by default
    would let one client present as thousands.
    """
    if current_app.config.get("PHISH_TRIAGE_TRUST_PROXY"):
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def rate_limited(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        limiter = current_app.extensions["phish_triage"]["limiter"]
        if not limiter.check(client_key()):
            if request.path.startswith("/api/"):
                return jsonify(error="rate limit exceeded"), 429
            abort(429, description="Too many requests. Wait a moment and try again.")
        return view(*args, **kwargs)

    return wrapper
