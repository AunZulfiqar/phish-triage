"""SPF, DKIM and DMARC evaluation.

Two sources of truth are used, in this order of preference:

1. The ``Authentication-Results`` header written by the receiving MTA. This is
   the authoritative record -- it was produced at delivery time, by a server
   that could see the connecting IP.
2. ``Received-SPF``, as a fallback for older or simpler mail paths.

Note the trust caveat, which matters for real casework: ``Authentication-Results``
is only trustworthy if it was written by *your own* infrastructure. An attacker
can forge the header outright. ``--org-domain`` lets the analyst declare which
authserv-ids they trust; without it the tool reports what the header claims and
says so, rather than pretending to have verified anything.

DMARC alignment is evaluated in relaxed mode (registrable domain must match),
which is the default policy mode and the one that matters for spoofing.
"""

from __future__ import annotations

import re

from ..models import Finding, ParsedEmail
from ..utils import domains
from .base import Context, finding

_RESULT_RE = re.compile(
    r"\b(spf|dkim|dmarc)\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror|policy|bestguesspass)",
    re.IGNORECASE,
)
_DKIM_DOMAIN_RE = re.compile(r"header\.(?:d|i)\s*=\s*@?([A-Za-z0-9.-]+)", re.IGNORECASE)
_SPF_DOMAIN_RE = re.compile(
    r"smtp\.(?:mailfrom|helo)\s*=\s*(?:[^@\s]*@)?([A-Za-z0-9.-]+)", re.IGNORECASE
)


class AuthAnalyzer:
    name = "authentication"
    category = "authentication"

    def run(self, email: ParsedEmail, ctx: Context) -> list[Finding]:
        results = self._collect_results(email)
        ctx.shared["auth_results"] = results
        findings: list[Finding] = []

        if not results["raw_headers"]:
            findings.append(finding(
                "AUTH-006",
                "Neither Authentication-Results nor Received-SPF is present",
                headers_checked=["Authentication-Results", "Received-SPF",
                                 "ARC-Authentication-Results"],
            ))
            return findings

        findings.extend(self._spf_findings(results))
        findings.extend(self._dkim_findings(results))
        findings.extend(self._dmarc_findings(results))
        findings.extend(self._alignment_findings(email, results))

        if ctx.online:
            findings.extend(self._live_dns_findings(email))
        return findings

    # ------------------------------------------------------------------ parse
    def _collect_results(self, email: ParsedEmail) -> dict:
        raw_headers = (
            email.header_all("authentication-results")
            + email.header_all("arc-authentication-results")
            + email.header_all("received-spf")
        )
        blob = " ; ".join(raw_headers)

        verdicts: dict[str, str] = {}
        for mech, value in _RESULT_RE.findall(blob):
            key = mech.lower()
            # Keep the worst result seen; a pass elsewhere does not cancel a fail.
            ranking = {"fail": 4, "softfail": 3, "permerror": 3, "temperror": 2,
                       "neutral": 2, "none": 1, "policy": 1, "pass": 0, "bestguesspass": 0}
            current = verdicts.get(key)
            if current is None or ranking.get(value.lower(), 0) > ranking.get(current, 0):
                verdicts[key] = value.lower()

        # Received-SPF states its verdict as the first token of the header.
        for header in email.header_all("received-spf"):
            token = header.strip().split()[0].lower() if header.strip() else ""
            if token in ("pass", "fail", "softfail", "neutral", "none", "permerror", "temperror"):
                verdicts.setdefault("spf", token)

        dkim_match = _DKIM_DOMAIN_RE.search(blob)
        spf_match = _SPF_DOMAIN_RE.search(blob)
        return {
            "raw_headers": raw_headers,
            "spf": verdicts.get("spf"),
            "dkim": verdicts.get("dkim"),
            "dmarc": verdicts.get("dmarc"),
            "dkim_domain": (dkim_match.group(1).lower() if dkim_match else ""),
            "spf_domain": (spf_match.group(1).lower() if spf_match else ""),
            "has_dkim_signature": bool(email.header_all("dkim-signature")),
        }

    # --------------------------------------------------------------- findings
    def _spf_findings(self, results: dict) -> list[Finding]:
        spf = results["spf"]
        if spf == "fail":
            return [finding("AUTH-001", f"Authentication-Results reports spf={spf}",
                            spf_domain=results["spf_domain"] or "unknown")]
        if spf in ("softfail", "neutral", "permerror"):
            return [finding("AUTH-002", f"Authentication-Results reports spf={spf}",
                            spf_domain=results["spf_domain"] or "unknown")]
        return []

    def _dkim_findings(self, results: dict) -> list[Finding]:
        dkim = results["dkim"]
        if dkim in ("fail", "permerror"):
            return [finding("AUTH-003", f"Authentication-Results reports dkim={dkim}",
                            dkim_domain=results["dkim_domain"] or "unknown")]
        if not results["has_dkim_signature"] and dkim in (None, "none"):
            return [finding("AUTH-004", "No DKIM-Signature header on the message")]
        return []

    def _dmarc_findings(self, results: dict) -> list[Finding]:
        if results["dmarc"] in ("fail", "permerror"):
            return [finding("AUTH-005",
                            f"Authentication-Results reports dmarc={results['dmarc']}")]
        return []

    def _alignment_findings(self, email: ParsedEmail, results: dict) -> list[Finding]:
        """Relaxed DMARC alignment: the authenticated domain must share the
        registrable domain of the visible From address."""
        if not email.from_domain:
            return []
        passing: list[tuple[str, str]] = []
        if results["spf"] == "pass" and results["spf_domain"]:
            passing.append(("SPF", results["spf_domain"]))
        if results["dkim"] == "pass" and results["dkim_domain"]:
            passing.append(("DKIM", results["dkim_domain"]))
        if not passing:
            return []
        if any(domains.same_org(auth_domain, email.from_domain) for _, auth_domain in passing):
            return []
        detail = ", ".join(f"{mech} authenticated {dom}" for mech, dom in passing)
        return [finding(
            "AUTH-007",
            f"{detail}, but From: shows {email.from_domain}",
            from_domain=email.from_domain,
            authenticated=[{"mechanism": m, "domain": d} for m, d in passing],
        )]

    # ------------------------------------------------------------ online only
    def _live_dns_findings(self, email: ParsedEmail) -> list[Finding]:
        if not email.from_domain:
            return []
        try:
            import dns.resolver  # noqa: PLC0415 - optional dependency, online mode only
        except ImportError:
            return []

        findings: list[Finding] = []
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 5.0

        try:
            resolver.resolve(f"_dmarc.{email.from_domain}", "TXT")
        except Exception:
            findings.append(finding(
                "AUTH-008", f"No _dmarc TXT record found for {email.from_domain}",
                domain=email.from_domain,
            ))

        try:
            answers = resolver.resolve(email.from_domain, "TXT")
            for record in answers:
                text = b"".join(record.strings).decode("utf-8", "replace")
                if text.lower().startswith("v=spf1") and re.search(r"[+]?all\s*$", text):
                    if not re.search(r"[-~?]all\s*$", text):
                        findings.append(finding(
                            "AUTH-009", f"SPF record permits all senders: {text[:160]}",
                            domain=email.from_domain, record=text[:300],
                        ))
        except Exception:
            pass
        return findings
