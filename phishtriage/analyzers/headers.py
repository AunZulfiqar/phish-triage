"""Header and Received-chain analysis.

Most of the value here comes from *disagreement between identities*. A message
carries several notions of "who sent this" -- the display name, the From address,
the Return-Path, the Reply-To, the Message-ID domain -- and legitimate mail
generally keeps them consistent or diverges in well-understood ways (mailing
lists, ticketing systems, marketing platforms). Attackers have to make at least
one of them lie, and the lie usually shows up as a mismatch.
"""

from __future__ import annotations

import email.utils
import re
from datetime import timezone

from ..intel import brands
from ..models import Finding, ParsedEmail
from ..utils import domains
from .base import Context, finding

_MESSAGE_ID_RE = re.compile(r"^<[^<>@\s]+@([^<>@\s]+)>$")
_BULK_MAILER_RE = re.compile(
    r"(phpmailer|swiftmailer|python-?(?:urllib|requests|smtplib)|mass\s*mail|"
    r"bulk\s*mail|sendblaster|mailer\s*king|turbo-?smtp|libesmtp|"
    r"perl.*mail::sender|axigen|smtplib)",
    re.IGNORECASE,
)
_FAKE_EXTERNAL_RE = re.compile(r"\[\s*(external|extern|caution|suspicious)\s*\]", re.IGNORECASE)
_REPLY_PREFIX_RE = re.compile(r"^\s*(re|fw|fwd|aw|wg|antw)\s*:", re.IGNORECASE)

_MAX_PLAUSIBLE_HOP_SECONDS = 6 * 60 * 60
_MAX_DATE_SKEW_SECONDS = 24 * 60 * 60


class HeaderAnalyzer:
    name = "headers"
    category = "headers"

    def run(self, email_msg: ParsedEmail, ctx: Context) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._identity_mismatches(email_msg))
        findings.extend(self._display_name(email_msg, ctx))
        findings.extend(self._message_id(email_msg))
        findings.extend(self._mailer(email_msg))
        findings.extend(self._chain(email_msg))
        findings.extend(self._recipients(email_msg, ctx))
        findings.extend(self._subject(email_msg, ctx))
        return findings

    # ---------------------------------------------------------------- identity
    def _identity_mismatches(self, msg: ParsedEmail) -> list[Finding]:
        out: list[Finding] = []
        from_domain = msg.from_domain
        if not from_domain:
            return out

        reply_domain = domains.domain_of_address(msg.reply_to)
        if reply_domain and not domains.same_org(reply_domain, from_domain):
            out.append(finding(
                "HDR-001",
                f"From: {msg.from_address} but Reply-To: {msg.reply_to}",
                from_domain=from_domain, reply_to_domain=reply_domain,
                reply_to_is_freemail=reply_domain in brands.FREEMAIL_DOMAINS,
                reply_to_is_disposable=reply_domain in brands.DISPOSABLE_DOMAINS,
            ))

        if msg.return_path and not domains.same_org(msg.return_path, from_domain):
            out.append(finding(
                "HDR-002",
                f"Return-Path domain {msg.return_path} != From domain {from_domain}",
                return_path_domain=msg.return_path, from_domain=from_domain,
            ))
        return out

    # ------------------------------------------------------------ display name
    def _display_name(self, msg: ParsedEmail, ctx: Context) -> list[Finding]:
        out: list[Finding] = []
        display = msg.from_display
        if not display or not msg.from_domain:
            return out

        # An address hiding inside the display name.
        for embedded in domains.addresses_in(display):
            if embedded != msg.from_address and not domains.same_org(
                domains.domain_of_address(embedded), msg.from_domain
            ):
                out.append(finding(
                    "HDR-003",
                    f'Display name reads "{display}" but the real sender is '
                    f"{msg.from_address}",
                    display_name=display, embedded_address=embedded,
                    actual_address=msg.from_address,
                ))
                break

        # A brand claimed in the display name that the sending domain does not own.
        lowered = display.lower()
        sender_rd = domains.registered_domain(msg.from_domain)
        for brand, legit_domains in brands.BRANDS.items():
            if brand not in lowered:
                continue
            if sender_rd in legit_domains:
                break
            if any(domains.same_org(sender_rd, d) for d in legit_domains):
                break
            if any(domains.same_org(sender_rd, d) for d in ctx.org_domains):
                break
            out.append(finding(
                "HDR-004",
                f'Display name claims "{display}" but the message was sent from {sender_rd}',
                display_name=display, claimed_brand=brand,
                sender_domain=sender_rd, legitimate_domains=list(legit_domains),
            ))
            break

        # Organisational authority asserted from a consumer mailbox.
        if sender_rd in brands.FREEMAIL_DOMAINS:
            authority = re.search(
                r"\b(ceo|cfo|coo|cto|director|president|chairman|manager|head of|"
                r"accounts?|payroll|finance|hr|human resources|it\s*(?:support|desk|help))\b",
                lowered,
            )
            if authority:
                out.append(finding(
                    "HDR-012",
                    f'Display name asserts "{authority.group(0)}" from freemail account '
                    f"{msg.from_address}",
                    display_name=display, role_claimed=authority.group(0),
                    freemail_domain=sender_rd,
                ))
        return out

    # -------------------------------------------------------------- message-id
    def _message_id(self, msg: ParsedEmail) -> list[Finding]:
        if not msg.message_id:
            return [finding("HDR-006", "Message-ID header is absent")]
        match = _MESSAGE_ID_RE.match(msg.message_id)
        if not match:
            return [finding("HDR-006", f"Malformed Message-ID: {msg.message_id[:120]}",
                            message_id=msg.message_id)]
        mid_domain = match.group(1).lower()
        if msg.from_domain and not domains.same_org(mid_domain, msg.from_domain):
            return [finding(
                "HDR-005",
                f"Message-ID was issued by {mid_domain}, sender domain is {msg.from_domain}",
                message_id_domain=mid_domain, from_domain=msg.from_domain,
            )]
        return []

    # ------------------------------------------------------------------ mailer
    def _mailer(self, msg: ParsedEmail) -> list[Finding]:
        for header_name in ("x-mailer", "user-agent", "x-php-originating-script"):
            value = msg.header(header_name)
            if value and _BULK_MAILER_RE.search(value):
                return [finding(
                    "HDR-007", f"{header_name}: {value[:120]}",
                    header=header_name, value=value[:200],
                )]
        return []

    # ------------------------------------------------------------------- chain
    def _chain(self, msg: ParsedEmail) -> list[Finding]:
        out: list[Finding] = []
        if len(msg.hops) <= 1:
            out.append(finding(
                "HDR-010",
                f"Received chain contains {len(msg.hops)} hop(s)",
                hop_count=len(msg.hops),
            ))

        for hop in msg.hops:
            if hop.delay_seconds is None:
                continue
            if hop.delay_seconds < -60:
                out.append(finding(
                    "HDR-008",
                    f"Hop {hop.index} is timestamped {abs(hop.delay_seconds):.0f}s "
                    "*before* the hop that preceded it",
                    hop_index=hop.index, delay_seconds=hop.delay_seconds, raw=hop.raw[:200],
                ))
                break
            if hop.delay_seconds > _MAX_PLAUSIBLE_HOP_SECONDS:
                out.append(finding(
                    "HDR-008",
                    f"Hop {hop.index} sat for {hop.delay_seconds / 3600:.1f}h "
                    "before the next relay",
                    hop_index=hop.index, delay_seconds=hop.delay_seconds, raw=hop.raw[:200],
                ))
                break

        out.extend(self._date_skew(msg))
        return out

    def _date_skew(self, msg: ParsedEmail) -> list[Finding]:
        if not msg.date_header or not msg.hops:
            return []
        try:
            claimed = email.utils.parsedate_to_datetime(msg.date_header)
        except (TypeError, ValueError):
            return []
        if claimed is None:
            return []
        if claimed.tzinfo is None:
            claimed = claimed.replace(tzinfo=timezone.utc)

        newest = next((h.timestamp for h in msg.hops if h.timestamp), None)
        if newest is None:
            return []
        skew = abs((claimed - newest).total_seconds())
        if skew > _MAX_DATE_SKEW_SECONDS:
            return [finding(
                "HDR-009",
                f"Date: header is {skew / 3600:.1f}h from the delivering hop's timestamp",
                date_header=msg.date_header, delivery_time=newest.isoformat(),
                skew_seconds=skew,
            )]
        return []

    # -------------------------------------------------------------- recipients
    def _recipients(self, msg: ParsedEmail, ctx: Context) -> list[Finding]:
        if not ctx.org_domains:
            return []
        visible = set(msg.to) | set(msg.cc)
        if not visible:
            return [finding("HDR-011", "Message has no To or Cc recipients at all")]
        if any(domains.domain_of_address(a) in ctx.org_domains for a in visible):
            return []
        delivered = msg.header("delivered-to") or msg.header("x-original-to")
        if delivered:
            return [finding(
                "HDR-011",
                f"Delivered to {delivered} which appears in neither To nor Cc",
                delivered_to=delivered, to=msg.to, cc=msg.cc,
            )]
        return []

    # ----------------------------------------------------------------- subject
    def _subject(self, msg: ParsedEmail, ctx: Context) -> list[Finding]:
        subject = msg.subject
        if not subject:
            return []
        out: list[Finding] = []

        if _FAKE_EXTERNAL_RE.search(subject) and ctx.org_domains:
            if not any(domains.same_org(msg.from_domain, d) for d in ctx.org_domains):
                out.append(finding(
                    "HDR-013",
                    "Subject carries an external-sender banner from outside the "
                    f'org: "{subject[:100]}"',
                    subject=subject[:200],
                ))
                return out

        # A reply prefix with no thread to reply to.
        if _REPLY_PREFIX_RE.match(subject):
            has_thread = bool(msg.header("in-reply-to") or msg.header("references"))
            if not has_thread:
                out.append(finding(
                    "HDR-013",
                    f'Subject "{subject[:80]}" implies a reply, but there is no '
                    "In-Reply-To or References header",
                    subject=subject[:200],
                ))
        return out
