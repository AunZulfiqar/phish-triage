"""Body and content analysis.

Keyword lexicons are the weakest evidence this tool produces, and they are
weighted accordingly. The checks that carry real weight are structural rather
than lexical: an HTML form with a password field, text hidden with
``display:none``, a text/plain part that says something different from the HTML,
a body that is nothing but an image. Those are choices an attacker makes to
defeat a filter, and legitimate senders rarely make them.

Body text is normalised through :func:`homoglyph.strip_invisible` before keyword
matching, so that "u‌r‌g‌e‌n‌t" with zero-width joiners still matches "urgent" --
while the joiners themselves are reported separately as their own indicator.
"""

from __future__ import annotations

import difflib
import re

from ..intel import lexicon
from ..models import Finding, ParsedEmail
from ..utils import homoglyph
from .base import Context, finding

_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")
_PASSWORD_INPUT_RE = re.compile(r"password|passwd|pwd|pin|otp|mfa|token|ssn|card", re.IGNORECASE)

_MIN_BODY_FOR_IMAGE_CHECK = 0
_IMAGE_ONLY_TEXT_THRESHOLD = 120
_PART_DIVERGENCE_THRESHOLD = 0.45


def _html_to_text(html: str) -> str:
    return _WS_RE.sub(" ", _TAG_RE.sub(" ", html or "")).strip()


class ContentAnalyzer:
    name = "content"
    category = "content"

    def run(self, email: ParsedEmail, ctx: Context) -> list[Finding]:
        facts = email.html_facts
        raw_body = f"{email.subject}\n{email.body_text}\n{_html_to_text(email.body_html)}"
        body = homoglyph.strip_invisible(raw_body)

        findings: list[Finding] = []
        findings.extend(self._lexical(body))
        findings.extend(self._invisible(raw_body))
        findings.extend(self._structural(email, facts))
        findings.extend(self._part_divergence(email))
        findings.extend(self._bec_shape(email, body))
        return findings

    # ---------------------------------------------------------------- lexical
    def _lexical(self, body: str) -> list[Finding]:
        out: list[Finding] = []
        # (lexicon, indicator, label, minimum distinct hits)
        #
        # Financial wording needs two hits. Legitimate receipts and invoices say
        # "payment details" all day long; what separates BEC is the pile-up of
        # "wire transfer" *and* "beneficiary details" *and* "SWIFT code". A
        # single-hit threshold here was the tool's main false-positive source.
        checks = (
            ("urgency", "CNT-001", "Urgency wording", 1),
            ("credentials", "CNT-002", "Credential-request wording", 1),
            ("financial", "CNT-003", "Financial-instruction wording", 2),
            ("threat", "CNT-010", "Consequence wording", 1),
            ("secrecy", "CNT-012", "Secrecy or process-bypass wording", 1),
            ("salutation", "CNT-009", "Generic salutation", 1),
        )
        for category, indicator_id, label, minimum in checks:
            hits = lexicon.matches(category, body)
            if len(hits) < minimum:
                continue
            out.append(finding(
                indicator_id,
                f"{label}: {', '.join(repr(h) for h in hits[:4])}",
                phrases=hits, phrase_count=len(hits),
            ))
        return out

    # -------------------------------------------------------------- invisible
    def _invisible(self, raw_body: str) -> list[Finding]:
        invisible = homoglyph.find_invisible(raw_body)
        if not invisible:
            return []
        total = sum(count for _, _, count in invisible)
        # A handful of soft hyphens is normal in justified marketing HTML.
        if total < 5:
            return []
        described = ", ".join(f"{name} x{count}" for _, name, count in invisible[:3])
        return [finding(
            "CNT-005",
            f"{total} invisible characters in the body ({described})",
            total=total,
            characters=[{"codepoint": cp, "name": n, "count": c} for cp, n, c in invisible],
        )]

    # ------------------------------------------------------------- structural
    def _structural(self, email: ParsedEmail, facts) -> list[Finding]:
        if facts is None:
            return []
        out: list[Finding] = []

        if facts.has_form:
            sensitive = [t for t in facts.input_types if _PASSWORD_INPUT_RE.search(t)]
            if sensitive:
                out.append(finding(
                    "CNT-006",
                    f"HTML form in the body collects {', '.join(sorted(set(sensitive))[:4])}",
                    input_types=sorted(set(facts.input_types)),
                    form_actions=facts.form_actions[:3],
                ))

        if facts.hidden_text:
            sample = " | ".join(t[:60] for t in facts.hidden_text[:3])
            hidden_len = sum(len(t) for t in facts.hidden_text)
            if hidden_len > 40:
                out.append(finding(
                    "CNT-004",
                    f"{hidden_len} characters of hidden text, e.g. {sample!r}",
                    hidden_characters=hidden_len,
                    samples=[t[:120] for t in facts.hidden_text[:5]],
                ))

        if facts.image_count >= 1 and facts.visible_text_len < _IMAGE_ONLY_TEXT_THRESHOLD:
            if email.body_html:
                out.append(finding(
                    "CNT-007",
                    f"{facts.image_count} image(s) but only {facts.visible_text_len} "
                    "characters of readable text",
                    image_count=facts.image_count,
                    visible_text_length=facts.visible_text_len,
                ))
        return out

    # -------------------------------------------------------- part divergence
    def _part_divergence(self, email: ParsedEmail) -> list[Finding]:
        text = _WS_RE.sub(" ", email.body_text).strip().lower()
        html_text = _html_to_text(email.body_html).lower()
        if len(text) < 80 or len(html_text) < 80:
            return []
        ratio = difflib.SequenceMatcher(None, text[:4000], html_text[:4000]).quick_ratio()
        if ratio >= _PART_DIVERGENCE_THRESHOLD:
            return []
        return [finding(
            "CNT-008",
            f"text/plain and text/html parts are only {ratio:.0%} similar",
            similarity=round(ratio, 3),
            text_preview=text[:180], html_preview=html_text[:180],
        )]

    # ---------------------------------------------------------------- bec
    def _bec_shape(self, email: ParsedEmail, body: str) -> list[Finding]:
        """Short, link-free, attachment-free messages that ask for a reply.

        BEC deliberately carries no payload on the first message, so every
        payload-driven check above stays silent. The shape of the message is
        the only thing left to detect.
        """
        if email.urls or email.attachments:
            return []
        stripped = _WS_RE.sub(" ", body).strip()
        if not 20 < len(stripped) < 900:
            return []
        solicitation = re.search(
            r"\b(are you (?:available|around|at your desk)|let me know|reply (?:to me|back)|"
            r"can you (?:help|handle|do)|need (?:you|your) (?:to|help)|quick (?:task|favou?r)|"
            r"i need a favou?r|send me your|what is your (?:number|cell|mobile))\b",
            stripped, re.IGNORECASE,
        )
        if not solicitation:
            return []
        return [finding(
            "CNT-011",
            f'Payload-free reply solicitation: "{solicitation.group(0)}"',
            trigger=solicitation.group(0), body_length=len(stripped),
        )]
