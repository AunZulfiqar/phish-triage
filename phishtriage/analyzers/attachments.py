"""Attachment analysis.

Static only -- nothing is extracted, executed or detonated. The tool reports what
the file *claims* to be, what its name suggests, and its hashes, then leaves the
decision to the analyst. Hashes are the deliverable that matters most here: they
are what gets pivoted on in VirusTotal, a SIEM or an EDR console, and producing
them without ever opening the payload is the point.

Filename handling is where care is needed. A filename is attacker-controlled
text, so it is examined for right-to-left override, double extensions and
extension/MIME disagreement rather than trusted at face value.
"""

from __future__ import annotations

import re

from ..intel import lexicon, tlds
from ..models import Attachment, Finding, ParsedEmail
from ..utils import homoglyph
from .base import Context, finding

_EXT_RE = re.compile(r"\.([A-Za-z0-9]{1,8})$")
_DOUBLE_EXT_RE = re.compile(r"\.([A-Za-z0-9]{1,8})\s*\.([A-Za-z0-9]{1,8})$")


def _extension(filename: str) -> str:
    match = _EXT_RE.search(filename.strip())
    return match.group(1).lower() if match else ""


class AttachmentAnalyzer:
    name = "attachments"
    category = "attachments"

    def run(self, email: ParsedEmail, ctx: Context) -> list[Finding]:
        if not email.attachments:
            return []
        findings: list[Finding] = []
        seen: set[str] = set()

        body = f"{email.body_text}\n{email.subject}"
        archive_password_hits = lexicon.matches("archive_password", body)

        for attachment in email.attachments:
            for result in self._inspect(attachment, archive_password_hits):
                if result.id in seen:
                    continue
                seen.add(result.id)
                findings.append(result)
        return findings

    def _inspect(self, att: Attachment, password_hits: list[str]) -> list[Finding]:
        out: list[Finding] = []
        name = att.filename
        display_ext = _extension(name)

        # -- right-to-left override --------------------------------------
        if homoglyph.has_rtlo(name):
            visible = name.replace(homoglyph.RTLO, "")
            out.append(finding(
                "ATT-008",
                f"Filename contains U+202E; it displays as one thing and is another: {name!r}",
                filename=name, filename_without_rtlo=visible,
                real_extension=_extension(visible[::-1]) or _extension(visible),
                **_hashes(att),
            ))

        # -- double extension --------------------------------------------
        if match := _DOUBLE_EXT_RE.search(name):
            first, second = match.group(1).lower(), match.group(2).lower()
            dangerous = tlds.EXECUTABLE_EXTENSIONS | tlds.SCRIPT_EXTENSIONS
            if first in tlds.DECOY_EXTENSIONS and second in dangerous:
                out.append(finding(
                    "ATT-002",
                    f'"{name}" presents as .{first} but is a .{second}',
                    filename=name, decoy_extension=first, real_extension=second,
                    **_hashes(att),
                ))

        # -- category by extension ---------------------------------------
        category_map = (
            (tlds.EXECUTABLE_EXTENSIONS, "ATT-001", "executable"),
            (tlds.SCRIPT_EXTENSIONS, "ATT-007", "script"),
            (tlds.MACRO_OFFICE_EXTENSIONS, "ATT-003", "macro-capable document"),
            (tlds.CONTAINER_EXTENSIONS, "ATT-010", "disk image"),
            (tlds.SHORTCUT_EXTENSIONS, "ATT-011", "shortcut"),
            (tlds.HTML_EXTENSIONS, "ATT-009", "HTML document"),
            (tlds.ARCHIVE_EXTENSIONS, "ATT-004", "archive"),
        )
        for extensions, indicator_id, label in category_map:
            if display_ext in extensions:
                out.append(finding(
                    indicator_id,
                    f'"{name}" is a {label} (.{display_ext}, {att.size:,} bytes)',
                    filename=name, extension=display_ext, size=att.size,
                    content_type=att.content_type, **_hashes(att),
                ))
                break

        # -- encrypted archive whose key is in the body -------------------
        if display_ext in tlds.ARCHIVE_EXTENSIONS and password_hits:
            out.append(finding(
                "ATT-006",
                f'Archive "{name}" arrives with password wording in the body: '
                f"{', '.join(password_hits[:3])}",
                filename=name, password_phrases=password_hits, **_hashes(att),
            ))

        # -- MIME vs extension -------------------------------------------
        expected = tlds.EXPECTED_MIME.get(display_ext)
        if expected and att.content_type and att.content_type not in expected:
            if att.content_type != "application/octet-stream":
                out.append(finding(
                    "ATT-005",
                    f'"{name}" declares Content-Type {att.content_type}, '
                    f"but .{display_ext} should be {expected[0]}",
                    filename=name, declared=att.content_type,
                    expected=list(expected), **_hashes(att),
                ))
        return out


def _hashes(att: Attachment) -> dict[str, str]:
    return {"sha256": att.sha256, "md5": att.md5}
