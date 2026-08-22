"""Homoglyph and invisible-character detection.

Two distinct problems are handled here:

1. **Mixed-script hostnames.** ``paypal.com`` written with a Cyrillic ``а`` is a
   different domain that renders identically. Rather than maintaining a
   confusable table, the check classifies each character's Unicode script and
   flags labels that mix scripts -- the approach browsers use for their own IDN
   display policy, and far harder to evade than a fixed lookup table.

2. **Invisible characters in body text.** Zero-width joiners inserted mid-word
   defeat naive keyword filters while rendering identically to the reader.
"""

from __future__ import annotations

import unicodedata

# Codepoint ranges that identify a script without needing a full ICU dependency.
_SCRIPT_RANGES: tuple[tuple[int, int, str], ...] = (
    (0x0041, 0x024F, "Latin"),
    (0x0370, 0x03FF, "Greek"),
    (0x1F00, 0x1FFF, "Greek"),
    (0x0400, 0x04FF, "Cyrillic"),
    (0x0500, 0x052F, "Cyrillic"),
    (0x0530, 0x058F, "Armenian"),
    (0x0590, 0x05FF, "Hebrew"),
    (0x0600, 0x06FF, "Arabic"),
    (0x0900, 0x097F, "Devanagari"),
    (0x0E00, 0x0E7F, "Thai"),
    (0x3040, 0x30FF, "Kana"),
    (0x4E00, 0x9FFF, "Han"),
)

INVISIBLE_CHARS: dict[str, str] = {
    "​": "ZERO WIDTH SPACE",
    "‌": "ZERO WIDTH NON-JOINER",
    "‍": "ZERO WIDTH JOINER",
    "⁠": "WORD JOINER",
    "﻿": "ZERO WIDTH NO-BREAK SPACE",
    "­": "SOFT HYPHEN",
    "᠎": "MONGOLIAN VOWEL SEPARATOR",
    "⁡": "FUNCTION APPLICATION",
    "⁢": "INVISIBLE TIMES",
    "⁣": "INVISIBLE SEPARATOR",
    "⁤": "INVISIBLE PLUS",
}

BIDI_CONTROLS: dict[str, str] = {
    "‪": "LEFT-TO-RIGHT EMBEDDING",
    "‫": "RIGHT-TO-LEFT EMBEDDING",
    "‬": "POP DIRECTIONAL FORMATTING",
    "‭": "LEFT-TO-RIGHT OVERRIDE",
    "‮": "RIGHT-TO-LEFT OVERRIDE",
    "⁦": "LEFT-TO-RIGHT ISOLATE",
    "⁧": "RIGHT-TO-LEFT ISOLATE",
    "⁨": "FIRST STRONG ISOLATE",
    "⁩": "POP DIRECTIONAL ISOLATE",
}

RTLO = "‮"


def script_of(char: str) -> str:
    """Best-effort Unicode script name for a single character."""
    code = ord(char)
    if code < 0x0041:
        return "Common"
    for start, end, name in _SCRIPT_RANGES:
        if start <= code <= end:
            return name
    return "Common" if unicodedata.category(char).startswith(("P", "N", "Z")) else "Other"


def scripts_in(text: str) -> set[str]:
    """The set of non-common scripts present in ``text``."""
    return {s for s in (script_of(c) for c in text if c.isalpha()) if s != "Common"}


def is_mixed_script(text: str) -> bool:
    """True when a string draws its letters from more than one script."""
    return len(scripts_in(text)) > 1


def confusable_chars(text: str) -> list[tuple[str, str, str]]:
    """Non-Latin letters in an otherwise Latin string.

    Returns ``(character, unicode name, script)`` triples -- the evidence an
    analyst needs in order to see exactly which character is the impostor.
    """
    scripts = scripts_in(text)
    if len(scripts) <= 1:
        return []
    out: list[tuple[str, str, str]] = []
    for char in text:
        if not char.isalpha():
            continue
        script = script_of(char)
        if script not in ("Latin", "Common"):
            name = unicodedata.name(char, f"U+{ord(char):04X}")
            entry = (char, name, script)
            if entry not in out:
                out.append(entry)
    return out


def find_invisible(text: str) -> list[tuple[str, str, int]]:
    """Invisible characters present in ``text`` as ``(char, name, count)``."""
    out: list[tuple[str, str, int]] = []
    for char, name in {**INVISIBLE_CHARS, **BIDI_CONTROLS}.items():
        count = text.count(char)
        if count:
            out.append((f"U+{ord(char):04X}", name, count))
    return sorted(out, key=lambda item: -item[2])


def has_rtlo(text: str) -> bool:
    return RTLO in text


def strip_invisible(text: str) -> str:
    """Remove invisible characters so downstream matching sees the real words."""
    table = {ord(c): None for c in {**INVISIBLE_CHARS, **BIDI_CONTROLS}}
    return text.translate(table)


def decode_punycode(host: str) -> str | None:
    """Render an ``xn--`` hostname as the Unicode it displays as."""
    if "xn--" not in host.lower():
        return None
    try:
        return host.encode("ascii").decode("idna")
    except (UnicodeError, UnicodeDecodeError):
        return None
