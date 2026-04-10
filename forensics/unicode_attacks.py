"""
forensics/unicode_attacks.py
Detection of non-rendering Unicode attack vectors used for invisible-ink
prompt injection ("Tag Attacks"), zero-width smuggling, and BiDi spoofing.

All functions operate on plain str — no I/O, no file access.
"""

from __future__ import annotations
import re
from typing import List

# ─── Unicode Tag Block (U+E0000–U+E007F) ─────────────────────────────────────
#
# These characters were originally intended for language tagging but are
# deprecated and non-rendering in virtually all modern renderers. The range
# U+E0020–U+E007E maps one-to-one onto printable ASCII (add 0xE0000 to the
# ASCII code-point to get the tag character). This mapping is the basis of
# "invisible ink" prompt injection attacks as documented by Idan Gour (2025).

_TAG_BLOCK_START = 0xE0000
_TAG_BLOCK_END   = 0xE007F
# The printable ASCII sub-range that encodes actual text
_TAG_ASCII_START = 0xE0020
_TAG_ASCII_END   = 0xE007E


def decode_unicode_tags(text: str) -> str:
    """
    Extract Unicode Tag characters (U+E0020–U+E007E) from text and decode
    them to their ASCII equivalents.

    Characters outside the printable mapping range (e.g., U+E0001 language tag
    leader) are replaced with '?' in the decoded output.

    Returns the decoded string (empty if no tag characters were found).
    """
    decoded_chars = []
    for ch in text:
        cp = ord(ch)
        if _TAG_BLOCK_START <= cp <= _TAG_BLOCK_END:
            ascii_cp = cp - _TAG_BLOCK_START
            if 0x20 <= ascii_cp <= 0x7E:
                decoded_chars.append(chr(ascii_cp))
            else:
                decoded_chars.append("?")
    return "".join(decoded_chars)


def detect_unicode_tags(text: str, pi_patterns: List[re.Pattern] | None = None) -> dict:
    """
    Scan text for Unicode Tag characters (U+E0000–U+E007F).

    Returns:
        tag_count       — total number of Tag characters found
        decoded_payload — decoded ASCII text (empty string if none found)
        positions       — list of (index, codepoint_hex) for the first 20 hits
        pi_matches      — PI pattern matches found in the decoded payload
        verdict         — "CLEAN" | "SUSPICIOUS" | "NEEDS_REVIEW"
    """
    positions = []
    tag_chars = []

    for i, ch in enumerate(text):
        cp = ord(ch)
        if _TAG_BLOCK_START <= cp <= _TAG_BLOCK_END:
            tag_chars.append(ch)
            if len(positions) < 20:
                positions.append({"index": i, "codepoint": f"U+{cp:05X}"})

    if not tag_chars:
        return {
            "tag_count": 0,
            "decoded_payload": "",
            "positions": [],
            "pi_matches": [],
            "verdict": "CLEAN",
        }

    decoded = decode_unicode_tags("".join(tag_chars))

    # Scan the decoded payload for prompt injection patterns
    if pi_patterns is None:
        from .algorithms import _PI_COMPILED
        pi_patterns = _PI_COMPILED

    pi_matches: List[str] = []
    if pi_patterns:
        for pat in pi_patterns:
            m = pat.search(decoded)
            if m:
                snippet = decoded[max(0, m.start() - 15): m.end() + 25]
                pi_matches.append(f"Pattern matched in hidden payload: ...{snippet}...")

    # Verdict logic:
    #   - Tags present + PI match → high confidence attack
    #   - Tags present without PI → could still be an attack (payload may be
    #     a partial instruction or use novel phrasing), flag for review
    if pi_matches:
        verdict = "SUSPICIOUS"
    elif tag_chars:
        verdict = "NEEDS_REVIEW"
    else:
        verdict = "CLEAN"

    return {
        "tag_count": len(tag_chars),
        "decoded_payload": decoded[:500],   # cap at 500 chars for report safety
        "positions": positions,
        "pi_matches": pi_matches,
        "verdict": verdict,
    }


# ─── Zero-Width Character Smuggling ──────────────────────────────────────────
#
# Zero-width characters are invisible in most renderers but carry bit patterns
# that can be used for watermarking, covert channel encoding, or to split
# words in a way that defeats keyword filters while remaining readable by LLMs.

_ZWC_MAP = {
    "\u200b": "ZERO WIDTH SPACE",
    "\u200c": "ZERO WIDTH NON-JOINER",
    "\u200d": "ZERO WIDTH JOINER",
    "\u2060": "WORD JOINER",
    "\u2061": "FUNCTION APPLICATION",
    "\u2062": "INVISIBLE TIMES",
    "\u2063": "INVISIBLE SEPARATOR",
    "\u2064": "INVISIBLE PLUS",
    "\ufeff": "ZERO WIDTH NO-BREAK SPACE (BOM)",
}


def detect_zero_width_smuggling(text: str) -> dict:
    """
    Detect zero-width and functionally invisible Unicode characters.

    These can be used to:
    - Split words in ways that bypass keyword filters (e.g., "ig\u200bnore")
    - Encode binary payloads as sequences of ZWC/non-ZWC pairs
    - Watermark AI-generated text (the ZWC fingerprinting technique)

    Returns:
        total_count  — total number of suspicious characters
        by_type      — dict mapping character name to count
        verdict      — "CLEAN" | "LOW_RISK" | "SUSPICIOUS"
    """
    by_type: dict = {}
    total = 0

    for ch in text:
        name = _ZWC_MAP.get(ch)
        if name:
            by_type[name] = by_type.get(name, 0) + 1
            total += 1

    if total == 0:
        verdict = "CLEAN"
    elif total <= 3:
        verdict = "LOW_RISK"
    else:
        verdict = "SUSPICIOUS"

    return {
        "total_count": total,
        "by_type": by_type,
        "verdict": verdict,
    }


# ─── BiDi Override Attack ─────────────────────────────────────────────────────
#
# Right-to-left override and other bidirectional control characters can cause
# text to render in an entirely different visual order from its logical order.
# This creates a human/machine perception gap: the visible sequence of glyphs
# differs from what an LLM processes as the raw token stream.
# (CVE-2021-42574 "Trojan Source" uses this technique for source code.)

_BIDI_MAP = {
    "\u202a": "LEFT-TO-RIGHT EMBEDDING",
    "\u202b": "RIGHT-TO-LEFT EMBEDDING",
    "\u202c": "POP DIRECTIONAL FORMATTING",
    "\u202d": "LEFT-TO-RIGHT OVERRIDE",
    "\u202e": "RIGHT-TO-LEFT OVERRIDE",
    "\u2066": "LEFT-TO-RIGHT ISOLATE",
    "\u2067": "RIGHT-TO-LEFT ISOLATE",
    "\u2068": "FIRST STRONG ISOLATE",
    "\u2069": "POP DIRECTIONAL ISOLATE",
    "\u200f": "RIGHT-TO-LEFT MARK",
    "\u200e": "LEFT-TO-RIGHT MARK",
}


def detect_bidi_attacks(text: str) -> dict:
    """
    Detect Unicode BiDi control characters used for text-reordering attacks.

    Presence of RLO (U+202E) is particularly suspicious as it is the character
    used by Trojan Source attacks. Other BiDi controls may appear legitimately
    in genuinely multilingual text, but are unusual in typical documents.

    Returns:
        total_count — total BiDi control characters found
        by_type     — dict mapping character name to count
        has_override — True if any override character (U+202D/U+202E) present
        verdict     — "CLEAN" | "LOW_RISK" | "SUSPICIOUS"
    """
    by_type: dict = {}
    total = 0
    has_override = False

    for ch in text:
        name = _BIDI_MAP.get(ch)
        if name:
            by_type[name] = by_type.get(name, 0) + 1
            total += 1
            if ch in ("\u202d", "\u202e"):
                has_override = True

    if has_override:
        verdict = "SUSPICIOUS"
    elif total > 0:
        verdict = "LOW_RISK"
    else:
        verdict = "CLEAN"

    return {
        "total_count": total,
        "by_type": by_type,
        "has_override": has_override,
        "verdict": verdict,
    }


# ─── Master Scanner ───────────────────────────────────────────────────────────

def scan_all_unicode_attacks(
    text: str,
    pi_patterns: List[re.Pattern] | None = None,
) -> dict:
    """
    Run all Unicode-based attack checks on a string.

    Args:
        text        — the text to scan (should be the full decoded string)
        pi_patterns — optional compiled PI regex patterns for payload scanning;
                      if None, the imported PI patterns from algorithms are used

    Returns unified dict:
        tags        — result of detect_unicode_tags()
        zero_width  — result of detect_zero_width_smuggling()
        bidi        — result of detect_bidi_attacks()
        verdict     — "CLEAN" | "LOW_RISK" | "NEEDS_REVIEW" | "SUSPICIOUS"
        summary     — human-readable list of findings
    """
    if pi_patterns is None:
        from .algorithms import _PI_COMPILED
        pi_patterns = _PI_COMPILED

    tags = detect_unicode_tags(text, pi_patterns)
    zero_width = detect_zero_width_smuggling(text)
    bidi = detect_bidi_attacks(text)

    # Aggregate verdict: take the worst across all three checks
    _ORDER = {"CLEAN": 0, "LOW_RISK": 1, "NEEDS_REVIEW": 2, "SUSPICIOUS": 3}
    worst = max(
        tags["verdict"], zero_width["verdict"], bidi["verdict"],
        key=lambda v: _ORDER.get(v, 0),
    )

    summary: List[str] = []
    if tags["tag_count"] > 0:
        payload_preview = tags["decoded_payload"][:80].replace("\n", " ")
        summary.append(
            f"{tags['tag_count']} Unicode Tag char(s) found — "
            f"decoded: \"{payload_preview}\""
        )
        if tags["pi_matches"]:
            summary.append(
                f"  → {len(tags['pi_matches'])} PI pattern(s) matched in hidden payload"
            )
    if zero_width["total_count"] > 0:
        summary.append(
            f"{zero_width['total_count']} zero-width character(s) — "
            + ", ".join(f"{v}×{k}" for k, v in zero_width["by_type"].items())
        )
    if bidi["total_count"] > 0:
        override_note = " (OVERRIDE PRESENT)" if bidi["has_override"] else ""
        summary.append(
            f"{bidi['total_count']} BiDi control character(s){override_note}"
        )

    return {
        "tags": tags,
        "zero_width": zero_width,
        "bidi": bidi,
        "verdict": worst,
        "summary": summary,
    }
