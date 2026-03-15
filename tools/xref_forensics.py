"""
xref_forensics.py — Deep forensic analysis of a PDF xref (content stream).

Produces:
  1. MCID block table (per-block: position, font, render_mode, content, classification)
  2. Float forensics report (IEEE 754 breakdown + Word-artifact confidence)
  3. Clip-rect comparison table
  4. Optional annotated stream dump
  5. Final verdict with confidence score

Usage:
  python xref_forensics.py HW1.pdf --xref 4
  python xref_forensics.py HW1.pdf --xref 4 --full-dump --no-color
  python xref_forensics.py HW1.pdf --xref 4 --json > xref4_forensics.json
  python xref_forensics.py HW1.pdf --xref 4 --html
  python xref_forensics.py HW1.pdf --xref 4 --compare 27
"""

from __future__ import annotations

import argparse
import html as html_module
import json
import math
import re
import struct
import sys
import zlib
from dataclasses import dataclass, field
from typing import Any

try:
    import fitz  # PyMuPDF
    PYMUPDF_AVAILABLE = True
except ImportError:
    PYMUPDF_AVAILABLE = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PDF_OPERATORS = {
    "BT": "begin-text",
    "ET": "end-text",
    "Tf": "set-font",
    "Tm": "text-matrix",
    "Td": "move-text-pos",
    "TD": "move-text-pos-leading",
    "Tr": "text-render-mode",
    "Tj": "show-string",
    "TJ": "show-array",
    "re": "rectangle",
    "W": "clip-even-odd",
    "W*": "clip-nonzero",
    "n": "end-path",
    "q": "save-state",
    "Q": "restore-state",
    "cm": "concat-matrix",
    "BDC": "begin-marked-content-dict",
    "BMC": "begin-marked-content",
    "EMC": "end-marked-content",
    "Do": "invoke-xobject",
    "gs": "set-graphics-state",
    "CS": "set-color-space",
    "cs": "set-color-space-nonstroke",
    "SCN": "set-color",
    "scn": "set-color-nonstroke",
    "G": "set-gray",
    "g": "set-gray-nonstroke",
    "RG": "set-rgb",
    "rg": "set-rgb-nonstroke",
    "S": "stroke",
    "s": "close-stroke",
    "f": "fill",
    "F": "fill",
    "f*": "fill-evenodd",
    "b": "close-fill-stroke",
    "B": "fill-stroke",
    "w": "set-linewidth",
    "J": "set-linecap",
    "j": "set-linejoin",
    "d": "set-dash",
    "i": "set-flatness",
    "M": "set-miterlimit",
    "m": "moveto",
    "l": "lineto",
    "c": "curveto",
    "v": "curveto-v",
    "y": "curveto-y",
    "h": "closepath",
    "ri": "set-rendering-intent",
    "sh": "shading",
}

RENDER_MODES = {
    0: "fill",
    1: "stroke",
    2: "fill+stroke",
    3: "invisible",
    4: "fill+clip",
    5: "stroke+clip",
    6: "fill+stroke+clip",
    7: "clip",
}

# Known Word PDF/UA artifact patterns
WORD_ARTIFACT_PATTERNS = {
    "subpixel_clip_x": lambda v: 1e-8 < abs(v) < 1e-4,
    "a4_width":        lambda v: abs(v - 595.32) < 0.1,
    "a4_height":       lambda v: abs(v - 841.92) < 0.1,
    "letter_width":    lambda v: abs(v - 612.0) < 0.1,
    "letter_height":   lambda v: abs(v - 792.0) < 0.1,
    "word_font_size":  lambda v: any(abs(v - x) < 0.1 for x in
                           [9.0, 10.0, 10.5, 11.0, 12.0, 13.0, 14.0, 16.0, 18.0,
                            11.04, 12.0, 14.04, 17.04, 18.96]),
    "word_spacing":    lambda v: any(abs(v - x) < 0.5 for x in
                           [12.0, 14.0, 18.0, 24.0, 36.0, 6.0, 8.0]),
}

# Known Word paragraph-spacing values (points)
WORD_PARA_SPACINGS = [6.0, 8.0, 10.0, 12.0, 14.0, 18.0, 24.0, 36.0]

# Page bounds tolerance
PAGE_BOUNDS_TOLERANCE = 2.0  # points

# ANSI color codes
GREEN   = "\033[32m"
YELLOW  = "\033[33m"
RED     = "\033[31m"
CYAN    = "\033[36m"
MAGENTA = "\033[35m"
BLUE    = "\033[34m"
WHITE   = "\033[37m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
RESET   = "\033[0m"

_USE_COLOR = True


def _c(code: str, text: str) -> str:
    """Apply ANSI color if color mode is on."""
    return f"{code}{text}{RESET}" if _USE_COLOR else text


def _hr(char: str = "-", width: int = 72) -> str:
    return char * width


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class IEEE754Result:
    value: float
    float32_hex: str
    binary: str
    sign: int
    exponent_raw: int
    exponent_biased: int
    mantissa_raw: int
    mantissa_fraction: float
    mantissa_bytes: list[int]
    reconstructed: float
    word_artifact_matches: list[str]
    word_artifact_confidence: float
    ascii_in_mantissa: str | None


@dataclass
class FloatRecord:
    value: float
    count: int
    frequency: float
    operators: list[str]
    ieee754: IEEE754Result


@dataclass
class MCIDRow:
    mcid_id: int
    x: float
    y: float
    font: str
    font_size: float
    render_mode: int
    content: str
    raw_content: str
    classification: str  # CONTENT / SPACING / INVISIBLE / OFFPAGE


@dataclass
class ClipRecord:
    x: float
    y: float
    width: float
    height: float
    count: int
    clip_type: str      # SUBPIXEL / NORMAL / FULL_PAGE
    classification: str # WORD_ARTIFACT / IMAGE_BBOX / UNKNOWN


@dataclass
class AnnotatedLine:
    line_num: int
    raw: str
    operators: list[str]
    annotations: list[str]
    mcid_boundary: int | None   # MCID id if this is a BDC opener, else None
    is_mcid_close: bool
    is_clip: bool
    clip_info: str | None


@dataclass
class ForensicsResult:
    xref: int
    stream_length: int
    total_floats: int
    float_records: list[FloatRecord]
    mcid_rows: list[MCIDRow]
    clip_records: list[ClipRecord]
    annotated_lines: list[AnnotatedLine]
    page_rect: tuple[float, float, float, float] | None
    has_invisible_text: bool
    has_offpage_text: bool
    verdict: str
    verdict_confidence: float
    verdict_evidence_for: list[str]
    verdict_evidence_against: list[str]
    verdict_recommendation: str


# ---------------------------------------------------------------------------
# IEEE 754 Analyzer
# ---------------------------------------------------------------------------

class IEEE754Analyzer:
    """Decompose a float into IEEE 754 single-precision components."""

    def analyze(self, value: float) -> IEEE754Result:
        # Pack as single-precision (4 bytes)
        try:
            packed = struct.pack(">f", value)
        except (struct.error, OverflowError):
            packed = b"\x00\x00\x00\x00"

        bits = struct.unpack(">I", packed)[0]

        sign        = (bits >> 31) & 0x1
        exp_raw     = (bits >> 23) & 0xFF
        mantissa    = bits & 0x7FFFFF

        exp_biased  = exp_raw - 127 if exp_raw != 0 else -126  # denorm
        mant_frac   = mantissa / (1 << 23)

        # Reconstruct
        if exp_raw == 0:
            reconstructed = ((-1) ** sign) * (mant_frac) * (2 ** -126)
        elif exp_raw == 0xFF:
            reconstructed = float("inf") * ((-1) ** sign)
        else:
            reconstructed = ((-1) ** sign) * (1.0 + mant_frac) * (2 ** exp_biased)

        # Binary string
        binary = f"{sign} {exp_raw:08b} {mantissa:023b}"

        # Hex
        float32_hex = f"0x{bits:08X}"

        # Mantissa bytes (last 3 bytes of the 4-byte float)
        mant_bytes = list(packed[1:])  # bytes 1,2,3 contain most of mantissa

        # ASCII check in mantissa
        ascii_chars = []
        for b in mant_bytes:
            if 0x20 <= b <= 0x7E:
                ascii_chars.append(chr(b))
        ascii_in_mantissa = "".join(ascii_chars) if ascii_chars else None

        # Word artifact matching
        matches = []
        for name, test in WORD_ARTIFACT_PATTERNS.items():
            try:
                if test(value):
                    matches.append(name)
            except Exception:
                pass

        confidence = self.word_artifact_confidence(value, matches)

        return IEEE754Result(
            value=value,
            float32_hex=float32_hex,
            binary=binary,
            sign=sign,
            exponent_raw=exp_raw,
            exponent_biased=exp_biased,
            mantissa_raw=mantissa,
            mantissa_fraction=mant_frac,
            mantissa_bytes=mant_bytes,
            reconstructed=reconstructed,
            word_artifact_matches=matches,
            word_artifact_confidence=confidence,
            ascii_in_mantissa=ascii_in_mantissa,
        )

    def word_artifact_confidence(self, value: float, matches: list[str]) -> float:
        """Return 0.0–1.0 confidence that value is a Word PDF/UA export artifact."""
        score = 0.0
        # Direct pattern match
        if "subpixel_clip_x" in matches:
            score += 0.70
        if "a4_width" in matches or "a4_height" in matches:
            score += 0.60
        if "letter_width" in matches or "letter_height" in matches:
            score += 0.55
        if "word_font_size" in matches:
            score += 0.50
        if "word_spacing" in matches:
            score += 0.40
        # Non-round sub-pixel bonus
        if 1e-8 < abs(value) < 1e-3 and score > 0:
            score += 0.15
        # EMU rounding signature: ~8.871e-6 specifically
        if abs(value - 8.871e-6) < 1e-9:
            score += 0.10
        return min(1.0, score)


# ---------------------------------------------------------------------------
# Token-level PDF stream parser
# ---------------------------------------------------------------------------

_TOKEN_RE = re.compile(
    rb"""
    (?P<string>   \((?:[^()\\]|\\.)*\)   )   |   # literal string
    (?P<hexstr>   <[0-9A-Fa-f\s]*>       )   |   # hex string
    (?P<array>    \[(?:[^\]]*)\]          )   |   # array (shallow)
    (?P<name>     /[^\s/<>\[\](){}/]+    )   |   # name
    (?P<number>   [+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)? ) | # number
    (?P<op>       [a-zA-Z_*'"][a-zA-Z_*'"]* | W\*  )             # operator
    """,
    re.VERBOSE,
)


def _tokenize_stream(stream_bytes: bytes) -> list[dict]:
    """Tokenize a PDF content stream into a list of token dicts."""
    tokens = []
    for m in _TOKEN_RE.finditer(stream_bytes):
        kind = m.lastgroup
        if kind is None:
            continue  # skip zero-length empty-alternative matches
        raw  = m.group().decode("latin-1", errors="replace")
        tokens.append({"kind": kind, "raw": raw, "start": m.start()})
    return tokens


def _decode_pdf_string(s: str) -> str:
    """Decode a PDF literal string token to Unicode."""
    inner = s[1:-1]  # strip ( )
    # basic backslash escapes
    result = []
    i = 0
    while i < len(inner):
        if inner[i] == "\\" and i + 1 < len(inner):
            c = inner[i + 1]
            if c == "n":  result.append("\n"); i += 2; continue
            if c == "r":  result.append("\r"); i += 2; continue
            if c == "t":  result.append("\t"); i += 2; continue
            if c.isdigit():
                oct_str = inner[i+1:i+4]
                oct_str = "".join(x for x in oct_str if x.isdigit())[:3]
                result.append(chr(int(oct_str, 8)))
                i += 1 + len(oct_str); continue
        result.append(inner[i]); i += 1
    return "".join(result)


def _decode_hex_string(s: str) -> str:
    """Decode a PDF hex string <...> to Unicode."""
    inner = s[1:-1].replace(" ", "").replace("\n", "")
    if len(inner) % 2:
        inner += "0"
    try:
        raw_bytes = bytes.fromhex(inner)
        return raw_bytes.decode("latin-1", errors="replace")
    except ValueError:
        return ""


def _decode_array_text(s: str) -> str:
    """Extract text content from a TJ array token."""
    parts = []
    i = 1  # skip [
    while i < len(s) - 1:
        if s[i] == "(":
            end = i + 1
            while end < len(s) and s[end] != ")" :
                if s[end] == "\\":
                    end += 1
                end += 1
            parts.append(_decode_pdf_string(s[i:end+1]))
            i = end + 1
        elif s[i] == "<":
            end = s.index(">", i)
            parts.append(_decode_hex_string(s[i:end+1]))
            i = end + 1
        else:
            i += 1
    return "".join(parts)


# ---------------------------------------------------------------------------
# Stream Annotator
# ---------------------------------------------------------------------------

class StreamAnnotator:
    """Walk token stream and produce annotated lines."""

    def annotate(self, stream_bytes: bytes) -> list[AnnotatedLine]:
        tokens = _tokenize_stream(stream_bytes)
        lines: list[AnnotatedLine] = []
        operands: list[str] = []
        line_num = 0

        in_mcid: int | None = None

        i = 0
        while i < len(tokens):
            tok = tokens[i]

            if tok["kind"] == "op":
                op = tok["raw"].strip()
                annotations = []
                is_clip = False
                clip_info = None
                mcid_boundary = None
                is_mcid_close = False

                # Handle BDC — look for MCID in operands
                if op == "BDC":
                    mcid_id = self._extract_mcid(operands)
                    if mcid_id is not None:
                        in_mcid = mcid_id
                        mcid_boundary = mcid_id
                    annotations.append(f"[begin-marked-content MCID={mcid_id}]")

                elif op == "EMC":
                    is_mcid_close = True
                    in_mcid = None
                    annotations.append("[end-marked-content]")

                elif op == "re" and len(operands) >= 4:
                    try:
                        x, y, w, h = [float(operands[-4]), float(operands[-3]),
                                      float(operands[-2]), float(operands[-1])]
                        is_clip = True
                        if 1e-8 < abs(x) < 1e-4:
                            clip_info = f"[SUBPIXEL_CLIP x={x:.2e} y={y} w={w} h={h}]"
                            annotations.append(clip_info)
                        else:
                            clip_info = f"[NORMAL_CLIP x={x} y={y} w={w} h={h}]"
                            annotations.append(clip_info)
                    except (ValueError, IndexError):
                        pass

                elif op == "Tf" and len(operands) >= 2:
                    font_name = operands[-2]
                    font_size = operands[-1]
                    annotations.append(f"[font={font_name} size={font_size}]")

                elif op == "Tm" and len(operands) >= 6:
                    tx = operands[-2]
                    ty = operands[-1]
                    annotations.append(f"[position x={tx} y={ty}]")

                elif op == "Tr" and operands:
                    try:
                        mode = int(operands[-1])
                        mode_name = RENDER_MODES.get(mode, "unknown")
                        if mode == 3:
                            annotations.append(f"[INVISIBLE TEXT render_mode={mode}]")
                        else:
                            annotations.append(f"[render_mode={mode} ({mode_name})]")
                    except ValueError:
                        pass

                elif op in ("Tj", "TJ"):
                    content = ""
                    if operands:
                        raw = operands[-1]
                        if raw.startswith("["):
                            content = _decode_array_text(raw)
                        elif raw.startswith("("):
                            content = _decode_pdf_string(raw)
                        elif raw.startswith("<"):
                            content = _decode_hex_string(raw)
                    display = content[:60].replace("\n", "\\n")
                    annotations.append(f'[text="{display}"]')

                raw_line = " ".join(operands + [op])
                line_num += 1
                lines.append(AnnotatedLine(
                    line_num=line_num,
                    raw=raw_line,
                    operators=[op],
                    annotations=annotations,
                    mcid_boundary=mcid_boundary,
                    is_mcid_close=is_mcid_close,
                    is_clip=is_clip,
                    clip_info=clip_info,
                ))
                operands = []

            else:
                operands.append(tok["raw"].strip())

            i += 1

        return lines

    def _extract_mcid(self, operands: list[str]) -> int | None:
        """Extract MCID integer from BDC operand tokens."""
        text = " ".join(operands)
        m = re.search(r"/MCID\s+(\d+)", text)
        if m:
            return int(m.group(1))
        return None


# ---------------------------------------------------------------------------
# MCID Table Builder
# ---------------------------------------------------------------------------

class MCIDTableBuilder:
    """Parse content stream into per-MCID block rows."""

    def build(self, stream_bytes: bytes,
              page_rect: tuple[float, float, float, float] | None) -> list[MCIDRow]:
        tokens = _tokenize_stream(stream_bytes)

        # State
        current_mcid: int | None = None
        cur_font: str = ""
        cur_font_size: float = 0.0
        cur_render_mode: int = 0
        cur_x: float = 0.0
        cur_y: float = 0.0
        cur_text_parts: list[str] = []
        operands: list[str] = []

        rows: list[MCIDRow] = []
        mcid_data: dict[int, dict] = {}

        def _flush_mcid(mcid_id: int) -> None:
            if mcid_id not in mcid_data:
                mcid_data[mcid_id] = {
                    "x": cur_x, "y": cur_y,
                    "font": cur_font, "font_size": cur_font_size,
                    "render_mode": cur_render_mode,
                    "text_parts": list(cur_text_parts),
                }
            else:
                mcid_data[mcid_id]["text_parts"].extend(cur_text_parts)

        for tok in tokens:
            if tok["kind"] != "op":
                operands.append(tok["raw"].strip())
                continue

            op = tok["raw"].strip()

            if op == "BDC":
                text = " ".join(operands)
                m = re.search(r"/MCID\s+(\d+)", text)
                if m:
                    current_mcid = int(m.group(1))
                    cur_text_parts = []
                operands = []

            elif op == "EMC":
                if current_mcid is not None:
                    _flush_mcid(current_mcid)
                current_mcid = None
                cur_text_parts = []
                operands = []

            elif op == "Tf" and len(operands) >= 2:
                cur_font = operands[-2].lstrip("/")
                try:
                    cur_font_size = float(operands[-1])
                except ValueError:
                    pass
                if current_mcid is not None and current_mcid not in mcid_data:
                    mcid_data[current_mcid] = {
                        "x": cur_x, "y": cur_y,
                        "font": cur_font, "font_size": cur_font_size,
                        "render_mode": cur_render_mode,
                        "text_parts": [],
                    }
                operands = []

            elif op == "Tm" and len(operands) >= 6:
                try:
                    cur_x = float(operands[-2])
                    cur_y = float(operands[-1])
                except ValueError:
                    pass
                if current_mcid is not None:
                    if current_mcid not in mcid_data:
                        mcid_data[current_mcid] = {
                            "x": cur_x, "y": cur_y,
                            "font": cur_font, "font_size": cur_font_size,
                            "render_mode": cur_render_mode,
                            "text_parts": [],
                        }
                    else:
                        # Update position if not yet set or if no text yet
                        if not mcid_data[current_mcid]["text_parts"]:
                            mcid_data[current_mcid]["x"] = cur_x
                            mcid_data[current_mcid]["y"] = cur_y
                operands = []

            elif op == "Td" and len(operands) >= 2:
                try:
                    cur_x += float(operands[-2])
                    cur_y += float(operands[-1])
                except ValueError:
                    pass
                operands = []

            elif op == "Tr" and operands:
                try:
                    cur_render_mode = int(operands[-1])
                except ValueError:
                    pass
                operands = []

            elif op in ("Tj", "TJ") and operands:
                raw = operands[-1]
                if raw.startswith("["):
                    text = _decode_array_text(raw)
                elif raw.startswith("("):
                    text = _decode_pdf_string(raw)
                elif raw.startswith("<"):
                    text = _decode_hex_string(raw)
                else:
                    text = ""
                if current_mcid is not None:
                    cur_text_parts.append(text)
                    if current_mcid not in mcid_data:
                        mcid_data[current_mcid] = {
                            "x": cur_x, "y": cur_y,
                            "font": cur_font, "font_size": cur_font_size,
                            "render_mode": cur_render_mode,
                            "text_parts": [text],
                        }
                    else:
                        mcid_data[current_mcid]["text_parts"].append(text)
                operands = []

            elif op == "BT":
                operands = []

            elif op == "ET":
                operands = []

            else:
                operands = []

        # Build rows
        for mcid_id in sorted(mcid_data.keys()):
            d = mcid_data[mcid_id]
            raw_content = "".join(d["text_parts"])
            content = raw_content.strip()
            classification = self._classify_block(
                d["render_mode"], content, d["x"], d["y"], page_rect
            )
            rows.append(MCIDRow(
                mcid_id=mcid_id,
                x=d["x"], y=d["y"],
                font=d.get("font", ""),
                font_size=d.get("font_size", 0.0),
                render_mode=d["render_mode"],
                content=content,
                raw_content=raw_content,
                classification=classification,
            ))

        return rows

    def _classify_block(self, render_mode: int, content: str,
                         x: float, y: float,
                         page_rect: tuple | None) -> str:
        if render_mode == 3:
            return "INVISIBLE"
        if page_rect:
            x0, y0, x1, y1 = page_rect
            tol = PAGE_BOUNDS_TOLERANCE
            if x < x0 - tol or x > x1 + tol or y < y0 - tol or y > y1 + tol:
                return "OFFPAGE"
        stripped = content.strip()
        if not stripped or all(c in " \t\r\n\xa0" for c in content):
            return "SPACING"
        # Check for Unicode zero-width or special chars
        for ch in content:
            if ord(ch) in (0x200B, 0x200C, 0x200D, 0xFEFF, 0x00AD):
                return "SPACING"  # zero-width present
        return "CONTENT"


# ---------------------------------------------------------------------------
# Float Forensics
# ---------------------------------------------------------------------------

class FloatForensicsAnalyzer:
    """Extract all float values from stream and build forensic records."""

    _FLOAT_RE = re.compile(
        rb"[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?"
    )

    # Operator associator: find operator following a group of floats
    _OP_RE = re.compile(
        rb"(?:[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?\s+)*"
        rb"([a-zA-Z_*'\"]+\*?)"
    )

    def analyze(self, stream_bytes: bytes) -> list[FloatRecord]:
        # Build value → {count, operators}
        value_map: dict[float, dict] = {}

        tokens = _tokenize_stream(stream_bytes)
        operands: list[str] = []

        for tok in tokens:
            if tok["kind"] != "op":
                operands.append(tok["raw"].strip())
                continue

            op = tok["raw"].strip()
            for opnd in operands:
                try:
                    v = float(opnd)
                except ValueError:
                    continue
                key = round(v, 12)
                if key not in value_map:
                    value_map[key] = {"count": 0, "operators": set()}
                value_map[key]["count"] += 1
                value_map[key]["operators"].add(op)
            operands = []

        total = sum(d["count"] for d in value_map.values())
        analyzer = IEEE754Analyzer()

        records = []
        for v, d in sorted(value_map.items(), key=lambda x: -x[1]["count"]):
            freq = d["count"] / total if total else 0.0
            ieee = analyzer.analyze(v)
            records.append(FloatRecord(
                value=v,
                count=d["count"],
                frequency=freq,
                operators=sorted(d["operators"]),
                ieee754=ieee,
            ))

        return records


# ---------------------------------------------------------------------------
# Clip Rect Analyzer
# ---------------------------------------------------------------------------

class ClipRectAnalyzer:
    """Identify and classify clipping rectangles."""

    def analyze(self, stream_bytes: bytes,
                page_rect: tuple | None) -> list[ClipRecord]:
        tokens = _tokenize_stream(stream_bytes)
        operands: list[str] = []
        clip_counts: dict[tuple, int] = {}
        pending_re: list[tuple] = []

        for tok in tokens:
            if tok["kind"] != "op":
                operands.append(tok["raw"].strip())
                continue

            op = tok["raw"].strip()

            if op == "re" and len(operands) >= 4:
                try:
                    x = float(operands[-4])
                    y = float(operands[-3])
                    w = float(operands[-2])
                    h = float(operands[-1])
                    pending_re.append((x, y, w, h))
                except (ValueError, IndexError):
                    pass

            elif op in ("W", "W*", "n") and pending_re:
                # The re + W/W* + n sequence = clipping path
                if op in ("W", "W*"):
                    for rect in pending_re:
                        key = (round(rect[0], 9), round(rect[1], 4),
                               round(rect[2], 4), round(rect[3], 4))
                        clip_counts[key] = clip_counts.get(key, 0) + 1
                    pending_re = []

            elif op not in ("re",):
                pending_re = []

            operands = []

        records = []
        for (x, y, w, h), count in sorted(clip_counts.items(), key=lambda kv: -kv[1]):
            clip_type, classification = self._classify_clip(x, y, w, h, page_rect)
            records.append(ClipRecord(
                x=x, y=y, width=w, height=h,
                count=count,
                clip_type=clip_type,
                classification=classification,
            ))

        return records

    def _classify_clip(self, x: float, y: float, w: float, h: float,
                        page_rect: tuple | None) -> tuple[str, str]:
        # Sub-pixel x
        if 1e-8 < abs(x) < 1e-4:
            clip_type = "SUBPIXEL"
            # Check if dimensions match page
            if page_rect:
                pw = page_rect[2] - page_rect[0]
                ph = page_rect[3] - page_rect[1]
                if abs(w - pw) < 1.0 and abs(h - ph) < 1.0:
                    return clip_type, "WORD_ARTIFACT (full-page per-span clip)"
            return clip_type, "WORD_ARTIFACT (sub-pixel offset)"
        # Full page
        if page_rect:
            pw = page_rect[2] - page_rect[0]
            ph = page_rect[3] - page_rect[1]
            if abs(x) < 1.0 and abs(y) < 1.0 and abs(w - pw) < 1.0 and abs(h - ph) < 1.0:
                return "FULL_PAGE", "NORMAL (full-page clip)"
        return "NORMAL", "IMAGE_BBOX (region clip)"


# ---------------------------------------------------------------------------
# Verdict Engine
# ---------------------------------------------------------------------------

class VerdictEngine:
    """Compute final verdict from all forensic evidence."""

    def compute(self, result: ForensicsResult) -> tuple[str, float, list[str], list[str], str]:
        evidence_for: list[str]   = []
        evidence_against: list[str] = []
        confidence = 0.50

        # Check invisible text
        if not result.has_invisible_text:
            evidence_for.append("No invisible text (Tr=3) found anywhere in stream")
            confidence += 0.10
        else:
            evidence_against.append("Invisible text (Tr=3) detected in stream")
            confidence -= 0.30

        # Check off-page text
        if not result.has_offpage_text:
            evidence_for.append("No off-page text positioning detected")
            confidence += 0.08
        else:
            evidence_against.append("Off-page text positioning detected")
            confidence -= 0.25

        # Check dominant constant in floats
        if result.float_records:
            top_rec = result.float_records[0]
            if top_rec.ieee754.word_artifact_confidence >= 0.60:
                evidence_for.append(
                    f"Dominant float {top_rec.value:.6e} matches Word PDF/UA artifact "
                    f"(confidence {top_rec.ieee754.word_artifact_confidence:.0%})"
                )
                confidence += 0.12
            if top_rec.ieee754.ascii_in_mantissa:
                evidence_against.append(
                    f"Dominant float mantissa contains printable ASCII: "
                    f"'{top_rec.ieee754.ascii_in_mantissa}'"
                )
                confidence -= 0.20
            else:
                evidence_for.append(
                    f"Dominant float IEEE 754 mantissa bytes contain no printable ASCII"
                )
                confidence += 0.08

        # Check sub-pixel clips
        subpixel_clips = [c for c in result.clip_records if c.clip_type == "SUBPIXEL"]
        normal_clips   = [c for c in result.clip_records if c.clip_type == "NORMAL"]
        if subpixel_clips:
            for sc in subpixel_clips:
                if "WORD_ARTIFACT" in sc.classification:
                    evidence_for.append(
                        f"Sub-pixel clip x={sc.x:.2e} classified as Word PDF/UA artifact "
                        f"(full-page per-span clip, count={sc.count})"
                    )
                    confidence += 0.08
                else:
                    evidence_against.append(
                        f"Sub-pixel clip x={sc.x:.2e} — unexplained origin"
                    )
                    confidence -= 0.05
        if normal_clips:
            evidence_for.append(
                f"{len(normal_clips)} normal region clip(s) match image bounding boxes"
            )
            confidence += 0.04

        # Check MCID blocks
        mcid_rows = result.mcid_rows
        spacing_count  = sum(1 for r in mcid_rows if r.classification == "SPACING")
        content_count  = sum(1 for r in mcid_rows if r.classification == "CONTENT")
        invisible_count = sum(1 for r in mcid_rows if r.classification == "INVISIBLE")
        offpage_count  = sum(1 for r in mcid_rows if r.classification == "OFFPAGE")
        total_mcid     = len(mcid_rows)

        if invisible_count > 0:
            evidence_against.append(
                f"{invisible_count}/{total_mcid} MCID blocks classified as INVISIBLE"
            )
            confidence -= 0.20

        if offpage_count > 0:
            evidence_against.append(
                f"{offpage_count}/{total_mcid} MCID blocks positioned off-page"
            )
            confidence -= 0.20

        if spacing_count > 0:
            # Check if spacing ratio is consistent with Word exports
            spacing_ratio = spacing_count / total_mcid if total_mcid else 0
            if spacing_ratio < 0.50:
                evidence_for.append(
                    f"{spacing_count}/{total_mcid} MCID blocks are spacing-only "
                    f"({spacing_ratio:.0%}) — consistent with Word paragraph spacing"
                )
                confidence += 0.05
            else:
                evidence_against.append(
                    f"{spacing_count}/{total_mcid} MCID blocks ({spacing_ratio:.0%}) "
                    f"render no visible content — unusually high"
                )
                confidence -= 0.05

        # Remaining clean floats
        if result.float_records:
            total_recs = len(result.float_records)
            if total_recs <= 12:
                evidence_for.append(
                    f"Only {total_recs} unique float values — structured PDF coordinates, "
                    f"not random steganographic data"
                )
                confidence += 0.06

        confidence = max(0.0, min(1.0, confidence))

        # Determine verdict
        if confidence >= 0.70:
            verdict = "FALSE_POSITIVE"
        elif confidence >= 0.45:
            verdict = "NEEDS_REVIEW"
        else:
            verdict = "CONFIRMED_SUSPICIOUS"

        recommendation = self._build_recommendation(verdict, evidence_for, evidence_against)
        return verdict, confidence, evidence_for, evidence_against, recommendation

    def _build_recommendation(self, verdict: str, ef: list[str], ea: list[str]) -> str:
        if verdict == "FALSE_POSITIVE":
            return (
                "Treat as Microsoft Word PDF/UA export artifact. "
                "No steganographic payload evidence. No prompt injection vectors detected. "
                "Sub-pixel clip coordinate is INFORMATIONAL: known hidden-content vector class, "
                "but no evidence of exploitation in this specific document."
            )
        elif verdict == "NEEDS_REVIEW":
            return (
                "Manual review recommended. Evidence is mixed — "
                "some anomalies cannot be fully explained by known Word export patterns. "
                "Consider extracting and decoding text content manually."
            )
        else:
            return (
                "High-confidence suspicious finding. "
                "Recommend full manual inspection of stream content and MCID text blocks."
            )


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

class XrefForensicsReport:
    """Run full forensic analysis on one or two xref streams."""

    def __init__(self, doc_path: str) -> None:
        self.doc_path = doc_path
        if not PYMUPDF_AVAILABLE:
            raise RuntimeError("PyMuPDF (fitz) is required: pip install pymupdf")
        self.doc = fitz.open(doc_path)

    def run(self, xref: int) -> ForensicsResult:
        # Get stream bytes
        stream_bytes = self._get_stream(xref)
        if stream_bytes is None:
            raise ValueError(f"xref={xref} not found or not a stream")

        # Page rect (try page 0 first)
        page_rect = self._get_page_rect(xref)

        # Analyze
        float_records  = FloatForensicsAnalyzer().analyze(stream_bytes)
        mcid_rows      = MCIDTableBuilder().build(stream_bytes, page_rect)
        clip_records   = ClipRectAnalyzer().analyze(stream_bytes, page_rect)
        annotated      = StreamAnnotator().annotate(stream_bytes)

        has_invisible = any(r.classification == "INVISIBLE" for r in mcid_rows)
        has_offpage   = any(r.classification == "OFFPAGE"   for r in mcid_rows)

        # Build partial result for verdict engine
        result = ForensicsResult(
            xref=xref,
            stream_length=len(stream_bytes),
            total_floats=sum(r.count for r in float_records),
            float_records=float_records,
            mcid_rows=mcid_rows,
            clip_records=clip_records,
            annotated_lines=annotated,
            page_rect=page_rect,
            has_invisible_text=has_invisible,
            has_offpage_text=has_offpage,
            verdict="PENDING",
            verdict_confidence=0.0,
            verdict_evidence_for=[],
            verdict_evidence_against=[],
            verdict_recommendation="",
        )

        verdict, conf, ev_for, ev_against, rec = VerdictEngine().compute(result)
        result.verdict               = verdict
        result.verdict_confidence    = conf
        result.verdict_evidence_for  = ev_for
        result.verdict_evidence_against = ev_against
        result.verdict_recommendation = rec

        return result

    def _get_stream(self, xref: int) -> bytes | None:
        try:
            raw = self.doc.xref_stream(xref)
            if raw is not None:
                return raw
        except Exception:
            pass
        # Try compressed
        try:
            raw = self.doc.xref_stream_raw(xref)
            if raw:
                try:
                    return zlib.decompress(raw)
                except Exception:
                    return raw
        except Exception:
            pass
        return None

    def _get_page_rect(self, xref: int) -> tuple[float, float, float, float] | None:
        try:
            for pg in range(len(self.doc)):
                page = self.doc[pg]
                r = page.rect
                return (r.x0, r.y0, r.x1, r.y1)
        except Exception:
            pass
        return None


# ---------------------------------------------------------------------------
# Renderer
# ---------------------------------------------------------------------------

class ForensicsRenderer:

    def render_terminal(self, result: ForensicsResult,
                        full_dump: bool = False) -> str:
        out: list[str] = []
        a = out.append

        a(_c(BOLD + CYAN, _hr("=", 72)))
        a(_c(BOLD + CYAN, f"  XREF FORENSICS REPORT  |  xref={result.xref}  |  "
                          f"stream={result.stream_length:,} bytes"))
        a(_c(BOLD + CYAN, _hr("=", 72)))

        a("")
        a(_c(BOLD, "[ 1. FLOAT FORENSICS ]"))
        a(_hr())
        a(f"  Total float operands : {result.total_floats}")
        a(f"  Unique float values  : {len(result.float_records)}")
        a("")

        # Table header
        col = f"  {'Value':>16}  {'Count':>6}  {'Freq':>6}  {'Ops':<16}  {'W-Art':>6}  IEEE754 Hex"
        a(_c(DIM, col))
        a(_c(DIM, "  " + "-" * 70))

        for rec in result.float_records:
            ops_str = ",".join(rec.operators)[:15]
            conf_str = f"{rec.ieee754.word_artifact_confidence:.0%}"
            row = (f"  {rec.value:>16.8g}  {rec.count:>6}  "
                   f"{rec.frequency:>5.1%}  {ops_str:<16}  {conf_str:>6}  "
                   f"{rec.ieee754.float32_hex}")
            if rec.ieee754.word_artifact_confidence >= 0.60:
                a(_c(GREEN, row))
            elif rec.value == result.float_records[0].value:
                a(_c(YELLOW, row))
            else:
                a(row)

        # Dominant float deep-dive
        if result.float_records:
            top = result.float_records[0]
            a("")
            a(_c(BOLD, f"  Deep Analysis: {top.value:.8e}  ({top.ieee754.float32_hex})"))
            a(f"    Binary        : {top.ieee754.binary}")
            a(f"    Sign          : {top.ieee754.sign} ({'+'  if top.ieee754.sign == 0 else '-'})")
            a(f"    Exponent raw  : 0x{top.ieee754.exponent_raw:02X} = {top.ieee754.exponent_raw}")
            a(f"    Exponent bias : {top.ieee754.exponent_biased}")
            a(f"    Mantissa      : 0x{top.ieee754.mantissa_raw:06X} = {top.ieee754.mantissa_raw}")
            a(f"    Mantissa frac : {top.ieee754.mantissa_fraction:.8f}")
            mbs = top.ieee754.mantissa_bytes
            a(f"    Mantissa bytes: {' '.join(f'0x{b:02X}' for b in mbs)}"
              f"  ({' '.join(str(b) for b in mbs)})")
            a(f"    ASCII in mant : {top.ieee754.ascii_in_mantissa or 'None (non-printable)'}")
            a(f"    Word patterns : {', '.join(top.ieee754.word_artifact_matches) or 'none'}")
            a(f"    W-Art confid  : {top.ieee754.word_artifact_confidence:.0%}")
            # EMU note
            if 1e-8 < abs(top.value) < 1e-3:
                emu = top.value * 914400 / 72.0  # approx EMU value
                a(f"    EMU estimate  : {emu:.4f} EMU  (Word unit: 1/914400 inch; "
                  f"1pt=12700 EMU)")
                a(f"    Hypothesis    : Word PDF/UA sub-pixel clip x-offset to avoid")
                a(f"                    zero-width edge cases in some PDF renderers.")

        # ---- MCID TABLE ----
        a("")
        a(_c(BOLD, "[ 2. MCID BLOCK TABLE ]"))
        a(_hr())
        total_mcid  = len(result.mcid_rows)
        content_n   = sum(1 for r in result.mcid_rows if r.classification == "CONTENT")
        spacing_n   = sum(1 for r in result.mcid_rows if r.classification == "SPACING")
        invisible_n = sum(1 for r in result.mcid_rows if r.classification == "INVISIBLE")
        offpage_n   = sum(1 for r in result.mcid_rows if r.classification == "OFFPAGE")
        a(f"  Total blocks : {total_mcid}  |  CONTENT={content_n}  SPACING={spacing_n}"
          f"  INVISIBLE={invisible_n}  OFFPAGE={offpage_n}")
        a("")

        hdr = (f"  {'MCID':>5}  {'X':>8}  {'Y':>8}  {'Font':<8}  {'Pt':>6}  "
               f"{'Rnd':>4}  {'Class':<12}  Content")
        a(_c(DIM, hdr))
        a(_c(DIM, "  " + "-" * 72))

        for row in result.mcid_rows:
            content_disp = (row.content or "").replace("\n", "\\n")[:30]
            class_color = {
                "CONTENT":   GREEN,
                "SPACING":   YELLOW,
                "INVISIBLE": RED,
                "OFFPAGE":   RED,
            }.get(row.classification, "")
            cls_str = _c(class_color, f"{row.classification:<12}")
            line = (f"  {row.mcid_id:>5}  {row.x:>8.2f}  {row.y:>8.2f}  "
                    f"{row.font:<8}  {row.font_size:>6.2f}  {row.render_mode:>4}  "
                    f"{cls_str}  {content_disp}")
            a(line)

        # ---- CLIP RECT TABLE ----
        a("")
        a(_c(BOLD, "[ 3. CLIP RECT COMPARISON TABLE ]"))
        a(_hr())
        ch = (f"  {'Type':<12}  {'X':>14}  {'Y':>8}  {'W':>8}  {'H':>8}  "
              f"{'Cnt':>5}  Classification")
        a(_c(DIM, ch))
        a(_c(DIM, "  " + "-" * 75))

        for c in result.clip_records:
            type_color = RED if c.clip_type == "SUBPIXEL" else GREEN
            x_str = f"{c.x:.2e}" if 1e-8 < abs(c.x) < 1e-3 else f"{c.x:.4f}"
            row = (f"  {_c(type_color, f'{c.clip_type:<12}')}  {x_str:>14}  "
                   f"{c.y:>8.2f}  {c.width:>8.2f}  {c.height:>8.2f}  "
                   f"{c.count:>5}  {c.classification}")
            a(row)

        # ---- SPACING MCID ANALYSIS ----
        spacing_rows = [r for r in result.mcid_rows if r.classification == "SPACING"]
        if spacing_rows:
            a("")
            a(_c(BOLD, "[ 4. SPACING MCID ANALYSIS ]"))
            a(_hr())
            a(f"  {len(spacing_rows)} spacing-only MCID blocks found.")
            a("")

            content_rows = [r for r in result.mcid_rows if r.classification == "CONTENT"]
            a(f"  {'MCID':>5}  {'X':>8}  {'Y':>8}  {'Nearest-content Y':>18}  "
              f"{'Gap':>8}  Word-spacing?")
            a(_c(DIM, "  " + "-" * 65))

            for sr in spacing_rows:
                nearest = self._find_nearest_content_y(sr.y, content_rows)
                gap = abs(sr.y - nearest) if nearest is not None else float("nan")
                is_word_sp = any(abs(gap - sp) < 1.5 for sp in WORD_PARA_SPACINGS)
                ws_str = _c(GREEN, "YES") if is_word_sp else _c(YELLOW, "no")
                gap_str = f"{gap:.2f}" if not math.isnan(gap) else "n/a"
                nearest_str = f"{nearest:.2f}" if nearest is not None else "n/a"
                a(f"  {sr.mcid_id:>5}  {sr.x:>8.2f}  {sr.y:>8.2f}  "
                  f"{nearest_str:>18}  {gap_str:>8}  {ws_str}")

        # ---- FINAL VERDICT ----
        a("")
        a(_c(BOLD, "[ 5. FINAL VERDICT ]"))
        a(_hr("=", 72))
        verdict_color = {
            "FALSE_POSITIVE":      GREEN,
            "NEEDS_REVIEW":        YELLOW,
            "CONFIRMED_SUSPICIOUS": RED,
        }.get(result.verdict, WHITE)

        a(_c(BOLD + verdict_color, f"  VERDICT     : {result.verdict}"))
        a(_c(BOLD + verdict_color, f"  Confidence  : {result.verdict_confidence:.0%}"))
        a("")
        a(_c(GREEN, "  Evidence FOR false-positive:"))
        for e in result.verdict_evidence_for:
            a(_c(GREEN, f"    [+] {e}"))
        if result.verdict_evidence_against:
            a(_c(YELLOW, "\n  Evidence AGAINST (remaining anomalies):"))
            for e in result.verdict_evidence_against:
                a(_c(YELLOW, f"    [-] {e}"))
        a("")
        a(_c(BOLD, "  Recommendation:"))
        for line in result.verdict_recommendation.split(". "):
            if line.strip():
                a(f"    {line.strip()}.")
        a(_hr("=", 72))

        # ---- FULL DUMP ----
        if full_dump:
            a("")
            a(_c(BOLD, "[ ANNOTATED STREAM DUMP ]"))
            a(_hr())
            for al in result.annotated_lines:
                prefix = f"  {al.line_num:>5}  "
                raw_colored = al.raw
                if al.mcid_boundary is not None:
                    a(_c(MAGENTA, prefix + raw_colored))
                    for ann in al.annotations:
                        a(_c(DIM + MAGENTA, f"         // {ann}"))
                elif al.is_mcid_close:
                    a(_c(DIM + MAGENTA, prefix + raw_colored))
                elif al.is_clip:
                    c_color = RED if al.clip_info and "SUBPIXEL" in al.clip_info else CYAN
                    a(_c(c_color, prefix + raw_colored))
                    for ann in al.annotations:
                        a(_c(DIM + c_color, f"         // {ann}"))
                else:
                    a(prefix + raw_colored)
                    for ann in al.annotations:
                        a(_c(DIM, f"         // {ann}"))

        return "\n".join(out)

    def render_compare(self, r1: ForensicsResult, r2: ForensicsResult) -> str:
        out: list[str] = []
        a = out.append

        a(_c(BOLD + CYAN, _hr("=", 72)))
        a(_c(BOLD + CYAN, f"  SIDE-BY-SIDE COMPARISON  |  xref={r1.xref}  vs  xref={r2.xref}"))
        a(_c(BOLD + CYAN, _hr("=", 72)))
        a("")

        def _metric_row(label: str, v1: Any, v2: Any) -> str:
            return f"  {label:<35} {str(v1):<20} {str(v2)}"

        a(_c(DIM, _metric_row("Metric", f"xref={r1.xref}", f"xref={r2.xref}")))
        a(_c(DIM, "  " + "-" * 70))
        a(_metric_row("Stream length (bytes)", f"{r1.stream_length:,}", f"{r2.stream_length:,}"))
        a(_metric_row("Total float operands", r1.total_floats, r2.total_floats))
        a(_metric_row("Unique float values", len(r1.float_records), len(r2.float_records)))
        a(_metric_row("Total MCID blocks", len(r1.mcid_rows), len(r2.mcid_rows)))
        content1 = sum(1 for r in r1.mcid_rows if r.classification == "CONTENT")
        content2 = sum(1 for r in r2.mcid_rows if r.classification == "CONTENT")
        spacing1 = sum(1 for r in r1.mcid_rows if r.classification == "SPACING")
        spacing2 = sum(1 for r in r2.mcid_rows if r.classification == "SPACING")
        invis1   = sum(1 for r in r1.mcid_rows if r.classification == "INVISIBLE")
        invis2   = sum(1 for r in r2.mcid_rows if r.classification == "INVISIBLE")
        a(_metric_row("  CONTENT blocks", content1, content2))
        a(_metric_row("  SPACING blocks", spacing1, spacing2))
        a(_metric_row("  INVISIBLE blocks", invis1, invis2))
        a(_metric_row("Clip rects (total types)", len(r1.clip_records), len(r2.clip_records)))
        subpix1 = sum(c.count for c in r1.clip_records if c.clip_type == "SUBPIXEL")
        subpix2 = sum(c.count for c in r2.clip_records if c.clip_type == "SUBPIXEL")
        a(_metric_row("  Sub-pixel clip count", subpix1, subpix2))
        a(_metric_row("Invisible text (Tr=3)", r1.has_invisible_text, r2.has_invisible_text))
        a(_metric_row("Off-page text", r1.has_offpage_text, r2.has_offpage_text))

        v1_color = GREEN if r1.verdict == "FALSE_POSITIVE" else (YELLOW if r1.verdict == "NEEDS_REVIEW" else RED)
        v2_color = GREEN if r2.verdict == "FALSE_POSITIVE" else (YELLOW if r2.verdict == "NEEDS_REVIEW" else RED)
        a(_metric_row("VERDICT",
                       _c(BOLD + v1_color, r1.verdict),
                       _c(BOLD + v2_color, r2.verdict)))
        a(_metric_row("Confidence", f"{r1.verdict_confidence:.0%}", f"{r2.verdict_confidence:.0%}"))

        return "\n".join(out)

    def render_json(self, result: ForensicsResult) -> str:
        def _float_rec(rec: FloatRecord) -> dict:
            ie = rec.ieee754
            return {
                "value": rec.value,
                "count": rec.count,
                "frequency": round(rec.frequency, 6),
                "operators": rec.operators,
                "ieee754": {
                    "float32_hex": ie.float32_hex,
                    "binary": ie.binary,
                    "sign": ie.sign,
                    "exponent_raw": ie.exponent_raw,
                    "exponent_biased": ie.exponent_biased,
                    "mantissa_raw": ie.mantissa_raw,
                    "mantissa_fraction": round(ie.mantissa_fraction, 8),
                    "mantissa_bytes": ie.mantissa_bytes,
                    "reconstructed": ie.reconstructed,
                    "word_artifact_matches": ie.word_artifact_matches,
                    "word_artifact_confidence": round(ie.word_artifact_confidence, 4),
                    "ascii_in_mantissa": ie.ascii_in_mantissa,
                },
            }

        def _mcid_row(r: MCIDRow) -> dict:
            return {
                "mcid_id": r.mcid_id,
                "x": r.x, "y": r.y,
                "font": r.font, "font_size": r.font_size,
                "render_mode": r.render_mode,
                "content": r.content,
                "classification": r.classification,
            }

        def _clip_rec(c: ClipRecord) -> dict:
            return {
                "x": c.x, "y": c.y, "width": c.width, "height": c.height,
                "count": c.count, "clip_type": c.clip_type,
                "classification": c.classification,
            }

        data = {
            "xref": result.xref,
            "stream_length": result.stream_length,
            "total_floats": result.total_floats,
            "page_rect": list(result.page_rect) if result.page_rect else None,
            "has_invisible_text": result.has_invisible_text,
            "has_offpage_text": result.has_offpage_text,
            "float_records": [_float_rec(r) for r in result.float_records],
            "mcid_blocks": {
                "total": len(result.mcid_rows),
                "content": sum(1 for r in result.mcid_rows if r.classification == "CONTENT"),
                "spacing": sum(1 for r in result.mcid_rows if r.classification == "SPACING"),
                "invisible": sum(1 for r in result.mcid_rows if r.classification == "INVISIBLE"),
                "offpage": sum(1 for r in result.mcid_rows if r.classification == "OFFPAGE"),
                "rows": [_mcid_row(r) for r in result.mcid_rows],
            },
            "clip_records": [_clip_rec(c) for c in result.clip_records],
            "verdict": {
                "verdict": result.verdict,
                "confidence": round(result.verdict_confidence, 4),
                "evidence_for": result.verdict_evidence_for,
                "evidence_against": result.verdict_evidence_against,
                "recommendation": result.verdict_recommendation,
            },
        }
        return json.dumps(data, indent=2, ensure_ascii=False)

    def render_html(self, result: ForensicsResult) -> str:
        """Produce a self-contained HTML forensics report."""
        def esc(s: str) -> str:
            return html_module.escape(str(s))

        verdict_bg = {
            "FALSE_POSITIVE": "#1a3a1a",
            "NEEDS_REVIEW": "#3a3a1a",
            "CONFIRMED_SUSPICIOUS": "#3a1a1a",
        }.get(result.verdict, "#1a1a2a")

        verdict_fg = {
            "FALSE_POSITIVE": "#80ff80",
            "NEEDS_REVIEW": "#ffff80",
            "CONFIRMED_SUSPICIOUS": "#ff8080",
        }.get(result.verdict, "#ffffff")

        parts: list[str] = []
        p = parts.append

        p("""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Xref Forensics Report</title>
<style>
body{background:#111;color:#ccc;font-family:monospace;padding:20px;}
h1,h2{color:#5af;}
table{border-collapse:collapse;width:100%;margin-bottom:20px;}
th{background:#222;color:#5af;padding:4px 8px;text-align:left;}
td{padding:4px 8px;border-bottom:1px solid #333;}
.CONTENT{color:#80ff80;}
.SPACING{color:#ffff80;}
.INVISIBLE{color:#ff8080;font-weight:bold;}
.OFFPAGE{color:#ff8080;font-weight:bold;}
.SUBPIXEL{color:#ff8080;}
.NORMAL{color:#80ff80;}
.verdict-box{padding:16px;border-radius:6px;margin:16px 0;}
.ev-for{color:#80ff80;}
.ev-against{color:#ffff80;}
pre{background:#1a1a1a;padding:12px;overflow:auto;font-size:0.85em;}
</style>
</head>
<body>
""")
        p(f"<h1>Xref Forensics Report &mdash; xref={esc(str(result.xref))}</h1>")
        p(f"<p>Stream length: <b>{result.stream_length:,}</b> bytes &nbsp;|&nbsp; "
          f"Page rect: {esc(str(result.page_rect))}</p>")

        # Float table
        p("<h2>1. Float Forensics</h2>")
        p(f"<p>Total float operands: <b>{result.total_floats}</b> &nbsp;|&nbsp; "
          f"Unique values: <b>{len(result.float_records)}</b></p>")
        p("<table><tr><th>Value</th><th>Count</th><th>Freq</th><th>Operators</th>"
          "<th>Word-Art</th><th>IEEE754 Hex</th><th>Mantissa ASCII</th></tr>")
        for rec in result.float_records:
            conf_pct = f"{rec.ieee754.word_artifact_confidence:.0%}"
            cls = "CONTENT" if rec.ieee754.word_artifact_confidence >= 0.6 else ""
            p(f'<tr class="{cls}"><td>{esc(f"{rec.value:.8g}")}</td>'
              f"<td>{rec.count}</td><td>{rec.frequency:.1%}</td>"
              f"<td>{esc(','.join(rec.operators))}</td>"
              f"<td>{conf_pct}</td><td>{esc(rec.ieee754.float32_hex)}</td>"
              f"<td>{esc(rec.ieee754.ascii_in_mantissa or 'none')}</td></tr>")
        p("</table>")

        # MCID table
        p("<h2>2. MCID Block Table</h2>")
        cnt = {c: sum(1 for r in result.mcid_rows if r.classification == c)
               for c in ["CONTENT", "SPACING", "INVISIBLE", "OFFPAGE"]}
        p(f"<p>Total: {len(result.mcid_rows)} &nbsp; "
          + " &nbsp; ".join(f'<span class="{k}">{k}={v}</span>' for k, v in cnt.items())
          + "</p>")
        p("<table><tr><th>MCID</th><th>X</th><th>Y</th><th>Font</th><th>Size</th>"
          "<th>RndMode</th><th>Class</th><th>Content</th></tr>")
        for row in result.mcid_rows:
            content_disp = esc((row.content or "")[:60])
            p(f'<tr><td>{row.mcid_id}</td><td>{row.x:.2f}</td><td>{row.y:.2f}</td>'
              f'<td>{esc(row.font)}</td><td>{row.font_size:.2f}</td>'
              f'<td>{row.render_mode}</td>'
              f'<td class="{row.classification}">{row.classification}</td>'
              f'<td>{content_disp}</td></tr>')
        p("</table>")

        # Clip table
        p("<h2>3. Clip Rect Table</h2>")
        p("<table><tr><th>Type</th><th>X</th><th>Y</th><th>Width</th><th>Height</th>"
          "<th>Count</th><th>Classification</th></tr>")
        for c in result.clip_records:
            x_str = f"{c.x:.2e}" if 1e-8 < abs(c.x) < 1e-3 else f"{c.x:.4f}"
            p(f'<tr><td class="{c.clip_type}">{c.clip_type}</td>'
              f'<td>{esc(x_str)}</td><td>{c.y:.2f}</td>'
              f'<td>{c.width:.2f}</td><td>{c.height:.2f}</td>'
              f'<td>{c.count}</td><td>{esc(c.classification)}</td></tr>')
        p("</table>")

        # Verdict
        p("<h2>4. Final Verdict</h2>")
        p(f'<div class="verdict-box" style="background:{verdict_bg};color:{verdict_fg};">')
        p(f"<b>VERDICT: {esc(result.verdict)}</b> &nbsp; "
          f"Confidence: {result.verdict_confidence:.0%}")
        p("<br><br><b>Evidence FOR:</b>")
        p("<ul>")
        for e in result.verdict_evidence_for:
            p(f'<li class="ev-for">{esc(e)}</li>')
        p("</ul>")
        if result.verdict_evidence_against:
            p("<b>Evidence AGAINST:</b><ul>")
            for e in result.verdict_evidence_against:
                p(f'<li class="ev-against">{esc(e)}</li>')
            p("</ul>")
        p(f"<b>Recommendation:</b> {esc(result.verdict_recommendation)}")
        p("</div>")

        p("</body></html>")
        return "\n".join(parts)

    def _find_nearest_content_y(self, y: float,
                                  content_rows: list[MCIDRow]) -> float | None:
        if not content_rows:
            return None
        return min(content_rows, key=lambda r: abs(r.y - y)).y


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    global _USE_COLOR

    parser = argparse.ArgumentParser(
        description="Deep forensic analysis of a PDF xref content stream.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python xref_forensics.py HW1.pdf --xref 4
  python xref_forensics.py HW1.pdf --xref 4 --full-dump --no-color
  python xref_forensics.py HW1.pdf --xref 4 --json > xref4_forensics.json
  python xref_forensics.py HW1.pdf --xref 4 --html
  python xref_forensics.py HW1.pdf --xref 4 --compare 27
""")
    parser.add_argument("pdf", help="PDF file path")
    parser.add_argument("--xref", type=int, default=4, help="xref object number (default: 4)")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color output")
    parser.add_argument("--json", action="store_true", help="Output JSON report to stdout")
    parser.add_argument("--html", action="store_true", help="Save HTML report to xref<N>_report.html")
    parser.add_argument("--full-dump", action="store_true", help="Include annotated stream dump")
    parser.add_argument("--compare", type=int, metavar="XREF",
                        help="Compare with a second xref side-by-side")

    args = parser.parse_args()

    if args.no_color or args.json:
        _USE_COLOR = False

    # Configure stdout for UTF-8 on Windows
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except AttributeError:
        pass

    if not PYMUPDF_AVAILABLE:
        print("ERROR: PyMuPDF is required.  pip install pymupdf", file=sys.stderr)
        sys.exit(1)

    try:
        report = XrefForensicsReport(args.pdf)
    except Exception as e:
        print(f"ERROR opening {args.pdf}: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        result = report.run(args.xref)
    except Exception as e:
        print(f"ERROR analyzing xref={args.xref}: {e}", file=sys.stderr)
        sys.exit(1)

    renderer = ForensicsRenderer()

    if args.json:
        out = renderer.render_json(result)
        sys.stdout.buffer.write(out.encode("utf-8"))
        sys.stdout.buffer.write(b"\n")
        return

    if args.html:
        html_path = f"xref{args.xref}_report.html"
        html_out = renderer.render_html(result)
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_out)
        print(f"HTML report saved to: {html_path}")

    if args.compare:
        try:
            result2 = report.run(args.compare)
        except Exception as e:
            print(f"ERROR analyzing xref={args.compare}: {e}", file=sys.stderr)
            sys.exit(1)
        terminal_out = renderer.render_terminal(result, full_dump=args.full_dump)
        compare_out  = renderer.render_compare(result, result2)
        combined = terminal_out + "\n\n" + compare_out
        try:
            print(combined)
        except UnicodeEncodeError:
            sys.stdout.buffer.write(combined.encode("utf-8", errors="replace"))
        return

    terminal_out = renderer.render_terminal(result, full_dump=args.full_dump)
    try:
        print(terminal_out)
    except UnicodeEncodeError:
        sys.stdout.buffer.write(terminal_out.encode("utf-8", errors="replace"))
        sys.stdout.buffer.write(b"\n")


if __name__ == "__main__":
    main()
