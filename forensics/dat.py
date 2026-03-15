"""
forensics/dat.py
Forensic checks for .dat and generic binary/text files.
"""

from __future__ import annotations
import json
import re
from typing import Optional

import numpy as np

from .algorithms import (
    chi2_pov, rs_steganalysis, lsb_bitstream, scan_prompt_injection,
    shannon_entropy, PI_PATTERNS,
)

_PI_COMPILED = [re.compile(p, re.IGNORECASE) for p in PI_PATTERNS]

# ─── Format Detection ─────────────────────────────────────────────────────────

def detect_format(raw_bytes: bytes) -> dict:
    """
    Detect whether a file is text or binary, and guess its structure.
    Returns {is_binary, encoding, likely_format, printable_ratio}.
    """
    if not raw_bytes:
        return {"is_binary": False, "encoding": "empty", "likely_format": "empty",
                "printable_ratio": 0.0}

    total = len(raw_bytes)
    printable = sum(1 for b in raw_bytes if 0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D))
    printable_ratio = printable / total

    is_binary = printable_ratio < 0.90

    if is_binary:
        return {
            "is_binary": True,
            "encoding": "binary",
            "likely_format": "binary/unknown",
            "printable_ratio": round(printable_ratio, 4),
        }

    # Try to decode as text
    for enc in ("utf-8", "utf-16", "latin-1", "ascii"):
        try:
            text = raw_bytes.decode(enc)
            # Determine structure
            lines = text.splitlines()
            non_empty = [l for l in lines if l.strip()]

            likely_format = "text/plain"
            if non_empty:
                first = non_empty[0].strip()
                if first.startswith("{") or first.startswith("["):
                    try:
                        json.loads(text)
                        likely_format = "text/json"
                    except Exception:
                        likely_format = "text/plain"
                elif "," in first and len(first.split(",")) > 1:
                    likely_format = "text/csv"
                elif "\t" in first:
                    # Check if it looks like a matrix (all-numeric tab-separated)
                    cells = first.split("\t")
                    if all(_is_number(c) for c in cells if c.strip()):
                        likely_format = "text/matrix"
                elif first and all(_is_number(c) for c in first.split() if c):
                    likely_format = "text/matrix"

            return {
                "is_binary": False,
                "encoding": enc,
                "likely_format": likely_format,
                "printable_ratio": round(printable_ratio, 4),
            }
        except (UnicodeDecodeError, UnicodeError):
            continue

    return {
        "is_binary": True,
        "encoding": "unknown",
        "likely_format": "binary/unknown",
        "printable_ratio": round(printable_ratio, 4),
    }


def _is_number(s: str) -> bool:
    s = s.strip()
    if not s:
        return True
    try:
        float(s)
        return True
    except ValueError:
        return False


# ─── Text Content Analysis ────────────────────────────────────────────────────

def check_text_content(text: str) -> dict:
    """
    Analyze text content for structure and prompt injection.
    Returns {line_count, char_count, word_count, structure, prompt_injection}.
    """
    lines = text.splitlines()
    non_empty = [l for l in lines if l.strip()]
    words = text.split()

    # Detect structure
    structure = "plain"
    if non_empty:
        cells_per_line = []
        for line in non_empty[:20]:
            if "\t" in line:
                cells = len(line.split("\t"))
            elif "," in line:
                cells = len(line.split(","))
            else:
                cells = len(line.split())
            cells_per_line.append(cells)
        if cells_per_line:
            avg = sum(cells_per_line) / len(cells_per_line)
            variance = sum((c - avg) ** 2 for c in cells_per_line) / len(cells_per_line)
            if variance < 2.0 and avg > 1:
                if "\t" in text:
                    structure = "matrix/tsv"
                elif "," in non_empty[0] if non_empty else False:
                    structure = "csv"
                else:
                    structure = "matrix"

    # Prompt injection scan on full text
    pi_matches = []
    for pat, compiled in zip(PI_PATTERNS, _PI_COMPILED):
        m = compiled.search(text)
        if m:
            snippet = text[max(0, m.start() - 20):m.end() + 30].replace("\n", " ")
            pi_matches.append({
                "pattern": pat,
                "context": f"...{snippet}...",
            })

    return {
        "line_count": len(lines),
        "non_empty_lines": len(non_empty),
        "char_count": len(text),
        "word_count": len(words),
        "structure": structure,
        "prompt_injection": {
            "patterns_checked": len(PI_PATTERNS),
            "matches": pi_matches,
            "verdict": "SUSPICIOUS" if pi_matches else "CLEAN",
        },
    }


# ─── Binary Steganography Check ───────────────────────────────────────────────

def check_binary_steg(raw_bytes: bytes) -> dict:
    """
    Treat binary file as a flat grayscale 'image' and apply LSB analysis.
    Returns steg analysis dict.
    """
    arr = np.frombuffer(raw_bytes, dtype=np.uint8)

    lsb_ratio = float((arr & 1).mean())

    chi2_stat, chi2_p, chi2_verdict = chi2_pov(arr)

    # RS analysis — treat as 1D strip
    side = max(1, int(len(arr) ** 0.5))
    n = (len(arr) // (side * 4)) * side * 4
    if n > 0:
        arr2d = arr[:n].reshape(-1, side)
        rs = rs_steganalysis(arr2d[:, :side], m=4)
    else:
        rs = {"embedding_rate": 0.0, "verdict": "CLEAN"}

    # LSB PI scan
    bs = lsb_bitstream(arr)
    pi_matches = scan_prompt_injection(bs[:512])

    return {
        "lsb_ones_ratio": round(lsb_ratio, 4),
        "lsb_deviation_from_half": round(abs(0.5 - lsb_ratio), 4),
        "chi2_stat": round(chi2_stat, 2),
        "chi2_p": round(chi2_p, 6),
        "chi2_verdict": chi2_verdict,
        "rs_embedding_rate": rs.get("embedding_rate", 0.0),
        "rs_verdict": rs.get("verdict", "CLEAN"),
        "pi_matches": pi_matches,
        "verdict": (
            "SUSPICIOUS"
            if (chi2_verdict == "SUSPICIOUS" or rs.get("verdict") == "SUSPICIOUS" or pi_matches)
            else "CLEAN"
        ),
    }


# ─── Master DAT Check ─────────────────────────────────────────────────────────

def check_dat(path: str, raw_bytes: bytes) -> dict:
    """
    Run all applicable checks on a DAT or generic binary file.
    Returns unified dict with verdict and confidence.
    """
    fmt = detect_format(raw_bytes)
    entropy = shannon_entropy(raw_bytes)

    text_analysis: Optional[dict] = None
    binary_analysis: Optional[dict] = None

    if not fmt["is_binary"]:
        # Text file
        try:
            text = raw_bytes.decode(fmt["encoding"], errors="replace")
        except Exception:
            text = raw_bytes.decode("latin-1", errors="replace")
        text_analysis = check_text_content(text)
    else:
        # Binary file
        binary_analysis = check_binary_steg(raw_bytes)

    # ── Verdict ──────────────────────────────────────────────────
    evidence_against = []
    evidence_for = []

    if text_analysis:
        pi = text_analysis["prompt_injection"]
        if pi["verdict"] == "SUSPICIOUS":
            evidence_against.append(
                f"{len(pi['matches'])} prompt injection pattern(s) in text content"
            )
        else:
            evidence_for.append("no prompt injection patterns in text content")
        evidence_for.append(
            f"printable ratio {fmt['printable_ratio']:.0%} (plain text file)"
        )

    if binary_analysis:
        if binary_analysis["verdict"] == "SUSPICIOUS":
            if binary_analysis["chi2_verdict"] == "SUSPICIOUS":
                evidence_against.append(
                    f"chi2 p={binary_analysis['chi2_p']:.4f} (LSB pairs equalized)"
                )
            if binary_analysis["rs_verdict"] == "SUSPICIOUS":
                evidence_against.append(
                    f"RS embedding rate {binary_analysis['rs_embedding_rate']:.1%}"
                )
            if binary_analysis["pi_matches"]:
                evidence_against.append(
                    f"{len(binary_analysis['pi_matches'])} PI pattern(s) in LSB bitstream"
                )
        else:
            evidence_for.append("LSB analysis: no steganography detected")

    if not evidence_against:
        verdict = "CLEAN"
        confidence = 0.95
    elif len(evidence_against) >= 2:
        verdict = "SUSPICIOUS"
        confidence = 0.80
    else:
        verdict = "NEEDS_REVIEW"
        confidence = 0.55

    return {
        "format": fmt,
        "size_bytes": len(raw_bytes),
        "entropy": round(entropy, 4),
        "text_analysis": text_analysis,
        "binary_analysis": binary_analysis,
        "evidence_for_clean": evidence_for,
        "evidence_against": evidence_against,
        "verdict": verdict,
        "confidence": confidence,
    }
