"""
forensics/algorithms.py
Pure-math steganography detection algorithms.
No I/O, no file access — only numpy arrays and bytes.
"""

from __future__ import annotations
import math
import re
import struct
from collections import Counter
from typing import List, Tuple

import numpy as np

# ─── Prompt-Injection Patterns ───────────────────────────────────────────────

PI_PATTERNS: List[str] = [
    r"ignore\s+(previous|prior|above|all)\s+(instructions?|context|prompt)",
    r"you\s+are\s+(now|a|an)\s+",
    r"(system|user|assistant)\s*:\s*",
    r"<\s*(system|user|assistant|inst|\/inst)\s*>",
    r"\[INST\]|\[\/INST\]|<<SYS>>",
    r"###\s*(instruction|system|prompt|input|output)",
    r"disregard\s+(previous|prior|above)",
    r"new\s+(instruction|directive|command|task)s?\s*:",
    r"(act\s+as|pretend\s+(to\s+be|you\s+are))",
    r"override\s+(previous|prior|above|safety|filter)",
    r"reveal\s+(your\s+)?(system\s+)?prompt",
    r"print\s+the\s+above",
    r"translate\s+the\s+above\s+to",
]

_PI_COMPILED = [re.compile(p, re.IGNORECASE) for p in PI_PATTERNS]

# ─── Shannon Entropy ──────────────────────────────────────────────────────────

def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte. Returns 0.0 for empty input."""
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    probs = np.array(list(counts.values()), dtype=np.float64) / total
    nz = probs[probs > 0]
    return float(-np.sum(nz * np.log2(nz)))


# ─── Chi-Square PoV LSB Attack ────────────────────────────────────────────────

def _chi2_sf(chi2_val: float, df: int) -> float:
    """Chi-squared survival function P(X > chi2_val) — pure Python, no scipy."""
    if chi2_val <= 0:
        return 1.0
    # Use regularized upper incomplete gamma: sf = 1 - gammainc(df/2, chi2/2)
    a = df / 2.0
    x = chi2_val / 2.0
    return _upper_incomplete_gamma_reg(a, x)


def _upper_incomplete_gamma_reg(a: float, x: float) -> float:
    """Regularized upper incomplete gamma function Q(a, x) = 1 - P(a, x)."""
    if x < 0:
        return 1.0
    if x == 0:
        return 1.0
    # For small x use series expansion; for large x use continued fraction
    if x < a + 1.0:
        return 1.0 - _gamma_series(a, x)
    else:
        return _gamma_cf(a, x)


def _gamma_series(a: float, x: float) -> float:
    """Regularized lower incomplete gamma P(a,x) via series."""
    if x <= 0:
        return 0.0
    ap = a
    delta = 1.0 / a
    total = delta
    for _ in range(300):
        ap += 1.0
        delta *= x / ap
        total += delta
        if abs(delta) < abs(total) * 1e-12:
            break
    return total * math.exp(-x + a * math.log(x) - math.lgamma(a))


def _gamma_cf(a: float, x: float) -> float:
    """Regularized upper incomplete gamma Q(a,x) via continued fraction."""
    fpmin = 1e-300
    b = x + 1.0 - a
    c = 1.0 / fpmin
    d = 1.0 / b
    h = d
    for i in range(1, 301):
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        if abs(d) < fpmin:
            d = fpmin
        c = b + an / c
        if abs(c) < fpmin:
            c = fpmin
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 1e-12:
            break
    return math.exp(-x + a * math.log(x) - math.lgamma(a)) * h


def chi2_pov(channel: np.ndarray) -> Tuple[float, float, str]:
    """
    Pairs-of-Values chi-square LSB steganography test (Westfeld & Pfitzmann 2000).

    H0: pairs (2k, 2k+1) are equalized (steganography present).
    HIGH p-value → fail to reject H0 → pairs equalized → SUSPICIOUS.
    LOW p-value → reject H0 → pairs unequal → CLEAN.

    Returns:
        (chi2_stat, p_value, verdict)  where verdict in {"CLEAN", "SUSPICIOUS"}
    """
    flat = channel.ravel().astype(np.int32)
    counts = np.bincount(flat, minlength=256)

    chi2_stat = 0.0
    df = 0
    for k in range(128):
        n0 = int(counts[2 * k])
        n1 = int(counts[2 * k + 1])
        total = n0 + n1
        if total == 0:
            continue
        expected = total / 2.0
        chi2_stat += (n0 - expected) ** 2 / expected + (n1 - expected) ** 2 / expected
        df += 1

    if df == 0:
        return 0.0, 1.0, "CLEAN"

    p_value = _chi2_sf(chi2_stat, df)
    verdict = "SUSPICIOUS" if p_value > 0.05 else "CLEAN"
    return chi2_stat, p_value, verdict


# ─── RS Steganalysis (Fridrich et al. 2001) ───────────────────────────────────

def _discrimination(group: np.ndarray) -> float:
    """Smoothness discrimination function f(x) = sum |x[i+1] - x[i]|."""
    return float(np.sum(np.abs(np.diff(group.astype(np.int32)))))


def _flip_lsb(group: np.ndarray, negative: bool) -> np.ndarray:
    """Apply identity (F1) or negative-identity (F_{-1}) flip to group LSBs."""
    g = group.copy().astype(np.int32)
    if not negative:
        # F1: flip LSB (0↔1)
        g ^= 1
    else:
        # F_{-1}: -1 ↔ 0 in the invertible map -1→0, 0→-1, 1→0, ...
        # Implemented as: even → odd via (v XOR 1) if v%2==0 else (v XOR 1)
        # The standard F_{-1} map: 0→-1→(wrap 255), 1→0, 2→1, 3→2...
        # Simplified: v → v-1 if even, v → v+1 if odd (with clipping)
        even = (g % 2) == 0
        g[even] -= 1
        g[~even] += 1
        g = np.clip(g, 0, 255)
    return g.astype(np.uint8)


def rs_steganalysis(channel: np.ndarray, m: int = 4) -> dict:
    """
    Fridrich 2001 RS steganalysis on a single channel.

    Partitions pixels into groups of m, classifies each as Regular (R),
    Singular (S), or Unusable (U) under identity and negative-identity flip.

    Returns dict with:
        rm, sm, r_neg, s_neg  — group fractions
        embedding_rate        — estimated fraction of LSBs modified (0.0–1.0)
        verdict               — "CLEAN" | "LOW_RISK" | "SUSPICIOUS"
    """
    flat = channel.ravel().astype(np.uint8)
    # Trim to multiple of m
    n = (len(flat) // m) * m
    if n == 0:
        return {"rm": 0, "sm": 0, "r_neg": 0, "s_neg": 0,
                "embedding_rate": 0.0, "verdict": "CLEAN"}
    groups = flat[:n].reshape(-1, m)

    r_count = s_count = r_neg_count = s_neg_count = 0
    total = len(groups)

    for g in groups:
        f0 = _discrimination(g)
        # Identity flip
        f1 = _discrimination(_flip_lsb(g, negative=False))
        if f1 > f0:
            r_count += 1
        elif f1 < f0:
            s_count += 1
        # Negative-identity flip
        f_neg = _discrimination(_flip_lsb(g, negative=True))
        if f_neg > f0:
            r_neg_count += 1
        elif f_neg < f0:
            s_neg_count += 1

    rm = r_count / total
    sm = s_count / total
    r_neg = r_neg_count / total
    s_neg = s_neg_count / total

    # Estimate embedding rate from RS signature
    # If rm ≈ r_neg and sm ≈ s_neg → no embedding; if rm ≈ sm → fully embedded
    # Simple estimator: rate ≈ |rm - r_neg| / (rm + r_neg + 1e-9)
    # More precise: solve quadratic from Fridrich paper (simplified here)
    d = abs(rm - r_neg)
    rate = min(d * 2.0, 1.0)  # Conservative estimate

    if rate < 0.02:
        verdict = "CLEAN"
    elif rate < 0.05:
        verdict = "LOW_RISK"
    else:
        verdict = "SUSPICIOUS"

    return {
        "rm": round(rm, 4),
        "sm": round(sm, 4),
        "r_neg": round(r_neg, 4),
        "s_neg": round(s_neg, 4),
        "embedding_rate": round(rate, 4),
        "verdict": verdict,
    }


# ─── LSB Bitstream ────────────────────────────────────────────────────────────

def lsb_bitstream(arr: np.ndarray) -> bytes:
    """
    Extract LSBs in raster order, pack to bytes.
    For RGB: R→G→B per pixel. For grayscale: one bit per pixel.
    """
    flat = arr.ravel() & 1  # all LSBs as 0/1 array
    # Pad to multiple of 8
    pad = (8 - len(flat) % 8) % 8
    if pad:
        flat = np.concatenate([flat, np.zeros(pad, dtype=np.uint8)])
    # Pack bits (MSB first per byte)
    result = bytearray()
    for i in range(0, len(flat), 8):
        byte = 0
        for bit in flat[i:i+8]:
            byte = (byte << 1) | int(bit)
        result.append(byte)
    return bytes(result)


def scan_prompt_injection(bs: bytes) -> List[str]:
    """
    Decode bytes as ASCII and scan for prompt injection patterns.
    Returns list of human-readable match descriptions.
    """
    try:
        text = bs.decode("ascii", errors="replace")
    except Exception:
        text = "".join(chr(b) if 32 <= b < 127 else "?" for b in bs)

    matches = []
    for pat, compiled in zip(PI_PATTERNS, _PI_COMPILED):
        m = compiled.search(text)
        if m:
            snippet = text[max(0, m.start()-10):m.end()+20].replace("\n", " ")
            matches.append(f"Pattern '{pat[:40]}' matched: ...{snippet}...")
    return matches


# ─── Spatial Autocorrelation ──────────────────────────────────────────────────

def lsb_spatial_autocorr(channel: np.ndarray) -> float:
    """
    Lag-1 row-wise spatial autocorrelation of the LSB plane.
    Returns value in [-1, 1].
    High value (>0.80) → structured/uniform (false positive indicator).
    Near zero → random-looking (potential steganography).
    """
    lsb = (channel & 1).astype(np.float32)
    rows = lsb.reshape(lsb.shape[0], -1) if lsb.ndim > 1 else lsb.reshape(1, -1)
    if rows.shape[1] < 2:
        return 0.0
    x = rows[:, :-1].ravel()
    y = rows[:, 1:].ravel()
    if len(x) == 0:
        return 0.0
    xm = x - x.mean()
    ym = y - y.mean()
    denom = np.sqrt((xm**2).sum() * (ym**2).sum())
    if denom < 1e-10:
        return 1.0  # all identical → perfectly correlated
    return float(np.dot(xm, ym) / denom)


# ─── LSB Heatmap ─────────────────────────────────────────────────────────────

def lsb_heatmap(arr: np.ndarray, cols: int = 60, rows: int = 20) -> List[str]:
    """
    ASCII heatmap of LSB density (downsampled).
    '#' = dense (>0.35), 'o' = mid (0.15–0.35), '.' = sparse (<0.15).
    Works for both RGB (H×W×3) and grayscale (H×W) arrays.
    """
    if arr.ndim == 3:
        lsb = (arr[:, :, 0] & 1).astype(np.float32)
    else:
        lsb = (arr & 1).astype(np.float32)

    h, w = lsb.shape
    if h == 0 or w == 0:
        return []

    row_h = max(1, h // rows)
    col_w = max(1, w // cols)
    lines = []
    for r in range(min(rows, h // row_h)):
        row_slice = lsb[r * row_h:(r + 1) * row_h, :]
        line = ""
        for c in range(min(cols, w // col_w)):
            cell = row_slice[:, c * col_w:(c + 1) * col_w]
            density = cell.mean() if cell.size > 0 else 0.0
            if density > 0.35:
                line += "#"
            elif density > 0.15:
                line += "o"
            else:
                line += "."
        lines.append(line)
    return lines


# ─── IEEE 754 Word Artifact Detection ────────────────────────────────────────

# Known Microsoft Word PDF/UA sub-pixel clip offset values (EMU rounding artifacts)
_WORD_ARTIFACT_VALUES = {
    8.871e-6: 1.0,   # 0x3714D4A8 — primary artifact
    8.87e-6:  0.9,
    8.9e-6:   0.7,
    0.0:      0.0,   # not an artifact
}
_WORD_ARTIFACT_RANGE = (5e-7, 5e-5)  # any sub-pixel value in this range


def ieee754_word_artifact_confidence(f: float) -> float:
    """
    Returns 0.0–1.0 confidence that a float is a Microsoft Word PDF/UA
    sub-pixel clip x-offset artifact.

    Key signature: 8.871e-6 (0x3714D4A8) — EMU rounding from 1 EMU coordinate.
    """
    if f == 0.0:
        return 0.0
    if f < 0:
        f = -f

    # Exact match
    for known, conf in _WORD_ARTIFACT_VALUES.items():
        if known > 0 and abs(f - known) / known < 0.01:
            return conf

    # In range and suspiciously small (sub-pixel)
    if _WORD_ARTIFACT_RANGE[0] <= f <= _WORD_ARTIFACT_RANGE[1]:
        # Check IEEE 754 representation
        packed = struct.pack(">f", f)
        word = struct.unpack(">I", packed)[0]
        # Word artifacts tend to have specific mantissa patterns
        mantissa = word & 0x7FFFFF
        # 0x14D4A8 is the mantissa for 8.871e-6
        if abs(mantissa - 0x14D4A8) < 0x10000:
            return 0.85
        return 0.60

    return 0.0
