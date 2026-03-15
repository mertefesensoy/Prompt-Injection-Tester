"""
image_forensics.py — Deep forensic analysis of a PDF image xref.

Applies RS steganalysis, chi-square LSB attack, spatial autocorrelation,
bitstream decoding with prompt-injection scan, and pixel sparsity checks
to produce a final FALSE_POSITIVE / NEEDS_REVIEW / CONFIRMED verdict.

Usage:
  python image_forensics.py HW1.pdf --xref 24
  python image_forensics.py HW1.pdf --xref 24 --no-color
  python image_forensics.py HW1.pdf --xref 24 --json > xref24_image.json
  python image_forensics.py HW1.pdf --xref 22
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from dataclasses import dataclass, field
from io import BytesIO
from typing import Any

try:
    import fitz
    PYMUPDF_AVAILABLE = True
except ImportError:
    PYMUPDF_AVAILABLE = False

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False

try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BUCKET_SIZE = 32   # pixel value histogram bucket width (0-31, 32-63, …)

# Prompt injection patterns (case-insensitive)
PI_PATTERNS = [
    r"ignore\s+(previous|prior|above|all)",
    r"you\s+are\s+(now|a|an)\b",
    r"system\s*:",
    r"assistant\s*:",
    r"<\s*(system|user|assistant)\s*[/>]",
    r"\[INST\]",
    r"###\s*(instruction|system|prompt)",
    r"act\s+as\s+(a|an)\b",
    r"disregard\s+(all|previous|prior)",
    r"new\s+instructions?\s*:",
    r"override\s+(previous|system)",
]

# False-positive thresholds (from deep_investigate.py)
SPARSITY_FP_THRESHOLD     = 0.50   # >50% near-zero pixels → FP
AUTOCORR_FP_THRESHOLD     = 0.80   # lag-1 autocorr > 0.80 → FP (uniform runs)
ONES_RATIO_FP_THRESHOLD   = 0.40   # deviation from 0.5 > 0.40 → FP
RS_EMBEDDING_SUSPICIOUS   = 0.05   # RS estimated rate > 5% → suspicious
CHI2_PVALUE_THRESHOLD     = 0.05   # p < 0.05 → suspicious

# ANSI codes
GREEN   = "\033[32m"
YELLOW  = "\033[33m"
RED     = "\033[31m"
CYAN    = "\033[36m"
MAGENTA = "\033[35m"
BLUE    = "\033[34m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
RESET   = "\033[0m"

_USE_COLOR = True


def _c(code: str, text: str) -> str:
    return f"{code}{text}{RESET}" if _USE_COLOR else text


def _hr(char: str = "-", width: int = 72) -> str:
    return char * width


# ---------------------------------------------------------------------------
# Pure-Python chi-square CDF (regularized incomplete gamma)
# ---------------------------------------------------------------------------

def _chi2_pvalue(chi2_stat: float, df: int) -> float:
    """Return P(X > chi2_stat) for chi-squared distribution with df degrees of freedom."""
    if chi2_stat <= 0:
        return 1.0
    # Regularized upper incomplete gamma: Q(df/2, chi2_stat/2)
    a = df / 2.0
    x = chi2_stat / 2.0
    return _upper_incomplete_gamma(a, x)


def _upper_incomplete_gamma(a: float, x: float) -> float:
    """Upper regularized incomplete gamma Q(a, x) via series expansion."""
    if x < 0:
        return 1.0
    if x == 0:
        return 1.0
    # Use series for small x, continued fraction for large x
    if x < a + 1.0:
        return 1.0 - _gamma_series(a, x)
    else:
        return _gamma_cf(a, x)


def _gamma_series(a: float, x: float) -> float:
    """Regularized lower incomplete gamma via series."""
    if x == 0:
        return 0.0
    ln_gamma_a = math.lgamma(a)
    ap = a
    total = 1.0 / a
    delta = total
    for _ in range(200):
        ap += 1.0
        delta *= x / ap
        total += delta
        if abs(delta) < abs(total) * 1e-10:
            break
    return total * math.exp(-x + a * math.log(x) - ln_gamma_a)


def _gamma_cf(a: float, x: float) -> float:
    """Regularized upper incomplete gamma via continued fraction (Lentz)."""
    ln_gamma_a = math.lgamma(a)
    fpmin = 1e-300
    b = x + 1.0 - a
    c = 1.0 / fpmin
    d = 1.0 / b
    h = d
    for i in range(1, 201):
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
        if abs(delta - 1.0) < 1e-10:
            break
    return math.exp(-x + a * math.log(x) - ln_gamma_a) * h


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ChannelStats:
    name: str
    mean: float
    stddev: float
    entropy: float
    sparsity: float          # fraction of pixels with value <= 10
    lsb_ones_ratio: float
    lsb_expected_ratio: float
    lsb_ratio_deviation: float
    autocorrelation: float
    histogram: list[tuple[int, int, float]]   # (bucket_start, count, lsb_ones)


@dataclass
class Chi2Result:
    chi2_stat: float
    p_value: float
    df: int
    verdict: str   # CLEAN / SUSPICIOUS
    detail: str


@dataclass
class RSResult:
    r_pos: float   # fraction of Regular groups under identity
    s_pos: float   # fraction of Singular groups under identity
    r_neg: float   # fraction of Regular groups under negative identity
    s_neg: float   # fraction of Singular groups under negative identity
    embedding_rate: float
    verdict: str   # CLEAN / SUSPICIOUS


@dataclass
class LSBBitstreamResult:
    total_bits: int
    printable_ratio: float
    sample_ascii: str
    prompt_injection_matches: list[str]
    verdict: str   # CLEAN / SUSPICIOUS


@dataclass
class CrossChannelResult:
    rg_correlation: float
    rb_correlation: float
    gb_correlation: float
    lsb_rg_correlation: float
    lsb_rb_correlation: float
    lsb_gb_correlation: float
    verdict: str


@dataclass
class ForensicsResult:
    xref: int
    width: int
    height: int
    total_pixels: int
    mode: str
    format_str: str
    colorspace: str
    channel_stats: list[ChannelStats]
    chi2: Chi2Result
    rs: RSResult
    lsb_bitstream: LSBBitstreamResult
    cross_channel: CrossChannelResult
    lsb_heatmap_lines: list[str]
    verdict: str
    verdict_confidence: float
    verdict_evidence_for: list[str]
    verdict_evidence_against: list[str]
    verdict_recommendation: str


# ---------------------------------------------------------------------------
# Pixel Histogram Analyzer
# ---------------------------------------------------------------------------

class PixelHistogramAnalyzer:

    def analyze(self, arr: "np.ndarray") -> list[ChannelStats]:
        """Compute per-channel stats from an HxWxC uint8 array."""
        stats = []
        channel_names = ["R", "G", "B"] if arr.shape[2] >= 3 else ["L"]
        for ci, name in enumerate(channel_names[:arr.shape[2]]):
            ch = arr[:, :, ci].astype(np.float64)
            flat = ch.flatten()
            flat_int = flat.astype(np.uint8)

            mean  = float(np.mean(flat))
            std   = float(np.std(flat))

            # Shannon entropy
            counts = np.bincount(flat_int, minlength=256)
            probs  = counts / counts.sum()
            nz     = probs[probs > 0]
            ent    = float(-np.sum(nz * np.log2(nz)))

            # Sparsity
            sparse = float(np.sum(flat_int <= 10)) / len(flat_int)

            # LSB analysis
            lsb = flat_int & 1
            ones_ratio = float(np.mean(lsb))

            # Expected LSB ones-ratio from actual pixel distribution
            # Expected = fraction of ODD-valued pixels
            odd_count  = np.sum(flat_int % 2 == 1)
            expected   = float(odd_count) / len(flat_int)

            deviation  = abs(ones_ratio - 0.5)

            # Autocorrelation (lag-1)
            lsb_float = lsb.astype(np.float32)
            lsb_2d    = lsb_float.reshape(arr.shape[0], arr.shape[1])
            autocorr  = self._autocorr(lsb_2d)

            # Histogram buckets
            histogram = []
            for b in range(0, 256, BUCKET_SIZE):
                mask  = (flat_int >= b) & (flat_int < b + BUCKET_SIZE)
                cnt   = int(np.sum(mask))
                if cnt == 0:
                    histogram.append((b, 0, 0.0))
                    continue
                lsb_b = float(np.mean(lsb[mask]))
                histogram.append((b, cnt, lsb_b))

            stats.append(ChannelStats(
                name=name,
                mean=round(mean, 3),
                stddev=round(std, 3),
                entropy=round(ent, 4),
                sparsity=round(sparse, 4),
                lsb_ones_ratio=round(ones_ratio, 4),
                lsb_expected_ratio=round(expected, 4),
                lsb_ratio_deviation=round(deviation, 4),
                autocorrelation=round(autocorr, 4),
                histogram=histogram,
            ))
        return stats

    def chi_square_lsb(self, arr: "np.ndarray") -> Chi2Result:
        """PoV chi-square test across all channels combined."""
        # Collect all pixel values from all channels
        pixels = arr[:, :, :3].reshape(-1, 3) if arr.shape[2] >= 3 else arr[:, :, 0].reshape(-1, 1)
        flat   = pixels.flatten().astype(np.uint8)

        # Count pairs (2k, 2k+1) for k in 0..127
        counts = np.bincount(flat, minlength=256)
        chi2   = 0.0
        used_pairs = 0
        for k in range(128):
            n0 = counts[2 * k]
            n1 = counts[2 * k + 1]
            total = n0 + n1
            if total == 0:
                continue
            expected = total / 2.0
            chi2 += (n0 - expected) ** 2 / expected
            chi2 += (n1 - expected) ** 2 / expected
            used_pairs += 1

        df      = max(1, used_pairs - 1)
        p_value = _chi2_pvalue(chi2, df)
        # PoV chi-square interpretation (Westfeld & Pfitzmann 2000):
        # H0 = pairs are equalized (stego). HIGH p = fail to reject = suspicious.
        # LOW p = pairs are unequal = natural image = CLEAN.
        verdict = "SUSPICIOUS" if p_value > CHI2_PVALUE_THRESHOLD else "CLEAN"
        detail  = (f"chi2={chi2:.2f} df={df} p={p_value:.4f} "
                   f"({'pairs equalized — stego possible' if verdict == 'SUSPICIOUS' else 'pairs unequal — natural distribution'})")

        return Chi2Result(
            chi2_stat=round(chi2, 4),
            p_value=round(p_value, 6),
            df=df,
            verdict=verdict,
            detail=detail,
        )

    def _autocorr(self, lsb_2d: "np.ndarray") -> float:
        flat = lsb_2d.flatten()
        mean = float(flat.mean())
        var  = float(np.var(flat))
        if var < 1e-9:
            return 1.0
        cov = float(np.mean((flat[:-1] - mean) * (flat[1:] - mean)))
        return max(-1.0, min(1.0, cov / var))


# ---------------------------------------------------------------------------
# RS Steganalysis
# ---------------------------------------------------------------------------

class RSSteganalyzer:
    """Fridrich et al. Regular-Singular steganalysis."""

    # Discrimination function: sum of absolute differences between adjacent pixels
    @staticmethod
    def _discriminate(group: "np.ndarray") -> float:
        return float(np.sum(np.abs(np.diff(group.astype(np.int32)))))

    @staticmethod
    def _flip(group: "np.ndarray") -> "np.ndarray":
        """LSB flip: toggle bit 0 of each pixel."""
        return group ^ 1

    @staticmethod
    def _neg_flip(group: "np.ndarray") -> "np.ndarray":
        """Negative flip: invert LSB in a specific way (F_{-1})."""
        # F_{-1}: flip LSB, then flip all bits (i.e. subtract 1 from even, add 1 to odd)
        result = group.copy().astype(np.int32)
        even_mask = (result % 2 == 0)
        result[even_mask] -= 1
        result[~even_mask] += 1
        return np.clip(result, 0, 255).astype(np.uint8)

    def analyze(self, arr: "np.ndarray", m: int = 4) -> RSResult:
        """Run RS analysis on all channels combined."""
        # Work on grayscale average for simplicity
        if arr.shape[2] >= 3:
            gray = arr[:, :, :3].mean(axis=2).astype(np.uint8)
        else:
            gray = arr[:, :, 0]

        h, w = gray.shape
        r_pos = s_pos = r_neg = s_neg = u_pos = u_neg = 0
        total = 0

        for row in range(h):
            for col in range(0, w - m + 1, m):
                group = gray[row, col:col + m].copy()
                if len(group) < m:
                    continue
                total += 1

                f0 = self._discriminate(group)
                f1 = self._discriminate(self._flip(group))
                fn = self._discriminate(self._neg_flip(group))

                # Positive mask (identity flip)
                if f1 > f0:
                    r_pos += 1
                elif f1 < f0:
                    s_pos += 1
                else:
                    u_pos += 1

                # Negative mask
                if fn > f0:
                    r_neg += 1
                elif fn < f0:
                    s_neg += 1
                else:
                    u_neg += 1

        if total == 0:
            return RSResult(0, 0, 0, 0, 0.0, "CLEAN")

        rp = r_pos / total
        sp = s_pos / total
        rn = r_neg / total
        sn = s_neg / total

        rate = self.estimate_embedding_rate(rp, sp, rn, sn)
        verdict = "SUSPICIOUS" if rate > RS_EMBEDDING_SUSPICIOUS else "CLEAN"

        return RSResult(
            r_pos=round(rp, 4),
            s_pos=round(sp, 4),
            r_neg=round(rn, 4),
            s_neg=round(sn, 4),
            embedding_rate=round(rate, 4),
            verdict=verdict,
        )

    def estimate_embedding_rate(self, rp: float, sp: float,
                                 rn: float, sn: float) -> float:
        """Estimate LSB embedding rate from RS signature."""
        # Fridrich: solve quadratic in p (embedding rate)
        # 2(d1+d0)p^2 - (d1+3d0)p + d0 - d1 = 0 ... simplified approximation:
        # Rate ≈ |R_pos - S_pos| / (R_pos + S_pos) when R_neg ≈ S_neg
        if rp + sp < 1e-6:
            return 0.0
        diff = abs(rp - sp)
        rate = diff / (rp + sp)
        # Adjust: for a clean image, R >> S naturally; we want divergence from this ratio
        # Simple approximation: rate = 2 * |R-S| / (R+S+R_neg+S_neg)
        if rp + sp + rn + sn < 1e-6:
            return 0.0
        rate = 2.0 * abs(rp - sp) / (rp + sp + rn + sn)
        return min(1.0, max(0.0, rate))


# ---------------------------------------------------------------------------
# LSB Bitstream Analyzer
# ---------------------------------------------------------------------------

class LSBBitstreamAnalyzer:

    def extract(self, arr: "np.ndarray") -> bytes:
        """Extract all LSBs in R→G→B→R→G→B raster order."""
        if arr.shape[2] >= 3:
            flat = arr[:, :, :3].reshape(-1)
        else:
            flat = arr[:, :, 0].reshape(-1)
        bits = (flat & 1).tolist()
        # Pack into bytes
        result = bytearray()
        for i in range(0, len(bits) - 7, 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | bits[i + j]
            result.append(byte)
        return bytes(result)

    def printable_ratio(self, bitstream: bytes) -> float:
        if not bitstream:
            return 0.0
        printable = sum(1 for b in bitstream if 0x20 <= b <= 0x7E)
        return printable / len(bitstream)

    def scan_prompt_injection(self, bitstream: bytes) -> list[str]:
        """Try to decode bitstream as text and scan for PI patterns."""
        # Try decoding as ASCII/Latin-1
        try:
            text = bitstream.decode("ascii", errors="replace")
        except Exception:
            text = bitstream.decode("latin-1", errors="replace")

        matches = []
        for pattern in PI_PATTERNS:
            m = re.search(pattern, text, re.IGNORECASE)
            if m:
                matches.append(f"Pattern '{pattern}' matched: '{m.group()[:40]}'")
        return matches

    def analyze(self, arr: "np.ndarray") -> LSBBitstreamResult:
        bitstream = self.extract(arr)
        pr = self.printable_ratio(bitstream)
        pi_matches = self.scan_prompt_injection(bitstream)

        # Sample: first 64 bytes as ASCII preview
        sample_bytes = bitstream[:64]
        sample = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in sample_bytes)

        verdict = "CLEAN"
        if pi_matches:
            verdict = "SUSPICIOUS"
        elif pr > 0.70:
            verdict = "NEEDS_REVIEW"  # suspiciously high printable ratio

        return LSBBitstreamResult(
            total_bits=len(bitstream) * 8,
            printable_ratio=round(pr, 4),
            sample_ascii=sample,
            prompt_injection_matches=pi_matches,
            verdict=verdict,
        )


# ---------------------------------------------------------------------------
# Spatial & Cross-Channel Correlation
# ---------------------------------------------------------------------------

class SpatialCorrelationAnalyzer:

    def cross_channel_correlation(self, arr: "np.ndarray") -> CrossChannelResult:
        if arr.shape[2] < 3:
            return CrossChannelResult(0, 0, 0, 0, 0, 0, "CLEAN")

        r = arr[:, :, 0].flatten().astype(np.float64)
        g = arr[:, :, 1].flatten().astype(np.float64)
        b = arr[:, :, 2].flatten().astype(np.float64)

        r_lsb = (arr[:, :, 0] & 1).flatten().astype(np.float64)
        g_lsb = (arr[:, :, 1] & 1).flatten().astype(np.float64)
        b_lsb = (arr[:, :, 2] & 1).flatten().astype(np.float64)

        def _corr(x: "np.ndarray", y: "np.ndarray") -> float:
            xm = x - x.mean(); ym = y - y.mean()
            denom = math.sqrt((xm**2).sum() * (ym**2).sum())
            if denom < 1e-9:
                return 0.0
            return float((xm * ym).sum() / denom)

        rg  = _corr(r, g)
        rb  = _corr(r, b)
        gb  = _corr(g, b)
        lrg = _corr(r_lsb, g_lsb)
        lrb = _corr(r_lsb, b_lsb)
        lgb = _corr(g_lsb, b_lsb)

        # If pixel channels are highly correlated but LSB planes are not → suspicious
        pixel_corr_avg = (abs(rg) + abs(rb) + abs(gb)) / 3
        lsb_corr_avg   = (abs(lrg) + abs(lrb) + abs(lgb)) / 3
        verdict = "CLEAN"
        if pixel_corr_avg > 0.70 and lsb_corr_avg < 0.20:
            verdict = "SUSPICIOUS"

        return CrossChannelResult(
            rg_correlation=round(rg, 4),
            rb_correlation=round(rb, 4),
            gb_correlation=round(gb, 4),
            lsb_rg_correlation=round(lrg, 4),
            lsb_rb_correlation=round(lrb, 4),
            lsb_gb_correlation=round(lgb, 4),
            verdict=verdict,
        )


# ---------------------------------------------------------------------------
# ASCII Heatmap Builder
# ---------------------------------------------------------------------------

def _build_lsb_heatmap(arr: "np.ndarray",
                        cols: int = 60, rows: int = 12) -> list[str]:
    """Downsample LSB plane to a text heatmap."""
    if arr.shape[2] >= 3:
        lsb_plane = (arr[:, :, :3] & 1).mean(axis=2)  # HxW, 0.0-1.0
    else:
        lsb_plane = (arr[:, :, 0] & 1).astype(np.float32)

    h, w = lsb_plane.shape
    row_h = max(1, h // rows)
    col_w = max(1, w // cols)

    lines = []
    for r in range(rows):
        line = ""
        for c in range(cols):
            r0 = r * row_h; r1 = min(h, r0 + row_h)
            c0 = c * col_w; c1 = min(w, c0 + col_w)
            cell = lsb_plane[r0:r1, c0:c1]
            if cell.size == 0:
                line += " "
                continue
            density = float(cell.mean())
            if density < 0.15:
                line += "."
            elif density < 0.35:
                line += "o"
            else:
                line += "#"
        lines.append(line)
    return lines


# ---------------------------------------------------------------------------
# Verdict Engine
# ---------------------------------------------------------------------------

class VerdictEngine:

    def compute(self, result: "ForensicsResult") -> tuple[str, float, list[str], list[str], str]:
        ev_for: list[str]     = []
        ev_against: list[str] = []
        confidence = 0.50

        # Chi-square
        if result.chi2.verdict == "CLEAN":
            ev_for.append(f"Chi-square p={result.chi2.p_value:.4f} — no LSB pair equalization")
            confidence += 0.12
        else:
            ev_against.append(f"Chi-square p={result.chi2.p_value:.4f} — suspicious pair equalization")
            confidence -= 0.20

        # RS
        if result.rs.verdict == "CLEAN":
            ev_for.append(
                f"RS steganalysis: estimated embedding rate={result.rs.embedding_rate:.2%} (clean)"
            )
            confidence += 0.15
        else:
            ev_against.append(
                f"RS steganalysis: embedding rate={result.rs.embedding_rate:.2%} (suspicious)"
            )
            confidence -= 0.20

        # LSB bitstream
        if result.lsb_bitstream.verdict == "CLEAN":
            ev_for.append(
                f"LSB bitstream: no prompt injection patterns; "
                f"printable_ratio={result.lsb_bitstream.printable_ratio:.2%}"
            )
            confidence += 0.08
        elif result.lsb_bitstream.verdict == "SUSPICIOUS":
            ev_against.append(
                f"LSB bitstream: prompt injection patterns found: "
                f"{result.lsb_bitstream.prompt_injection_matches}"
            )
            confidence -= 0.30
        else:
            ev_against.append(
                f"LSB bitstream: high printable ratio {result.lsb_bitstream.printable_ratio:.2%}"
            )
            confidence -= 0.10

        # Per-channel checks
        for cs in result.channel_stats:
            # Sparsity
            if cs.sparsity > SPARSITY_FP_THRESHOLD:
                ev_for.append(
                    f"Channel {cs.name}: sparsity={cs.sparsity:.1%} > 50% near-zero pixels "
                    f"(sparse image — LSB skew explained)"
                )
                confidence += 0.06
            # Autocorrelation
            if cs.autocorrelation > AUTOCORR_FP_THRESHOLD:
                ev_for.append(
                    f"Channel {cs.name}: LSB autocorr={cs.autocorrelation:.3f} > 0.80 "
                    f"(structured/uniform, not random)"
                )
                confidence += 0.05
            # LSB deviation explained by pixel distribution
            diff = abs(cs.lsb_ones_ratio - cs.lsb_expected_ratio)
            if diff < 0.03:
                ev_for.append(
                    f"Channel {cs.name}: observed LSB ratio ({cs.lsb_ones_ratio:.3f}) "
                    f"matches expected from pixel distribution ({cs.lsb_expected_ratio:.3f})"
                )
                confidence += 0.05
            elif diff > 0.10:
                ev_against.append(
                    f"Channel {cs.name}: LSB ratio ({cs.lsb_ones_ratio:.3f}) "
                    f"deviates from expected ({cs.lsb_expected_ratio:.3f}) by {diff:.3f}"
                )
                confidence -= 0.08

        # Heatmap structural analysis: check left vs right column density per row
        if result.lsb_heatmap_lines:
            _val = {"#": 1.0, "o": 0.25, ".": 0.0, " ": 0.0}
            left_scores = []
            right_scores = []
            for line in result.lsb_heatmap_lines:
                if not line:
                    continue
                mid = len(line) // 2
                l_d = [_val.get(c, 0.0) for c in line[:mid]]
                r_d = [_val.get(c, 0.0) for c in line[mid:]]
                if l_d: left_scores.append(sum(l_d) / len(l_d))
                if r_d: right_scores.append(sum(r_d) / len(r_d))
            left_avg  = sum(left_scores)  / len(left_scores)  if left_scores  else 0
            right_avg = sum(right_scores) / len(right_scores) if right_scores else 0
            if left_avg > 0.25 and right_avg < 0.10:
                ev_for.append(
                    f"LSB heatmap: dense-left ({left_avg:.0%}) / sparse-right ({right_avg:.0%}) "
                    f"per-row split — logo+whitespace structure, not uniform stego embedding"
                )
                confidence += 0.10

        # Cross-channel
        if result.cross_channel.verdict == "SUSPICIOUS":
            ev_against.append(
                "Cross-channel: pixel channels correlated but LSB planes are not "
                "(possible multi-channel stego)"
            )
            confidence -= 0.15
        else:
            ev_for.append("Cross-channel: LSB plane correlations consistent with pixel correlations")
            confidence += 0.04

        confidence = max(0.0, min(1.0, confidence))

        if confidence >= 0.70:
            verdict = "FALSE_POSITIVE"
        elif confidence >= 0.45:
            verdict = "NEEDS_REVIEW"
        else:
            verdict = "CONFIRMED_SUSPICIOUS"

        rec = self._recommendation(verdict, ev_against)
        return verdict, confidence, ev_for, ev_against, rec

    def _recommendation(self, verdict: str, ev_against: list[str]) -> str:
        if verdict == "FALSE_POSITIVE":
            return (
                "Image is consistent with a natural sparse/dark graphic (logo or diagram). "
                "LSB distribution is fully explained by the pixel value distribution — "
                "no steganographic payload evidence. No prompt injection vectors detected."
            )
        elif verdict == "NEEDS_REVIEW":
            return (
                "Some anomalies cannot be fully explained by natural image statistics. "
                "Manual inspection of the saved LSB plane image is recommended. "
                "Consider running an external steganalysis tool (StegExpose, zsteg) for confirmation."
            )
        else:
            return (
                "High-confidence suspicious finding. Recommend extracting raw image bytes "
                "and applying dedicated steganalysis (zsteg, StegExpose, OpenStego detection mode). "
                "Check if image is rendered at full resolution or downscaled (hidden content "
                "may be in non-rendered pixels)."
            )


# ---------------------------------------------------------------------------
# Main Report Orchestrator
# ---------------------------------------------------------------------------

class ImageForensicsReport:

    def __init__(self, doc_path: str) -> None:
        if not PYMUPDF_AVAILABLE:
            raise RuntimeError("PyMuPDF required: pip install pymupdf")
        if not NUMPY_AVAILABLE:
            raise RuntimeError("NumPy required: pip install numpy")
        if not PIL_AVAILABLE:
            raise RuntimeError("Pillow required: pip install Pillow")
        self.doc = fitz.open(doc_path)

    def run(self, xref: int) -> ForensicsResult:
        # Extract image
        img_data = self.doc.extract_image(xref)
        if img_data is None:
            raise ValueError(f"xref={xref} is not an image or could not be extracted")

        raw_bytes   = img_data.get("image", b"")
        fmt         = img_data.get("ext", "unknown").upper()
        width       = img_data.get("width", 0)
        height      = img_data.get("height", 0)
        colorspace  = img_data.get("colorspace", 0)
        cs_name     = {1: "Gray", 3: "RGB", 4: "CMYK"}.get(colorspace, f"CS{colorspace}")

        img   = Image.open(BytesIO(raw_bytes)).convert("RGB")
        arr   = np.array(img, dtype=np.uint8)   # H x W x 3
        total = arr.shape[0] * arr.shape[1]

        # Analyses
        hist_analyzer = PixelHistogramAnalyzer()
        channel_stats = hist_analyzer.analyze(arr)
        chi2          = hist_analyzer.chi_square_lsb(arr)
        rs            = RSSteganalyzer().analyze(arr)
        lsb_bs        = LSBBitstreamAnalyzer().analyze(arr)
        cross         = SpatialCorrelationAnalyzer().cross_channel_correlation(arr)
        heatmap       = _build_lsb_heatmap(arr)

        # Partial result for verdict
        result = ForensicsResult(
            xref=xref, width=width, height=height, total_pixels=total,
            mode=img.mode, format_str=fmt, colorspace=cs_name,
            channel_stats=channel_stats, chi2=chi2, rs=rs,
            lsb_bitstream=lsb_bs, cross_channel=cross,
            lsb_heatmap_lines=heatmap,
            verdict="PENDING", verdict_confidence=0.0,
            verdict_evidence_for=[], verdict_evidence_against=[],
            verdict_recommendation="",
        )

        v, conf, ef, ea, rec = VerdictEngine().compute(result)
        result.verdict               = v
        result.verdict_confidence    = conf
        result.verdict_evidence_for  = ef
        result.verdict_evidence_against = ea
        result.verdict_recommendation = rec

        return result


# ---------------------------------------------------------------------------
# Renderer
# ---------------------------------------------------------------------------

class ForensicsRenderer:

    def render_terminal(self, result: ForensicsResult) -> str:
        out: list[str] = []
        a = out.append

        a(_c(BOLD + CYAN, _hr("=", 72)))
        a(_c(BOLD + CYAN,
             f"  IMAGE FORENSICS REPORT  |  xref={result.xref}  |  "
             f"{result.width}x{result.height}  {result.format_str}  {result.colorspace}"))
        a(_c(BOLD + CYAN, _hr("=", 72)))
        a(f"  Total pixels : {result.total_pixels:,}  |  Mode: {result.mode}")

        # --- CHANNEL STATS ---
        a("")
        a(_c(BOLD, "[ 1. PIXEL DISTRIBUTION & LSB PROFILE ]"))
        a(_hr())
        a(_c(DIM, f"  {'Ch':<3}  {'Mean':>7}  {'Std':>7}  {'Entropy':>8}  "
                  f"{'Sparsity':>9}  {'LSB-obs':>8}  {'LSB-exp':>8}  "
                  f"{'Delta':>7}  {'AutoCorr':>9}"))
        a(_c(DIM, "  " + "-" * 70))

        for cs in result.channel_stats:
            delta_color = GREEN if abs(cs.lsb_ones_ratio - cs.lsb_expected_ratio) < 0.03 else YELLOW
            row = (f"  {cs.name:<3}  {cs.mean:>7.2f}  {cs.stddev:>7.2f}  "
                   f"{cs.entropy:>8.4f}  {cs.sparsity:>8.1%}  "
                   f"{cs.lsb_ones_ratio:>8.4f}  {cs.lsb_expected_ratio:>8.4f}  "
                   f"{abs(cs.lsb_ones_ratio-cs.lsb_expected_ratio):>7.4f}  "
                   f"{cs.autocorrelation:>9.4f}")
            a(_c(delta_color, row))

        # Histogram for first channel
        first = result.channel_stats[0] if result.channel_stats else None
        if first:
            a("")
            a(_c(DIM, f"  Histogram (channel {first.name}):"))
            for (bstart, cnt, lsb_b) in first.histogram:
                if cnt == 0:
                    continue
                bar_len = min(30, max(1, int(cnt / result.total_pixels * 300)))
                bar = "#" * bar_len
                a(f"  {bstart:>3}-{bstart+BUCKET_SIZE-1:<3}  {cnt:>7,}  "
                  f"|{bar:<30}  LSB={lsb_b:.3f}")

        # --- CHI-SQUARE ---
        a("")
        a(_c(BOLD, "[ 2. CHI-SQUARE LSB ATTACK (Pairs of Values) ]"))
        a(_hr())
        chi_color = GREEN if result.chi2.verdict == "CLEAN" else RED
        a(_c(chi_color, f"  Result  : {result.chi2.verdict}"))
        a(f"  {result.chi2.detail}")

        # --- RS STEGANALYSIS ---
        a("")
        a(_c(BOLD, "[ 3. RS STEGANALYSIS (Fridrich et al.) ]"))
        a(_hr())
        rs_color = GREEN if result.rs.verdict == "CLEAN" else RED
        a(_c(rs_color, f"  Result         : {result.rs.verdict}"))
        a(f"  R_pos={result.rs.r_pos:.4f}  S_pos={result.rs.s_pos:.4f}  "
          f"R_neg={result.rs.r_neg:.4f}  S_neg={result.rs.s_neg:.4f}")
        a(f"  Embedding rate : {result.rs.embedding_rate:.2%}  "
          f"(threshold: >{RS_EMBEDDING_SUSPICIOUS:.0%} = suspicious)")

        # --- LSB BITSTREAM ---
        a("")
        a(_c(BOLD, "[ 4. LSB BITSTREAM DECODE & PROMPT INJECTION SCAN ]"))
        a(_hr())
        bs_color = GREEN if result.lsb_bitstream.verdict == "CLEAN" else (
            RED if result.lsb_bitstream.verdict == "SUSPICIOUS" else YELLOW)
        a(_c(bs_color, f"  Result         : {result.lsb_bitstream.verdict}"))
        a(f"  Total bits     : {result.lsb_bitstream.total_bits:,}")
        a(f"  Printable ratio: {result.lsb_bitstream.printable_ratio:.2%}")
        a(f"  Sample (64B)   : {result.lsb_bitstream.sample_ascii}")
        if result.lsb_bitstream.prompt_injection_matches:
            a(_c(RED, "  PI MATCHES:"))
            for m in result.lsb_bitstream.prompt_injection_matches:
                a(_c(RED, f"    [!] {m}"))
        else:
            a(_c(GREEN, "  No prompt injection patterns detected"))

        # --- CROSS-CHANNEL ---
        a("")
        a(_c(BOLD, "[ 5. CROSS-CHANNEL LSB CORRELATION ]"))
        a(_hr())
        cc = result.cross_channel
        cc_color = GREEN if cc.verdict == "CLEAN" else RED
        a(_c(DIM, f"  {'':20} {'Pixel corr':>12}  {'LSB corr':>10}"))
        a(f"  {'R vs G':<20} {cc.rg_correlation:>12.4f}  {cc.lsb_rg_correlation:>10.4f}")
        a(f"  {'R vs B':<20} {cc.rb_correlation:>12.4f}  {cc.lsb_rb_correlation:>10.4f}")
        a(f"  {'G vs B':<20} {cc.gb_correlation:>12.4f}  {cc.lsb_gb_correlation:>10.4f}")
        a(_c(cc_color, f"  Verdict: {cc.verdict}"))

        # --- HEATMAP ---
        a("")
        a(_c(BOLD, "[ 6. LSB DENSITY HEATMAP  (. <15%  o 15-35%  # >35%) ]"))
        a(_hr())
        for line in result.lsb_heatmap_lines:
            a("  " + _c(DIM, line))

        # --- VERDICT ---
        a("")
        a(_c(BOLD, "[ 7. FINAL VERDICT ]"))
        a(_hr("=", 72))
        v_color = {
            "FALSE_POSITIVE":      GREEN,
            "NEEDS_REVIEW":        YELLOW,
            "CONFIRMED_SUSPICIOUS": RED,
        }.get(result.verdict, "")

        a(_c(BOLD + v_color, f"  VERDICT     : {result.verdict}"))
        a(_c(BOLD + v_color, f"  Confidence  : {result.verdict_confidence:.0%}"))
        a("")
        a(_c(GREEN, "  Evidence FOR false-positive:"))
        for e in result.verdict_evidence_for:
            a(_c(GREEN, f"    [+] {e}"))
        if result.verdict_evidence_against:
            a(_c(YELLOW, "\n  Evidence AGAINST:"))
            for e in result.verdict_evidence_against:
                a(_c(YELLOW, f"    [-] {e}"))
        a("")
        a(_c(BOLD, "  Recommendation:"))
        for part in result.verdict_recommendation.split(". "):
            if part.strip():
                a(f"    {part.strip()}.")
        a(_hr("=", 72))

        return "\n".join(out)

    def render_json(self, result: ForensicsResult) -> str:
        def _cs(cs: ChannelStats) -> dict:
            return {
                "name": cs.name,
                "mean": cs.mean,
                "stddev": cs.stddev,
                "entropy": cs.entropy,
                "sparsity": cs.sparsity,
                "lsb_ones_ratio": cs.lsb_ones_ratio,
                "lsb_expected_ratio": cs.lsb_expected_ratio,
                "lsb_ratio_deviation": cs.lsb_ratio_deviation,
                "autocorrelation": cs.autocorrelation,
                "histogram": [{"bucket_start": b, "count": c, "lsb_ones": round(l, 4)}
                               for b, c, l in cs.histogram],
            }

        data = {
            "xref": result.xref,
            "dimensions": {"width": result.width, "height": result.height,
                            "total_pixels": result.total_pixels},
            "format": result.format_str,
            "colorspace": result.colorspace,
            "channel_stats": [_cs(cs) for cs in result.channel_stats],
            "chi2_lsb_attack": {
                "chi2_stat": result.chi2.chi2_stat,
                "p_value": result.chi2.p_value,
                "df": result.chi2.df,
                "verdict": result.chi2.verdict,
                "detail": result.chi2.detail,
            },
            "rs_steganalysis": {
                "r_pos": result.rs.r_pos,
                "s_pos": result.rs.s_pos,
                "r_neg": result.rs.r_neg,
                "s_neg": result.rs.s_neg,
                "embedding_rate": result.rs.embedding_rate,
                "verdict": result.rs.verdict,
            },
            "lsb_bitstream": {
                "total_bits": result.lsb_bitstream.total_bits,
                "printable_ratio": result.lsb_bitstream.printable_ratio,
                "sample_ascii": result.lsb_bitstream.sample_ascii,
                "prompt_injection_matches": result.lsb_bitstream.prompt_injection_matches,
                "verdict": result.lsb_bitstream.verdict,
            },
            "cross_channel": {
                "pixel": {
                    "RG": result.cross_channel.rg_correlation,
                    "RB": result.cross_channel.rb_correlation,
                    "GB": result.cross_channel.gb_correlation,
                },
                "lsb": {
                    "RG": result.cross_channel.lsb_rg_correlation,
                    "RB": result.cross_channel.lsb_rb_correlation,
                    "GB": result.cross_channel.lsb_gb_correlation,
                },
                "verdict": result.cross_channel.verdict,
            },
            "verdict": {
                "verdict": result.verdict,
                "confidence": round(result.verdict_confidence, 4),
                "evidence_for": result.verdict_evidence_for,
                "evidence_against": result.verdict_evidence_against,
                "recommendation": result.verdict_recommendation,
            },
        }
        return json.dumps(data, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    global _USE_COLOR

    parser = argparse.ArgumentParser(
        description="Deep forensic analysis of a PDF image xref.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python image_forensics.py HW1.pdf --xref 24
  python image_forensics.py HW1.pdf --xref 24 --no-color
  python image_forensics.py HW1.pdf --xref 24 --json > xref24_image.json
  python image_forensics.py HW1.pdf --xref 22
""")
    parser.add_argument("pdf", help="PDF file path")
    parser.add_argument("--xref", type=int, default=24, help="xref object number (default: 24)")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color")
    parser.add_argument("--json", action="store_true", help="Output JSON to stdout")

    args = parser.parse_args()

    if args.no_color or args.json:
        _USE_COLOR = False

    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except AttributeError:
        pass

    if not PYMUPDF_AVAILABLE:
        print("ERROR: pip install pymupdf", file=sys.stderr); sys.exit(1)
    if not NUMPY_AVAILABLE:
        print("ERROR: pip install numpy", file=sys.stderr); sys.exit(1)
    if not PIL_AVAILABLE:
        print("ERROR: pip install Pillow", file=sys.stderr); sys.exit(1)

    try:
        report = ImageForensicsReport(args.pdf)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr); sys.exit(1)

    try:
        result = report.run(args.xref)
    except Exception as e:
        print(f"ERROR analyzing xref={args.xref}: {e}", file=sys.stderr); sys.exit(1)

    renderer = ForensicsRenderer()

    if args.json:
        out = renderer.render_json(result)
        sys.stdout.buffer.write(out.encode("utf-8"))
        sys.stdout.buffer.write(b"\n")
        return

    terminal_out = renderer.render_terminal(result)
    try:
        print(terminal_out)
    except UnicodeEncodeError:
        sys.stdout.buffer.write(terminal_out.encode("utf-8", errors="replace"))
        sys.stdout.buffer.write(b"\n")


if __name__ == "__main__":
    main()
