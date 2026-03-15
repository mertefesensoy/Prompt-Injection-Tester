"""
Deep Investigation of High-Risk Steganography Findings
Validates findings from pixel_entropy_scanner.py by separating true anomalies
from false positives caused by repeated constants, sparse images, etc.

Verdicts per finding:
  CONFIRMED      - Anomaly persists after all false-positive filters
  FALSE_POSITIVE - Explained by repeated constants or image sparsity
  INFORMATIONAL  - Not steganography but a noteworthy separate anomaly
  NEEDS_REVIEW   - Ambiguous; manual forensic inspection required

Usage: python deep_investigate.py <pdf_path> [options]
"""

import sys
import os
import re
import io
import json
import math
import struct
import argparse
import datetime
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple

# ── Dependencies ──────────────────────────────────────────────────────────────
try:
    import fitz
except ImportError:
    print("ERROR: pymupdf not installed. Run: pip install pymupdf", file=sys.stderr)
    sys.exit(1)

try:
    from PIL import Image
    import numpy as np
    IMAGING_AVAILABLE = True
except ImportError:
    IMAGING_AVAILABLE = False

# ── ANSI colors ───────────────────────────────────────────────────────────────
RESET   = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
RED     = "\033[91m"
YELLOW  = "\033[93m"
GREEN   = "\033[92m"
CYAN    = "\033[96m"
MAGENTA = "\033[95m"
BLUE    = "\033[94m"

VERDICT_COLORS = {
    "CONFIRMED":      RED,
    "FALSE_POSITIVE": GREEN,
    "INFORMATIONAL":  YELLOW,
    "NEEDS_REVIEW":   MAGENTA,
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def safe_print(text: str):
    try:
        print(text)
    except UnicodeEncodeError:
        encoded = text.encode(sys.stdout.encoding or "ascii", errors="replace")
        sys.stdout.buffer.write(encoded)
        sys.stdout.buffer.write(b"\n")


def _c(color: str, text: str, use_color: bool) -> str:
    return (color + text + RESET) if use_color else text


def _bar(score: float, width: int = 18) -> str:
    filled = max(0, min(int(round(score * width)), width))
    return "[" + "#" * filled + "." * (width - filled) + "]"


def _box_top(width: int = 68) -> str:
    return "  +" + "-" * (width - 4) + "+"


def _box_mid(text: str, width: int = 68) -> str:
    inner = width - 6
    return "  | " + text[:inner].ljust(inner) + " |"


def _box_bot(width: int = 68) -> str:
    return "  +" + "-" * (width - 4) + "+"


def _lsb_chi_square(floats: List[float]) -> Tuple[float, int, int]:
    """Returns (score 0-1, ones_count, zeros_count)."""
    lsbs = []
    for v in floats:
        try:
            packed   = struct.pack('>f', v)
            int_repr = struct.unpack('>I', packed)[0]
            lsbs.append(int_repr & 0x1)
        except (struct.error, OverflowError):
            pass
    if len(lsbs) < 2:
        return 0.0, 0, 0
    ones     = sum(lsbs)
    zeros    = len(lsbs) - ones
    n        = len(lsbs)
    expected = n / 2.0
    chi2     = ((ones - expected) ** 2 + (zeros - expected) ** 2) / expected
    return min(chi2 / 10.0, 1.0), ones, zeros


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class SubAnomaly:
    """A secondary finding within a primary anomaly (e.g., invisible clip rect)."""
    anomaly_type: str
    verdict: str
    description: str
    details: List[str] = field(default_factory=list)


@dataclass
class InvestigationResult:
    xref: int
    finding_type: str          # "stream" | "image"
    original_score: float
    verdict: str               # CONFIRMED | FALSE_POSITIVE | INFORMATIONAL | NEEDS_REVIEW
    verdict_reason: str
    details: List[str] = field(default_factory=list)
    sub_anomalies: List[SubAnomaly] = field(default_factory=list)
    evidence: dict = field(default_factory=dict)


# ── Stream Analyzer ───────────────────────────────────────────────────────────

class ConstantAwareLSBAnalyzer:

    FLOAT_RE    = re.compile(rb'(-?\d+\.\d{3,})')
    BDC_RE      = re.compile(rb'<<[^>]*/MCID\s+(\d+)[^>]*>>\s*BDC(.*?)EMC', re.DOTALL)
    TM_RE       = re.compile(rb'([-\d.]+)\s+([-\d.]+)\s+([-\d.]+)\s+([-\d.]+)\s+([-\d.]+)\s+([-\d.]+)\s+Tm')
    TD_RE       = re.compile(rb'([-\d.]+)\s+([-\d.]+)\s+T[dD]')
    TJ_RE       = re.compile(rb'\[([^\]]*)\]\s*TJ')
    Tj_RE       = re.compile(rb'\(([^)]*)\)\s*Tj')
    TR_RE       = re.compile(rb'(\d+)\s+Tr\b')
    CLIP_RE     = re.compile(
        rb'([-\d.]+)\s+([-\d.]+)\s+([-\d.]+)\s+([-\d.]+)\s+re\s*[\r\n\s]*W\*?\s+n'
    )

    CONSTANT_DOMINANCE_THRESHOLD  = 0.30   # value appearing >30% of floats = constant
    CHI2_THRESHOLD                = 0.38   # normalized chi2 score (p<0.05)
    STRUCTURED_COORD_UNIQUE_RATIO = 0.25   # if <25% unique values → structured coordinates

    def analyze(self, stream_bytes: bytes, lsb_threshold: float = 0.5) -> dict:
        """
        Returns a dict with keys:
          original_chi2, dominant_constants, clean_chi2, clean_ones, clean_zeros,
          verdict, verdict_reason, clipping_rects, mcid_blocks, text_content
        """
        float_matches = self.FLOAT_RE.findall(stream_bytes)
        floats = []
        for m in float_matches:
            try:
                floats.append(float(m))
            except ValueError:
                pass

        if len(floats) < 5:
            return {"verdict": "NEEDS_REVIEW", "verdict_reason": "Too few floats to analyze"}

        total = len(floats)
        original_chi2, orig_ones, orig_zeros = _lsb_chi_square(floats)

        # ── Group by exact value ──────────────────────────────────────────────
        value_counts = Counter(floats)
        dominant     = {
            v: cnt for v, cnt in value_counts.items()
            if cnt / total >= self.CONSTANT_DOMINANCE_THRESHOLD
        }

        # ── Clean floats = remove dominant constants ──────────────────────────
        clean_floats = [v for v in floats if v not in dominant]
        if clean_floats:
            clean_chi2, clean_ones, clean_zeros = _lsb_chi_square(clean_floats)
        else:
            clean_chi2, clean_ones, clean_zeros = 0.0, 0, 0

        # ── Second-level: are clean floats also structured coordinates? ──────
        # If the "clean" floats are themselves a small set of repeating values
        # (e.g. only 6 unique values out of 37), they are PDF coordinates,
        # not a payload. True steganographic LSB data has high unique-value density.
        clean_value_counts = Counter(clean_floats)
        clean_unique_ratio = (
            len(clean_value_counts) / max(len(clean_floats), 1)
            if clean_floats else 0.0
        )
        clean_is_structured = (
            clean_unique_ratio < self.STRUCTURED_COORD_UNIQUE_RATIO
            and len(clean_value_counts) < 20
        )

        # ── Verdict ───────────────────────────────────────────────────────────
        if original_chi2 >= lsb_threshold and dominant:
            if clean_chi2 < self.CHI2_THRESHOLD:
                verdict = "FALSE_POSITIVE"
                reason  = (
                    f"{sum(dominant.values())} of {total} floats "
                    f"({100*sum(dominant.values())/total:.1f}%) are dominant constants. "
                    f"Chi2 on remaining {len(clean_floats)} floats = {clean_chi2:.4f} "
                    f"(below {self.CHI2_THRESHOLD} threshold). "
                    f"LSB anomaly driven entirely by constant repetition."
                )
            elif clean_is_structured:
                verdict = "FALSE_POSITIVE"
                reason  = (
                    f"After removing dominant constants, remaining {len(clean_floats)} floats "
                    f"have only {len(clean_value_counts)} unique values "
                    f"(unique ratio={clean_unique_ratio:.2f} < {self.STRUCTURED_COORD_UNIQUE_RATIO}). "
                    f"These are repeating PDF coordinate/font-size values, not embedded payload data. "
                    f"Chi2={clean_chi2:.4f} is skewed by structured PDF coordinate patterns."
                )
            elif clean_chi2 >= 0.7:
                verdict = "CONFIRMED"
                reason  = (
                    f"After removing {sum(dominant.values())} constant floats, "
                    f"remaining {len(clean_floats)} floats have "
                    f"{len(clean_value_counts)} unique values "
                    f"(unique ratio={clean_unique_ratio:.2f}) and "
                    f"chi2={clean_chi2:.4f} — genuinely non-random LSB distribution."
                )
            else:
                verdict = "NEEDS_REVIEW"
                reason  = (
                    f"Dominant constants present ({sum(dominant.values())}/{total}), "
                    f"but clean chi2={clean_chi2:.4f} is ambiguous "
                    f"(threshold: {self.CHI2_THRESHOLD}). "
                    f"Clean floats: {len(clean_value_counts)} unique out of {len(clean_floats)}."
                )
        elif original_chi2 < lsb_threshold:
            verdict = "FALSE_POSITIVE"
            reason  = f"Original chi2 score {original_chi2:.4f} already below threshold {lsb_threshold}."
        else:
            verdict = "CONFIRMED"
            reason  = (
                f"Chi2={original_chi2:.4f} with no dominant constants. "
                f"LSB distribution is genuinely non-random."
            )

        # ── Clipping rect analysis ────────────────────────────────────────────
        clipping_rects = self._extract_clipping_rects(stream_bytes)

        # ── MCID content blocks ───────────────────────────────────────────────
        mcid_blocks = self._decode_mcid_blocks(stream_bytes)

        # ── Plain text content ────────────────────────────────────────────────
        text_content = self._extract_plain_text(stream_bytes)

        return {
            "total_floats":        total,
            "original_chi2":       round(original_chi2, 4),
            "original_ones":       orig_ones,
            "original_zeros":      orig_zeros,
            "dominant_constants":  {str(k): v for k, v in dominant.items()},
            "clean_float_count":   len(clean_floats),
            "clean_chi2":          round(clean_chi2, 4),
            "clean_ones":          clean_ones,
            "clean_zeros":         clean_zeros,
            "unique_values":       len(value_counts),
            "top_values": [
                {
                    "value":       v,
                    "count":       cnt,
                    "pct":         round(cnt / total * 100, 1),
                    "lsb":         struct.unpack('>I', struct.pack('>f', v))[0] & 1,
                }
                for v, cnt in value_counts.most_common(10)
            ],
            "verdict":        verdict,
            "verdict_reason": reason,
            "clipping_rects": clipping_rects,
            "mcid_blocks":    mcid_blocks,
            "text_content":   text_content,
        }

    def _extract_clipping_rects(self, stream_bytes: bytes) -> List[dict]:
        results = []
        for m in self.CLIP_RE.finditer(stream_bytes):
            try:
                x, y, w, h = (float(m.group(i)) for i in range(1, 5))
                is_subpixel = abs(x) < 0.01 or abs(y) < 0.01
                results.append({
                    "x": x, "y": y, "width": w, "height": h,
                    "is_subpixel": is_subpixel,
                    "snippet": stream_bytes[max(0, m.start()-5):m.end()+10].decode(
                        "latin-1", errors="replace"
                    ).replace("\r\n", " ").replace("\n", " ")[:80],
                })
            except (ValueError, struct.error):
                pass
        return results

    def _decode_mcid_blocks(self, stream_bytes: bytes) -> List[dict]:
        blocks = []
        for m in self.BDC_RE.finditer(stream_bytes):
            mcid_num = int(m.group(1))
            content  = m.group(2)

            # Extract text position (last Tm or Td in block)
            pos = None
            for tm in self.TM_RE.finditer(content):
                try:
                    pos = (float(tm.group(5)), float(tm.group(6)))
                except ValueError:
                    pass
            if pos is None:
                for td in self.TD_RE.finditer(content):
                    try:
                        pos = (float(td.group(1)), float(td.group(2)))
                    except ValueError:
                        pass

            # Extract text rendering mode
            tr_mode = 0
            tr_m = self.TR_RE.search(content)
            if tr_m:
                tr_mode = int(tr_m.group(1))

            # Extract text strings
            texts = []
            for tj in self.TJ_RE.finditer(content):
                raw = tj.group(1)
                # Extract string literals from TJ array
                for s in re.finditer(rb'\(([^)]*)\)', raw):
                    try:
                        decoded = s.group(1).decode("latin-1", errors="replace")
                        if decoded.strip():
                            texts.append(decoded)
                    except Exception:
                        pass
            for tj in self.Tj_RE.finditer(content):
                try:
                    decoded = tj.group(1).decode("latin-1", errors="replace")
                    if decoded.strip():
                        texts.append(decoded)
                except Exception:
                    pass

            # Check for invisible clipping rect in this block
            has_subpixel_clip = bool(self.CLIP_RE.search(content))

            rendered_text = " ".join(texts).strip() or "[empty/space]"

            blocks.append({
                "mcid":             mcid_num,
                "position":         pos,
                "text_render_mode": tr_mode,
                "invisible":        tr_mode == 3,
                "has_subpixel_clip": has_subpixel_clip,
                "rendered_text":    rendered_text[:120],
            })
        return blocks

    def _extract_plain_text(self, stream_bytes: bytes) -> str:
        """Extract all readable strings from TJ/Tj operators."""
        parts = []
        for m in self.TJ_RE.finditer(stream_bytes):
            for s in re.finditer(rb'\(([^)]*)\)', m.group(1)):
                try:
                    t = s.group(1).decode("latin-1", errors="replace").strip()
                    if t:
                        parts.append(t)
                except Exception:
                    pass
        for m in self.Tj_RE.finditer(stream_bytes):
            try:
                t = m.group(1).decode("latin-1", errors="replace").strip()
                if t:
                    parts.append(t)
            except Exception:
                pass
        return " ".join(parts)[:500]


# ── Image Checker ─────────────────────────────────────────────────────────────

class ImageFalsePositiveChecker:

    SPARSITY_THRESHOLD    = 0.50   # >50% near-zero pixels = sparse image
    AUTOCORR_FP_THRESHOLD = 0.80   # autocorr >0.80 = highly autocorrelated = likely sparse

    def analyze(self, doc, xref: int, page_idx: int) -> dict:
        if not IMAGING_AVAILABLE:
            return {"verdict": "NEEDS_REVIEW", "verdict_reason": "numpy/Pillow not available"}

        try:
            base      = doc.extract_image(xref)
            img_bytes = base.get("image", b"")
            img       = Image.open(io.BytesIO(img_bytes)).convert("L")
        except Exception as e:
            return {"verdict": "NEEDS_REVIEW", "verdict_reason": f"Could not load image: {e}"}

        arr      = np.array(img, dtype=np.float32)
        arr_u8   = arr.clip(0, 255).astype(np.uint8)
        lsb      = arr_u8 & 1

        sparsity     = self._sparsity_check(arr)
        autocorr     = self._lsb_spatial_autocorrelation(lsb)
        lsb_ones_ratio = float(lsb.mean())
        deviation    = abs(lsb_ones_ratio - 0.5)

        # LSB ASCII visualization
        lsb_ascii = self._render_lsb_ascii(lsb, w=40)

        # ── Verdict ───────────────────────────────────────────────────────────
        if sparsity > self.SPARSITY_THRESHOLD and autocorr > self.AUTOCORR_FP_THRESHOLD:
            verdict = "FALSE_POSITIVE"
            reason  = (
                f"Image is sparse (sparsity={sparsity:.2f}, {sparsity*100:.0f}% "
                f"near-zero pixels). "
                f"LSB spatial autocorrelation={autocorr:.4f} (>0.80 = uniform runs, "
                f"consistent with logo/icon rather than steganographic payload)."
            )
        elif deviation > 0.40:
            verdict = "FALSE_POSITIVE"
            reason  = (
                f"LSB ones-ratio={lsb_ones_ratio:.4f} is far from 0.5 "
                f"(deviation={deviation:.4f}), indicating highly non-uniform image "
                f"(e.g. mostly white or mostly black). "
                f"Steganographic LSB embedding would produce ratio closer to 0.5."
            )
        elif 0.3 <= autocorr <= 0.75 and deviation < 0.15:
            verdict = "NEEDS_REVIEW"
            reason  = (
                f"Autocorrelation={autocorr:.4f} and ones-ratio={lsb_ones_ratio:.4f} "
                f"are in a range consistent with either a textured natural image "
                f"or an embedded payload. Manual inspection recommended."
            )
        elif autocorr < 0.25 and deviation < 0.05:
            verdict = "CONFIRMED"
            reason  = (
                f"Near-random LSB plane: autocorr={autocorr:.4f} (low = random-like), "
                f"ones-ratio={lsb_ones_ratio:.4f} (close to 0.5 = uniform distribution). "
                f"This combination is consistent with embedded payload data."
            )
        else:
            verdict = "FALSE_POSITIVE"
            reason  = (
                f"LSB characteristics (autocorr={autocorr:.4f}, "
                f"ones-ratio={lsb_ones_ratio:.4f}) are consistent with a "
                f"natural image. No steganographic signature confirmed."
            )

        # Check for DCT-style uniform sign bits if JPEG
        fmt = base.get("ext", "").upper()
        dct_note = ""
        if fmt in ("JPEG", "JPG"):
            dct_note = "JPEG image — DCT sign-bit analysis: see pixel_entropy_scanner.py output."

        return {
            "xref":             xref,
            "page":             page_idx + 1,
            "dimensions":       f"{img.width}x{img.height}",
            "format":           fmt,
            "sparsity":         round(sparsity, 4),
            "autocorrelation":  round(autocorr, 4),
            "lsb_ones_ratio":   round(lsb_ones_ratio, 4),
            "deviation_from_half": round(deviation, 4),
            "lsb_ascii":        lsb_ascii,
            "dct_note":         dct_note,
            "verdict":          verdict,
            "verdict_reason":   reason,
        }

    def _sparsity_check(self, arr: np.ndarray) -> float:
        """Fraction of pixels with value < 10 (essentially zero/black)."""
        return float((arr < 10).sum() / arr.size)

    def _lsb_spatial_autocorrelation(self, lsb_plane: np.ndarray) -> float:
        """Lag-1 autocorrelation of the flattened LSB plane."""
        flat = lsb_plane.flatten().astype(np.float32)
        if len(flat) < 2:
            return 1.0
        mean  = float(flat.mean())
        var   = float(np.var(flat))
        if var < 1e-9:
            return 1.0  # constant → fully autocorrelated
        cov = float(np.mean((flat[:-1] - mean) * (flat[1:] - mean)))
        return max(-1.0, min(1.0, cov / var))

    def _render_lsb_ascii(self, lsb_plane: np.ndarray, w: int = 40) -> str:
        """Downsample LSB plane to w×h ASCII art using '#' for 1 and '.' for 0."""
        h_full, w_full = lsb_plane.shape
        if w_full == 0 or h_full == 0:
            return ""

        h = max(1, int(w * h_full / w_full / 2))  # /2 because terminal chars are ~2:1
        step_w = max(1, w_full // w)
        step_h = max(1, h_full // h)

        lines = []
        lines.append("  +" + "-" * w + "+")
        for row in range(min(h, h_full // step_h)):
            chunk = lsb_plane[
                row * step_h: row * step_h + step_h,
                0: step_w * w,
            ]
            if chunk.size == 0:
                continue
            # For each column block, check if majority of pixels are 1
            row_chars = []
            for col in range(min(w, w_full // step_w)):
                block = chunk[:, col * step_w: (col + 1) * step_w]
                if block.size == 0:
                    row_chars.append(" ")
                else:
                    row_chars.append("#" if block.mean() > 0.5 else ".")
            lines.append("  |" + "".join(row_chars) + "|")
        lines.append("  +" + "-" * w + "+")
        return "\n".join(lines)


# ── Orchestrator ──────────────────────────────────────────────────────────────

class DeepInvestigator:

    def __init__(
        self,
        pdf_path: str,
        report_json_path: str = "",
        lsb_threshold: float = 0.5,
        include_all_risk: bool = False,
        target_xrefs: Optional[List[int]] = None,
    ):
        self.pdf_path         = pdf_path
        self.report_json      = self._load_report(report_json_path)
        self.lsb_threshold    = lsb_threshold
        self.include_all_risk = include_all_risk
        self.target_xrefs     = target_xrefs or []
        self.doc              = None

    def _load_report(self, path: str) -> Optional[dict]:
        if path and os.path.isfile(path):
            try:
                with open(path, "rb") as f:
                    return json.load(f)
            except Exception:
                pass
        return None

    def run(self) -> List[InvestigationResult]:
        self.doc = fitz.open(self.pdf_path)

        stream_xrefs = self._collect_stream_xrefs()
        image_xrefs  = self._collect_image_xrefs()

        results: List[InvestigationResult] = []

        stream_analyzer = ConstantAwareLSBAnalyzer()
        image_checker   = ImageFalsePositiveChecker()

        # ── Streams ───────────────────────────────────────────────────────────
        for xref, orig_score in stream_xrefs:
            try:
                stream_bytes = self.doc.xref_stream(xref)
            except Exception:
                continue
            if not stream_bytes:
                continue

            analysis = stream_analyzer.analyze(stream_bytes, self.lsb_threshold)

            # Build sub-anomalies for clipping rects
            sub_anomalies: List[SubAnomaly] = []
            clip_rects = analysis.get("clipping_rects", [])
            subpixel_clips = [c for c in clip_rects if c["is_subpixel"]]

            if subpixel_clips:
                clip_details = [
                    f"  x={c['x']} y={c['y']} w={c['width']:.2f} h={c['height']:.2f} | "
                    f"snippet: {c['snippet']}"
                    for c in subpixel_clips[:5]
                ]
                sub_anomalies.append(SubAnomaly(
                    anomaly_type = "subpixel_clipping_rectangle",
                    verdict      = "INFORMATIONAL",
                    description  = (
                        f"{len(subpixel_clips)} sub-pixel clipping rectangle(s) found "
                        f"({len(subpixel_clips)}/{len(clip_rects)} total clips). "
                        f"Pattern: tiny x/y offset followed by full-page W*/n clip. "
                        f"This is a known vector for hiding content outside the visible area."
                    ),
                    details = clip_details,
                ))

            # Build MCID block summary
            mcid_blocks   = analysis.get("mcid_blocks", [])
            invisible_mcid = [b for b in mcid_blocks if b["invisible"]]
            space_only_mcid = [
                b for b in mcid_blocks
                if b["rendered_text"] in ("[empty/space]", " ", "( )")
            ]

            detail_lines = []
            # Constant analysis table
            for entry in analysis.get("top_values", [])[:8]:
                detail_lines.append(
                    f"  {entry['value']:>16.9f}  x{entry['count']:>3}  "
                    f"({entry['pct']:>5.1f}%)  LSB={entry['lsb']}"
                )
            detail_lines.append(
                f"  --- chi2 on {analysis.get('clean_float_count',0)} "
                f"non-constant floats: {analysis.get('clean_chi2', 0):.4f} "
                f"({'BELOW' if analysis.get('clean_chi2',0) < self.lsb_threshold else 'ABOVE'} "
                f"threshold {self.lsb_threshold})"
            )

            # Text content summary
            text = analysis.get("text_content", "").strip()
            if text:
                detail_lines.append(f"  Decoded text: {repr(text[:200])}")
            elif mcid_blocks:
                rendered = [b["rendered_text"] for b in mcid_blocks[:5]]
                detail_lines.append(f"  MCID sample texts: {rendered}")

            # Invisible/space-only MCID blocks
            if space_only_mcid:
                detail_lines.append(
                    f"  {len(space_only_mcid)} of {len(mcid_blocks)} MCID blocks "
                    f"render only whitespace/empty content"
                )
            if invisible_mcid:
                detail_lines.append(
                    f"  {len(invisible_mcid)} MCID block(s) use text render mode 3 "
                    f"(invisible — text exists but is not painted)"
                )

            results.append(InvestigationResult(
                xref          = xref,
                finding_type  = "stream",
                original_score = orig_score,
                verdict        = analysis["verdict"],
                verdict_reason = analysis["verdict_reason"],
                details        = detail_lines,
                sub_anomalies  = sub_anomalies,
                evidence       = {
                    k: v for k, v in analysis.items()
                    if k not in ("clipping_rects", "mcid_blocks", "text_content",
                                 "verdict", "verdict_reason")
                },
            ))

        # ── Images ────────────────────────────────────────────────────────────
        for xref, orig_score, page_idx in image_xrefs:
            analysis = image_checker.analyze(self.doc, xref, page_idx)

            detail_lines = [
                f"  Dimensions    : {analysis.get('dimensions')}  format={analysis.get('format')}",
                f"  Sparsity      : {analysis.get('sparsity'):.4f}  "
                f"({analysis.get('sparsity',0)*100:.1f}% near-zero pixels)",
                f"  Autocorrelation (LSB): {analysis.get('autocorrelation'):.4f}  "
                f"(>0.80 = sparse/logo, <0.25 = random-like)",
                f"  LSB ones-ratio: {analysis.get('lsb_ones_ratio'):.4f}  "
                f"(deviation from 0.5 = {analysis.get('deviation_from_half'):.4f})",
            ]
            if analysis.get("dct_note"):
                detail_lines.append(f"  {analysis['dct_note']}")

            lsb_ascii = analysis.get("lsb_ascii", "")

            results.append(InvestigationResult(
                xref           = xref,
                finding_type   = "image",
                original_score = orig_score,
                verdict        = analysis["verdict"],
                verdict_reason = analysis["verdict_reason"],
                details        = detail_lines + (
                    ["\n  LSB Plane visualization (# = 1-bit, . = 0-bit):"]
                    + ["  " + line for line in lsb_ascii.split("\n")]
                    if lsb_ascii else []
                ),
                evidence       = {
                    k: v for k, v in analysis.items()
                    if k != "lsb_ascii"
                },
            ))

        return results

    def _collect_stream_xrefs(self) -> List[Tuple[int, float]]:
        """Collect (xref, original_score) for streams to investigate."""
        xrefs = []

        if self.report_json:
            for s in self.report_json.get("stream_reports", []):
                score = s.get("risk_score", 0)
                xref  = s.get("xref", -1)
                if xref <= 0:
                    continue
                if self.target_xrefs and xref not in self.target_xrefs:
                    continue
                if score >= 0.5 or self.include_all_risk:
                    xrefs.append((xref, score))
        else:
            # Self-scan
            FLOAT_RE = re.compile(rb'(-?\d+\.\d{3,})')
            for xref in range(1, self.doc.xref_length()):
                if self.target_xrefs and xref not in self.target_xrefs:
                    continue
                try:
                    sb = self.doc.xref_stream(xref)
                except Exception:
                    continue
                if not sb:
                    continue
                floats = [float(m) for m in FLOAT_RE.findall(sb) if len(m) <= 15]
                if len(floats) < 10:
                    continue
                score, _, _ = _lsb_chi_square(floats)
                if score >= self.lsb_threshold or self.include_all_risk:
                    xrefs.append((xref, round(score, 4)))

        return sorted(xrefs, key=lambda x: -x[1])

    def _collect_image_xrefs(self) -> List[Tuple[int, float, int]]:
        """Collect (xref, original_score, page_idx) for images to investigate."""
        xrefs = []
        seen  = set()

        if self.report_json:
            img_xref_scores = {
                r["xref"]: r.get("risk_score", 0)
                for r in self.report_json.get("image_reports", [])
                if (r.get("risk_score", 0) >= 0.25 or self.include_all_risk)
            }
        else:
            img_xref_scores = {}  # will accept all images

        for page_idx, page in enumerate(self.doc):
            for img_info in page.get_images(full=True):
                xref = img_info[0]
                if xref in seen or xref <= 0:
                    continue
                if self.target_xrefs and xref not in self.target_xrefs:
                    continue

                if self.report_json:
                    if xref not in img_xref_scores:
                        continue
                    score = img_xref_scores[xref]
                else:
                    score = 0.5  # unknown, include for inspection

                seen.add(xref)
                xrefs.append((xref, score, page_idx))

        return sorted(xrefs, key=lambda x: -x[1])


# ── Report Renderer ───────────────────────────────────────────────────────────

class InvestigationRenderer:

    def __init__(
        self,
        results: List[InvestigationResult],
        pdf_path: str,
        report_source: str = "",
        use_color: bool = True,
    ):
        self.results       = results
        self.pdf_path      = pdf_path
        self.report_source = report_source
        self.use_color     = use_color

    def _vc(self, verdict: str, text: str = "") -> str:
        if not self.use_color:
            return text or verdict
        col = VERDICT_COLORS.get(verdict, "")
        return col + (text or verdict) + RESET

    def render_terminal(self) -> str:
        bold  = BOLD  if self.use_color else ""
        dim   = DIM   if self.use_color else ""
        reset = RESET if self.use_color else ""
        lines = []

        # ── Header ────────────────────────────────────────────────────────────
        lines.append("=" * 70)
        lines.append(f"{bold}  Deep Investigation Report - High-Risk Findings{reset}")
        src = f"  | Findings from: {self.report_source}" if self.report_source else ""
        lines.append(f"  Source: {os.path.basename(self.pdf_path)}{src}")
        lines.append("=" * 70)

        # ── Per-finding ───────────────────────────────────────────────────────
        for r in self.results:
            type_label = "STREAM" if r.finding_type == "stream" else "IMAGE"
            v_col = VERDICT_COLORS.get(r.verdict, "") if self.use_color else ""

            lines.append(
                f"\n{bold}[{type_label} xref={r.xref}]{reset}  "
                f"Original score: {_bar(r.original_score, 12)} {r.original_score:.4f}"
            )
            lines.append(
                f"  Verdict: {v_col}{bold}{r.verdict}{reset}"
            )
            lines.append(f"  Reason:  {r.verdict_reason}")

            if r.details:
                lines.append("")
                lines.append(_box_top())
                lines.append(_box_mid(f"  {'Stream Analysis' if r.finding_type == 'stream' else 'Image Analysis'}"))
                lines.append(_box_mid(""))
                for d in r.details:
                    # Handle multi-line detail entries
                    for sub_line in d.split("\n"):
                        lines.append(_box_mid(sub_line))
                lines.append(_box_bot())

            for sub in r.sub_anomalies:
                sub_v_col = VERDICT_COLORS.get(sub.verdict, "") if self.use_color else ""
                lines.append("")
                lines.append(_box_top())
                lines.append(_box_mid(
                    f"  SEPARATE ANOMALY: {sub.anomaly_type.upper().replace('_', ' ')}"
                ))
                lines.append(_box_mid(
                    f"  Verdict: {sub_v_col}{sub.verdict}{reset}"
                ))
                lines.append(_box_mid(""))
                for sub_line in sub.description.split(". "):
                    if sub_line.strip():
                        lines.append(_box_mid(f"  {sub_line.strip()}."))
                if sub.details:
                    lines.append(_box_mid(""))
                    lines.append(_box_mid("  Examples:"))
                    for d in sub.details[:3]:
                        lines.append(_box_mid(d))
                lines.append(_box_bot())

        # ── Summary ───────────────────────────────────────────────────────────
        counts = Counter(r.verdict for r in self.results)
        sub_counts = Counter(
            s.verdict
            for r in self.results
            for s in r.sub_anomalies
        )

        lines.append(f"\n{'=' * 70}")
        lines.append(f"{bold}  SUMMARY{reset}")
        lines.append("=" * 70)
        lines.append(f"\n  Primary findings ({len(self.results)} investigated):")
        for verdict, count in sorted(counts.items()):
            col = VERDICT_COLORS.get(verdict, "") if self.use_color else ""
            lines.append(f"    {col}{verdict:<20}{reset}  {count}")
        if sub_counts:
            lines.append(f"\n  Secondary / sub-anomalies ({sum(sub_counts.values())} total):")
            for verdict, count in sorted(sub_counts.items()):
                col = VERDICT_COLORS.get(verdict, "") if self.use_color else ""
                lines.append(f"    {col}{verdict:<20}{reset}  {count}")

        confirmed = counts.get("CONFIRMED", 0)
        info      = sub_counts.get("INFORMATIONAL", 0)
        if confirmed == 0 and info == 0:
            lines.append(
                f"\n  {self._vc('FALSE_POSITIVE', 'All primary findings are false positives.')}"
            )
            lines.append(
                f"  {dim}No steganographic payload evidence found in this document.{reset}"
            )
        elif confirmed == 0 and info > 0:
            lines.append(
                f"\n  {self._vc('INFORMATIONAL', 'No confirmed steganography.')}"
                f"  {info} informational anomaly(ies) warrant attention."
            )
        else:
            lines.append(
                f"\n  {self._vc('CONFIRMED', f'{confirmed} CONFIRMED anomaly(ies).')} "
                f"Immediate forensic review required."
            )
        lines.append("=" * 70 + "\n")
        return "\n".join(lines)

    def render_json(self) -> str:
        output = {
            "schema_version": "1.0",
            "file":           os.path.basename(self.pdf_path),
            "path":           os.path.abspath(self.pdf_path),
            "scan_timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "summary": {
                v: sum(1 for r in self.results if r.verdict == v)
                for v in ("CONFIRMED", "FALSE_POSITIVE", "INFORMATIONAL", "NEEDS_REVIEW")
            },
            "findings": [
                {
                    "xref":           r.xref,
                    "type":           r.finding_type,
                    "original_score": r.original_score,
                    "verdict":        r.verdict,
                    "verdict_reason": r.verdict_reason,
                    "details":        r.details,
                    "evidence":       r.evidence,
                    "sub_anomalies":  [
                        {
                            "type":        s.anomaly_type,
                            "verdict":     s.verdict,
                            "description": s.description,
                            "details":     s.details,
                        }
                        for s in r.sub_anomalies
                    ],
                }
                for r in self.results
            ],
        }
        return json.dumps(output, indent=2, default=str)


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Deep investigation of high-risk steganography findings",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Verdicts:
  CONFIRMED      - Genuine anomaly surviving all false-positive filters
  FALSE_POSITIVE - Explained by repeated constants or image sparsity
  INFORMATIONAL  - Secondary anomaly (e.g. sub-pixel clipping coordinates)
  NEEDS_REVIEW   - Ambiguous; human forensic inspection required

Examples:
  python deep_investigate.py HW1.pdf
  python deep_investigate.py HW1.pdf --report steg_report.json
  python deep_investigate.py HW1.pdf --xref 4,27
  python deep_investigate.py HW1.pdf --all --json > deep_report.json
""",
    )
    parser.add_argument("pdf_path",         help="PDF file to investigate")
    parser.add_argument("--report",         default="steg_report.json",
                        help="Pre-computed pixel_entropy_scanner JSON report (default: steg_report.json)")
    parser.add_argument("--json",           action="store_true", help="Output JSON")
    parser.add_argument("--no-color",       action="store_true", help="Disable ANSI colors")
    parser.add_argument("--all",            action="store_true", help="Include LOW/MEDIUM findings")
    parser.add_argument("--xref",           default="",
                        help="Comma-separated xref numbers to investigate (e.g. 4,27)")
    parser.add_argument("--threshold",      type=float, default=0.5,
                        help="LSB chi2 threshold for self-scan mode (default 0.5)")
    args = parser.parse_args()

    if not os.path.isfile(args.pdf_path):
        print(f"Error: File not found: {args.pdf_path}", file=sys.stderr)
        sys.exit(2)

    target_xrefs: List[int] = []
    if args.xref:
        try:
            target_xrefs = [int(x.strip()) for x in args.xref.split(",")]
        except ValueError:
            print("Error: --xref must be comma-separated integers", file=sys.stderr)
            sys.exit(2)

    # Determine report path
    report_path = args.report
    if not os.path.isfile(report_path):
        # Try same directory as PDF
        alt = os.path.join(os.path.dirname(args.pdf_path), args.report)
        if os.path.isfile(alt):
            report_path = alt
        else:
            report_path = ""

    investigator = DeepInvestigator(
        pdf_path         = args.pdf_path,
        report_json_path = report_path,
        lsb_threshold    = args.threshold,
        include_all_risk = args.all,
        target_xrefs     = target_xrefs,
    )

    try:
        results = investigator.run()
    except Exception as e:
        print(f"Fatal error: {e}", file=sys.stderr)
        sys.exit(2)

    if not results:
        print("No findings to investigate. Run pixel_entropy_scanner.py first, "
              "or use --all to include lower-risk items.", file=sys.stderr)
        sys.exit(0)

    use_color = not args.no_color and not args.json
    renderer  = InvestigationRenderer(
        results       = results,
        pdf_path      = args.pdf_path,
        report_source = os.path.basename(report_path) if report_path else "self-scan",
        use_color     = use_color,
    )

    if args.json:
        output_bytes = renderer.render_json().encode("utf-8")
        sys.stdout.buffer.write(output_bytes)
        sys.stdout.buffer.write(b"\n")
    else:
        safe_print(renderer.render_terminal())

    confirmed = sum(1 for r in results if r.verdict == "CONFIRMED")
    sys.exit(1 if confirmed > 0 else 0)


if __name__ == "__main__":
    main()
