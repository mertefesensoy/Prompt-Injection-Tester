"""
Pixel-Level Entropy & Steganography Scanner
Detailed analysis of embedded images and PDF content streams for hidden payloads.

Covers:
  - Per-image 8x8 entropy/edge heatmap
  - RGB per-channel analysis
  - JPEG DCT coefficient anomaly detection
  - LSB bit-plane extraction and pattern analysis
  - Contrast-enhanced image export to reveal hidden overlays
  - Per-stream operator-level float breakdown
  - Full 23-bit mantissa distribution analysis
  - LSB bitstream ASCII decode attempt
  - ASCII float value histogram

Usage: python pixel_entropy_scanner.py <pdf_path> [options]
"""

import sys
import os
import io
import re
import json
import math
import struct
import argparse
import datetime
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple

# ── Dependency checks ─────────────────────────────────────────────────────────
try:
    import fitz
    FITZ_AVAILABLE = True
except ImportError:
    FITZ_AVAILABLE = False
    print("ERROR: pymupdf not installed. Run: pip install pymupdf", file=sys.stderr)
    sys.exit(1)

try:
    from PIL import Image, ImageFilter, ImageEnhance, ImageOps
    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False
    print("ERROR: Pillow not installed. Run: pip install pillow", file=sys.stderr)
    sys.exit(1)

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    print("ERROR: numpy not installed. Run: pip install numpy", file=sys.stderr)
    sys.exit(1)

# ── Constants ─────────────────────────────────────────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
MAGENTA= "\033[95m"
BLUE   = "\033[94m"

RISK_LABELS  = {0: "NONE", 1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}
RISK_COLORS  = {0: GREEN, 1: CYAN, 2: YELLOW, 3: RED, 4: MAGENTA}

# PDF drawing operators that carry coordinate/size floats
PDF_FLOAT_OPERATORS = {
    b'm':   'moveto',
    b'l':   'lineto',
    b'c':   'curveto',
    b'v':   'curveto-v',
    b'y':   'curveto-y',
    b're':  'rectangle',
    b'w':   'linewidth',
    b'Td':  'text-move',
    b'TD':  'text-move-leading',
    b'Tm':  'text-matrix',
    b'cm':  'concat-matrix',
    b'Tf':  'font-size',
    b'Tc':  'char-spacing',
    b'Tw':  'word-spacing',
    b'Tz':  'horizontal-scale',
    b'TL':  'leading',
    b'Ts':  'text-rise',
    b'scn': 'color-nonstroke',
    b'SCN': 'color-stroke',
    b'sc':  'color-nonstroke-simple',
    b'SC':  'color-stroke-simple',
    b'rg':  'rgb-nonstroke',
    b'RG':  'rgb-stroke',
    b'g':   'gray-nonstroke',
    b'G':   'gray-stroke',
    b'k':   'cmyk-nonstroke',
    b'K':   'cmyk-stroke',
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _bar(score: float, width: int = 20) -> str:
    filled = max(0, min(int(round(score * width)), width))
    return "[" + "#" * filled + "." * (width - filled) + "]"


def _score_to_risk(score: float) -> int:
    if score >= 0.75: return 4
    if score >= 0.50: return 3
    if score >= 0.25: return 2
    if score > 0.00:  return 1
    return 0


def _risk_label(risk: int) -> str:
    return RISK_LABELS.get(risk, "UNKNOWN")


def safe_print(text: str):
    try:
        print(text)
    except UnicodeEncodeError:
        encoded = text.encode(sys.stdout.encoding or "ascii", errors="replace")
        sys.stdout.buffer.write(encoded)
        sys.stdout.buffer.write(b"\n")


def _section(title: str, width: int = 70, use_color: bool = True) -> str:
    bold = BOLD if use_color else ""
    reset = RESET if use_color else ""
    line = "=" * width
    return f"\n{bold}{line}\n  {title}\n{line}{reset}"


def _subsection(title: str, use_color: bool = True) -> str:
    bold = BOLD if use_color else ""
    reset = RESET if use_color else ""
    return f"\n{bold}  -- {title} --{reset}"


def _col(risk: int, text: str, use_color: bool) -> str:
    if not use_color:
        return text
    return RISK_COLORS.get(risk, "") + text + RESET


def _entropy_char(entropy: float) -> str:
    if entropy < 1.0:  return "."
    if entropy < 3.0:  return "+"
    if entropy < 5.0:  return "#"
    if entropy < 7.0:  return "@"
    return "X"


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class RegionCell:
    row: int
    col: int
    entropy: float
    variance: float
    edge_mean: float
    is_suspicious: bool


@dataclass
class ImageReport:
    xref: int
    page: int
    width: int
    height: int
    color_mode: str
    format: str
    compressed_size: int
    global_mean: float
    global_stddev: float
    global_entropy: float
    lsb_entropy: float
    lsb_pattern_score: float
    region_grid: List[RegionCell]
    suspicious_regions: List[RegionCell]
    rgb_channels: Dict[str, dict]
    dct_analysis: Dict
    risk_score: float
    saved_path: str = ""


@dataclass
class StreamReport:
    xref: int
    obj_type: str
    compressed_size: int
    decompressed_size: int
    float_count: int
    lsb_score: float
    lsb_decoded: str
    printable_ratio: float
    mantissa_distribution: List[float]
    flagged_mantissa_bits: List[int]
    operator_breakdown: Dict[str, int]
    float_histogram: str
    risk_score: float


@dataclass
class ScanResult:
    pdf_path: str
    page_count: int
    image_reports: List[ImageReport]
    stream_reports: List[StreamReport]
    composite_score: float
    scan_timestamp: str


# ── Image Analyzer ────────────────────────────────────────────────────────────

class ImageAnalyzer:

    def __init__(self, grid_size: int = 8, save_dir: str = ""):
        self.grid_size = grid_size
        self.save_dir  = save_dir

    def analyze(self, doc, xref: int, page_idx: int) -> Optional[ImageReport]:
        try:
            base = doc.extract_image(xref)
        except Exception:
            return None

        img_bytes = base.get("image", b"")
        if not img_bytes:
            return None

        fmt = base.get("ext", "unknown").upper()
        compressed_size = len(img_bytes)

        try:
            img_rgb = Image.open(io.BytesIO(img_bytes)).convert("RGB")
        except Exception:
            return None

        w, h = img_rgb.size
        if w < 20 or h < 20:
            return None

        img_gray = img_rgb.convert("L")
        arr_gray = np.array(img_gray, dtype=np.float32)

        # ── Global stats ──────────────────────────────────────────────────────
        global_mean   = float(np.mean(arr_gray))
        global_stddev = float(np.std(arr_gray))
        global_entropy = self._compute_entropy(arr_gray)

        # ── LSB plane analysis ────────────────────────────────────────────────
        arr_uint8     = arr_gray.clip(0, 255).astype(np.uint8)
        lsb_plane     = arr_uint8 & 1
        lsb_entropy   = self._compute_entropy(lsb_plane.astype(np.float32) * 255.0)
        lsb_score     = self._lsb_pattern_score(lsb_plane)

        # ── Region grid ───────────────────────────────────────────────────────
        grid = self._region_grid(arr_gray)
        suspicious = [c for c in grid if c.is_suspicious]

        # ── RGB channels ──────────────────────────────────────────────────────
        rgb_channels = self._rgb_channel_analysis(img_rgb)

        # ── JPEG DCT analysis ─────────────────────────────────────────────────
        dct_analysis: Dict = {}
        if fmt == "JPEG" or fmt == "JPG":
            dct_analysis = self._jpeg_dct_analysis(img_bytes)

        # ── Risk score ────────────────────────────────────────────────────────
        region_score = min(len(suspicious) / max(self.grid_size, 1), 1.0)
        lsb_risk     = lsb_score
        dct_risk     = dct_analysis.get("risk_score", 0.0)
        risk_score   = max(region_score, lsb_risk * 0.6, dct_risk * 0.5)

        # ── Save contrast-enhanced image ───────────────────────────────────────
        saved_path = ""
        if self.save_dir:
            saved_path = self._save_enhanced(img_rgb, img_bytes, xref, lsb_plane)

        return ImageReport(
            xref=xref,
            page=page_idx + 1,
            width=w, height=h,
            color_mode=img_rgb.mode,
            format=fmt,
            compressed_size=compressed_size,
            global_mean=round(global_mean, 2),
            global_stddev=round(global_stddev, 2),
            global_entropy=round(global_entropy, 4),
            lsb_entropy=round(lsb_entropy, 4),
            lsb_pattern_score=round(lsb_score, 4),
            region_grid=grid,
            suspicious_regions=suspicious,
            rgb_channels=rgb_channels,
            dct_analysis=dct_analysis,
            risk_score=round(risk_score, 4),
            saved_path=saved_path,
        )

    # ── Region grid ───────────────────────────────────────────────────────────

    def _region_grid(self, arr: np.ndarray) -> List[RegionCell]:
        h, w   = arr.shape
        bh     = max(h // self.grid_size, 1)
        bw     = max(w // self.grid_size, 1)
        cells  = []

        for row in range(min(self.grid_size, h // bh)):
            for col in range(min(self.grid_size, w // bw)):
                region = arr[row * bh:(row + 1) * bh, col * bw:(col + 1) * bw]
                if region.size == 0:
                    continue

                entropy  = self._compute_entropy(region)
                variance = float(np.var(region))

                try:
                    rim   = Image.fromarray(region.clip(0, 255).astype(np.uint8))
                    earr  = np.array(rim.filter(ImageFilter.FIND_EDGES), dtype=np.float32)
                    edge_mean = float(np.mean(earr))
                except Exception:
                    edge_mean = 0.0

                suspicious = edge_mean > 15.0 and variance < 200.0 and entropy > 3.5

                cells.append(RegionCell(
                    row=row, col=col,
                    entropy=round(entropy, 3),
                    variance=round(variance, 2),
                    edge_mean=round(edge_mean, 2),
                    is_suspicious=suspicious,
                ))
        return cells

    # ── RGB channel analysis ──────────────────────────────────────────────────

    def _rgb_channel_analysis(self, img: Image.Image) -> Dict[str, dict]:
        result = {}
        arr_rgb = np.array(img, dtype=np.float32)

        for i, ch_name in enumerate(["R", "G", "B"]):
            ch = arr_rgb[:, :, i]
            ch_uint8 = ch.clip(0, 255).astype(np.uint8)
            lsb_plane = ch_uint8 & 1
            ones_ratio = float(lsb_plane.mean())

            # Perfect 50% split is suspicious for LSB steganography
            deviation_from_half = abs(ones_ratio - 0.5)
            lsb_suspicious = deviation_from_half < 0.02  # very close to 50/50

            result[ch_name] = {
                "mean":            round(float(np.mean(ch)), 2),
                "stddev":          round(float(np.std(ch)), 2),
                "entropy":         round(self._compute_entropy(ch), 4),
                "lsb_ones_ratio":  round(ones_ratio, 4),
                "lsb_suspicious":  lsb_suspicious,
                "deviation_from_half": round(deviation_from_half, 4),
            }
        return result

    # ── JPEG DCT analysis ─────────────────────────────────────────────────────

    def _jpeg_dct_analysis(self, img_bytes: bytes) -> dict:
        """
        Parse JPEG markers to detect steganographic anomalies in DCT coefficients.
        Uses sign-bit uniformity as a proxy for RS steganalysis.
        """
        result = {
            "markers_found": [],
            "sign_bit_uniformity": 0.0,
            "zero_ac_ratio": 0.0,
            "risk_score": 0.0,
            "notes": [],
        }

        # Find JPEG markers
        i = 0
        markers = []
        while i < len(img_bytes) - 1:
            if img_bytes[i] == 0xFF and img_bytes[i + 1] not in (0x00, 0xFF):
                marker = img_bytes[i + 1]
                markers.append(hex(marker))
                # Skip marker + length
                if marker in (0xD8, 0xD9, 0xD0, 0xD1, 0xD2, 0xD3,
                               0xD4, 0xD5, 0xD6, 0xD7):
                    i += 2
                elif i + 3 < len(img_bytes):
                    length = struct.unpack(">H", img_bytes[i + 2: i + 4])[0]
                    i += 2 + length
                else:
                    break
            else:
                i += 1

        result["markers_found"] = markers[:20]

        # Analyze raw scan data bytes for sign-bit distribution
        # JPEG scan data starts after SOS (0xFFDA) marker
        sos_idx = img_bytes.find(b'\xff\xda')
        if sos_idx == -1:
            result["notes"].append("No SOS marker found — cannot analyze scan data")
            return result

        # Skip SOS header
        sos_length = struct.unpack(">H", img_bytes[sos_idx + 2: sos_idx + 4])[0]
        scan_start = sos_idx + 2 + sos_length
        scan_data  = img_bytes[scan_start:]

        # Remove byte stuffing (0xFF00 → 0xFF)
        scan_clean = scan_data.replace(b'\xff\x00', b'\xff')

        # Collect all non-zero, non-0xFF bytes from scan data as proxy coefficients
        coeff_bytes = [b for b in scan_clean if b not in (0x00, 0xFF)]
        if not coeff_bytes:
            result["notes"].append("No coefficient bytes extracted from scan data")
            return result

        # Sign bit (MSB) uniformity test: natural DCT data has ~50% set sign bits
        sign_bits = [(b >> 7) & 1 for b in coeff_bytes]
        sign_ratio = sum(sign_bits) / len(sign_bits)
        result["sign_bit_uniformity"] = round(sign_ratio, 4)

        deviation = abs(sign_ratio - 0.5)
        if deviation < 0.01:
            result["notes"].append(
                f"Sign bit ratio {sign_ratio:.4f} is extremely close to 0.5 "
                f"(deviation={deviation:.4f}) — LSB steganography indicator"
            )
            result["risk_score"] = 0.6
        elif deviation < 0.03:
            result["notes"].append(
                f"Sign bit ratio {sign_ratio:.4f} is close to 0.5 "
                f"(deviation={deviation:.4f}) — mild steganographic signal"
            )
            result["risk_score"] = 0.3

        # Zero AC coefficient ratio (natural JPEG: many zeros near quantization threshold)
        zero_count = coeff_bytes.count(0x80)  # 0x80 = -0 in sign-magnitude
        total      = max(len(coeff_bytes), 1)
        zero_ratio = zero_count / total
        result["zero_ac_ratio"] = round(zero_ratio, 4)
        if zero_ratio < 0.01:
            result["notes"].append(
                f"Very low zero AC ratio ({zero_ratio:.4f}) — "
                f"unusual for natural JPEG; may indicate steganographic fill"
            )
            result["risk_score"] = max(result["risk_score"], 0.4)

        return result

    # ── LSB pattern score ─────────────────────────────────────────────────────

    def _lsb_pattern_score(self, lsb_plane: np.ndarray) -> float:
        """
        A uniform random LSB plane has high entropy AND appears spatially random.
        A steganographic payload may have high entropy but NOT random spatial structure
        (e.g. embedded text has runs of similar bits).
        We measure this via run-length entropy vs. pixel entropy.
        """
        if lsb_plane.size == 0:
            return 0.0

        flat = lsb_plane.flatten()
        total = len(flat)

        # Bit entropy
        ones  = int(flat.sum())
        zeros = total - ones
        if ones == 0 or zeros == 0:
            return 0.0  # fully uniform = not hidden data

        p1 = ones / total
        p0 = zeros / total
        bit_entropy = -(p1 * math.log2(p1) + p0 * math.log2(p0))  # max=1.0

        # Run-length analysis
        runs = []
        current_run = 1
        for i in range(1, len(flat)):
            if flat[i] == flat[i - 1]:
                current_run += 1
            else:
                runs.append(current_run)
                current_run = 1
        runs.append(current_run)

        mean_run    = sum(runs) / max(len(runs), 1)
        # For purely random bits: mean run length ≈ 2.0
        # For text-encoded bits: longer runs (bits cluster)
        run_score   = min(abs(mean_run - 2.0) / 4.0, 1.0)

        # Combine: high bit entropy + anomalous run structure = suspicious
        score = bit_entropy * 0.4 + run_score * 0.6
        return round(min(score, 1.0), 4)

    # ── Entropy ───────────────────────────────────────────────────────────────

    def _compute_entropy(self, arr: np.ndarray) -> float:
        arr_u8 = arr.clip(0, 255).astype(np.uint8)
        hist, _ = np.histogram(arr_u8.flatten(), bins=256, range=(0, 256))
        total = hist.sum()
        if total == 0:
            return 0.0
        p = hist / total
        nz = p[p > 0]
        return float(-np.sum(nz * np.log2(nz)))

    # ── Contrast enhancement ──────────────────────────────────────────────────

    def _save_enhanced(
        self,
        img_rgb: Image.Image,
        img_bytes: bytes,
        xref: int,
        lsb_plane: np.ndarray,
    ) -> str:
        os.makedirs(self.save_dir, exist_ok=True)

        # 1. Extreme contrast enhance
        enhanced = ImageEnhance.Contrast(img_rgb).enhance(8.0)
        enhanced = ImageEnhance.Sharpness(enhanced).enhance(4.0)
        enhanced_path = os.path.join(self.save_dir, f"enhanced_xref{xref}.png")
        enhanced.save(enhanced_path)

        # 2. LSB plane visualized (0→black, 1→white)
        lsb_img = Image.fromarray((lsb_plane * 255).astype(np.uint8), mode="L")
        lsb_img = lsb_img.resize(
            (img_rgb.width * 2, img_rgb.height * 2), Image.NEAREST
        )
        lsb_path = os.path.join(self.save_dir, f"lsb_plane_xref{xref}.png")
        lsb_img.save(lsb_path)

        # 3. Edge-detected image
        gray = img_rgb.convert("L")
        edges = gray.filter(ImageFilter.FIND_EDGES)
        edges = ImageEnhance.Contrast(edges.convert("RGB")).enhance(5.0)
        edge_path = os.path.join(self.save_dir, f"edges_xref{xref}.png")
        edges.save(edge_path)

        return enhanced_path


# ── Stream Analyzer ───────────────────────────────────────────────────────────

class StreamAnalyzer:

    FLOAT_RE = re.compile(rb'(-?\d+\.\d{3,})')
    # Match: optional floats followed by a PDF operator keyword
    OPERATOR_RE = re.compile(
        rb'(?:(?:-?\d+(?:\.\d+)?\s+)+)([A-Za-z]{1,3}(?:\*)?)\b'
    )

    def __init__(self, min_floats: int = 20):
        self.min_floats = min_floats

    def analyze(self, doc, xref: int) -> Optional[StreamReport]:
        try:
            stream_bytes = doc.xref_stream(xref)
        except Exception:
            return None
        if not stream_bytes:
            return None

        compressed_size   = self._get_compressed_size(doc, xref)
        decompressed_size = len(stream_bytes)

        # Object type
        obj_type = self._get_obj_type(doc, xref)

        # Extract floats
        float_matches = self.FLOAT_RE.findall(stream_bytes)
        float_values  = []
        for m in float_matches:
            try:
                float_values.append(float(m))
            except ValueError:
                pass

        if len(float_values) < self.min_floats:
            return None

        # LSB chi-square
        lsb_score = self._lsb_chi_square(float_values)
        if lsb_score <= 0.0:
            return None

        # LSB decode attempt
        decoded, printable_ratio = self._decode_lsb_bitstream(float_values)

        # Mantissa distribution
        mantissa_dist, flagged_bits = self._mantissa_bit_distribution(float_values)

        # Operator breakdown
        op_breakdown = self._identify_operators(stream_bytes)

        # Float histogram
        float_hist = self._float_histogram(float_values)

        risk_score = lsb_score * 0.7 + (printable_ratio * 0.3 if printable_ratio > 0.4 else 0.0)

        return StreamReport(
            xref=xref,
            obj_type=obj_type,
            compressed_size=compressed_size,
            decompressed_size=decompressed_size,
            float_count=len(float_values),
            lsb_score=round(lsb_score, 4),
            lsb_decoded=decoded,
            printable_ratio=round(printable_ratio, 4),
            mantissa_distribution=mantissa_dist,
            flagged_mantissa_bits=flagged_bits,
            operator_breakdown=op_breakdown,
            float_histogram=float_hist,
            risk_score=round(risk_score, 4),
        )

    def _lsb_chi_square(self, values: List[float]) -> float:
        lsbs = []
        for v in values:
            try:
                packed   = struct.pack('>f', v)
                int_repr = struct.unpack('>I', packed)[0]
                lsbs.append(int_repr & 0x1)
            except (struct.error, OverflowError):
                pass
        if len(lsbs) < self.min_floats:
            return 0.0
        ones     = sum(lsbs)
        zeros    = len(lsbs) - ones
        n        = len(lsbs)
        expected = n / 2.0
        chi2     = ((ones - expected) ** 2 + (zeros - expected) ** 2) / expected
        return min(chi2 / 10.0, 1.0)

    def _decode_lsb_bitstream(self, values: List[float]) -> Tuple[str, float]:
        bits = []
        for v in values:
            try:
                packed   = struct.pack('>f', v)
                int_repr = struct.unpack('>I', packed)[0]
                bits.append(int_repr & 0x1)
            except (struct.error, OverflowError):
                pass

        # Group into bytes
        decoded_chars = []
        for i in range(0, len(bits) - 7, 8):
            byte_val = 0
            for bit_pos in range(8):
                byte_val |= bits[i + bit_pos] << (7 - bit_pos)
            decoded_chars.append(byte_val)

        if not decoded_chars:
            return "", 0.0

        printable = sum(1 for c in decoded_chars if 32 <= c <= 126)
        ratio     = printable / len(decoded_chars)

        # Render as string, replace non-printable with '.'
        decoded_str = "".join(
            chr(c) if 32 <= c <= 126 else "."
            for c in decoded_chars[:200]
        )
        return decoded_str, ratio

    def _mantissa_bit_distribution(
        self, values: List[float]
    ) -> Tuple[List[float], List[int]]:
        """
        For each of the 23 mantissa bits of IEEE 754 single-precision float,
        compute the fraction of 1-bits across all values.
        Natural data: higher bits (near MSB) have ~50% ones; LSB bits have random dist.
        Flagged: any bit with |ones_ratio - 0.5| > 0.15
        """
        bit_ones = [0] * 23
        total    = 0

        for v in values:
            try:
                packed   = struct.pack('>f', v)
                int_repr = struct.unpack('>I', packed)[0]
                mantissa = int_repr & 0x7FFFFF  # lower 23 bits
                for bit_idx in range(23):
                    if (mantissa >> bit_idx) & 1:
                        bit_ones[bit_idx] += 1
                total += 1
            except (struct.error, OverflowError):
                pass

        if total == 0:
            return [0.5] * 23, []

        dist         = [ones / total for ones in bit_ones]
        flagged_bits = [i for i, r in enumerate(dist) if abs(r - 0.5) > 0.15]
        return [round(r, 4) for r in dist], flagged_bits

    def _identify_operators(self, stream_bytes: bytes) -> Dict[str, int]:
        """Count occurrences of PDF drawing operators associated with float operands."""
        counts: Dict[str, int] = defaultdict(int)
        for m in self.OPERATOR_RE.finditer(stream_bytes):
            op = m.group(1)
            name = PDF_FLOAT_OPERATORS.get(op, op.decode("latin-1", errors="replace"))
            counts[name] += 1
        return dict(sorted(counts.items(), key=lambda x: -x[1]))

    def _float_histogram(self, values: List[float], bins: int = 20, width: int = 30) -> str:
        if not values:
            return ""

        v_min = min(values)
        v_max = max(values)
        if v_min == v_max:
            return f"  All values = {v_min}"

        bucket_size = (v_max - v_min) / bins
        buckets = [0] * bins

        for v in values:
            idx = min(int((v - v_min) / bucket_size), bins - 1)
            buckets[idx] += 1

        max_count = max(buckets) or 1
        lines = [f"  Float distribution  ({len(values)} values, range [{v_min:.3f}, {v_max:.3f}])"]
        for i, count in enumerate(buckets):
            lo     = v_min + i * bucket_size
            hi     = lo + bucket_size
            bar_w  = int(count / max_count * width)
            bar    = "#" * bar_w
            lines.append(f"  {lo:8.3f}-{hi:8.3f} | {bar:<{width}} {count}")
        return "\n".join(lines)

    def _get_compressed_size(self, doc, xref: int) -> int:
        try:
            length_key = doc.xref_get_key(xref, "Length")
            if length_key and length_key[0] == "int":
                return int(length_key[1])
        except Exception:
            pass
        return 0

    def _get_obj_type(self, doc, xref: int) -> str:
        for key in ("Subtype", "Type"):
            try:
                val = doc.xref_get_key(xref, key)
                if val and val[0] not in ("null", "none", ""):
                    return val[1].strip("/")
            except Exception:
                pass
        return "unknown"


# ── ASCII Heatmap Renderer ────────────────────────────────────────────────────

def render_heatmap(
    grid: List[RegionCell],
    grid_size: int,
    use_color: bool,
) -> str:
    # Build a 2D lookup
    cell_map = {(c.row, c.col): c for c in grid}
    max_row = max((c.row for c in grid), default=0) + 1
    max_col = max((c.col for c in grid), default=0) + 1

    lines = []
    header = "  +" + "--" * max_col + "-+"
    lines.append(header)

    for row in range(max_row):
        row_chars = []
        for col in range(max_col):
            cell = cell_map.get((row, col))
            if cell is None:
                row_chars.append(" ")
                continue
            ch = _entropy_char(cell.entropy)
            if cell.is_suspicious:
                ch = "*"
                if use_color:
                    ch = RED + ch + RESET
            row_chars.append(ch)
        lines.append("  | " + " ".join(row_chars) + " |")

    lines.append(header)
    lines.append(
        f"  Legend: .=low entropy  +=medium  #=high  @=very high  X=max  *=SUSPICIOUS"
    )
    return "\n".join(lines)


def render_mantissa_chart(
    dist: List[float],
    flagged: List[int],
    use_color: bool,
    bar_width: int = 20,
) -> str:
    lines = ["  Bit#  Ones-Ratio  Distribution (0.5 = expected)"]
    lines.append("  " + "-" * 55)
    for i, ratio in enumerate(dist):
        deviation = abs(ratio - 0.5)
        bar_fill  = int(ratio * bar_width)
        bar       = "[" + "#" * bar_fill + "." * (bar_width - bar_fill) + "]"
        flag_str  = ""
        if i in flagged:
            flag_str = "  <-- ANOMALY"
            if use_color:
                flag_str = RED + flag_str + RESET
        lines.append(f"  {i:>2}   {ratio:.4f}      {bar}  {deviation:+.4f}{flag_str}")
    return "\n".join(lines)


# ── Scanner Orchestrator ──────────────────────────────────────────────────────

class DetailedPixelEntropyScanner:

    def __init__(
        self,
        pdf_path: str,
        save_images: bool = False,
        target_image_xref: int = -1,
        target_stream_xref: int = -1,
        lsb_threshold: float = 0.5,
        grid_size: int = 8,
        min_floats: int = 20,
    ):
        self.pdf_path           = pdf_path
        self.save_images        = save_images
        self.target_image_xref  = target_image_xref
        self.target_stream_xref = target_stream_xref
        self.lsb_threshold      = lsb_threshold
        self.grid_size          = grid_size
        self.min_floats         = min_floats
        self.doc                = None

    def _load(self):
        self.doc = fitz.open(self.pdf_path)

    def scan(self) -> ScanResult:
        self._load()

        save_dir = ""
        if self.save_images:
            save_dir = os.path.join(
                os.path.dirname(os.path.abspath(self.pdf_path)),
                "steg_analysis",
            )

        img_analyzer    = ImageAnalyzer(grid_size=self.grid_size, save_dir=save_dir)
        stream_analyzer = StreamAnalyzer(min_floats=self.min_floats)

        # ── Image scans ───────────────────────────────────────────────────────
        image_reports: List[ImageReport] = []
        seen_xrefs: set = set()

        for page_idx, page in enumerate(self.doc):
            for img_info in page.get_images(full=True):
                xref = img_info[0]
                if self.target_image_xref > 0 and xref != self.target_image_xref:
                    continue
                if xref in seen_xrefs or xref <= 0:
                    continue
                seen_xrefs.add(xref)

                report = img_analyzer.analyze(self.doc, xref, page_idx)
                if report is not None:
                    image_reports.append(report)

        # ── Stream scans ──────────────────────────────────────────────────────
        stream_reports: List[StreamReport] = []

        xref_len = self.doc.xref_length()
        for xref in range(1, xref_len):
            if self.target_stream_xref > 0 and xref != self.target_stream_xref:
                continue

            report = stream_analyzer.analyze(self.doc, xref)
            if report is not None and report.lsb_score >= self.lsb_threshold:
                stream_reports.append(report)

        # ── Composite score ───────────────────────────────────────────────────
        all_scores = (
            [r.risk_score for r in image_reports if r.risk_score > 0]
            + [r.risk_score for r in stream_reports]
        )
        composite = round(max(all_scores) if all_scores else 0.0, 4)

        return ScanResult(
            pdf_path=self.pdf_path,
            page_count=self.doc.page_count,
            image_reports=image_reports,
            stream_reports=stream_reports,
            composite_score=composite,
            scan_timestamp=datetime.datetime.now(
                datetime.timezone.utc
            ).isoformat(),
        )


# ── Report Renderer ───────────────────────────────────────────────────────────

class DetailedReportRenderer:

    def __init__(self, result: ScanResult, use_color: bool = True, verbose: bool = False):
        self.result    = result
        self.use_color = use_color
        self.verbose   = verbose

    def _c(self, color_code: str, text: str) -> str:
        if not self.use_color:
            return text
        return color_code + text + RESET

    def render_terminal(self) -> str:
        r = self.result
        lines = []

        # ── Header ────────────────────────────────────────────────────────────
        bold  = BOLD  if self.use_color else ""
        reset = RESET if self.use_color else ""
        dim   = DIM   if self.use_color else ""

        lines.append("=" * 70)
        lines.append(f"{bold}  Pixel-Level Entropy & Steganography Scanner{reset}")
        try:
            size_kb = os.path.getsize(r.pdf_path) / 1024
        except Exception:
            size_kb = 0
        lines.append(
            f"  File:   {os.path.basename(r.pdf_path)}  "
            f"({size_kb:.1f} KB, {r.page_count} pages)"
        )
        lines.append(f"  Scanned: {r.scan_timestamp}")
        lines.append("=" * 70)

        total_imgs    = len(r.image_reports)
        total_streams = len(r.stream_reports)
        susp_imgs     = sum(1 for i in r.image_reports if i.suspicious_regions)
        susp_streams  = len(r.stream_reports)

        risk      = _score_to_risk(r.composite_score)
        risk_col  = RISK_COLORS.get(risk, "") if self.use_color else ""
        lines.append(f"\n  Images analyzed:   {total_imgs}  ({susp_imgs} with suspicious regions)")
        lines.append(f"  Streams analyzed:  {total_streams} flagged streams")
        lines.append(
            f"  Composite Score:   {risk_col}{_bar(r.composite_score)} "
            f"{r.composite_score:.4f}  {_risk_label(risk)}{reset}"
        )

        # ── Image reports ─────────────────────────────────────────────────────
        if r.image_reports:
            lines.append(_section("EMBEDDED IMAGE ANALYSIS", use_color=self.use_color))

            for img in r.image_reports:
                img_risk     = _score_to_risk(img.risk_score)
                img_risk_col = RISK_COLORS.get(img_risk, "") if self.use_color else ""

                lines.append(
                    f"\n{bold}  [IMAGE xref={img.xref}]  "
                    f"Page {img.page}  {img.width}x{img.height}px  "
                    f"{img.format}  ({img.compressed_size} bytes){reset}"
                )
                lines.append(
                    f"  Risk: {img_risk_col}{_bar(img.risk_score, 15)} "
                    f"{img.risk_score:.4f}  {_risk_label(img_risk)}{reset}"
                )

                # Global stats
                lines.append(_subsection("Global Statistics", self.use_color))
                lines.append(f"  Mean brightness : {img.global_mean:.2f} / 255")
                lines.append(f"  Std deviation   : {img.global_stddev:.2f}")
                lines.append(f"  Shannon entropy : {img.global_entropy:.4f} bits  "
                             f"(max=8.0 for fully random image)")
                lines.append(f"  LSB plane entropy: {img.lsb_entropy:.4f} bits")
                lines.append(
                    f"  LSB pattern score: "
                    f"{img_risk_col}{img.lsb_pattern_score:.4f}{reset}  "
                    f"{'(suspicious run structure)' if img.lsb_pattern_score > 0.4 else '(normal)'}"
                )

                # Heatmap
                lines.append(_subsection(
                    f"Region Entropy Heatmap ({len(img.region_grid)} cells, "
                    f"{sum(1 for c in img.region_grid if c.is_suspicious)} suspicious)",
                    self.use_color,
                ))
                lines.append(render_heatmap(img.region_grid, 8, self.use_color))

                # Suspicious region details
                if img.suspicious_regions:
                    lines.append(_subsection("Suspicious Regions Detail", self.use_color))
                    for cell in img.suspicious_regions:
                        lines.append(
                            f"  {self._c(RED, '*')} Region ({cell.row},{cell.col}):  "
                            f"entropy={cell.entropy:.3f}  "
                            f"variance={cell.variance:.1f}  "
                            f"edge_mean={cell.edge_mean:.2f}"
                        )
                        lines.append(
                            f"    Interpretation: High edge activity ({cell.edge_mean:.1f}) "
                            f"in a low-variance ({cell.variance:.1f}) region — "
                            f"consistent with low-contrast text overlay"
                        )

                # RGB channel analysis
                lines.append(_subsection("RGB Channel LSB Analysis", self.use_color))
                for ch_name, ch in img.rgb_channels.items():
                    susp_str = ""
                    if ch["lsb_suspicious"]:
                        susp_str = self._c(YELLOW, "  <-- near-perfect 50/50 split (LSB steg indicator)")
                    lines.append(
                        f"  Channel {ch_name}: mean={ch['mean']:6.1f}  "
                        f"stddev={ch['stddev']:5.1f}  "
                        f"entropy={ch['entropy']:.4f}  "
                        f"LSB_ones={ch['lsb_ones_ratio']:.4f} "
                        f"(dev={ch['deviation_from_half']:.4f}){susp_str}"
                    )

                # JPEG DCT analysis
                if img.dct_analysis:
                    lines.append(_subsection("JPEG DCT Coefficient Analysis", self.use_color))
                    dct = img.dct_analysis
                    lines.append(f"  Markers found: {dct.get('markers_found', [])}")
                    lines.append(f"  Sign-bit uniformity: {dct.get('sign_bit_uniformity', 0):.4f}  "
                                 f"(0.5000 = perfectly uniform = suspicious)")
                    lines.append(f"  Zero-AC coefficient ratio: {dct.get('zero_ac_ratio', 0):.4f}")
                    for note in dct.get("notes", []):
                        lines.append(f"  {self._c(YELLOW, '!')} {note}")
                    dct_risk = dct.get("risk_score", 0.0)
                    if dct_risk > 0:
                        lines.append(
                            f"  DCT anomaly score: "
                            f"{self._c(RED if dct_risk > 0.5 else YELLOW, f'{dct_risk:.4f}')}"
                        )

                if img.saved_path:
                    lines.append(
                        f"\n  {dim}Saved enhanced images to: "
                        f"{os.path.dirname(img.saved_path)}/{reset}"
                    )
                    lines.append(
                        f"  {dim}  enhanced_xref{img.xref}.png  |  "
                        f"lsb_plane_xref{img.xref}.png  |  "
                        f"edges_xref{img.xref}.png{reset}"
                    )

        # ── Stream reports ────────────────────────────────────────────────────
        if r.stream_reports:
            lines.append(_section("PDF CONTENT STREAM ANALYSIS", use_color=self.use_color))

            for stream in r.stream_reports:
                s_risk     = _score_to_risk(stream.risk_score)
                s_risk_col = RISK_COLORS.get(s_risk, "") if self.use_color else ""

                lines.append(
                    f"\n{bold}  [STREAM xref={stream.xref}]  "
                    f"type={stream.obj_type}  "
                    f"compressed={stream.compressed_size}B  "
                    f"decompressed={stream.decompressed_size}B{reset}"
                )
                lines.append(
                    f"  Risk: {s_risk_col}{_bar(stream.risk_score, 15)} "
                    f"{stream.risk_score:.4f}  {_risk_label(s_risk)}{reset}"
                )

                lines.append(_subsection("LSB Chi-Square Analysis", self.use_color))
                lines.append(f"  Floats extracted : {stream.float_count}")
                lines.append(
                    f"  LSB chi2 score   : "
                    f"{s_risk_col}{stream.lsb_score:.4f}{reset}  "
                    f"(>0.38 = p<0.05, statistically non-random)"
                )
                chi2_actual = stream.lsb_score * 10.0
                lines.append(
                    f"  Chi2 value       : {chi2_actual:.4f}  "
                    f"(critical value @ p=0.05: 3.84)"
                )

                lines.append(_subsection("LSB Bitstream Decode Attempt", self.use_color))
                lines.append(
                    f"  Printable ratio  : {stream.printable_ratio:.4f}  "
                    f"{'(' + self._c(YELLOW, 'LIKELY TEXT PAYLOAD') + ')' if stream.printable_ratio > 0.6 else '(no readable text detected)'}"
                )
                if stream.lsb_decoded.strip():
                    lines.append(f"  Decoded (200 chars): {self._c(CYAN, repr(stream.lsb_decoded))}")

                lines.append(_subsection("Mantissa Bit Distribution (23 bits)", self.use_color))
                if stream.flagged_mantissa_bits:
                    lines.append(
                        f"  {self._c(RED, 'Anomalous bits: ' + str(stream.flagged_mantissa_bits))}"
                        f"  (|ratio - 0.5| > 0.15)"
                    )
                else:
                    lines.append(f"  {self._c(GREEN, 'No anomalous mantissa bits detected')}")
                if self.verbose:
                    lines.append(render_mantissa_chart(
                        stream.mantissa_distribution,
                        stream.flagged_mantissa_bits,
                        self.use_color,
                    ))

                if stream.operator_breakdown:
                    lines.append(_subsection("Operator Breakdown (float-bearing ops)", self.use_color))
                    top_ops = list(stream.operator_breakdown.items())[:10]
                    for op_name, count in top_ops:
                        lines.append(f"  {op_name:<25} {count:>4}x")

                if self.verbose:
                    lines.append(_subsection("Float Value Histogram", self.use_color))
                    lines.append(stream.float_histogram)

        # ── Final verdict ─────────────────────────────────────────────────────
        lines.append(_section("VERDICT", use_color=self.use_color))
        risk     = _score_to_risk(r.composite_score)
        risk_col = RISK_COLORS.get(risk, "") if self.use_color else ""
        bold     = BOLD if self.use_color else ""
        reset    = RESET if self.use_color else ""

        verdicts = {
            4: "CRITICAL - Strong steganographic signals present. Do NOT ingest with LLMs.",
            3: "HIGH     - Significant anomalies detected. Manual forensic review required.",
            2: "MEDIUM   - Moderate anomalies. Treat PDF as untrusted input.",
            1: "LOW      - Minor anomalies. Exercise caution; unlikely to be malicious.",
            0: "CLEAN    - No steganographic signals detected.",
        }
        lines.append(
            f"\n  {bold}{risk_col}{verdicts.get(risk, 'UNKNOWN')}{reset}\n"
        )
        lines.append("=" * 70)
        return "\n".join(lines)

    def render_json(self) -> str:
        r = self.result
        risk = _score_to_risk(r.composite_score)
        out = {
            "schema_version":   "1.0",
            "file":             os.path.basename(r.pdf_path),
            "path":             os.path.abspath(r.pdf_path),
            "scan_timestamp":   r.scan_timestamp,
            "page_count":       r.page_count,
            "composite_score":  r.composite_score,
            "composite_risk":   _risk_label(risk),
            "image_reports": [
                {
                    "xref":               img.xref,
                    "page":               img.page,
                    "dimensions":         f"{img.width}x{img.height}",
                    "format":             img.format,
                    "compressed_bytes":   img.compressed_size,
                    "global_mean":        img.global_mean,
                    "global_stddev":      img.global_stddev,
                    "global_entropy":     img.global_entropy,
                    "lsb_entropy":        img.lsb_entropy,
                    "lsb_pattern_score":  img.lsb_pattern_score,
                    "risk_score":         img.risk_score,
                    "risk_label":         _risk_label(_score_to_risk(img.risk_score)),
                    "suspicious_regions": [
                        {
                            "row": c.row, "col": c.col,
                            "entropy": c.entropy,
                            "variance": c.variance,
                            "edge_mean": c.edge_mean,
                        }
                        for c in img.suspicious_regions
                    ],
                    "rgb_channels":  img.rgb_channels,
                    "dct_analysis":  img.dct_analysis,
                    "saved_path":    img.saved_path,
                }
                for img in r.image_reports
            ],
            "stream_reports": [
                {
                    "xref":                  s.xref,
                    "obj_type":              s.obj_type,
                    "compressed_bytes":      s.compressed_size,
                    "decompressed_bytes":    s.decompressed_size,
                    "float_count":           s.float_count,
                    "lsb_score":             s.lsb_score,
                    "lsb_decoded_sample":    s.lsb_decoded[:200],
                    "printable_ratio":       s.printable_ratio,
                    "flagged_mantissa_bits": s.flagged_mantissa_bits,
                    "mantissa_distribution": s.mantissa_distribution,
                    "operator_breakdown":    s.operator_breakdown,
                    "risk_score":            s.risk_score,
                    "risk_label":            _risk_label(_score_to_risk(s.risk_score)),
                }
                for s in r.stream_reports
            ],
        }
        return json.dumps(out, indent=2, default=str)


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Pixel-Level Entropy & Steganography Scanner — detailed forensic analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python pixel_entropy_scanner.py doc.pdf
  python pixel_entropy_scanner.py doc.pdf --save-images --verbose
  python pixel_entropy_scanner.py doc.pdf --stream 4
  python pixel_entropy_scanner.py doc.pdf --image 12
  python pixel_entropy_scanner.py doc.pdf --json > report.json
""",
    )
    parser.add_argument("pdf_path",        help="PDF file to analyze")
    parser.add_argument("--json",          action="store_true", help="Output JSON report")
    parser.add_argument("--no-color",      action="store_true", help="Disable ANSI colors")
    parser.add_argument("--verbose",       action="store_true", help="Show full mantissa chart and float histogram")
    parser.add_argument("--save-images",   action="store_true", help="Save enhanced images to ./steg_analysis/")
    parser.add_argument("--stream",        type=int, default=-1, metavar="XREF", help="Analyze only this stream xref")
    parser.add_argument("--image",         type=int, default=-1, metavar="XREF", help="Analyze only this image xref")
    parser.add_argument("--threshold",     type=float, default=0.5, help="LSB chi2 threshold for streams (default 0.5)")
    parser.add_argument("--grid-size",     type=int,   default=8,   help="Region grid dimension (default 8)")
    parser.add_argument("--min-floats",    type=int,   default=20,  help="Minimum floats per stream (default 20)")
    args = parser.parse_args()

    if not os.path.isfile(args.pdf_path):
        print(f"Error: File not found: {args.pdf_path}", file=sys.stderr)
        sys.exit(2)

    scanner = DetailedPixelEntropyScanner(
        pdf_path           = args.pdf_path,
        save_images        = args.save_images,
        target_image_xref  = args.image,
        target_stream_xref = args.stream,
        lsb_threshold      = args.threshold,
        grid_size          = args.grid_size,
        min_floats         = args.min_floats,
    )

    try:
        result = scanner.scan()
    except Exception as e:
        print(f"Fatal error during scan: {e}", file=sys.stderr)
        sys.exit(2)

    use_color = not args.no_color and not args.json
    renderer  = DetailedReportRenderer(result, use_color=use_color, verbose=args.verbose)

    if args.json:
        output_bytes = renderer.render_json().encode("utf-8")
        sys.stdout.buffer.write(output_bytes)
        sys.stdout.buffer.write(b"\n")
    else:
        safe_print(renderer.render_terminal())

    risk = _score_to_risk(result.composite_score)
    sys.exit(1 if risk >= 3 else 0)


if __name__ == "__main__":
    main()
