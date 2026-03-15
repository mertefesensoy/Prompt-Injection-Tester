"""
forensics/pdf.py
All PDF forensic checks — structure, content streams, images, fonts, metadata.
Each public function returns a plain dict (JSON-serializable).
"""

from __future__ import annotations
import re
import struct
import math
from typing import List, Dict, Any

import numpy as np

try:
    import fitz  # PyMuPDF
except ImportError:
    raise ImportError("PyMuPDF is required: pip install pymupdf")

from .algorithms import (
    chi2_pov, rs_steganalysis, lsb_bitstream, scan_prompt_injection,
    lsb_spatial_autocorr, lsb_heatmap, shannon_entropy,
    ieee754_word_artifact_confidence,
)

# ─── PDF Structure ────────────────────────────────────────────────────────────

def check_structure(doc: fitz.Document, raw_bytes: bytes) -> dict:
    """
    Check for active content, embedded files, and incremental updates.
    Returns JSON-serializable dict.
    """
    result: Dict[str, Any] = {
        "js_found": False,
        "open_action": False,
        "acroform": False,
        "annotations": [],
        "embedded_files": [],
        "incremental_updates": {},
        "viewer_prefs": {},
        "verdict": "CLEAN",
    }

    # ── Catalog checks ──────────────────────────────────────────
    try:
        cat = doc.xref_object(doc.pdf_catalog())
        if "/JS" in cat or "/JavaScript" in cat:
            result["js_found"] = True
        if "/OpenAction" in cat:
            result["open_action"] = True
        if "/AcroForm" in cat:
            result["acroform"] = True
        # ViewerPreferences
        m = re.search(r"/ViewerPreferences\s+(\d+)\s+\d+\s+R", cat)
        if m:
            vp_obj = doc.xref_object(int(m.group(1)))
            for key in ("/DisplayDocTitle", "/HideMenubar", "/HideToolbar", "/FitWindow"):
                if key in vp_obj:
                    result["viewer_prefs"][key.lstrip("/")] = True
    except Exception:
        pass

    # ── Annotations ─────────────────────────────────────────────
    for pno in range(doc.page_count):
        try:
            page = doc[pno]
            for annot in page.annots():
                entry = {"page": pno + 1, "type": str(annot.type[1])}
                if annot.uri:
                    entry["uri"] = annot.uri
                result["annotations"].append(entry)
        except Exception:
            pass

    # ── Embedded Files ───────────────────────────────────────────
    for xref in range(1, doc.xref_length()):
        try:
            obj = doc.xref_object(xref)
            if "/EmbeddedFile" in obj or "/Filespec" in obj or "/FileSpec" in obj:
                entry: Dict[str, Any] = {"xref": xref}
                m = re.search(r"/F\s*\(([^)]+)\)", obj)
                if m:
                    entry["name"] = m.group(1)
                result["embedded_files"].append(entry)
        except Exception:
            pass

    # ── Incremental Updates ──────────────────────────────────────
    eof_positions = [m.start() for m in re.finditer(b"%%EOF", raw_bytes)]
    update_count = max(0, len(eof_positions) - 1)
    new_xrefs: List[int] = []
    update_bytes = 0

    if update_count > 0:
        # Content after first %%EOF
        first_eof_end = eof_positions[0] + 5
        update_section = raw_bytes[first_eof_end:]
        update_bytes = len(update_section)
        # Find xrefs defined in the update
        for m in re.finditer(rb"(\d+)\s+\d+\s+obj", update_section):
            new_xrefs.append(int(m.group(1)))

    result["incremental_updates"] = {
        "count": update_count,
        "total_bytes": update_bytes,
        "new_xrefs": new_xrefs,
        "verdict": "SUSPICIOUS" if new_xrefs else "CLEAN",
    }

    # ── Final verdict ────────────────────────────────────────────
    flags = []
    if result["js_found"]:
        flags.append("JavaScript found")
    if result["open_action"]:
        flags.append("OpenAction found")
    if result["acroform"]:
        flags.append("AcroForm present")
    if result["embedded_files"]:
        flags.append(f"{len(result['embedded_files'])} embedded file(s)")
    if new_xrefs:
        flags.append(f"incremental update modified {len(new_xrefs)} objects")
    if result["annotations"]:
        uri_annots = [a for a in result["annotations"] if "uri" in a]
        if uri_annots:
            flags.append(f"{len(uri_annots)} URI annotation(s)")

    result["verdict"] = "SUSPICIOUS" if flags else "CLEAN"
    result["flags"] = flags
    return result


# ─── Content Streams ──────────────────────────────────────────────────────────

_TOKEN_RE = re.compile(
    rb"""
    (?P<string>   \((?:[^()\\]|\\.)*\)   )   |
    (?P<hexstr>   <[0-9A-Fa-f\s]*>       )   |
    (?P<array>    \[(?:[^\]]*)\]          )   |
    (?P<name>     /[^\s/<>\[\](){}/]+    )   |
    (?P<number>   [+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)? ) |
    (?P<op>       [a-zA-Z_*'"][a-zA-Z_*'"]*  |  W\*  )
    """,
    re.VERBOSE,
)


def _tokenize_stream(stream_bytes: bytes) -> List[dict]:
    tokens = []
    for m in _TOKEN_RE.finditer(stream_bytes):
        kind = m.lastgroup
        if kind is None:
            continue
        raw = m.group().decode("latin-1", errors="replace")
        tokens.append({"kind": kind, "raw": raw, "start": m.start()})
    return tokens


def _extract_text_from_token(tok: dict) -> str:
    """Decode a string/hexstr token to human-readable text."""
    raw = tok["raw"]
    if tok["kind"] == "string":
        # Strip outer parens, handle basic escapes
        inner = raw[1:-1]
        inner = inner.replace("\\n", "\n").replace("\\r", "\r").replace("\\t", "\t")
        inner = re.sub(r"\\(.)", r"\1", inner)
        return inner
    if tok["kind"] == "hexstr":
        hex_content = re.sub(r"\s", "", raw[1:-1])
        try:
            bts = bytes.fromhex(hex_content)
            # Try UTF-16-BE first (common for CID fonts)
            try:
                return bts.decode("utf-16-be")
            except Exception:
                return bts.decode("latin-1", errors="replace")
        except Exception:
            return raw
    if tok["kind"] == "array":
        parts = []
        for sub in re.finditer(rb"\(([^)]*)\)|<([0-9A-Fa-f\s]*)>", tok["raw"].encode("latin-1")):
            if sub.group(1):
                parts.append(sub.group(1).decode("latin-1", errors="replace"))
            elif sub.group(2):
                hex_c = re.sub(r"\s", "", sub.group(2).decode("latin-1"))
                try:
                    bts = bytes.fromhex(hex_c)
                    try:
                        parts.append(bts.decode("utf-16-be"))
                    except Exception:
                        parts.append(bts.decode("latin-1", errors="replace"))
                except Exception:
                    pass
        return "".join(parts)
    return ""


def _parse_mcid_blocks(tokens: List[dict]) -> List[dict]:
    """
    Extract Marked Content ID blocks from tokenized PDF stream.
    Returns list of {mcid, text, font, font_size, render_mode, x, y, classification}.
    """
    blocks = []
    i = 0
    n = len(tokens)
    stack_mcid = []
    current_font = ""
    current_size = 0.0
    current_render_mode = 0
    current_x = 0.0
    current_y = 0.0
    current_texts = []

    while i < n:
        tok = tokens[i]

        # Track font: /FontName size Tf
        if tok["kind"] == "op" and tok["raw"] == "Tf":
            if i >= 2:
                try:
                    current_size = float(tokens[i - 1]["raw"])
                except Exception:
                    pass
                if i >= 2 and tokens[i - 2]["kind"] == "name":
                    current_font = tokens[i - 2]["raw"]

        # Track render mode: N Tr
        elif tok["kind"] == "op" and tok["raw"] == "Tr":
            if i >= 1:
                try:
                    current_render_mode = int(tokens[i - 1]["raw"])
                except Exception:
                    pass

        # Track text matrix position: a b c d e f Tm
        elif tok["kind"] == "op" and tok["raw"] == "Tm":
            if i >= 6:
                try:
                    current_x = float(tokens[i - 2]["raw"])
                    current_y = float(tokens[i - 1]["raw"])
                except Exception:
                    pass

        # Marked content begin with MCID: /Tag <</MCID N>> BDC
        elif tok["kind"] == "op" and tok["raw"] == "BDC":
            mcid_val = None
            # Look backward for /MCID value
            for j in range(max(0, i - 8), i):
                if tokens[j]["kind"] == "name" and tokens[j]["raw"] == "/MCID":
                    if j + 1 < i and tokens[j + 1]["kind"] == "number":
                        try:
                            mcid_val = int(tokens[j + 1]["raw"])
                        except Exception:
                            pass
                        break
            stack_mcid.append({
                "mcid": mcid_val,
                "font": current_font,
                "font_size": current_size,
                "render_mode": current_render_mode,
                "x": current_x,
                "y": current_y,
                "texts": [],
            })

        # End marked content
        elif tok["kind"] == "op" and tok["raw"] == "EMC":
            if stack_mcid:
                block = stack_mcid.pop()
                text = "".join(block["texts"]).strip()
                rm = block["render_mode"]
                if rm == 3:
                    classification = "INVISIBLE"
                elif text:
                    classification = "CONTENT"
                else:
                    classification = "SPACING"
                blocks.append({
                    "mcid": block["mcid"],
                    "text": text,
                    "font": block["font"],
                    "font_size": block["font_size"],
                    "render_mode": rm,
                    "x": round(block["x"], 4),
                    "y": round(block["y"], 4),
                    "classification": classification,
                })

        # Collect text operators (Tj, TJ, ')
        elif tok["kind"] == "op" and tok["raw"] in ("Tj", "'"):
            if stack_mcid and i >= 1:
                text = _extract_text_from_token(tokens[i - 1])
                stack_mcid[-1]["texts"].append(text)

        elif tok["kind"] == "op" and tok["raw"] == "TJ":
            if stack_mcid and i >= 1 and tokens[i - 1]["kind"] == "array":
                text = _extract_text_from_token(tokens[i - 1])
                stack_mcid[-1]["texts"].append(text)

        i += 1

    return blocks


def _float_word_artifact_analysis(tokens: List[dict]) -> dict:
    """Analyze float values in stream for Word PDF/UA sub-pixel artifacts."""
    floats = []
    for tok in tokens:
        if tok["kind"] == "number":
            try:
                v = float(tok["raw"])
                floats.append(v)
            except Exception:
                pass

    if not floats:
        return {"count": 0, "word_artifact_count": 0,
                "max_confidence": 0.0, "verdict": "NO_FLOATS"}

    word_artifact_count = 0
    max_conf = 0.0
    for v in floats:
        conf = ieee754_word_artifact_confidence(v)
        if conf >= 0.5:
            word_artifact_count += 1
        max_conf = max(max_conf, conf)

    verdict = "WORD_ARTIFACT" if max_conf >= 0.8 else (
        "POSSIBLE_ARTIFACT" if max_conf >= 0.5 else "NATURAL"
    )
    return {
        "count": len(floats),
        "word_artifact_count": word_artifact_count,
        "max_confidence": round(max_conf, 4),
        "verdict": verdict,
    }


def _clip_rect_analysis(tokens: List[dict]) -> dict:
    """Detect sub-pixel clipping rectangles (Word PDF/UA artifact)."""
    clip_rects = []
    i = 0
    n = len(tokens)
    operand_stack: List[float] = []

    while i < n:
        tok = tokens[i]
        if tok["kind"] == "number":
            try:
                operand_stack.append(float(tok["raw"]))
            except Exception:
                pass
        elif tok["kind"] == "op":
            if tok["raw"] == "re" and len(operand_stack) >= 4:
                x, y, w, h = operand_stack[-4], operand_stack[-3], operand_stack[-2], operand_stack[-1]
                clip_rects.append((x, y, w, h))
                operand_stack = []
            elif tok["raw"] not in ("W", "W*", "n", "cm", "q", "Q"):
                operand_stack = []
        i += 1

    sub_pixel_count = 0
    word_artifact_count = 0
    for x, y, w, h in clip_rects:
        if 0 < abs(x) < 0.01 or 0 < abs(y) < 0.01:
            sub_pixel_count += 1
            conf = ieee754_word_artifact_confidence(x)
            if conf >= 0.5:
                word_artifact_count += 1

    verdict = "WORD_ARTIFACT" if word_artifact_count > 0 else (
        "SUB_PIXEL" if sub_pixel_count > 0 else "NORMAL"
    )
    return {
        "count": len(clip_rects),
        "sub_pixel_count": sub_pixel_count,
        "word_artifact_count": word_artifact_count,
        "verdict": verdict,
    }


def _stream_operator_breakdown(tokens: List[dict]) -> dict:
    """Count PDF operators in the stream."""
    OP_NAMES = {
        "re": "rectangle", "Tf": "font-size", "Tm": "text-matrix",
        "g": "gray-nonstroke", "G": "gray-stroke", "Tc": "char-spacing",
        "gs": "gs", "cm": "concat-matrix", "Do": "Do",
        "BDC": "BDC", "EMC": "EMC", "BT": "BT", "ET": "ET",
        "Tj": "Tj", "TJ": "TJ", "Tr": "Tr",
    }
    counts: Dict[str, int] = {}
    for tok in tokens:
        if tok["kind"] == "op":
            name = OP_NAMES.get(tok["raw"], tok["raw"])
            counts[name] = counts.get(name, 0) + 1
    return counts


def check_content_streams(doc: fitz.Document) -> List[dict]:
    """
    Analyze all content streams in the document.
    Returns list of per-stream analysis dicts.
    """
    results = []

    # Map pages to their content stream xrefs
    page_xref_map: Dict[int, int] = {}
    for pno in range(doc.page_count):
        page = doc[pno]
        page_xref_map[page.xref] = pno + 1

    # Find content streams: xrefs with FlateDecode filter but no /Type
    for xref in range(1, doc.xref_length()):
        try:
            if not doc.xref_is_stream(xref):
                continue
            obj = doc.xref_object(xref)
            # Skip typed objects (images, fonts, etc.)
            if "/Type" in obj:
                continue
            # Must have FlateDecode or be a raw stream
            if "/Filter" not in obj and "/Length" not in obj:
                continue
            # Skip if it looks like a font or CMap
            if any(k in obj for k in ("/CIDSystemInfo", "/ToUnicode", "/Registry")):
                continue

            raw = doc.xref_stream(xref)
            if not raw or len(raw) < 10:
                continue

            compressed_obj = doc.xref_object(xref)
            m_len = re.search(r"/Length\s+(\d+)", compressed_obj)
            compressed_size = int(m_len.group(1)) if m_len else 0

            tokens = _tokenize_stream(raw)
            if not tokens:
                continue

            # Only process if it looks like a page content stream
            op_names = {t["raw"] for t in tokens if t["kind"] == "op"}
            page_ops = {"BT", "ET", "Tf", "Tm", "Tj", "TJ", "re", "BDC", "EMC", "Do", "cm", "gs"}
            if not (op_names & page_ops):
                continue

            # Determine page number
            page_num = None
            for pg_xref, pg_num in page_xref_map.items():
                try:
                    pg_obj = doc.xref_object(pg_xref)
                    if str(xref) in pg_obj:
                        page_num = pg_num
                        break
                except Exception:
                    pass

            mcid_blocks = _parse_mcid_blocks(tokens)
            invisible = any(b["classification"] == "INVISIBLE" for b in mcid_blocks)
            floats_info = _float_word_artifact_analysis(tokens)
            clips_info = _clip_rect_analysis(tokens)
            op_breakdown = _stream_operator_breakdown(tokens)

            # Verdict
            if invisible:
                verdict = "SUSPICIOUS"
                confidence = 0.85
            elif floats_info["verdict"] == "WORD_ARTIFACT" and clips_info["verdict"] == "WORD_ARTIFACT":
                verdict = "FALSE_POSITIVE"
                confidence = 0.93
            elif floats_info["verdict"] == "WORD_ARTIFACT":
                verdict = "FALSE_POSITIVE"
                confidence = 0.85
            else:
                verdict = "NEEDS_REVIEW"
                confidence = 0.50

            content_count = sum(1 for b in mcid_blocks if b["classification"] == "CONTENT")
            invisible_blocks = [b for b in mcid_blocks if b["classification"] == "INVISIBLE"]

            results.append({
                "xref": xref,
                "page": page_num,
                "compressed_size": compressed_size,
                "decompressed_size": len(raw),
                "mcid_block_count": len(mcid_blocks),
                "content_block_count": content_count,
                "invisible_text": invisible,
                "invisible_blocks": invisible_blocks[:10],  # first 10
                "floats": floats_info,
                "clip_rects": clips_info,
                "operator_breakdown": op_breakdown,
                "verdict": verdict,
                "confidence": confidence,
            })
        except Exception:
            pass

    return results


# ─── Image Analysis ───────────────────────────────────────────────────────────

def _analyze_image_array(arr: np.ndarray, is_alpha: bool) -> dict:
    """Run full steg pipeline on a pixel array. Returns analysis dict."""
    result: Dict[str, Any] = {}

    if is_alpha or arr.ndim == 2:
        # Grayscale / alpha channel
        channels = {"A" if is_alpha else "L": arr}
    else:
        channels = {
            "R": arr[:, :, 0],
            "G": arr[:, :, 1],
            "B": arr[:, :, 2],
        }

    # Per-channel stats
    channel_stats = {}
    all_lsb_ratios = []
    for name, ch in channels.items():
        flat = ch.ravel().astype(np.float64)
        lsb = (ch.ravel() & 1).astype(np.float64)
        lsb_ratio = float(lsb.mean())
        all_lsb_ratios.append(lsb_ratio)
        chi2_stat, chi2_p, chi2_v = chi2_pov(ch)
        autocorr = lsb_spatial_autocorr(ch)
        channel_stats[name] = {
            "mean": round(float(flat.mean()), 3),
            "stddev": round(float(flat.std()), 3),
            "lsb_ones_ratio": round(lsb_ratio, 4),
            "deviation_from_half": round(abs(0.5 - lsb_ratio), 4),
            "chi2_stat": round(chi2_stat, 2),
            "chi2_p_value": round(chi2_p, 6),
            "chi2_verdict": chi2_v,
            "autocorr": round(autocorr, 4),
        }
    result["channels"] = channel_stats

    # Overall chi2 on first channel (or alpha)
    first_ch = list(channels.values())[0]
    chi2_stat, chi2_p, chi2_v = chi2_pov(first_ch)
    result["chi2"] = {
        "stat": round(chi2_stat, 2),
        "p_value": round(chi2_p, 6),
        "verdict": chi2_v,
    }

    # RS steganalysis on first channel
    rs = rs_steganalysis(first_ch)
    result["rs"] = rs

    # LSB bitstream + PI scan
    bs = lsb_bitstream(arr)
    printable = sum(1 for b in bs if 32 <= b < 127) / max(1, len(bs))
    pi_matches = scan_prompt_injection(bs[:512])
    result["lsb"] = {
        "bitstream_sample": bs[:32].hex(),
        "printable_ratio": round(printable, 4),
        "pi_matches": pi_matches,
    }

    # Sparsity: fraction of near-zero pixels
    if arr.ndim == 3:
        near_zero = np.all(arr < 15, axis=2)
    else:
        near_zero = arr < 15
    sparsity = float(near_zero.mean())
    result["sparsity"] = round(sparsity, 4)

    # Mean autocorrelation
    mean_autocorr = float(np.mean([
        s["autocorr"] for s in channel_stats.values()
    ]))
    result["mean_autocorr"] = round(mean_autocorr, 4)

    # LSB heatmap
    result["heatmap_lines"] = lsb_heatmap(arr)

    return result


def _image_verdict(analysis: dict) -> tuple:
    """Compute verdict and confidence from analysis dict."""
    evidence_for = []   # evidence for FALSE_POSITIVE
    evidence_against = []  # evidence of possible steganography

    # Sparsity
    sparsity = analysis.get("sparsity", 0)
    if sparsity > 0.50:
        evidence_for.append(f"high sparsity {sparsity:.0%} (sparse image, natural LSB skew)")

    # Autocorrelation
    autocorr = analysis.get("mean_autocorr", 0)
    if autocorr > 0.70:
        evidence_for.append(f"high autocorrelation {autocorr:.3f} (structured/uniform)")

    # Chi-square
    chi2 = analysis.get("chi2", {})
    if chi2.get("verdict") == "CLEAN":
        evidence_for.append(f"chi2 p={chi2.get('p_value', 0):.4f} (LSB pairs not equalized)")
    else:
        evidence_against.append(f"chi2 p={chi2.get('p_value', 0):.4f} (pairs equalized, suspicious)")

    # RS embedding rate — sparse images produce false RS signatures
    rs = analysis.get("rs", {})
    rs_rate = rs.get("embedding_rate", 0)
    chi2_clean = chi2.get("verdict") == "CLEAN"
    if rs_rate < 0.02:
        evidence_for.append(f"RS embedding rate {rs_rate:.1%} (clean)")
    elif rs_rate >= 0.05:
        if sparsity > 0.50 and chi2_clean:
            # Known RS false positive for non-uniform pixel distributions
            evidence_for.append(
                f"RS rate {rs_rate:.1%} is a known false positive for sparse images "
                f"(sparsity={sparsity:.0%}, chi2=CLEAN)"
            )
        else:
            evidence_against.append(f"RS embedding rate {rs_rate:.1%} (suspicious)")

    # Prompt injection
    pi = analysis.get("lsb", {}).get("pi_matches", [])
    if not pi:
        evidence_for.append("no prompt injection patterns in LSB bitstream")
    else:
        evidence_against.append(f"{len(pi)} prompt injection pattern(s) found")

    # LSB ones ratio check
    channels = analysis.get("channels", {})
    all_devs = [v["deviation_from_half"] for v in channels.values()]
    if all_devs and min(all_devs) > 0.25:
        evidence_for.append(f"all LSB ratios far from 0.5 (min deviation {min(all_devs):.3f})")

    # Heatmap left/right structural analysis
    heatmap = analysis.get("heatmap_lines", [])
    if heatmap:
        val_map = {"#": 1.0, "o": 0.25, ".": 0.0}
        left_scores, right_scores = [], []
        for line in heatmap:
            if not line:
                continue
            mid = len(line) // 2
            l = [val_map.get(c, 0.0) for c in line[:mid]]
            r = [val_map.get(c, 0.0) for c in line[mid:]]
            if l:
                left_scores.append(sum(l) / len(l))
            if r:
                right_scores.append(sum(r) / len(r))
        if left_scores and right_scores:
            la = sum(left_scores) / len(left_scores)
            ra = sum(right_scores) / len(right_scores)
            if la > 0.25 and ra < 0.10:
                evidence_for.append(
                    f"heatmap: dense-left ({la:.0%}) / sparse-right ({ra:.0%}) "
                    f"— logo+whitespace structure"
                )

    # Compute confidence
    n_for = len(evidence_for)
    n_against = len(evidence_against)

    if n_against == 0 and n_for >= 2:
        verdict = "FALSE_POSITIVE"
        confidence = min(0.98, 0.75 + n_for * 0.04)
    elif n_against == 0 and n_for == 1:
        verdict = "FALSE_POSITIVE"
        confidence = 0.75
    elif n_against >= 2 and n_for == 0:
        verdict = "CONFIRMED_SUSPICIOUS"
        confidence = min(0.95, 0.70 + n_against * 0.05)
    elif n_against >= 1:
        verdict = "NEEDS_REVIEW"
        confidence = 0.50 + (n_for - n_against) * 0.05
        confidence = max(0.30, min(0.70, confidence))
    else:
        verdict = "NEEDS_REVIEW"
        confidence = 0.50

    return verdict, round(confidence, 3), evidence_for, evidence_against


def check_images(doc: fitz.Document) -> List[dict]:
    """
    Analyze all Image XObjects (RGB and alpha/SMask channels).
    Returns list of per-image analysis dicts.
    """
    results = []
    processed = set()

    try:
        from PIL import Image
        import io as _io
    except ImportError:
        return [{"error": "Pillow not installed — pip install pillow"}]

    for xref in range(1, doc.xref_length()):
        if xref in processed:
            continue
        try:
            obj = doc.xref_object(xref)
            if "/Type /XObject" not in obj.replace("\n", " ") and "/Subtype /Image" not in obj.replace("\n", " "):
                continue
            if "/Subtype /Image" not in obj.replace("\n", " "):
                continue

            # Get image metadata
            m_w = re.search(r"/Width\s+(\d+)", obj)
            m_h = re.search(r"/Height\s+(\d+)", obj)
            m_cs = re.search(r"/ColorSpace\s+/(\w+)", obj)
            m_smask = re.search(r"/SMask\s+(\d+)\s+\d+\s+R", obj)
            m_len = re.search(r"/Length\s+(\d+)", obj)

            width = int(m_w.group(1)) if m_w else 0
            height = int(m_h.group(1)) if m_h else 0
            colorspace = m_cs.group(1) if m_cs else "Unknown"
            smask_xref = int(m_smask.group(1)) if m_smask else None
            compressed_bytes = int(m_len.group(1)) if m_len else 0
            is_alpha = colorspace == "DeviceGray" and smask_xref is None

            # Determine if this is an alpha channel for another image
            for_image_xref = None
            for other_xref in range(1, doc.xref_length()):
                if other_xref == xref:
                    continue
                try:
                    other_obj = doc.xref_object(other_xref)
                    if f"/SMask {xref} 0 R" in other_obj:
                        for_image_xref = other_xref
                        is_alpha = True
                        break
                except Exception:
                    pass

            # Determine page
            page_num = None
            for pno in range(doc.page_count):
                page = doc[pno]
                try:
                    pg_obj = doc.xref_object(page.xref)
                    if str(xref) in pg_obj:
                        page_num = pno + 1
                        break
                except Exception:
                    pass

            # Extract pixel data
            raw = doc.xref_stream(xref)
            if not raw:
                continue

            arr = None
            try:
                img = Image.frombytes(
                    "L" if colorspace == "DeviceGray" else "RGB",
                    (width, height),
                    raw
                )
                arr = np.array(img, dtype=np.uint8)
            except Exception:
                try:
                    img = Image.open(_io.BytesIO(raw))
                    arr = np.array(img.convert("RGB"), dtype=np.uint8)
                except Exception:
                    pass

            if arr is None or arr.size == 0:
                continue

            processed.add(xref)

            analysis = _analyze_image_array(arr, is_alpha)
            verdict, confidence, ev_for, ev_against = _image_verdict(analysis)

            results.append({
                "xref": xref,
                "page": page_num,
                "is_alpha": is_alpha,
                "for_image_xref": for_image_xref,
                "dimensions": f"{width}x{height}",
                "colorspace": colorspace,
                "compressed_bytes": compressed_bytes,
                "analysis": analysis,
                "evidence_for_fp": ev_for,
                "evidence_against": ev_against,
                "verdict": verdict,
                "confidence": confidence,
            })

            # Also process SMask alpha if present
            if smask_xref and smask_xref not in processed:
                try:
                    alpha_raw = doc.xref_stream(smask_xref)
                    if alpha_raw:
                        alpha_arr = np.frombuffer(alpha_raw, dtype=np.uint8).reshape(height, width)
                        processed.add(smask_xref)
                        alpha_analysis = _analyze_image_array(alpha_arr, is_alpha=True)
                        alpha_verdict, alpha_conf, av_for, av_against = _image_verdict(alpha_analysis)

                        alpha_obj = doc.xref_object(smask_xref)
                        a_len = re.search(r"/Length\s+(\d+)", alpha_obj)

                        results.append({
                            "xref": smask_xref,
                            "page": page_num,
                            "is_alpha": True,
                            "for_image_xref": xref,
                            "dimensions": f"{width}x{height}",
                            "colorspace": "DeviceGray (SMask)",
                            "compressed_bytes": int(a_len.group(1)) if a_len else 0,
                            "analysis": alpha_analysis,
                            "evidence_for_fp": av_for,
                            "evidence_against": av_against,
                            "verdict": alpha_verdict,
                            "confidence": alpha_conf,
                        })
                except Exception:
                    pass

        except Exception:
            pass

    return results


# ─── Font Analysis ────────────────────────────────────────────────────────────

def _decode_tounicode_cmap(stream_bytes: bytes) -> List[tuple]:
    """Parse a ToUnicode CMap stream. Returns list of (cid_hex, unicode_str)."""
    mappings = []
    text = stream_bytes.decode("latin-1", errors="replace")
    # bfchar mappings: <CID> <Unicode>
    for m in re.finditer(r"<([0-9A-Fa-f]+)>\s+<([0-9A-Fa-f]+)>", text):
        cid = m.group(1)
        uni_hex = m.group(2)
        try:
            uni_bytes = bytes.fromhex(uni_hex)
            uni_char = uni_bytes.decode("utf-16-be", errors="replace")
        except Exception:
            uni_char = f"U+{uni_hex}"
        mappings.append((cid, uni_char))
    # bfrange mappings: <start> <end> <unicode_start>
    for m in re.finditer(
        r"<([0-9A-Fa-f]+)>\s+<([0-9A-Fa-f]+)>\s+<([0-9A-Fa-f]+)>", text
    ):
        try:
            start = int(m.group(1), 16)
            end = int(m.group(2), 16)
            uni_start = int(m.group(3), 16)
            for i in range(min(end - start + 1, 256)):
                cid = format(start + i, "04x")
                uni_char = chr(uni_start + i)
                mappings.append((cid, uni_char))
        except Exception:
            pass
    return mappings


def _is_tounicode_suspicious(mappings: List[tuple]) -> bool:
    """Check if a ToUnicode CMap has suspicious (control/private-use) mappings."""
    if not mappings:
        return False
    suspicious_count = 0
    for _, uni_char in mappings:
        for ch in uni_char:
            cp = ord(ch)
            if (cp < 0x20 and cp not in (0x09, 0x0A, 0x0D)) or \
               (0xE000 <= cp <= 0xF8FF) or cp > 0x10FFFD:
                suspicious_count += 1
    return suspicious_count > len(mappings) // 4


def check_fonts(doc: fitz.Document) -> List[dict]:
    """Analyze all font objects in the document."""
    results = []
    font_xrefs = []

    for xref in range(1, doc.xref_length()):
        try:
            obj = doc.xref_object(xref)
            # Match /Type /Font exactly (not /FontDescriptor etc.)
            if re.search(r"/Type\s*/Font\b(?!Descriptor|File)", obj):
                font_xrefs.append(xref)
        except Exception:
            pass

    for xref in font_xrefs:
        try:
            obj = doc.xref_object(xref)

            m_sub = re.search(r"/Subtype\s*/(\w+)", obj)
            m_base = re.search(r"/BaseFont\s*/(\S+)", obj)
            subtype = m_sub.group(1) if m_sub else "Unknown"
            name = m_base.group(1) if m_base else "Unknown"

            # Encoding
            enc_inline = re.search(r"/Encoding\s*/(\w+)", obj)
            enc_ref = re.search(r"/Encoding\s+(\d+)\s+\d+\s+R", obj)
            encoding_type = enc_inline.group(1) if enc_inline else "indirect"

            has_differences = False
            differences = []
            if enc_ref:
                try:
                    enc_obj = doc.xref_object(int(enc_ref.group(1)))
                    if "/Differences" in enc_obj:
                        has_differences = True
                        # Extract differences list
                        m_diff = re.search(r"/Differences\s*\[([^\]]+)\]", enc_obj, re.DOTALL)
                        if m_diff:
                            diff_content = m_diff.group(1)[:500]
                            differences = diff_content.split()[:20]
                except Exception:
                    pass

            # ToUnicode CMap
            has_tounicode = "/ToUnicode" in obj
            tounicode_entries = []
            tounicode_suspicious = False
            if has_tounicode:
                m_tu = re.search(r"/ToUnicode\s+(\d+)\s+\d+\s+R", obj)
                if m_tu:
                    try:
                        tu_stream = doc.xref_stream(int(m_tu.group(1)))
                        if tu_stream:
                            tounicode_entries = _decode_tounicode_cmap(tu_stream)
                            tounicode_suspicious = _is_tounicode_suspicious(tounicode_entries)
                    except Exception:
                        pass

            # Font binary (FontFile2 / FontFile3)
            binary_xref = None
            binary_size_kb = 0.0
            binary_entropy = 0.0
            binary_magic_ok = False

            # Find FontDescriptor
            m_fd = re.search(r"/FontDescriptor\s+(\d+)\s+\d+\s+R", obj)
            if m_fd:
                try:
                    fd_obj = doc.xref_object(int(m_fd.group(1)))
                    for ff_key in ("/FontFile2", "/FontFile3", "/FontFile"):
                        m_ff = re.search(rf"{ff_key}\s+(\d+)\s+\d+\s+R", fd_obj)
                        if m_ff:
                            ff_xref = int(m_ff.group(1))
                            binary_xref = ff_xref
                            try:
                                ff_raw = doc.xref_stream(ff_xref)
                                if ff_raw:
                                    binary_size_kb = round(len(ff_raw) / 1024, 1)
                                    binary_entropy = round(shannon_entropy(ff_raw), 3)
                                    # Check TrueType magic: 00 01 00 00 or 'true' or 'OTTO'
                                    magic = ff_raw[:4]
                                    binary_magic_ok = magic in (
                                        b"\x00\x01\x00\x00", b"true", b"OTTO",
                                        b"\x00\x02\x00\x00",
                                    )
                            except Exception:
                                pass
                            break
                except Exception:
                    pass

            # Verdict
            flags = []
            if has_differences:
                flags.append("encoding /Differences present")
            if tounicode_suspicious:
                flags.append("suspicious ToUnicode mappings (control/PUA chars)")
            if binary_xref and not binary_magic_ok and binary_size_kb > 1:
                flags.append("font binary has unexpected magic bytes")

            results.append({
                "xref": xref,
                "name": name,
                "subtype": subtype,
                "encoding_type": encoding_type,
                "has_tounicode": has_tounicode,
                "tounicode_entry_count": len(tounicode_entries),
                "tounicode_suspicious": tounicode_suspicious,
                "has_differences": has_differences,
                "differences_sample": differences[:10],
                "binary_xref": binary_xref,
                "binary_size_kb": binary_size_kb,
                "binary_entropy": binary_entropy,
                "binary_magic_ok": binary_magic_ok,
                "flags": flags,
                "verdict": "SUSPICIOUS" if flags else "CLEAN",
            })
        except Exception:
            pass

    return results


# ─── Metadata ────────────────────────────────────────────────────────────────

def check_metadata(doc: fitz.Document, raw_bytes: bytes) -> dict:
    """Analyze XMP metadata and document info dict."""
    result: Dict[str, Any] = {
        "author": "",
        "creator": "",
        "producer": "",
        "created": "",
        "modified": "",
        "document_id": "",
        "instance_id": "",
        "ids_match": False,
        "xmp_padding_clean": True,
        "xmp_hidden_bytes": 0,
        "producer_is_word": False,
        "verdict": "CLEAN",
    }

    # ── Document Info Dict ───────────────────────────────────────
    meta = doc.metadata
    if meta:
        result["author"] = meta.get("author", "")
        result["creator"] = meta.get("creator", "")
        result["producer"] = meta.get("producer", "")
        result["created"] = meta.get("creationDate", "")
        result["modified"] = meta.get("modDate", "")

    result["producer_is_word"] = "Microsoft" in result["producer"] or \
                                  "Word" in result["producer"] or \
                                  "Word" in result["creator"]

    # ── XMP Metadata ─────────────────────────────────────────────
    xmp_xref = None
    try:
        cat_obj = doc.xref_object(doc.pdf_catalog())
        m = re.search(r"/Metadata\s+(\d+)\s+\d+\s+R", cat_obj)
        if m:
            xmp_xref = int(m.group(1))
    except Exception:
        pass

    if xmp_xref:
        try:
            xmp_raw = doc.xref_stream(xmp_xref)
            if xmp_raw:
                xmp_text = xmp_raw.decode("utf-8", errors="replace")

                # Extract IDs
                m_doc = re.search(r"DocumentID[\"'>]+([^\"'<]+)", xmp_text)
                m_inst = re.search(r"InstanceID[\"'>]+([^\"'<]+)", xmp_text)
                if m_doc:
                    result["document_id"] = m_doc.group(1).strip()
                if m_inst:
                    result["instance_id"] = m_inst.group(1).strip()
                result["ids_match"] = result["document_id"] == result["instance_id"]

                # Check padding between </rdf:RDF> and </x:xmpmeta>
                rdf_end = xmp_text.find("</rdf:RDF>")
                xmpmeta_end = xmp_text.find("</x:xmpmeta>")
                if rdf_end >= 0 and xmpmeta_end > rdf_end:
                    padding = xmp_text[rdf_end + 10:xmpmeta_end]
                    non_ws = [c for c in padding if c not in " \t\r\n"]
                    result["xmp_hidden_bytes"] = len(non_ws)
                    result["xmp_padding_clean"] = len(non_ws) == 0
        except Exception:
            pass

    # ── Verdict ──────────────────────────────────────────────────
    flags = []
    if result["xmp_hidden_bytes"] > 0:
        flags.append(f"{result['xmp_hidden_bytes']} non-whitespace bytes in XMP padding")
    if not result["ids_match"] and result["document_id"]:
        flags.append("DocumentID != InstanceID (file was re-saved/modified)")

    result["flags"] = flags
    result["verdict"] = "SUSPICIOUS" if flags else "CLEAN"
    return result
