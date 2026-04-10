#!/usr/bin/env python3
"""
scan.py — Unified Forensics Scanner
====================================
Scans PDF and DAT files for prompt injection, steganography, and
hidden-content attacks. Returns a single comprehensive report.

Usage:
    python scan.py file.pdf [file2.dat ...] [options]

Options:
    --json              Write JSON report to stdout (one per file)
    --html              Write self-contained HTML report to output dir
    --no-color          Disable ANSI colour output
    --output DIR        Directory for report files (default: reports/)
    --threshold FLOAT   Risk score threshold for exit-code 1 (default: 0.30)

Exit codes:
    0  All files clean
    1  At least one file above risk threshold
    2  Error / unsupported file type
"""

from __future__ import annotations
import argparse
import os
import sys
import json
from datetime import datetime, timezone
from pathlib import Path

# ── dependency check ──────────────────────────────────────────────────────────
_MISSING = []
try:
    import fitz
except ImportError:
    _MISSING.append("pymupdf  (pip install pymupdf)")
try:
    import numpy
except ImportError:
    _MISSING.append("numpy    (pip install numpy)")
try:
    from PIL import Image
except ImportError:
    _MISSING.append("pillow   (pip install pillow)")

if _MISSING:
    print("Missing required packages:")
    for m in _MISSING:
        print(f"  pip install {m.split()[0]}")
    sys.exit(2)

# ── internal imports ──────────────────────────────────────────────────────────
from forensics.pdf import (
    check_structure, check_content_streams, check_images,
    check_fonts, check_metadata,
)
from forensics.dat import check_dat
from forensics.report import render_terminal, render_json, render_html

SCHEMA_VERSION = "2.0"

# ─── Supported Extensions ────────────────────────────────────────────────────

_PDF_EXTS  = {".pdf"}
_DAT_EXTS  = {".dat", ".bin", ".data", ".raw", ".txt", ".csv", ".tsv",
              ".json", ".log", ".out"}
_PDF_MAGIC = b"%PDF"


def _detect_file_type(path: str) -> str:
    """Return 'PDF', 'DAT', or 'UNKNOWN'."""
    ext = Path(path).suffix.lower()
    if ext in _PDF_EXTS:
        return "PDF"
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
        if magic == _PDF_MAGIC:
            return "PDF"
    except Exception:
        pass
    if ext in _DAT_EXTS:
        return "DAT"
    # Probe: if > 90% printable → treat as DAT/text
    try:
        with open(path, "rb") as f:
            sample = f.read(4096)
        printable = sum(1 for b in sample if 0x20 <= b < 0x7F or b in (9, 10, 13))
        if printable / max(1, len(sample)) > 0.85:
            return "DAT"
    except Exception:
        pass
    return "DAT"  # default: treat unknown as DAT


# ─── Verdict Engine ───────────────────────────────────────────────────────────

def _overall_verdict(sections: dict, file_type: str) -> dict:
    """
    Weighted risk score across all section verdicts.
    Returns {verdict, confidence, risk_score, risk_level}.
    """
    score = 0.0

    if file_type == "PDF":
        struct = sections.get("structure", {})
        if struct.get("js_found") or struct.get("open_action"):
            score += 0.80
        if struct.get("acroform"):
            score += 0.30
        if struct.get("embedded_files"):
            score += 0.25
        if struct.get("annotations") and any("uri" in a for a in struct["annotations"]):
            score += 0.20
        inc = struct.get("incremental_updates", {})
        if inc.get("new_xrefs"):
            score += 0.20

        for cs in sections.get("content_streams", []):
            v = cs.get("verdict", "")
            if v == "SUSPICIOUS":
                score += 0.50
            elif v == "NEEDS_REVIEW":
                score += 0.15
            # Unicode invisible-ink attack in this stream
            ua = cs.get("unicode_attacks", {})
            if ua.get("tags", {}).get("pi_matches"):
                score += 0.70   # Tags + PI match → confirmed attack vector
            elif ua.get("tags", {}).get("tag_count", 0) > 0:
                score += 0.40   # Tags present without PI pattern match
            if ua.get("bidi", {}).get("has_override"):
                score += 0.30   # BiDi override (Trojan Source style)

        for img in sections.get("images", []):
            v = img.get("verdict", "")
            if v == "CONFIRMED_SUSPICIOUS":
                score += 0.45
            elif v == "NEEDS_REVIEW":
                score += 0.10

        for font in sections.get("fonts", []):
            if font.get("tounicode_suspicious"):
                score += 0.25
            if font.get("has_differences"):
                score += 0.15

        meta = sections.get("metadata", {})
        if meta.get("xmp_hidden_bytes", 0) > 0:
            score += 0.30

    else:  # DAT
        dat = sections.get("dat", {})
        dat_v = dat.get("verdict", "CLEAN")
        if dat_v == "SUSPICIOUS":
            score += 0.70
        elif dat_v == "NEEDS_REVIEW":
            score += 0.25
        # Unicode attack findings — check both text and binary analysis paths
        text_a = dat.get("text_analysis") or {}
        bin_a = dat.get("binary_analysis") or {}
        ua = text_a.get("unicode_attacks") or bin_a.get("unicode_attacks") or {}
        if ua.get("tags", {}).get("pi_matches"):
            score += 0.70
        elif ua.get("tags", {}).get("tag_count", 0) > 0:
            score += 0.40
        if ua.get("bidi", {}).get("has_override"):
            score += 0.30

    score = min(score, 1.0)

    if score < 0.10:
        verdict = "FALSE_POSITIVE" if file_type == "PDF" else "CLEAN"
        risk_level = "LOW"
        confidence = max(0.80, 1.0 - score * 5)
    elif score < 0.30:
        verdict = "LOW_RISK"
        risk_level = "LOW"
        confidence = 0.70
    elif score < 0.60:
        verdict = "NEEDS_REVIEW"
        risk_level = "MEDIUM"
        confidence = 0.55
    else:
        verdict = "SUSPICIOUS"
        risk_level = "HIGH"
        confidence = min(0.95, 0.60 + score * 0.35)

    return {
        "verdict": verdict,
        "confidence": round(confidence, 3),
        "risk_score": round(score, 3),
        "risk_level": risk_level,
    }


def _summary(sections: dict, file_type: str) -> dict:
    """Count total checks, passed, flagged."""
    total = 0
    passed = 0
    flagged = 0

    def _tally(v: str):
        nonlocal total, passed, flagged
        total += 1
        if v in ("CLEAN", "FALSE_POSITIVE", "WORD_ARTIFACT", "NATURAL", "NORMAL",
                  "LOW_RISK", "NO_FLOATS"):
            passed += 1
        elif v in ("SUSPICIOUS", "NEEDS_REVIEW", "CONFIRMED_SUSPICIOUS",
                   "SUB_PIXEL", "POSSIBLE_ARTIFACT"):
            flagged += 1
        else:
            passed += 1

    if file_type == "PDF":
        struct = sections.get("structure", {})
        _tally(struct.get("verdict", "CLEAN"))
        for cs in sections.get("content_streams", []):
            _tally(cs.get("verdict", "CLEAN"))
        for img in sections.get("images", []):
            _tally(img.get("verdict", "CLEAN"))
        for font in sections.get("fonts", []):
            _tally(font.get("verdict", "CLEAN"))
        _tally(sections.get("metadata", {}).get("verdict", "CLEAN"))
    else:
        dat = sections.get("dat", {})
        _tally(dat.get("verdict", "CLEAN"))

    return {"total_checks": total, "passed": passed, "flagged": flagged}


# ─── PDF Scanner ─────────────────────────────────────────────────────────────

def scan_pdf(path: str) -> dict:
    """Run all PDF forensic checks and return unified result dict."""
    import fitz

    with open(path, "rb") as f:
        raw_bytes = f.read()

    doc = fitz.open(path)

    sections = {}
    errors = []

    steps = [
        ("structure",       lambda: check_structure(doc, raw_bytes)),
        ("content_streams", lambda: check_content_streams(doc)),
        ("images",          lambda: check_images(doc)),
        ("fonts",           lambda: check_fonts(doc)),
        ("metadata",        lambda: check_metadata(doc, raw_bytes)),
    ]

    for name, fn in steps:
        try:
            sections[name] = fn()
        except Exception as e:
            sections[name] = {"error": str(e)}
            errors.append(f"{name}: {e}")

    doc.close()

    overall = _overall_verdict(sections, "PDF")
    summ = _summary(sections, "PDF")

    # Extra doc info for display
    try:
        doc2 = fitz.open(path)
        doc_info = {
            "page_count": doc2.page_count,
            "xref_count": doc2.xref_length(),
        }
        doc2.close()
    except Exception:
        doc_info = {}

    return {
        "schema_version": SCHEMA_VERSION,
        "file": os.path.basename(path),
        "file_path": str(Path(path).resolve()),
        "file_type": "PDF",
        "file_size_bytes": len(raw_bytes),
        "scan_timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "doc_info": doc_info,
        "overall": overall,
        "sections": sections,
        "summary": summ,
        "errors": errors,
    }


# ─── DAT Scanner ─────────────────────────────────────────────────────────────

def scan_dat(path: str) -> dict:
    """Run all DAT/binary forensic checks and return unified result dict."""
    with open(path, "rb") as f:
        raw_bytes = f.read()

    dat_result = check_dat(path, raw_bytes)
    sections = {"dat": dat_result}
    overall = _overall_verdict(sections, "DAT")
    summ = _summary(sections, "DAT")

    return {
        "schema_version": SCHEMA_VERSION,
        "file": os.path.basename(path),
        "file_path": str(Path(path).resolve()),
        "file_type": "DAT",
        "file_size_bytes": len(raw_bytes),
        "scan_timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "overall": overall,
        "sections": sections,
        "summary": summ,
        "errors": [],
    }


# ─── Unified Entry ────────────────────────────────────────────────────────────

def scan_file(path: str) -> dict:
    """Auto-detect file type and run appropriate scanner."""
    ft = _detect_file_type(path)
    if ft == "PDF":
        return scan_pdf(path)
    else:
        return scan_dat(path)


# ─── CLI ─────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        prog="scan.py",
        description="Forensics Scanner — prompt injection & steganography detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("files", nargs="+", metavar="FILE", help="Files to scan")
    parser.add_argument("--json",      action="store_true", help="Print JSON to stdout")
    parser.add_argument("--html",      action="store_true", help="Write HTML report")
    parser.add_argument("--no-color",  action="store_true", help="Disable ANSI colours")
    parser.add_argument("--output",    default="reports", metavar="DIR",
                        help="Output directory for reports (default: reports/)")
    parser.add_argument("--threshold", type=float, default=0.30, metavar="FLOAT",
                        help="Risk score threshold for exit code 1 (default: 0.30)")
    args = parser.parse_args()

    # Configure stdout encoding for Windows
    if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    # Ensure output dir exists
    if args.html:
        Path(args.output).mkdir(parents=True, exist_ok=True)

    any_flagged = False
    any_error = False

    for file_path in args.files:
        if not os.path.isfile(file_path):
            print(f"ERROR: File not found: {file_path}", file=sys.stderr)
            any_error = True
            continue

        try:
            result = scan_file(file_path)
        except Exception as e:
            print(f"ERROR scanning {file_path}: {e}", file=sys.stderr)
            any_error = True
            continue

        risk = result.get("overall", {}).get("risk_score", 0)
        if risk >= args.threshold:
            any_flagged = True

        # Always print terminal report (unless --json only)
        if not args.json:
            print(render_terminal(result, no_color=args.no_color))

        if args.json:
            print(render_json(result))

        # Write reports to disk
        base = Path(file_path).stem
        ts_short = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_dir = Path(args.output)
        out_dir.mkdir(parents=True, exist_ok=True)

        json_path = out_dir / f"{base}_{ts_short}.json"
        json_path.write_text(render_json(result), encoding="utf-8")
        if not args.json:
            print(f"  Report saved: {json_path}")

        if args.html:
            html_path = out_dir / f"{base}_{ts_short}.html"
            html_path.write_text(render_html(result), encoding="utf-8")
            if not args.json:
                print(f"  HTML saved:   {html_path}")

    if any_error:
        return 2
    if any_flagged:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
