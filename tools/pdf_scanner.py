"""
PDF Prompt Injection Scanner
Scans PDF files for 15 prompt injection vectors and produces a risk report.
Usage: python pdf_scanner.py <pdf_path> [--no-color] [--json] [--verbose]
"""

import sys
import os
import io
import re
import json
import argparse
from dataclasses import dataclass, field
from enum import IntEnum
from typing import List, Optional

try:
    from PyPDF2 import PdfReader
    from PyPDF2.generic import ArrayObject
except ImportError:
    print("Error: PyPDF2 is required. Install with: pip install PyPDF2")
    sys.exit(1)


# --- Constants ---

class RiskLevel(IntEnum):
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

RISK_LABELS = {
    RiskLevel.NONE: "NONE",
    RiskLevel.LOW: "LOW",
    RiskLevel.MEDIUM: "MEDIUM",
    RiskLevel.HIGH: "HIGH",
    RiskLevel.CRITICAL: "CRITICAL",
}

ANSI_COLORS = {
    RiskLevel.NONE: "\033[92m",
    RiskLevel.LOW: "\033[96m",
    RiskLevel.MEDIUM: "\033[93m",
    RiskLevel.HIGH: "\033[91m",
    RiskLevel.CRITICAL: "\033[95;1m",
}
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

ZERO_WIDTH_CHARS = {
    '\u200b': 'ZERO WIDTH SPACE',
    '\u200c': 'ZERO WIDTH NON-JOINER',
    '\u200d': 'ZERO WIDTH JOINER',
    '\ufeff': 'ZERO WIDTH NO-BREAK SPACE (BOM)',
    '\u2060': 'WORD JOINER',
    '\u2061': 'FUNCTION APPLICATION',
    '\u2062': 'INVISIBLE TIMES',
    '\u2063': 'INVISIBLE SEPARATOR',
    '\u2064': 'INVISIBLE PLUS',
    '\u180e': 'MONGOLIAN VOWEL SEPARATOR',
    '\u00ad': 'SOFT HYPHEN',
}

BIDI_CHARS = {
    '\u202a': 'LEFT-TO-RIGHT EMBEDDING',
    '\u202b': 'RIGHT-TO-LEFT EMBEDDING',
    '\u202c': 'POP DIRECTIONAL FORMATTING',
    '\u202d': 'LEFT-TO-RIGHT OVERRIDE',
    '\u202e': 'RIGHT-TO-LEFT OVERRIDE',
    '\u200e': 'LEFT-TO-RIGHT MARK',
    '\u200f': 'RIGHT-TO-LEFT MARK',
    '\u2066': 'LEFT-TO-RIGHT ISOLATE',
    '\u2067': 'RIGHT-TO-LEFT ISOLATE',
    '\u2068': 'FIRST STRONG ISOLATE',
    '\u2069': 'POP DIRECTIONAL ISOLATE',
}

HOMOGLYPH_MAP = {
    '\u0410': ('A', 'Cyrillic A'),
    '\u0430': ('a', 'Cyrillic a'),
    '\u0412': ('B', 'Cyrillic Ve'),
    '\u0435': ('e', 'Cyrillic ie'),
    '\u0415': ('E', 'Cyrillic Ie'),
    '\u041a': ('K', 'Cyrillic Ka'),
    '\u041c': ('M', 'Cyrillic Em'),
    '\u041d': ('H', 'Cyrillic En'),
    '\u043e': ('o', 'Cyrillic o'),
    '\u041e': ('O', 'Cyrillic O'),
    '\u0440': ('p', 'Cyrillic er'),
    '\u0420': ('P', 'Cyrillic Er'),
    '\u0441': ('c', 'Cyrillic es'),
    '\u0421': ('C', 'Cyrillic Es'),
    '\u0422': ('T', 'Cyrillic Te'),
    '\u0443': ('y', 'Cyrillic u'),
    '\u0445': ('x', 'Cyrillic kha'),
    '\u0425': ('X', 'Cyrillic Kha'),
    '\u03bf': ('o', 'Greek omicron'),
    '\u039f': ('O', 'Greek Omicron'),
    '\u03b1': ('a', 'Greek alpha'),
    '\u0391': ('A', 'Greek Alpha'),
    '\u03b5': ('e', 'Greek epsilon'),
    '\u0395': ('E', 'Greek Epsilon'),
    '\u03ba': ('k', 'Greek kappa'),
    '\u039a': ('K', 'Greek Kappa'),
    '\u03c1': ('p', 'Greek rho'),
    '\u03a1': ('P', 'Greek Rho'),
    '\u03c4': ('t', 'Greek tau'),
    '\u03a4': ('T', 'Greek Tau'),
    '\u0131': ('i', 'Latin dotless i'),
    '\uff41': ('a', 'Fullwidth a'),
    '\uff42': ('b', 'Fullwidth b'),
    '\uff43': ('c', 'Fullwidth c'),
}

SUSPICIOUS_PATTERNS = [
    (r'ignore\s+(previous|above|all|prior)\s+instructions?', 'CRITICAL'),
    (r'you\s+are\s+now', 'HIGH'),
    (r'disregard\s+(all|previous|prior)', 'CRITICAL'),
    (r'system\s*prompt', 'HIGH'),
    (r'new\s+instructions?', 'MEDIUM'),
    (r'act\s+as\s+(if|a|an)', 'MEDIUM'),
    (r'pretend\s+(you|to\s+be)', 'MEDIUM'),
    (r'override\s+instructions?', 'HIGH'),
    (r'bypass\s+(safety|filter|restriction)', 'HIGH'),
]

SUSPICIOUS_KEYWORDS = [
    'inject', 'exploit', 'payload', 'execute', 'hidden instruction',
    'secret instruction', 'do not tell', 'answer key',
]

JS_KEYWORDS = [b'/JS', b'/JavaScript', b'/OpenAction', b'/AA',
               b'/Launch', b'/RichMedia']
EMBED_KEYWORDS = [b'/EmbeddedFile', b'/EmbeddedFiles', b'/Filespec']
FORM_KEYWORDS = [b'/AcroForm', b'/Widget', b'/SubmitForm', b'/ImportData']


# --- Data structures ---

@dataclass
class Finding:
    check_name: str
    risk: RiskLevel
    details: List[str] = field(default_factory=list)
    status: str = "CLEAN"


# --- Scanner ---

class PDFScanner:
    def __init__(self, pdf_path: str):
        self.pdf_path = pdf_path
        self.reader: Optional[PdfReader] = None
        self.raw_bytes: bytes = b""
        self.raw_text: str = ""
        self.findings: List[Finding] = []
        self.page_texts: List[str] = []

    def _load_pdf(self):
        with open(self.pdf_path, "rb") as f:
            self.raw_bytes = f.read()
        self.raw_text = self.raw_bytes.decode('latin-1')
        self.reader = PdfReader(io.BytesIO(self.raw_bytes))
        self.page_texts = []
        for page in self.reader.pages:
            try:
                text = page.extract_text() or ""
            except Exception:
                text = ""
            self.page_texts.append(text)

    def _get_content_stream_data(self, page) -> bytes:
        try:
            contents = page.get("/Contents")
            if contents is None:
                return b""
            resolved = contents.get_object()
            if isinstance(resolved, ArrayObject):
                data = b""
                for obj in resolved:
                    data += obj.get_object().get_data()
                return data
            else:
                return resolved.get_data()
        except Exception:
            return b""

    def scan(self) -> List[Finding]:
        self._load_pdf()
        checkers = [
            ("Zero-Width Unicode Characters", self.check_zero_width_chars),
            ("Bidi Override Characters", self.check_bidi_overrides),
            ("Homoglyph Characters", self.check_homoglyphs),
            ("JavaScript / Auto-Execution", self.check_javascript_autoexec),
            ("Embedded Files / Attachments", self.check_embedded_files),
            ("Form Fields / Data Submission", self.check_form_fields),
            ("External URIs", self.check_external_uris),
            ("White / Near-White Text", self.check_white_text),
            ("Tiny Font Sizes (< 2pt)", self.check_tiny_fonts),
            ("Off-Page Text", self.check_off_page_text),
            ("Invisible Text Rendering", self.check_invisible_text_rendering),
            ("Hidden Annotations", self.check_hidden_annotations),
            ("XMP Metadata Analysis", self.check_xmp_metadata),
            ("Suspicious Keywords / Phrases", self.check_suspicious_keywords),
            ("Overlapping Text Objects", self.check_overlapping_text),
        ]
        for name, checker in checkers:
            try:
                finding = checker()
                finding.check_name = name
                self.findings.append(finding)
            except Exception as e:
                self.findings.append(Finding(
                    check_name=name,
                    risk=RiskLevel.LOW,
                    details=[f"Check failed with error: {e}"],
                    status="ERROR",
                ))
        return self.findings

    # --- Check 1: Zero-width Unicode ---
    def check_zero_width_chars(self) -> Finding:
        found = []
        for i, text in enumerate(self.page_texts):
            for char, name in ZERO_WIDTH_CHARS.items():
                count = text.count(char)
                if count > 0:
                    found.append(f"Page {i+1}: {name} (U+{ord(char):04X}) x{count}")
        # Also check raw bytes for FEFF BOM (common, usually benign)
        raw_feff = self.raw_bytes.count(b'\xfe\xff')
        if raw_feff > 0 and not found:
            return Finding(
                check_name="", risk=RiskLevel.NONE,
                details=[f"BOM marker (U+FEFF) found in raw bytes x{raw_feff} (standard, benign)"],
                status="CLEAN",
            )
        if found:
            return Finding(
                check_name="", risk=RiskLevel.HIGH,
                details=found, status="FOUND",
            )
        return Finding(check_name="", risk=RiskLevel.NONE, status="CLEAN")

    # --- Check 2: Bidi overrides ---
    def check_bidi_overrides(self) -> Finding:
        found = []
        for i, text in enumerate(self.page_texts):
            for char, name in BIDI_CHARS.items():
                count = text.count(char)
                if count > 0:
                    found.append(f"Page {i+1}: {name} (U+{ord(char):04X}) x{count}")
        if found:
            return Finding(check_name="", risk=RiskLevel.HIGH, details=found, status="FOUND")
        return Finding(check_name="", risk=RiskLevel.NONE, status="CLEAN")

    # --- Check 3: Homoglyphs ---
    def check_homoglyphs(self) -> Finding:
        found = []
        for i, text in enumerate(self.page_texts):
            for char, (ascii_eq, name) in HOMOGLYPH_MAP.items():
                count = text.count(char)
                if count > 0:
                    found.append(f"Page {i+1}: '{char}' ({name}) looks like '{ascii_eq}' x{count}")
        if found:
            return Finding(check_name="", risk=RiskLevel.MEDIUM, details=found, status="FOUND")
        return Finding(check_name="", risk=RiskLevel.NONE, status="CLEAN")

    # --- Check 4: JavaScript / auto-execution ---
    def check_javascript_autoexec(self) -> Finding:
        found = []
        for keyword in JS_KEYWORDS:
            count = self.raw_bytes.count(keyword)
            if count > 0:
                found.append(f"{keyword.decode()} found x{count}")
        if found:
            risk = RiskLevel.CRITICAL
            return Finding(check_name="", risk=risk, details=found, status="FOUND")
        return Finding(check_name="", risk=RiskLevel.NONE, status="CLEAN")

    # --- Check 5: Embedded files ---
    def check_embedded_files(self) -> Finding:
        found = []
        for keyword in EMBED_KEYWORDS:
            count = self.raw_bytes.count(keyword)
            if count > 0:
                found.append(f"{keyword.decode()} found x{count}")
        if found:
            return Finding(check_name="", risk=RiskLevel.HIGH, details=found, status="FOUND")
        return Finding(check_name="", risk=RiskLevel.NONE, status="CLEAN")

    # --- Check 6: Form fields ---
    def check_form_fields(self) -> Finding:
        found = []
        for keyword in FORM_KEYWORDS:
            count = self.raw_bytes.count(keyword)
            if count > 0:
                found.append(f"{keyword.decode()} found x{count}")
        if found:
            risk = RiskLevel.HIGH
            if b'/SubmitForm' in self.raw_bytes:
                risk = RiskLevel.CRITICAL
                found.append("WARNING: /SubmitForm can exfiltrate data!")
            return Finding(check_name="", risk=risk, details=found, status="FOUND")
        return Finding(check_name="", risk=RiskLevel.NONE, status="CLEAN")

    # --- Check 7: External URIs ---
    def check_external_uris(self) -> Finding:
        found = []
        uri_pattern = rb'/URI\s*\(([^)]*)\)'
        matches = re.findall(uri_pattern, self.raw_bytes)
        for m in matches:
            try:
                uri = m.decode('utf-8', errors='replace')
            except Exception:
                uri = str(m)
            found.append(f"URI: {uri}")
        # Also check hex-encoded URIs
        uri_hex_pattern = rb'/URI\s*<([^>]*)>'
        hex_matches = re.findall(uri_hex_pattern, self.raw_bytes)
        for m in hex_matches:
            try:
                uri = bytes.fromhex(m.decode()).decode('utf-8', errors='replace')
            except Exception:
                uri = str(m)
            found.append(f"URI (hex): {uri}")
        if found:
            return Finding(check_name="", risk=RiskLevel.MEDIUM, details=found, status="FOUND")
        return Finding(check_name="", risk=RiskLevel.NONE, status="CLEAN")

    # --- Check 8: White / near-white text ---
    def check_white_text(self) -> Finding:
        found = []
        for i, page in enumerate(self.reader.pages):
            stream = self._get_content_stream_data(page)
            if not stream:
                continue
            stream_text = stream.decode('latin-1', errors='replace')
            # Check for "1 1 1 rg" (white fill color for text)
            white_rgb = re.findall(r'([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+rg', stream_text)
            for r, g, b in white_rgb:
                try:
                    rf, gf, bf = float(r), float(g), float(b)
                    if rf > 0.95 and gf > 0.95 and bf > 0.95:
                        found.append(f"Page {i+1}: Near-white text color ({r}, {g}, {b}) rg")
                except ValueError:
                    pass
            # Check for "1 g" (grayscale white)
            white_gray = re.findall(r'([\d.]+)\s+g(?:\s|$)', stream_text)
            for val in white_gray:
                try:
                    if float(val) > 0.95:
                        found.append(f"Page {i+1}: Near-white grayscale text ({val} g)")
                except ValueError:
                    pass
        if found:
            return Finding(check_name="", risk=RiskLevel.HIGH, details=found, status="FOUND")
        return Finding(check_name="", risk=RiskLevel.NONE, status="CLEAN")

    # --- Check 9: Tiny fonts ---
    def check_tiny_fonts(self) -> Finding:
        found = []
        for i, page in enumerate(self.reader.pages):
            stream = self._get_content_stream_data(page)
            if not stream:
                continue
            stream_text = stream.decode('latin-1', errors='replace')
            font_sizes = re.findall(r'([\d.]+)\s+Tf', stream_text)
            for size_str in font_sizes:
                try:
                    size = float(size_str)
                    if 0 < size < 2.0:
                        found.append(f"Page {i+1}: Tiny font size {size}pt")
                except ValueError:
                    pass
        if found:
            return Finding(check_name="", risk=RiskLevel.HIGH, details=found, status="FOUND")
        return Finding(check_name="", risk=RiskLevel.NONE, status="CLEAN")

    # --- Check 10: Off-page text ---
    def check_off_page_text(self) -> Finding:
        found = []
        for i, page in enumerate(self.reader.pages):
            mediabox = page.get("/MediaBox")
            if not mediabox:
                continue
            try:
                page_width = float(mediabox[2])
                page_height = float(mediabox[3])
            except (IndexError, TypeError, ValueError):
                continue
            stream = self._get_content_stream_data(page)
            if not stream:
                continue
            stream_text = stream.decode('latin-1', errors='replace')
            # Check Td (text position) operators
            positions = re.findall(r'([-\d.]+)\s+([-\d.]+)\s+Td', stream_text)
            for x_str, y_str in positions:
                try:
                    x, y = float(x_str), float(y_str)
                    if x < -100 or y < -100 or x > page_width + 100 or y > page_height + 100:
                        found.append(f"Page {i+1}: Off-page text position ({x}, {y}), page size ({page_width}x{page_height})")
                except ValueError:
                    pass
            # Check Tm (text matrix) operators
            tm_matches = re.findall(
                r'([-\d.]+)\s+([-\d.]+)\s+([-\d.]+)\s+([-\d.]+)\s+([-\d.]+)\s+([-\d.]+)\s+Tm',
                stream_text
            )
            for a, b, c, d, e, f_val in tm_matches:
                try:
                    tx, ty = float(e), float(f_val)
                    if tx < -100 or ty < -100 or tx > page_width + 100 or ty > page_height + 100:
                        found.append(f"Page {i+1}: Off-page text matrix position ({tx}, {ty})")
                except ValueError:
                    pass
        if found:
            return Finding(check_name="", risk=RiskLevel.HIGH, details=found, status="FOUND")
        return Finding(check_name="", risk=RiskLevel.NONE, status="CLEAN")

    # --- Check 11: Invisible text rendering ---
    def check_invisible_text_rendering(self) -> Finding:
        found = []
        for i, page in enumerate(self.reader.pages):
            stream = self._get_content_stream_data(page)
            if not stream:
                continue
            stream_text = stream.decode('latin-1', errors='replace')
            invisible = re.findall(r'3\s+Tr', stream_text)
            if invisible:
                found.append(f"Page {i+1}: Invisible text rendering mode (3 Tr) x{len(invisible)}")
        if found:
            return Finding(check_name="", risk=RiskLevel.CRITICAL, details=found, status="FOUND")
        return Finding(check_name="", risk=RiskLevel.NONE, status="CLEAN")

    # --- Check 12: Hidden annotations ---
    def check_hidden_annotations(self) -> Finding:
        found = []
        for i, page in enumerate(self.reader.pages):
            annots = page.get("/Annots")
            if not annots:
                continue
            try:
                annots_resolved = annots.get_object()
            except Exception:
                continue
            if not isinstance(annots_resolved, (list, ArrayObject)):
                continue
            for annot_ref in annots_resolved:
                try:
                    annot = annot_ref.get_object()
                except Exception:
                    continue
                # Check hidden flag (bit 2)
                flags = annot.get("/F", 0)
                try:
                    flags = int(flags)
                except (TypeError, ValueError):
                    flags = 0
                if flags & 2:  # Hidden bit
                    contents = annot.get("/Contents", "")
                    found.append(f"Page {i+1}: Hidden annotation with contents: {str(contents)[:100]}")
                # Check for zero-size annotations
                rect = annot.get("/Rect")
                if rect:
                    try:
                        coords = [float(x) for x in rect]
                        width = abs(coords[2] - coords[0])
                        height = abs(coords[3] - coords[1])
                        if width < 1 and height < 1:
                            contents = annot.get("/Contents", "")
                            if contents:
                                found.append(f"Page {i+1}: Zero-size annotation with contents: {str(contents)[:100]}")
                    except (TypeError, ValueError, IndexError):
                        pass
        if found:
            return Finding(check_name="", risk=RiskLevel.MEDIUM, details=found, status="FOUND")
        return Finding(check_name="", risk=RiskLevel.NONE, status="CLEAN")

    # --- Check 13: XMP metadata ---
    def check_xmp_metadata(self) -> Finding:
        details = []
        # Extract metadata via PyPDF2
        meta = self.reader.metadata
        if meta:
            for key in ['/Title', '/Author', '/Subject', '/Keywords',
                        '/Creator', '/Producer', '/CreationDate', '/ModDate']:
                val = meta.get(key)
                if val:
                    details.append(f"{key}: {str(val)[:200]}")
        # Check for XMP packet in raw bytes
        xmp_start = self.raw_bytes.find(b'<?xpacket begin')
        xmp_end = self.raw_bytes.find(b'<?xpacket end')
        if xmp_start >= 0 and xmp_end >= 0:
            xmp_size = xmp_end - xmp_start
            details.append(f"XMP metadata packet found ({xmp_size} bytes)")
            # Check XMP content for suspicious strings
            xmp_content = self.raw_bytes[xmp_start:xmp_end].decode('utf-8', errors='replace').lower()
            for kw in SUSPICIOUS_KEYWORDS:
                if kw.lower() in xmp_content:
                    details.append(f"SUSPICIOUS: keyword '{kw}' found in XMP metadata!")
                    return Finding(check_name="", risk=RiskLevel.HIGH, details=details, status="SUSPICIOUS")
        if details:
            return Finding(check_name="", risk=RiskLevel.NONE, details=details, status="INFO")
        return Finding(check_name="", risk=RiskLevel.NONE, status="CLEAN")

    # --- Check 14: Suspicious keywords ---
    def check_suspicious_keywords(self) -> Finding:
        found = []
        all_text = "\n".join(self.page_texts).lower()
        max_risk = RiskLevel.NONE
        # Check phrase patterns
        for pattern, risk_str in SUSPICIOUS_PATTERNS:
            matches = re.findall(pattern, all_text, re.IGNORECASE)
            if matches:
                risk = getattr(RiskLevel, risk_str)
                max_risk = max(max_risk, risk)
                found.append(f"Pattern '{pattern}' matched ({risk_str})")
        # Check individual keywords
        for kw in SUSPICIOUS_KEYWORDS:
            if kw.lower() in all_text:
                max_risk = max(max_risk, RiskLevel.MEDIUM)
                found.append(f"Keyword '{kw}' found in text")
        # Also check raw bytes for keywords (catches hidden text)
        raw_lower = self.raw_text.lower()
        for pattern, risk_str in SUSPICIOUS_PATTERNS:
            matches = re.findall(pattern, raw_lower, re.IGNORECASE)
            if matches:
                risk = getattr(RiskLevel, risk_str)
                max_risk = max(max_risk, risk)
                found.append(f"Pattern '{pattern}' matched in raw bytes ({risk_str})")
        if found:
            # Deduplicate
            found = list(dict.fromkeys(found))
            return Finding(check_name="", risk=max_risk, details=found, status="FOUND")
        return Finding(check_name="", risk=RiskLevel.NONE, status="CLEAN")

    # --- Check 15: Overlapping text ---
    def check_overlapping_text(self) -> Finding:
        found = []
        for i, page in enumerate(self.reader.pages):
            stream = self._get_content_stream_data(page)
            if not stream:
                continue
            stream_text = stream.decode('latin-1', errors='replace')
            # Collect all text positioning operations
            positions = []
            for match in re.finditer(
                r'([-\d.]+)\s+([-\d.]+)\s+([-\d.]+)\s+([-\d.]+)\s+([-\d.]+)\s+([-\d.]+)\s+Tm',
                stream_text
            ):
                try:
                    tx, ty = float(match.group(5)), float(match.group(6))
                    positions.append((tx, ty))
                except ValueError:
                    pass
            # Check for duplicate positions (within tolerance)
            seen = {}
            for tx, ty in positions:
                key = (round(tx, 1), round(ty, 1))
                seen[key] = seen.get(key, 0) + 1
            overlaps = {k: v for k, v in seen.items() if v > 2}
            if overlaps:
                for (tx, ty), count in overlaps.items():
                    found.append(f"Page {i+1}: {count} text objects at position ({tx}, {ty})")
        if found:
            return Finding(check_name="", risk=RiskLevel.MEDIUM,
                           details=found + ["Note: Some overlap is normal in formatted documents"],
                           status="FOUND")
        return Finding(check_name="", risk=RiskLevel.NONE, status="CLEAN")


# --- Report Renderer ---

class ReportRenderer:
    def __init__(self, pdf_path: str, reader: PdfReader, findings: List[Finding],
                 use_color: bool = True, verbose: bool = False):
        self.pdf_path = pdf_path
        self.reader = reader
        self.findings = findings
        self.use_color = use_color
        self.verbose = verbose

    def _c(self, risk: RiskLevel, text: str) -> str:
        if not self.use_color:
            return text
        return f"{ANSI_COLORS[risk]}{text}{RESET}"

    def _bold(self, text: str) -> str:
        if not self.use_color:
            return text
        return f"{BOLD}{text}{RESET}"

    def _dim(self, text: str) -> str:
        if not self.use_color:
            return text
        return f"{DIM}{text}{RESET}"

    def render(self) -> str:
        lines = []
        sep = "=" * 62
        file_size = os.path.getsize(self.pdf_path)
        num_pages = len(self.reader.pages)

        if file_size >= 1024 * 1024:
            size_str = f"{file_size / (1024*1024):.1f} MB"
        else:
            size_str = f"{file_size / 1024:.1f} KB"

        lines.append(sep)
        lines.append(self._bold("  PDF Prompt Injection Scanner"))
        lines.append(f"  File:  {os.path.basename(self.pdf_path)}")
        lines.append(f"  Pages: {num_pages} | Size: {size_str}")
        lines.append(sep)
        lines.append("")

        for idx, finding in enumerate(self.findings):
            num = f"[{idx+1:2d}/{len(self.findings)}]"
            lines.append(f"{self._bold(num)} {finding.check_name}")
            status_str = self._c(finding.risk, finding.status)
            risk_str = self._c(finding.risk, RISK_LABELS[finding.risk])
            lines.append(f"  Status: {status_str}")
            lines.append(f"  Risk:   {risk_str}")
            if finding.details and (self.verbose or finding.risk > RiskLevel.NONE):
                lines.append("  Details:")
                for detail in finding.details:
                    lines.append(f"    - {detail}")
            lines.append("")

        # Overall assessment
        max_risk = max((f.risk for f in self.findings), default=RiskLevel.NONE)
        issues = sum(1 for f in self.findings if f.risk > RiskLevel.NONE)
        passed = len(self.findings) - issues
        errors = sum(1 for f in self.findings if f.status == "ERROR")

        lines.append(sep)
        lines.append(self._bold("  OVERALL RISK ASSESSMENT: ") + self._c(max_risk, RISK_LABELS[max_risk]))
        lines.append(sep)
        lines.append(f"  Checks passed:  {passed}/{len(self.findings)}")
        lines.append(f"  Issues found:   {issues}")
        if errors:
            lines.append(f"  Check errors:   {errors}")
        if max_risk >= RiskLevel.HIGH:
            highest = [f.check_name for f in self.findings if f.risk == max_risk]
            lines.append(f"  Highest risk:   {RISK_LABELS[max_risk]} ({', '.join(highest)})")
            lines.append("")
            lines.append(self._c(max_risk,
                "  WARNING: This PDF contains potential prompt injection vectors."))
            lines.append(self._c(max_risk,
                "  Exercise caution when processing with LLMs."))
        else:
            lines.append("")
            lines.append(self._c(RiskLevel.NONE,
                "  This PDF appears safe. No prompt injection vectors detected."))
        lines.append(sep)
        return "\n".join(lines)

    def to_dict(self) -> dict:
        file_size = os.path.getsize(self.pdf_path)
        return {
            "file": os.path.basename(self.pdf_path),
            "path": os.path.abspath(self.pdf_path),
            "pages": len(self.reader.pages),
            "size_bytes": file_size,
            "overall_risk": RISK_LABELS[max((f.risk for f in self.findings), default=RiskLevel.NONE)],
            "checks": [
                {
                    "name": f.check_name,
                    "status": f.status,
                    "risk": RISK_LABELS[f.risk],
                    "details": f.details,
                }
                for f in self.findings
            ],
        }


# --- CLI ---

def main():
    parser = argparse.ArgumentParser(
        description="PDF Prompt Injection Scanner - Scan PDFs for 15 injection vectors"
    )
    parser.add_argument("pdf_path", help="Path to the PDF file to scan")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color codes")
    parser.add_argument("--json", action="store_true", dest="json_output", help="Output as JSON")
    parser.add_argument("--verbose", action="store_true", help="Show details for all checks")
    args = parser.parse_args()

    if not os.path.isfile(args.pdf_path):
        print(f"Error: File not found: {args.pdf_path}")
        sys.exit(1)

    if not args.pdf_path.lower().endswith('.pdf'):
        print(f"Warning: File does not have .pdf extension: {args.pdf_path}")

    scanner = PDFScanner(args.pdf_path)
    try:
        findings = scanner.scan()
    except Exception as e:
        print(f"Error: Failed to scan PDF: {e}")
        sys.exit(1)

    renderer = ReportRenderer(
        pdf_path=args.pdf_path,
        reader=scanner.reader,
        findings=findings,
        use_color=not args.no_color and not args.json_output,
        verbose=args.verbose,
    )

    if args.json_output:
        print(json.dumps(renderer.to_dict(), indent=2))
    else:
        print(renderer.render())

    # Exit code based on risk
    max_risk = max((f.risk for f in findings), default=RiskLevel.NONE)
    sys.exit(1 if max_risk >= RiskLevel.HIGH else 0)


if __name__ == "__main__":
    main()
