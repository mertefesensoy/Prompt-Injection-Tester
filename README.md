# Prompt Injection & Steganography Forensics Scanner

A forensic analysis tool that scans **PDF** and **DAT/binary** files for prompt injection attacks, steganographic payloads, and hidden content. One command, one comprehensive report.

---

## Quick Start

```bash
pip install -r requirements.txt
python scan.py file.pdf
python scan.py file.pdf report.dat --html --output reports/
```

---

## CLI Reference

```
python scan.py FILE [FILE ...] [options]

Arguments:
  FILE              One or more PDF or DAT files to scan

Options:
  --json            Print JSON report to stdout (machine-readable)
  --html            Write self-contained HTML report to output dir
  --no-color        Disable ANSI colour output (for logs/CI)
  --output DIR      Directory for report files  [default: reports/]
  --threshold N     Risk score for exit-code 1  [default: 0.30]
```

**Exit codes:**
| Code | Meaning |
|------|---------|
| `0` | All files clean / false positive |
| `1` | At least one file above risk threshold |
| `2` | File not found or unrecoverable error |

---

## What Gets Checked

### PDF Files

| Check | What it detects |
|-------|-----------------|
| **Active content** | JavaScript, OpenAction, Launch actions |
| **Form & interactive** | AcroForm fields, URI annotations |
| **Embedded files** | Attachments hidden inside the PDF |
| **Incremental updates** | Second-revision objects that shadow original content |
| **Content streams** | Invisible text (Tr=3), sub-pixel off-page positioning |
| **Unicode Tag attack** | Invisible Unicode Tags embedded in stream bytes decoded to reveal hidden prompt injection instructions |
| **BiDi override** | Right-to-left override characters in stream content |
| **Float forensics** | IEEE 754 sub-pixel clip offsets (Word artifact vs. manipulation) |
| **MCID block analysis** | Marked-content blocks classified as CONTENT / SPACING / INVISIBLE |
| **Image RGB channels** | Chi-square PoV LSB test, RS steganalysis, LSB bitstream PI scan |
| **Alpha / SMask channels** | Same steg pipeline on transparency layers |
| **Spatial autocorrelation** | Structured vs. random LSB patterns |
| **Pixel sparsity** | Sparse logo images explained as false positives |
| **Font encoding** | `/Differences` vectors, suspicious ToUnicode CMap entries |
| **Font binaries** | TrueType magic bytes, entropy anomalies |
| **XMP metadata** | Non-whitespace content hidden in padding section |
| **Document IDs** | DocumentID ≠ InstanceID (file re-saved after creation) |

### DAT / Binary Files

| Check | What it detects |
|-------|-----------------|
| **Format detection** | Text vs. binary; matrix / CSV / JSON / plain |
| **Text PI scan** | 12 prompt injection regex patterns over full text content |
| **Unicode Tag attack** | Invisible Unicode Tags (U+E0000–U+E007F) encoding hidden ASCII instructions ("invisible ink"); decoded payload is scanned for PI patterns |
| **Zero-width smuggling** | Zero-width space, joiner, non-joiner, BOM, and invisible math chars used for covert channel encoding or keyword-filter evasion |
| **BiDi override attack** | Right-to-left override chars (Trojan Source / CVE-2021-42574) that cause human-visible text to differ from machine-readable content |
| **Shannon entropy** | Compressed / encrypted content masquerading as data |
| **Binary LSB analysis** | Chi-square PoV + RS steganalysis on binary payloads |
| **LSB bitstream PI** | Decode LSB plane to bytes, scan for injected instructions |

---

## Interpreting the Report

### Verdicts

| Verdict | Meaning |
|---------|---------|
| `FALSE_POSITIVE` | All risk flags explained by known benign patterns |
| `CLEAN` | No suspicious indicators found |
| `LOW_RISK` | Minor anomalies; likely benign but worth noting |
| `NEEDS_REVIEW` | Conflicting signals; manual inspection recommended |
| `SUSPICIOUS` | Multiple indicators pointing to potential attack |

### Risk Score

0.0 = fully clean · 1.0 = confirmed attack vector

Scores are additive: each detected risk factor contributes a fixed weight. See the *Verdict Engine* section in `scan.py` for exact weights.

---

## False Positive Guide

Several patterns in legitimate PDF files reliably trigger steganography scanners. This tool recognises and explains them:

| Pattern | Cause | How we detect it |
|---------|-------|-----------------|
| Sub-pixel clip rect `x=8.871e-6` | Microsoft Word PDF/UA EMU rounding (1 EMU = 1/914400 inch) | IEEE 754 mantissa match `0x14D4A8` |
| 82–84 identical clip rects per page | Word wraps every MCID span in a full-page clip | Count of sub-pixel rects == MCID span count |
| LSB ratio << 0.5 in sparse images | Logo/icon images are mostly transparent/black; even-valued pixels dominate | Sparsity check + chi-square PoV |
| High RS embedding rate in sparse image | RS analysis breaks down for highly non-uniform distributions | Require: sparsity > 50% AND chi-square CLEAN |
| Alpha channel LSB ratio ≈ 0.5 at edges | Anti-aliased PNG edges have smooth gradients | Chi-square pairs unequal → CLEAN |
| XMP padding whitespace | Word reserves ~2 KB for in-place metadata edits | Count non-whitespace chars in padding |

---

## Architecture

```
scan.py                    Single entry point — auto-detects file type, runs all checks,
                           renders report to terminal + JSON + HTML.

forensics/
  algorithms.py            Pure-math steg algorithms (no I/O):
                             chi2_pov · rs_steganalysis · lsb_bitstream
                             scan_prompt_injection · lsb_spatial_autocorr
                             lsb_heatmap · shannon_entropy · ieee754_word_artifact_confidence

  pdf.py                   All PDF forensic checks:
                             check_structure · check_content_streams
                             check_images · check_fonts · check_metadata

  dat.py                   All DAT/binary checks:
                             detect_format · check_text_content
                             check_binary_steg · check_dat

  report.py                Rendering:
                             render_terminal · render_json · render_html

tools/                     Legacy deep-dive tools for manual investigation
                           (see tools/README.md)
```

---

## Deep-Dive Tools

The `tools/` directory contains specialised scripts for detailed manual investigation of individual objects:

| Script | Purpose |
|--------|---------|
| `xref_forensics.py` | Deep analysis of a single PDF content stream (MCID table, float IEEE 754, clip rect table, full annotated dump) |
| `image_forensics.py` | Deep analysis of a single PDF image XObject (all steg tests + ASCII heatmap) |
| `deep_investigate.py` | False-positive validation for `steg_report.json` findings |
| `pixel_entropy_scanner.py` | Initial entropy-based scan producing `steg_report.json` |
| `advanced_scanner.py` | Multi-strategy scanner (OCR discrepancy, CMap, OCG, perplexity) |
| `pdf_scanner.py` | Baseline prompt-injection scanner (15 vectors) |

---

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `pymupdf` | ≥ 1.23 | PDF parsing, object extraction, pixel data |
| `numpy` | ≥ 1.24 | Array operations for steg math |
| `pillow` | ≥ 10.0 | Image decoding from raw pixel streams |

No scipy required — chi-square CDF is computed via pure-Python regularised incomplete gamma.

---

## Background

This scanner was developed by progressively forensicating a real student homework submission (`HW1.pdf`) that triggered multiple steganography and prompt injection alerts. Every check in this tool has been validated against known clean data and the following reference papers:

- **Westfeld & Pfitzmann (2000)** — Chi-square attack on LSB steganography
- **Fridrich, Goljan & Du (2001)** — Reliable detection of LSB steganography in grayscale and color images (RS analysis)
- **PDF 2.0 Specification (ISO 32000-2)** — Content stream operators, marked content, Type0 fonts
- **PDF/UA-1 (ISO 14289-1)** — Microsoft Word PDF accessibility export format

---

## License

MIT
