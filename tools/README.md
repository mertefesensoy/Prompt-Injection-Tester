# Deep-Dive Forensic Tools

These scripts were developed during iterative forensic investigation of `HW1.pdf`. They are **standalone CLI tools** for detailed manual analysis of individual PDF objects — complementing the automated `scan.py` at the repo root.

> **For automated scanning, use `scan.py` at the project root — not these scripts.**

---

## Tools

### `xref_forensics.py` — Content Stream Deep-Dive
Detailed forensic analysis of a single PDF content stream (xref object).

```bash
python tools/xref_forensics.py HW1.pdf --xref 4 --no-color
python tools/xref_forensics.py HW1.pdf --xref 4 --json > xref4.json
python tools/xref_forensics.py HW1.pdf --xref 4 --html > xref4.html
python tools/xref_forensics.py HW1.pdf --xref 4 --full-dump   # hex dump
python tools/xref_forensics.py HW1.pdf --xref 4 --compare 27  # compare two streams
```

**Output sections:**
- MCID block table (text, font, render mode, position, classification)
- IEEE 754 float forensics with Word artifact confidence scores
- Clip rectangle comparison table
- Optional annotated stream hex dump

---

### `image_forensics.py` — Image XObject Deep-Dive
Full steganography analysis of a single PDF image XObject.

```bash
python tools/image_forensics.py HW1.pdf --xref 24 --no-color
python tools/image_forensics.py HW1.pdf --xref 22 --json > xref22.json
```

**Output sections:**
1. Pixel value histogram + LSB profile per channel
2. Chi-square PoV LSB attack (Westfeld & Pfitzmann 2000)
3. RS Steganalysis (Fridrich et al. 2001)
4. LSB bitstream decode + prompt injection scan
5. Spatial autocorrelation of LSB plane
6. Cross-channel LSB correlation
7. ASCII LSB heatmap
8. Final verdict with evidence for/against

---

### `pixel_entropy_scanner.py` — Initial Entropy Scan
Produces `steg_report.json` with per-image and per-stream risk scores.
Used as input to `deep_investigate.py`.

```bash
python tools/pixel_entropy_scanner.py HW1.pdf --json --output steg_report.json
```

---

### `deep_investigate.py` — False-Positive Validator
Validates findings from `steg_report.json`, classifying each as
CONFIRMED / FALSE_POSITIVE / INFORMATIONAL / NEEDS_REVIEW.

```bash
python tools/deep_investigate.py HW1.pdf --report steg_report.json --no-color
python tools/deep_investigate.py HW1.pdf --all                    # include LOW findings
python tools/deep_investigate.py HW1.pdf --xref 4,24,27          # specific xrefs only
```

---

### `advanced_scanner.py` — Multi-Strategy Scanner
Five advanced detection strategies beyond basic entropy:
- S1: Cross-modal OCR discrepancy analysis
- S2: CMap & font subsetting validation
- S3: Multi-state OCG (Optional Content Group) enumeration
- S4: Pixel-level entropy & steganography scanning
- S5: Semantic coherence & perplexity analysis

```bash
python tools/advanced_scanner.py HW1.pdf --no-color
python tools/advanced_scanner.py HW1.pdf --strategies S1,S2,S4 --json
```

---

### `pdf_scanner.py` — Baseline Prompt Injection Scanner
Original 15-vector prompt injection scanner. Detects zero-width chars,
off-page text, invisible layers, annotation URI injection, and more.

```bash
python tools/pdf_scanner.py HW1.pdf --no-color
python tools/pdf_scanner.py HW1.pdf --json --verbose
```

---

## Investigation Workflow

For a new suspicious file, the recommended deep-dive sequence is:

```
1. python scan.py file.pdf                        # automated overview
2. python tools/pdf_scanner.py file.pdf            # 15-vector baseline
3. python tools/pixel_entropy_scanner.py file.pdf  # entropy + steg scores → steg_report.json
4. python tools/deep_investigate.py file.pdf       # false-positive filtering
5. python tools/xref_forensics.py file.pdf --xref N    # deep-dive on flagged streams
6. python tools/image_forensics.py file.pdf --xref N   # deep-dive on flagged images
```

---

## Dependencies

All tools require the same packages as the main scanner:
```bash
pip install pymupdf numpy pillow
```

`pdf_scanner.py` additionally requires:
```bash
pip install pypdf2
```
