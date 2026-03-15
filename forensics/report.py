"""
forensics/report.py
Render unified scan results as terminal text, JSON, or self-contained HTML.
"""

from __future__ import annotations
import json
import html as _html_module
from datetime import datetime
from typing import Any

# ─── ANSI Colour Helpers ─────────────────────────────────────────────────────

_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_DIM    = "\033[2m"
_GREEN  = "\033[92m"
_YELLOW = "\033[93m"
_RED    = "\033[91m"
_CYAN   = "\033[96m"
_MAGENTA= "\033[95m"
_WHITE  = "\033[97m"

_VERDICT_COLORS = {
    "CLEAN":               _GREEN,
    "FALSE_POSITIVE":      _GREEN,
    "LOW":                 _CYAN,
    "LOW_RISK":            _CYAN,
    "NEEDS_REVIEW":        _YELLOW,
    "SUSPICIOUS":          _RED,
    "CONFIRMED_SUSPICIOUS":_MAGENTA,
    "WORD_ARTIFACT":       _CYAN,
    "NATURAL":             _GREEN,
    "POSSIBLE_ARTIFACT":   _YELLOW,
    "NO_FLOATS":           _DIM,
    "NORMAL":              _GREEN,
    "SUB_PIXEL":           _YELLOW,
}

_RISK_COLORS = {
    "LOW":      _GREEN,
    "MEDIUM":   _YELLOW,
    "HIGH":     _RED,
    "CRITICAL": _MAGENTA,
}


def _c(text: str, color: str, no_color: bool) -> str:
    return text if no_color else f"{color}{text}{_RESET}"


def _vc(verdict: str, no_color: bool) -> str:
    color = _VERDICT_COLORS.get(verdict, _WHITE)
    return _c(verdict, color, no_color)


def _sep(char: str = "─", width: int = 72, no_color: bool = False) -> str:
    return _c(char * width, _DIM, no_color)


def _header(title: str, width: int = 72, no_color: bool = False) -> str:
    line = _c("═" * width, _BOLD, no_color)
    padded = title.center(width)
    return f"{line}\n{_c(padded, _BOLD + _WHITE, no_color)}\n{line}"


def _section(title: str, no_color: bool = False) -> str:
    return _c(f"  ▸ {title}", _BOLD + _CYAN, no_color)


def _check(text: str, ok: bool, no_color: bool = False) -> str:
    if ok:
        mark = _c("✓", _GREEN, no_color)
    else:
        mark = _c("✗", _RED, no_color)
    return f"    [{mark}] {text}"


# ─── Terminal Renderer ────────────────────────────────────────────────────────

def render_terminal(result: dict, no_color: bool = False) -> str:
    lines = []
    W = 72

    ft = result.get("file_type", "UNKNOWN")
    fname = result.get("file", "?")
    fsize = result.get("file_size_bytes", 0)
    ts = result.get("scan_timestamp", "")
    overall = result.get("overall", {})
    verdict = overall.get("verdict", "UNKNOWN")
    confidence = overall.get("confidence", 0)
    risk_score = overall.get("risk_score", 0)
    risk_level = overall.get("risk_level", "UNKNOWN")
    sections = result.get("sections", {})

    # ── Header ──────────────────────────────────────────────────
    lines.append("")
    lines.append(_header(f"FORENSICS SCANNER  |  {fname}", W, no_color))
    lines.append(f"  File Type  : {ft}   |   Size: {fsize/1024:.1f} KB   |   {ts}")
    lines.append(_sep(width=W, no_color=no_color))

    # ── Overall ─────────────────────────────────────────────────
    verdict_str = _vc(verdict, no_color)
    risk_color = _RISK_COLORS.get(risk_level, _WHITE)
    risk_str = _c(risk_level, risk_color, no_color)
    lines.append(f"  VERDICT  :  {verdict_str}  ({confidence:.0%} confidence)")
    lines.append(f"  RISK     :  {risk_str}  (score {risk_score:.2f} / 1.00)")
    lines.append(_sep(width=W, no_color=no_color))

    if ft == "PDF":
        _render_pdf_sections(lines, sections, no_color, W)
    else:
        _render_dat_sections(lines, sections, no_color, W)

    # ── Summary ──────────────────────────────────────────────────
    summary = result.get("summary", {})
    lines.append(_sep(width=W, no_color=no_color))
    total = summary.get("total_checks", 0)
    passed = summary.get("passed", 0)
    flagged = summary.get("flagged", 0)
    lines.append(f"  Checks: {total} total  |  "
                 f"{_c(str(passed)+' passed', _GREEN, no_color)}  |  "
                 f"{_c(str(flagged)+' flagged', _RED if flagged else _GREEN, no_color)}")
    lines.append(_sep("═", W, no_color))
    lines.append("")
    return "\n".join(lines)


def _render_pdf_sections(lines: list, sections: dict, no_color: bool, W: int) -> None:
    # §1 Structure
    lines.append(_section("§1  PDF STRUCTURE", no_color))
    struct = sections.get("structure", {})
    lines.append(_check("No JavaScript / OpenAction", not struct.get("js_found") and not struct.get("open_action"), no_color))
    lines.append(_check("No AcroForm / form fields", not struct.get("acroform"), no_color))
    annots = struct.get("annotations", [])
    lines.append(_check(f"Annotations: {len(annots)} found" if annots else "No annotations", not any("uri" in a for a in annots), no_color))
    emb = struct.get("embedded_files", [])
    lines.append(_check(f"No embedded file attachments" if not emb else f"{len(emb)} embedded file(s) found", not emb, no_color))
    inc = struct.get("incremental_updates", {})
    new_x = inc.get("new_xrefs", [])
    lines.append(_check(
        f"Incremental updates: {inc.get('count',0)} found, {inc.get('total_bytes',0)} bytes" +
        (f", modifies {len(new_x)} objects — SUSPICIOUS" if new_x else ", no new objects"),
        not new_x, no_color
    ))
    lines.append("")

    # §2 Content Streams
    lines.append(_section("§2  CONTENT STREAMS", no_color))
    for cs in sections.get("content_streams", []):
        xref = cs.get("xref")
        page = cs.get("page", "?")
        v = cs.get("verdict", "?")
        conf = cs.get("confidence", 0)
        inv = cs.get("invisible_text", False)
        mcid = cs.get("mcid_block_count", 0)
        floats = cs.get("floats", {})
        clips = cs.get("clip_rects", {})
        vstr = _vc(v, no_color)
        lines.append(f"    xref={xref} (page {page})  ► {vstr}  {conf:.0%}")
        lines.append(_check("No invisible text (Tr=3)", not inv, no_color))
        lines.append(_check(f"MCID blocks: {mcid}", True, no_color))
        lines.append(_check(
            f"Floats: {floats.get('count',0)} total, "
            f"{floats.get('word_artifact_count',0)} Word artifacts — {floats.get('verdict','')}",
            floats.get("verdict") in ("WORD_ARTIFACT", "NATURAL", "NO_FLOATS"),
            no_color
        ))
        lines.append(_check(
            f"Clip rects: {clips.get('count',0)}, "
            f"{clips.get('word_artifact_count',0)} Word artifacts — {clips.get('verdict','')}",
            clips.get("verdict") in ("WORD_ARTIFACT", "NORMAL"),
            no_color
        ))
    if not sections.get("content_streams"):
        lines.append("    (none found)")
    lines.append("")

    # §3 Images & Alpha Channels
    lines.append(_section("§3  IMAGES & ALPHA CHANNELS", no_color))
    for img in sections.get("images", []):
        xref = img.get("xref")
        dims = img.get("dimensions", "?")
        cs_name = img.get("colorspace", "")
        is_alpha = img.get("is_alpha", False)
        for_xref = img.get("for_image_xref")
        v = img.get("verdict", "?")
        conf = img.get("confidence", 0)
        analysis = img.get("analysis", {})
        chi2 = analysis.get("chi2", {})
        rs = analysis.get("rs", {})
        lsb = analysis.get("lsb", {})
        sparsity = analysis.get("sparsity", 0)

        label = "Alpha" if is_alpha else "Image"
        for_str = f" (alpha for xref={for_xref})" if for_xref else ""
        vstr = _vc(v, no_color)
        lines.append(f"    xref={xref} {dims} {cs_name}{for_str}  ► {vstr}  {conf:.0%}")
        lines.append(_check(
            f"Chi-square: p={chi2.get('p_value',0):.4f} → {chi2.get('verdict','')}",
            chi2.get("verdict") == "CLEAN", no_color
        ))
        lines.append(_check(
            f"RS embedding rate: {rs.get('embedding_rate',0):.1%} → {rs.get('verdict','')}",
            rs.get("verdict") in ("CLEAN", "LOW_RISK"), no_color
        ))
        lines.append(_check(
            f"Sparsity: {sparsity:.0%}",
            sparsity > 0.40, no_color
        ))
        pi = lsb.get("pi_matches", [])
        lines.append(_check(
            "No prompt injection in LSB bitstream" if not pi else f"{len(pi)} PI pattern(s) found",
            not pi, no_color
        ))
        ev_for = img.get("evidence_for_fp", [])
        for ev in ev_for[:2]:
            lines.append(f"      {_c('+', _GREEN, no_color)} {ev}")
        ev_ag = img.get("evidence_against", [])
        for ev in ev_ag[:2]:
            lines.append(f"      {_c('-', _RED, no_color)} {ev}")
    if not sections.get("images"):
        lines.append("    (none found)")
    lines.append("")

    # §4 Fonts
    lines.append(_section("§4  FONTS", no_color))
    fonts = sections.get("fonts", [])
    clean_fonts = [f for f in fonts if f.get("verdict") == "CLEAN"]
    flagged_fonts = [f for f in fonts if f.get("verdict") != "CLEAN"]
    if clean_fonts:
        subtypes = {}
        for f in clean_fonts:
            st = f.get("subtype", "?")
            subtypes[st] = subtypes.get(st, 0) + 1
        for st, cnt in subtypes.items():
            lines.append(_check(f"{cnt} {st} font(s) — clean", True, no_color))
    for f in flagged_fonts:
        name = f.get("name", "?")
        flags = f.get("flags", [])
        lines.append(_check(f"xref={f['xref']} {name}: {'; '.join(flags)}", False, no_color))
    if not fonts:
        lines.append("    (none found)")
    lines.append("")

    # §5 Metadata
    lines.append(_section("§5  METADATA", no_color))
    meta = sections.get("metadata", {})
    if meta.get("author"):
        lines.append(f"    Author   : {meta['author']}")
    if meta.get("producer"):
        prod = meta["producer"][:60]
        lines.append(f"    Producer : {prod}")
    if meta.get("created"):
        lines.append(f"    Created  : {meta['created']}")
    lines.append(_check("XMP padding clean (no hidden content)", meta.get("xmp_padding_clean", True), no_color))
    lines.append(_check(
        "Producer is Microsoft Word (explains PDF/UA artifacts)" if meta.get("producer_is_word") else "Non-Word producer",
        True, no_color
    ))
    flags = meta.get("flags", [])
    for flag in flags:
        lines.append(f"      {_c('!', _YELLOW, no_color)} {flag}")
    lines.append("")


def _render_dat_sections(lines: list, sections: dict, no_color: bool, W: int) -> None:
    dat = sections.get("dat", {})
    if not dat:
        lines.append("    (no analysis available)")
        return

    fmt = dat.get("format", {})
    lines.append(_section("§1  FILE FORMAT", no_color))
    lines.append(f"    Format      : {fmt.get('likely_format','?')}")
    lines.append(f"    Encoding    : {fmt.get('encoding','?')}")
    lines.append(f"    Size        : {dat.get('size_bytes',0)} bytes")
    lines.append(f"    Entropy     : {dat.get('entropy',0):.3f} bits/byte")
    lines.append(f"    Printable   : {fmt.get('printable_ratio',0):.0%}")
    lines.append("")

    text_a = dat.get("text_analysis")
    if text_a:
        lines.append(_section("§2  TEXT CONTENT", no_color))
        lines.append(f"    Lines       : {text_a.get('line_count',0)}")
        lines.append(f"    Words       : {text_a.get('word_count',0)}")
        lines.append(f"    Structure   : {text_a.get('structure','?')}")
        pi = text_a.get("prompt_injection", {})
        lines.append(_check(
            f"Prompt injection scan: {pi.get('verdict','?')}",
            pi.get("verdict") == "CLEAN", no_color
        ))
        for m in pi.get("matches", []):
            lines.append(f"      {_c('!', _RED, no_color)} {m.get('context','')[:80]}")
        lines.append("")

    bin_a = dat.get("binary_analysis")
    if bin_a:
        lines.append(_section("§2  BINARY STEGANOGRAPHY", no_color))
        lines.append(f"    LSB ratio   : {bin_a.get('lsb_ones_ratio',0):.4f}")
        lines.append(_check(
            f"Chi-square: p={bin_a.get('chi2_p',0):.4f} → {bin_a.get('chi2_verdict','')}",
            bin_a.get("chi2_verdict") == "CLEAN", no_color
        ))
        lines.append(_check(
            f"RS embedding: {bin_a.get('rs_embedding_rate',0):.1%} → {bin_a.get('rs_verdict','')}",
            bin_a.get("rs_verdict") in ("CLEAN", "LOW_RISK"), no_color
        ))
        pi = bin_a.get("pi_matches", [])
        lines.append(_check(
            "No PI patterns in LSB bitstream" if not pi else f"{len(pi)} PI matches",
            not pi, no_color
        ))
        lines.append("")

    ev_for = dat.get("evidence_for_clean", [])
    ev_ag = dat.get("evidence_against", [])
    for ev in ev_for:
        lines.append(f"    {_c('+', _GREEN, no_color)} {ev}")
    for ev in ev_ag:
        lines.append(f"    {_c('-', _RED, no_color)} {ev}")
    if ev_for or ev_ag:
        lines.append("")


# ─── JSON Renderer ────────────────────────────────────────────────────────────

def render_json(result: dict) -> str:
    return json.dumps(result, indent=2, ensure_ascii=False, default=str)


# ─── HTML Renderer ────────────────────────────────────────────────────────────

_HTML_VERDICT_CLASSES = {
    "CLEAN": "clean", "FALSE_POSITIVE": "clean",
    "LOW_RISK": "low", "NEEDS_REVIEW": "warn",
    "SUSPICIOUS": "bad", "CONFIRMED_SUSPICIOUS": "bad",
    "WORD_ARTIFACT": "low", "NATURAL": "clean",
}


def render_html(result: dict) -> str:
    fname = _html_module.escape(result.get("file", "?"))
    ft = result.get("file_type", "?")
    ts = result.get("scan_timestamp", "")
    overall = result.get("overall", {})
    verdict = overall.get("verdict", "?")
    confidence = overall.get("confidence", 0)
    risk_score = overall.get("risk_score", 0)
    risk_level = overall.get("risk_level", "?")
    sections = result.get("sections", {})
    summary = result.get("summary", {})

    v_class = _HTML_VERDICT_CLASSES.get(verdict, "warn")

    body_parts = []

    if ft == "PDF":
        body_parts.append(_html_pdf_sections(sections))
    else:
        body_parts.append(_html_dat_sections(sections))

    json_data = _html_module.escape(render_json(result))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Forensics Report — {fname}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: #0d1117; color: #c9d1d9; font-family: 'Consolas','Menlo',monospace;
         font-size: 13px; padding: 24px; }}
  h1 {{ font-size: 18px; color: #e6edf3; margin-bottom: 4px; }}
  .subtitle {{ color: #8b949e; font-size: 12px; margin-bottom: 20px; }}
  .overall {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px;
              padding: 16px; margin-bottom: 20px; }}
  .verdict {{ font-size: 20px; font-weight: bold; }}
  .clean  {{ color: #3fb950; }}
  .low    {{ color: #58a6ff; }}
  .warn   {{ color: #d29922; }}
  .bad    {{ color: #f85149; }}
  section {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px;
             padding: 16px; margin-bottom: 16px; }}
  section h2 {{ font-size: 14px; color: #79c0ff; margin-bottom: 12px; border-bottom:
                1px solid #30363d; padding-bottom: 6px; }}
  .item {{ margin: 4px 0; padding-left: 12px; }}
  .pass::before {{ content: "✓ "; color: #3fb950; }}
  .fail::before {{ content: "✗ "; color: #f85149; }}
  .info::before {{ content: "● "; color: #8b949e; }}
  .ev-for {{ color: #3fb950; padding-left: 20px; }}
  .ev-against {{ color: #f85149; padding-left: 20px; }}
  details {{ margin: 8px 0; }}
  summary {{ cursor: pointer; color: #79c0ff; user-select: none; }}
  pre {{ background: #0d1117; padding: 12px; border-radius: 4px; overflow-x: auto;
         font-size: 11px; color: #8b949e; margin-top: 8px; border: 1px solid #21262d; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
           gap: 8px; margin-top: 8px; }}
  .kv {{ background: #0d1117; padding: 8px; border-radius: 4px; border: 1px solid #21262d; }}
  .kv-key {{ color: #8b949e; font-size: 11px; }}
  .kv-val {{ color: #e6edf3; font-size: 13px; font-weight: bold; }}
</style>
</head>
<body>
<h1>Forensics Report — {fname}</h1>
<div class="subtitle">{ft} &nbsp;|&nbsp; {ts}</div>

<div class="overall">
  <div class="verdict {v_class}">{verdict}</div>
  <div style="margin-top:8px">
    Confidence: <strong>{confidence:.0%}</strong> &nbsp;|&nbsp;
    Risk Score: <strong>{risk_score:.2f}</strong> &nbsp;|&nbsp;
    Risk Level: <strong class="{_HTML_VERDICT_CLASSES.get(risk_level,'warn')}">{risk_level}</strong>
  </div>
  <div style="margin-top:8px;color:#8b949e">
    Checks: {summary.get('total_checks',0)} total &nbsp;|&nbsp;
    <span class="clean">{summary.get('passed',0)} passed</span> &nbsp;|&nbsp;
    <span class="{'bad' if summary.get('flagged',0) else 'clean'}">{summary.get('flagged',0)} flagged</span>
  </div>
</div>

{"".join(body_parts)}

<details>
  <summary>▸ Full JSON Report</summary>
  <pre>{json_data}</pre>
</details>
</body>
</html>"""


def _html_check(text: str, ok: bool) -> str:
    cls = "pass" if ok else "fail"
    return f'<div class="item {cls}">{_html_module.escape(text)}</div>'


def _html_pdf_sections(sections: dict) -> str:
    parts = []

    # Structure
    struct = sections.get("structure", {})
    annots = struct.get("annotations", [])
    emb = struct.get("embedded_files", [])
    inc = struct.get("incremental_updates", {})
    new_x = inc.get("new_xrefs", [])
    parts.append(f"""<section>
<h2>§1 PDF Structure</h2>
{_html_check("No JavaScript / OpenAction", not struct.get("js_found") and not struct.get("open_action"))}
{_html_check("No AcroForm", not struct.get("acroform"))}
{_html_check(f"Annotations: {len(annots)}", not any("uri" in a for a in annots))}
{_html_check("No embedded files", not emb)}
{_html_check(f"Incremental updates: {inc.get('count',0)} ({inc.get('total_bytes',0)} bytes)", not new_x)}
</section>""")

    # Content streams
    cs_items = []
    for cs in sections.get("content_streams", []):
        xref = cs.get("xref")
        v = cs.get("verdict", "?")
        conf = cs.get("confidence", 0)
        vc = _HTML_VERDICT_CLASSES.get(v, "warn")
        floats = cs.get("floats", {})
        clips = cs.get("clip_rects", {})
        cs_items.append(f"""<details>
  <summary>xref={xref} (page {cs.get('page','?')}) &nbsp;
    <span class="{vc}">{_html_module.escape(v)}</span> {conf:.0%}</summary>
  {_html_check("No invisible text (Tr=3)", not cs.get("invisible_text"))}
  {_html_check(f"MCID blocks: {cs.get('mcid_block_count',0)}", True)}
  {_html_check(f"Floats: {floats.get('count',0)}, verdict={floats.get('verdict','')}", floats.get('verdict') in ('WORD_ARTIFACT','NATURAL','NO_FLOATS'))}
  {_html_check(f"Clip rects: {clips.get('count',0)}, verdict={clips.get('verdict','')}", clips.get('verdict') in ('WORD_ARTIFACT','NORMAL'))}
</details>""")
    parts.append(f'<section><h2>§2 Content Streams</h2>{"".join(cs_items) or "<div class=info>None found</div>"}</section>')

    # Images
    img_items = []
    for img in sections.get("images", []):
        xref = img.get("xref")
        v = img.get("verdict", "?")
        conf = img.get("confidence", 0)
        vc = _HTML_VERDICT_CLASSES.get(v, "warn")
        analysis = img.get("analysis", {})
        chi2 = analysis.get("chi2", {})
        rs = analysis.get("rs", {})
        sparsity = analysis.get("sparsity", 0)
        ev_for = img.get("evidence_for_fp", [])
        ev_ag = img.get("evidence_against", [])
        ev_html = "".join(f'<div class="ev-for">+ {_html_module.escape(e)}</div>' for e in ev_for)
        ev_html += "".join(f'<div class="ev-against">- {_html_module.escape(e)}</div>' for e in ev_ag)
        alpha_str = " (alpha)" if img.get("is_alpha") else ""
        img_items.append(f"""<details>
  <summary>xref={xref} {_html_module.escape(img.get('dimensions','?'))}{alpha_str} &nbsp;
    <span class="{vc}">{_html_module.escape(v)}</span> {conf:.0%}</summary>
  {_html_check(f"Chi-square p={chi2.get('p_value',0):.4f} → {chi2.get('verdict','')}", chi2.get('verdict') == 'CLEAN')}
  {_html_check(f"RS rate {rs.get('embedding_rate',0):.1%} → {rs.get('verdict','')}", rs.get('verdict') in ('CLEAN','LOW_RISK'))}
  {_html_check(f"Sparsity {sparsity:.0%}", sparsity > 0.40)}
  {ev_html}
</details>""")
    parts.append(f'<section><h2>§3 Images & Alpha Channels</h2>{"".join(img_items) or "<div class=info>None found</div>"}</section>')

    # Fonts
    fonts = sections.get("fonts", [])
    clean_f = [f for f in fonts if f.get("verdict") == "CLEAN"]
    bad_f = [f for f in fonts if f.get("verdict") != "CLEAN"]
    font_items = []
    if clean_f:
        from collections import Counter
        subtypes = Counter(f.get("subtype", "?") for f in clean_f)
        for st, cnt in subtypes.items():
            font_items.append(_html_check(f"{cnt} {st} font(s) — clean", True))
    for f in bad_f:
        font_items.append(_html_check(f"xref={f['xref']} {f.get('name','?')}: {'; '.join(f.get('flags',[]))}", False))
    parts.append(f'<section><h2>§4 Fonts</h2>{"".join(font_items) or "<div class=info>None found</div>"}</section>')

    # Metadata
    meta = sections.get("metadata", {})
    meta_html = ""
    for key in ("author", "producer", "created", "modified"):
        val = meta.get(key, "")
        if val:
            meta_html += f'<div class="item info"><span style="color:#8b949e">{key.title()}</span>: {_html_module.escape(str(val)[:80])}</div>'
    meta_html += _html_check("XMP padding clean", meta.get("xmp_padding_clean", True))
    meta_html += _html_check("Producer is Microsoft Word", meta.get("producer_is_word", False))
    parts.append(f"<section><h2>§5 Metadata</h2>{meta_html}</section>")

    return "\n".join(parts)


def _html_dat_sections(sections: dict) -> str:
    dat = sections.get("dat", {})
    if not dat:
        return "<section><h2>Analysis</h2><div class='info'>No data</div></section>"

    fmt = dat.get("format", {})
    text_a = dat.get("text_analysis")
    bin_a = dat.get("binary_analysis")
    ev_for = dat.get("evidence_for_clean", [])
    ev_ag = dat.get("evidence_against", [])

    parts = [f"""<section>
<h2>File Analysis</h2>
<div class="item info">Format: {_html_module.escape(fmt.get('likely_format','?'))}</div>
<div class="item info">Entropy: {dat.get('entropy',0):.3f} bits/byte</div>
<div class="item info">Printable: {fmt.get('printable_ratio',0):.0%}</div>
</section>"""]

    if text_a:
        pi = text_a.get("prompt_injection", {})
        pi_items = "".join(
            f'<div class="ev-against">{_html_module.escape(m.get("context","")[:100])}</div>'
            for m in pi.get("matches", [])
        )
        parts.append(f"""<section>
<h2>Text Content</h2>
<div class="item info">Lines: {text_a.get('line_count',0)} | Words: {text_a.get('word_count',0)} | Structure: {text_a.get('structure','?')}</div>
{_html_check(f"Prompt injection: {pi.get('verdict','?')}", pi.get('verdict') == 'CLEAN')}
{pi_items}
</section>""")

    if bin_a:
        parts.append(f"""<section>
<h2>Binary Steganography</h2>
{_html_check(f"LSB ratio {bin_a.get('lsb_ones_ratio',0):.4f}", abs(0.5 - bin_a.get('lsb_ones_ratio',0)) > 0.1)}
{_html_check(f"Chi-square p={bin_a.get('chi2_p',0):.4f} → {bin_a.get('chi2_verdict','')}", bin_a.get('chi2_verdict') == 'CLEAN')}
{_html_check(f"RS rate {bin_a.get('rs_embedding_rate',0):.1%} → {bin_a.get('rs_verdict','')}", bin_a.get('rs_verdict') in ('CLEAN','LOW_RISK'))}
</section>""")

    ev_html = "".join(f'<div class="ev-for">+ {_html_module.escape(e)}</div>' for e in ev_for)
    ev_html += "".join(f'<div class="ev-against">- {_html_module.escape(e)}</div>' for e in ev_ag)
    if ev_html:
        parts.append(f"<section><h2>Evidence Summary</h2>{ev_html}</section>")

    return "\n".join(parts)
