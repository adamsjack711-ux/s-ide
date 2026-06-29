"""Engagement report exporter — markdown + PDF from one structured payload.

The payload assembled by `build_report_payload()` is the single source of
truth; both renderers read from it. The executive summary is template-
based (counts + highest-severity findings in plain English) so reports
render with zero Anthropic key configured — the AI is optional everywhere,
reports included.

Defensible-workflow positioning: every finding carries its CVSS score +
vector, its evidence timeline with `captured_at` observation timestamps,
and the authorized-testing disclaimer appears in every export.
"""
from __future__ import annotations

import io
from datetime import datetime, timezone
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import (
    BaseDocTemplate, Frame, PageTemplate, Paragraph, Preformatted,
    Spacer, Table, TableStyle,
)

from . import engagements as eng_db


# Authorized-testing disclaimer appears verbatim in every export.
DISCLAIMER = (
    "This report documents findings from authorized security testing under "
    "the engagement scope listed above. Tests were conducted with the "
    "operator's explicit permission and within the agreed timeframe. "
    "Findings reflect the state of the targets at the time of testing; "
    "subsequent changes by the target operator may render specific "
    "details inaccurate. Evidence timestamps record when each piece of "
    "proof was observed."
)

METHODOLOGY = (
    "Findings were captured via the s-ide evidence layer: every "
    "result row from a tool was promoted into a tracked finding on the "
    "active engagement and scored against CVSS v3.1 where applicable. "
    "Each finding carries an evidence timeline of one or more discrete "
    "proof items (scan output, request/response, screenshots, analyst "
    "notes, commands) with the `captured_at` timestamp recording the "
    "observation time. Every mutation is recorded in the engagement's "
    "append-only audit log."
)

# Severity order for sort + display.
_SEVERITY_RANK: dict[str, int] = {
    "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
}


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _format_ts(ts: str | None) -> str:
    """Render an ISO-ish timestamp for human reading without dropping data."""
    if not ts:
        return "-"
    # Keep the original string for fidelity; just normalise trailing Z.
    return ts.replace("T", " ").rstrip("Z").strip() + " UTC" if ts.endswith("Z") else ts


def _executive_summary(stats: dict[str, Any],
                       findings: list[dict[str, Any]]) -> str:
    """Template-based plain-English summary. No LLM, no API key required."""
    by_sev: dict[str, int] = stats.get("findings_by_severity", {}) or {}
    total = sum(by_sev.values()) if by_sev else len(findings)

    if total == 0:
        return (
            "No findings were captured on this engagement. The engagement's "
            "scope was tested without surfacing any tracked issues."
        )

    parts: list[str] = []
    label_order = ["critical", "high", "medium", "low", "info"]
    counted = [(s, by_sev.get(s, 0)) for s in label_order if by_sev.get(s, 0)]
    sev_phrase = ", ".join(f"{n} {s}" for s, n in counted)
    parts.append(
        f"This engagement produced {total} tracked finding"
        f"{'s' if total != 1 else ''}: {sev_phrase}."
    )

    # Highest-severity finding callouts (up to three) in plain language.
    top: list[dict[str, Any]] = sorted(
        findings,
        key=lambda f: (_SEVERITY_RANK.get(f.get("severity", "info"), 99),
                       -(f.get("cvss") or 0)),
    )[:3]
    if top:
        names = ", ".join(
            f"{(f.get('severity') or 'info').upper()} `{(f.get('title') or '').strip()[:80]}`"
            for f in top
        )
        parts.append(f"Highest-severity items: {names}.")

    return " ".join(parts)


def _evidence_for_finding(fid: str, legacy_blob: str,
                          legacy_tool: str, legacy_ts: str) -> list[dict[str, Any]]:
    """Return the finding's evidence timeline, falling back to a synthesized
    item from the legacy `findings.evidence` blob (matches the runtime
    list_evidence behaviour so the report and the UI agree on the same
    timeline for legacy findings)."""
    items = eng_db.list_evidence(fid)
    if items:
        return items
    # Mirror lib.engagements.list_evidence fallback locally so a stale
    # process-cached db can't desync. Returns identical shape.
    if (legacy_blob or "").strip():
        return [{
            "id":          f"legacy-{fid}",
            "finding_id":  fid,
            "type":        "scan_output",
            "content":     legacy_blob,
            "source_tool": legacy_tool or None,
            "captured_at": legacy_ts,
            "created_at":  legacy_ts,
        }]
    return []


def build_report_payload(engagement_id: str) -> dict[str, Any]:
    """Assemble the structured intermediate. Renderers read this; the
    /preview endpoint returns it verbatim so the frontend can show the same
    structure on-screen as it would appear in markdown or PDF.
    """
    eng = eng_db.get_engagement(engagement_id)
    if eng is None:
        raise ValueError(f"engagement not found: {engagement_id!r}")

    stats = eng_db.engagement_stats(engagement_id)
    raw_findings = eng_db.list_findings(engagement_id)
    findings_sorted = sorted(
        raw_findings,
        key=lambda f: (_SEVERITY_RANK.get(f.get("severity", "info"), 99),
                       -(f.get("cvss") or 0),
                       f.get("ts") or ""),
    )

    findings_block: list[dict[str, Any]] = []
    for f in findings_sorted:
        findings_block.append({
            "id":          f["id"],
            "title":       f.get("title") or "",
            "severity":    f.get("severity") or "info",
            "status":      f.get("status") or "open",
            "tool":        f.get("tool") or "",
            "target":      f.get("target") or "",
            "description": f.get("description") or "",
            "cvss":        f.get("cvss"),
            "cvss_vector": f.get("cvss_vector"),
            "ai_summary":  f.get("ai_summary") or "",
            "captured_at": f.get("ts") or "",
            "evidence":    _evidence_for_finding(
                fid=f["id"],
                legacy_blob=f.get("evidence") or "",
                legacy_tool=f.get("tool") or "",
                legacy_ts=f.get("ts") or "",
            ),
        })

    # Date range — use earliest finding ts to latest, falling back to
    # engagement created/updated_at when there are no findings yet.
    if findings_sorted:
        timestamps = [f.get("ts") for f in findings_sorted if f.get("ts")]
        date_from = min(timestamps) if timestamps else eng.get("created_at", "")
        date_to = max(timestamps) if timestamps else eng.get("updated_at", "")
    else:
        date_from = eng.get("created_at", "")
        date_to = eng.get("updated_at", "")

    return {
        "header": {
            "engagement_id":   engagement_id,
            "engagement_name": eng.get("name") or "(unnamed)",
            "scope":           eng.get("scope") or [],
            "exclusions":      eng.get("exclusions") or [],
            "notes":           eng.get("notes") or "",
            "status":          eng.get("status") or "active",
            "date_from":       date_from,
            "date_to":         date_to,
            "operator":        "Local operator",  # placeholder; engagements
                                                  # don't track an operator
                                                  # identity yet.
            "generated_at":    _now_utc(),
        },
        "exec_summary": {
            "counts":  stats.get("findings_by_severity") or {},
            "total":   len(raw_findings),
            "summary": _executive_summary(stats, raw_findings),
        },
        "findings":   findings_block,
        "methodology": METHODOLOGY,
        "disclaimer":  DISCLAIMER,
    }


# ── Markdown renderer ───────────────────────────────────────────────────────

def _md_evidence_block(ev: dict[str, Any]) -> str:
    type_label = ev.get("type", "scan_output").upper()
    captured = _format_ts(ev.get("captured_at"))
    tool = ev.get("source_tool") or ""
    head_bits = [f"`{type_label}`", f"captured {captured}"]
    if tool:
        head_bits.append(f"via `{tool}`")
    head = " - ".join(head_bits)

    content = (ev.get("content") or "").rstrip()
    if ev.get("type") == "note":
        body = content
    elif ev.get("type") == "screenshot_ref":
        body = f"[screenshot_ref] {content}"
    else:
        body = "```\n" + content + "\n```"
    return f"- {head}\n\n{body}\n"


def render_markdown(payload: dict[str, Any]) -> str:
    h = payload["header"]
    e = payload["exec_summary"]
    out: list[str] = []

    out.append(f"# {h['engagement_name']} - Engagement Report")
    out.append("")
    out.append(f"- **Engagement:** {h['engagement_name']}")
    out.append(f"- **Status:** {h['status']}")
    if h.get("scope"):
        out.append("- **Scope:** " + ", ".join(h["scope"]))
    if h.get("exclusions"):
        out.append("- **Exclusions:** " + ", ".join(h["exclusions"]))
    out.append(f"- **Date range:** {h.get('date_from') or '-'} to {h.get('date_to') or '-'}")
    out.append(f"- **Operator:** {h['operator']}")
    out.append(f"- **Generated:** {h['generated_at']}")
    out.append("")

    out.append("## Executive Summary")
    out.append("")
    if e.get("total", 0) > 0 and e.get("counts"):
        sev_line = " - ".join(
            f"{e['counts'].get(s, 0)} {s}"
            for s in ("critical", "high", "medium", "low", "info")
            if e['counts'].get(s, 0)
        )
        if sev_line:
            out.append(f"**Counts:** {sev_line}")
            out.append("")
    out.append(e["summary"])
    out.append("")

    out.append("## Findings")
    out.append("")
    if not payload["findings"]:
        out.append("_No findings tracked on this engagement._")
        out.append("")
    for idx, f in enumerate(payload["findings"], 1):
        sev = (f["severity"] or "info").upper()
        out.append(f"### {idx}. [{sev}] {f['title']}")
        out.append("")
        meta_bits: list[str] = []
        if f.get("cvss") is not None:
            meta_bits.append(f"**CVSS:** {f['cvss']:.1f}")
            if f.get("cvss_vector"):
                meta_bits.append(f"`{f['cvss_vector']}`")
        if f.get("status"):
            meta_bits.append(f"**Status:** {f['status']}")
        if f.get("tool"):
            meta_bits.append(f"**Tool:** `{f['tool']}`")
        if f.get("target"):
            meta_bits.append(f"**Target:** `{f['target']}`")
        if meta_bits:
            out.append(" - ".join(meta_bits))
            out.append("")
        if f.get("description"):
            out.append(f["description"])
            out.append("")
        if f.get("ai_summary"):
            out.append("**AI summary:**")
            out.append("")
            out.append(f["ai_summary"])
            out.append("")
        out.append("**Evidence timeline:**")
        out.append("")
        if not f["evidence"]:
            out.append("_No evidence captured._")
            out.append("")
        for ev in f["evidence"]:
            out.append(_md_evidence_block(ev))

    out.append("## Methodology")
    out.append("")
    out.append(payload["methodology"])
    out.append("")

    out.append("## Authorization & Disclaimer")
    out.append("")
    out.append(payload["disclaimer"])
    out.append("")

    return "\n".join(out)


# ── PDF renderer (reportlab) ────────────────────────────────────────────────

# Severity → fill colour for headers. Aligned with the frontend palette
# (danger=red, amber=orange, info=grey, low=cyan-ish).
_SEV_BG: dict[str, colors.Color] = {
    "critical": colors.HexColor("#7f1d1d"),
    "high":     colors.HexColor("#92400e"),
    "medium":   colors.HexColor("#a16207"),
    "low":      colors.HexColor("#0e7490"),
    "info":     colors.HexColor("#374151"),
}


def _pdf_styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "ReportTitle", parent=base["Title"],
            fontSize=20, spaceAfter=14, alignment=TA_LEFT,
        ),
        "h1": ParagraphStyle(
            "H1", parent=base["Heading1"],
            fontSize=14, spaceBefore=12, spaceAfter=6,
            textColor=colors.HexColor("#111827"),
        ),
        "h2": ParagraphStyle(
            "H2", parent=base["Heading2"],
            fontSize=12, spaceBefore=10, spaceAfter=4,
            textColor=colors.HexColor("#1f2937"),
        ),
        "body": ParagraphStyle(
            "Body", parent=base["BodyText"],
            fontSize=10, leading=13, spaceAfter=4,
        ),
        "meta": ParagraphStyle(
            "Meta", parent=base["BodyText"],
            fontSize=9, leading=11, textColor=colors.HexColor("#4b5563"),
            spaceAfter=4,
        ),
        "code": ParagraphStyle(
            "Code", parent=base["Code"],
            fontName="Courier", fontSize=8, leading=10,
            backColor=colors.HexColor("#f3f4f6"),
            borderColor=colors.HexColor("#d1d5db"),
            borderWidth=0.25, borderPadding=4,
            spaceAfter=6,
        ),
    }


def _footer_for(payload: dict[str, Any]):
    """Return a page-handler that draws the footer on every page."""
    eng_name = payload["header"]["engagement_name"]
    generated = payload["header"]["generated_at"]

    def draw(canvas: Canvas, doc) -> None:  # type: ignore[no-untyped-def]
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#6b7280"))
        # Left footer: engagement + generated stamp
        canvas.drawString(
            0.75 * inch, 0.5 * inch,
            f"{eng_name} - Generated {generated}",
        )
        # Right footer: page number
        canvas.drawRightString(
            LETTER[0] - 0.75 * inch, 0.5 * inch,
            f"Page {doc.page}",
        )
        canvas.restoreState()

    return draw


def _sev_header_table(label: str, idx: int, title: str,
                      styles: dict[str, ParagraphStyle]) -> Table:
    sev = label.lower()
    bg = _SEV_BG.get(sev, _SEV_BG["info"])
    cell = Paragraph(
        f'<font color="white"><b>{idx}. [{label.upper()}]</b> '
        f"{_escape(title)}</font>",
        ParagraphStyle("SevHead", parent=styles["h1"],
                       fontSize=12, leading=14, spaceBefore=0, spaceAfter=0,
                       textColor=colors.white),
    )
    t = Table([[cell]], colWidths=[6.7 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, -1), bg),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING",  (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    return t


def _escape(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def render_pdf(payload: dict[str, Any]) -> bytes:
    buf = io.BytesIO()
    doc = BaseDocTemplate(
        buf, pagesize=LETTER,
        leftMargin=0.75 * inch, rightMargin=0.75 * inch,
        topMargin=0.75 * inch, bottomMargin=0.75 * inch,
        title=f"{payload['header']['engagement_name']} - Engagement Report",
    )
    frame = Frame(doc.leftMargin, doc.bottomMargin,
                  doc.width, doc.height, id="body")
    doc.addPageTemplates([
        PageTemplate(id="all", frames=[frame], onPage=_footer_for(payload)),
    ])

    styles = _pdf_styles()
    story: list[Any] = []
    h = payload["header"]
    e = payload["exec_summary"]

    story.append(Paragraph(_escape(f"{h['engagement_name']} - Engagement Report"),
                           styles["title"]))
    meta_lines = [
        f"<b>Status:</b> {_escape(h.get('status', ''))}",
        f"<b>Operator:</b> {_escape(h['operator'])}",
        f"<b>Date range:</b> {_escape(h.get('date_from') or '-')} to "
        f"{_escape(h.get('date_to') or '-')}",
        f"<b>Generated:</b> {_escape(h['generated_at'])}",
    ]
    if h.get("scope"):
        meta_lines.append("<b>Scope:</b> " + _escape(", ".join(h["scope"])))
    if h.get("exclusions"):
        meta_lines.append("<b>Exclusions:</b> "
                          + _escape(", ".join(h["exclusions"])))
    for line in meta_lines:
        story.append(Paragraph(line, styles["meta"]))
    story.append(Spacer(1, 0.15 * inch))

    story.append(Paragraph("Executive Summary", styles["h1"]))
    if e.get("counts"):
        counts_line = "  ".join(
            f"<b>{s}:</b> {n}"
            for s, n in (
                (s, e["counts"].get(s, 0))
                for s in ("critical", "high", "medium", "low", "info")
            ) if n
        )
        if counts_line:
            story.append(Paragraph(counts_line, styles["meta"]))
    story.append(Paragraph(_escape(e["summary"]), styles["body"]))
    story.append(Spacer(1, 0.15 * inch))

    story.append(Paragraph("Findings", styles["h1"]))
    if not payload["findings"]:
        story.append(Paragraph("<i>No findings tracked on this engagement.</i>",
                               styles["body"]))
    for idx, f in enumerate(payload["findings"], 1):
        story.append(_sev_header_table(f["severity"], idx, f["title"], styles))
        story.append(Spacer(1, 4))

        meta_bits: list[str] = []
        if f.get("cvss") is not None:
            cv = f"<b>CVSS:</b> {f['cvss']:.1f}"
            if f.get("cvss_vector"):
                cv += f" <font face=\"Courier\">{_escape(f['cvss_vector'])}</font>"
            meta_bits.append(cv)
        if f.get("status"):
            meta_bits.append(f"<b>Status:</b> {_escape(f['status'])}")
        if f.get("tool"):
            meta_bits.append(
                f"<b>Tool:</b> <font face=\"Courier\">{_escape(f['tool'])}</font>")
        if f.get("target"):
            meta_bits.append(
                f"<b>Target:</b> <font face=\"Courier\">{_escape(f['target'])}</font>")
        if meta_bits:
            story.append(Paragraph("  ".join(meta_bits), styles["meta"]))

        if f.get("description"):
            story.append(Paragraph(_escape(f["description"]), styles["body"]))

        if f.get("ai_summary"):
            story.append(Paragraph("<b>AI summary</b>", styles["h2"]))
            story.append(Paragraph(_escape(f["ai_summary"]), styles["body"]))

        story.append(Paragraph("<b>Evidence timeline</b>", styles["h2"]))
        if not f["evidence"]:
            story.append(Paragraph("<i>No evidence captured.</i>", styles["body"]))
        for ev in f["evidence"]:
            type_label = (ev.get("type") or "scan_output").upper()
            head_bits = [f"<b>{type_label}</b>",
                         f"captured {_escape(_format_ts(ev.get('captured_at')))}"]
            if ev.get("source_tool"):
                head_bits.append(
                    f"via <font face=\"Courier\">{_escape(ev['source_tool'])}</font>")
            story.append(Paragraph(" - ".join(head_bits), styles["meta"]))
            content = (ev.get("content") or "").rstrip()
            if ev.get("type") == "note":
                story.append(Paragraph(_escape(content), styles["body"]))
            elif ev.get("type") == "screenshot_ref":
                story.append(Paragraph(
                    f"<i>screenshot_ref</i> <font face=\"Courier\">{_escape(content)}</font>",
                    styles["body"],
                ))
            else:
                story.append(Preformatted(content, styles["code"]))
        story.append(Spacer(1, 0.1 * inch))

    story.append(Paragraph("Methodology", styles["h1"]))
    story.append(Paragraph(_escape(payload["methodology"]), styles["body"]))

    story.append(Paragraph("Authorization & Disclaimer", styles["h1"]))
    story.append(Paragraph(_escape(payload["disclaimer"]), styles["body"]))

    doc.build(story)
    return buf.getvalue()
