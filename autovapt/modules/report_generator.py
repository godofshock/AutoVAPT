"""
AutoVAPT — Phase 5: Report Generator
Produces two artefacts:
  1. Professional PDF report  (executive summary + technical findings)
  2. Machine-readable JSON    (for SOC platform ingestion or archival)

PDF is built with ReportLab (pure Python, no LaTeX dependency).
"""

import os
import json
from datetime import datetime
from typing import List, Dict

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm, mm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, HRFlowable, KeepTogether
    )
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


# Severity colour palette
SEVERITY_COLOURS = {
    "CRITICAL": colors.HexColor("#C0392B"),
    "HIGH":     colors.HexColor("#E67E22"),
    "MEDIUM":   colors.HexColor("#F1C40F"),
    "LOW":      colors.HexColor("#27AE60"),
    "INFO":     colors.HexColor("#2980B9"),
}

SEVERITY_TEXT_COLOURS = {
    "CRITICAL": colors.white,
    "HIGH":     colors.white,
    "MEDIUM":   colors.black,
    "LOW":      colors.white,
    "INFO":     colors.white,
}


class ReportGenerator:

    def __init__(self, results: dict, output_dir: str, scan_id: str, logger):
        self.results    = results
        self.output_dir = output_dir
        self.scan_id    = scan_id
        self.logger     = logger
        os.makedirs(output_dir, exist_ok=True)

    # ── JSON ──────────────────────────────────────────────────────────────────

    def generate_json(self) -> str:
        path = os.path.join(self.output_dir, f"autovapt_{self.scan_id}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=2, default=str)
        self.logger.debug(f"[*] JSON report written: {path}")
        return path

    # ── PDF ───────────────────────────────────────────────────────────────────

    def generate_pdf(self) -> str:
        path = os.path.join(self.output_dir, f"autovapt_{self.scan_id}.pdf")

        if not REPORTLAB_AVAILABLE:
            self.logger.warning(
                "[!] ReportLab not installed — PDF generation skipped. "
                "Run: pip install reportlab --break-system-packages"
            )
            # Write a plain-text fallback
            txt_path = path.replace(".pdf", "_fallback.txt")
            self._write_text_fallback(txt_path)
            return txt_path

        doc = SimpleDocTemplate(
            path,
            pagesize=A4,
            leftMargin=2*cm, rightMargin=2*cm,
            topMargin=2.5*cm, bottomMargin=2*cm,
        )

        styles = self._build_styles()
        story  = []

        # Cover page
        story += self._cover_page(styles)
        story.append(PageBreak())

        # Executive summary
        story += self._executive_summary(styles)
        story.append(PageBreak())

        # Findings
        story += self._findings_section(styles)
        story.append(PageBreak())

        # Remediation table
        story += self._remediation_table(styles)
        story.append(PageBreak())

        # Appendix — raw recon data
        story += self._appendix_recon(styles)

        doc.build(story)
        self.logger.debug(f"[*] PDF report written: {path}")
        return path

    # ── Cover page ────────────────────────────────────────────────────────────

    def _cover_page(self, styles) -> list:
        target    = self.results.get("target", "Unknown")
        ts        = self.results.get("timestamp", datetime.now().isoformat())[:10]
        assessor  = self.results.get("config", {}).get("assessor_name", "Aagnik")
        summary   = self.results.get("summary", {})
        overall   = summary.get("overall_risk", "UNKNOWN")
        colour    = SEVERITY_COLOURS.get(overall, colors.grey)

        elems = []
        elems.append(Spacer(1, 3*cm))
        elems.append(Paragraph("AutoVAPT", styles["cover_title"]))
        elems.append(Spacer(1, 0.3*cm))
        elems.append(Paragraph(
            "Automated Vulnerability Assessment &amp; Penetration Testing Report",
            styles["cover_subtitle"]
        ))
        elems.append(Spacer(1, 1.5*cm))
        elems.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#2C3E50")))
        elems.append(Spacer(1, 0.8*cm))

        meta = [
            ["Target",      target],
            ["Scan Date",   ts],
            ["Assessor",    assessor],
            ["Scan ID",     self.scan_id],
            ["Mode",        self.results.get("mode", "full").upper()],
        ]
        meta_table = Table(meta, colWidths=[4*cm, 12*cm])
        meta_table.setStyle(TableStyle([
            ("FONTNAME",  (0, 0), (-1, -1), "Helvetica"),
            ("FONTSIZE",  (0, 0), (-1, -1), 11),
            ("FONTNAME",  (0, 0), (0, -1),  "Helvetica-Bold"),
            ("TEXTCOLOR", (0, 0), (0, -1),  colors.HexColor("#2C3E50")),
            ("TOPPADDING",(0, 0), (-1, -1), 6),
            ("BOTTOMPADDING",(0,0),(-1,-1), 6),
        ]))
        elems.append(meta_table)
        elems.append(Spacer(1, 1.5*cm))

        # Overall risk badge
        risk_table = Table(
            [[f"OVERALL RISK: {overall}"]],
            colWidths=[16*cm]
        )
        risk_table.setStyle(TableStyle([
            ("BACKGROUND",   (0,0), (-1,-1), colour),
            ("TEXTCOLOR",    (0,0), (-1,-1), SEVERITY_TEXT_COLOURS.get(overall, colors.white)),
            ("FONTNAME",     (0,0), (-1,-1), "Helvetica-Bold"),
            ("FONTSIZE",     (0,0), (-1,-1), 18),
            ("ALIGN",        (0,0), (-1,-1), "CENTER"),
            ("TOPPADDING",   (0,0), (-1,-1), 14),
            ("BOTTOMPADDING",(0,0), (-1,-1), 14),
            ("ROUNDEDCORNERS", [4]),
        ]))
        elems.append(risk_table)
        elems.append(Spacer(1, 2*cm))
        elems.append(Paragraph(
            "<font color='#E74C3C'><b>CONFIDENTIAL — AUTHORISED USE ONLY</b></font>",
            styles["centred"]
        ))
        return elems

    # ── Executive Summary ─────────────────────────────────────────────────────

    def _executive_summary(self, styles) -> list:
        summary  = self.results.get("summary", {})
        recon    = self.results.get("recon", {})

        elems = []
        elems.append(Paragraph("1. Executive Summary", styles["h1"]))
        elems.append(Spacer(1, 0.3*cm))
        elems.append(Paragraph(
            f"An automated vulnerability assessment was performed against the target "
            f"<b>{self.results.get('target','Unknown')}</b> on "
            f"{self.results.get('timestamp','')[:10]}. "
            f"The assessment identified <b>{summary.get('total', 0)}</b> vulnerabilities "
            f"across all assessed services.",
            styles["body"]
        ))
        elems.append(Spacer(1, 0.5*cm))

        # Stats table
        stats = [
            ["Severity",  "Count"],
            ["CRITICAL",  str(summary.get("critical", 0))],
            ["HIGH",      str(summary.get("high",     0))],
            ["MEDIUM",    str(summary.get("medium",   0))],
            ["LOW",       str(summary.get("low",      0))],
            ["INFO",      str(summary.get("info",     0))],
        ]
        t = Table(stats, colWidths=[6*cm, 4*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0),  colors.HexColor("#2C3E50")),
            ("TEXTCOLOR",     (0, 0), (-1, 0),  colors.white),
            ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTNAME",      (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE",      (0, 0), (-1, -1), 10),
            ("ALIGN",         (1, 0), (1, -1),  "CENTER"),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, colors.HexColor("#F8F9FA")]),
            ("GRID",          (0, 0), (-1, -1), 0.5, colors.HexColor("#DEE2E6")),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))

        # Colour severity rows
        severity_rows = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "INFO": 5}
        for sev, row in severity_rows.items():
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, row), (0, row), SEVERITY_COLOURS.get(sev, colors.grey)),
                ("TEXTCOLOR",  (0, row), (0, row), SEVERITY_TEXT_COLOURS.get(sev, colors.white)),
                ("FONTNAME",   (0, row), (0, row), "Helvetica-Bold"),
            ]))

        elems.append(t)
        elems.append(Spacer(1, 0.8*cm))

        # Top findings
        top3 = summary.get("top_findings", [])
        if top3:
            elems.append(Paragraph("Top Findings Requiring Immediate Attention", styles["h2"]))
            for i, f in enumerate(top3, 1):
                colour = SEVERITY_COLOURS.get(f.get("risk_level", "INFO"), colors.grey)
                elems.append(Paragraph(
                    f"<b>{i}. {f['title']}</b> — "
                    f"Composite Score: <b>{f['composite_score']}</b> | "
                    f"Risk: {f.get('risk_level','?')}",
                    styles["body"]
                ))
            elems.append(Spacer(1, 0.5*cm))

        # Recon stats
        elems.append(Paragraph("Reconnaissance Overview", styles["h2"]))
        hosts  = len(recon.get("hosts", []))
        ports  = recon.get("total_open_ports", 0)
        elems.append(Paragraph(
            f"Hosts discovered: <b>{hosts}</b> | Open ports: <b>{ports}</b>",
            styles["body"]
        ))

        return elems

    # ── Findings ──────────────────────────────────────────────────────────────

    def _findings_section(self, styles) -> list:
        risk_scores = self.results.get("risk_scores", [])
        elems = []
        elems.append(Paragraph("2. Vulnerability Findings", styles["h1"]))
        elems.append(Spacer(1, 0.3*cm))

        if not risk_scores:
            elems.append(Paragraph("No vulnerabilities identified.", styles["body"]))
            return elems

        for idx, f in enumerate(risk_scores, 1):
            severity = f.get("risk_level", f.get("severity", "INFO"))
            colour   = SEVERITY_COLOURS.get(severity, colors.grey)
            txt_col  = SEVERITY_TEXT_COLOURS.get(severity, colors.white)

            # Finding header
            header = Table(
                [[f"  [{idx}] {f.get('title','')}", f"  {severity}  "]],
                colWidths=[13*cm, 3*cm]
            )
            header.setStyle(TableStyle([
                ("BACKGROUND",    (0,0), (0,0),   colors.HexColor("#2C3E50")),
                ("TEXTCOLOR",     (0,0), (0,0),   colors.white),
                ("BACKGROUND",    (1,0), (1,0),   colour),
                ("TEXTCOLOR",     (1,0), (1,0),   txt_col),
                ("FONTNAME",      (0,0), (-1,-1),  "Helvetica-Bold"),
                ("FONTSIZE",      (0,0), (-1,-1),  10),
                ("TOPPADDING",    (0,0), (-1,-1),  8),
                ("BOTTOMPADDING", (0,0), (-1,-1),  8),
                ("ALIGN",         (1,0), (1,0),   "CENTER"),
            ]))
            elems.append(KeepTogether([header]))
            elems.append(Spacer(1, 0.1*cm))

            # Details table
            details_data = [
                ["IP / Port",      f"{f.get('ip','')} : {f.get('port','')} ({f.get('service','')})"],
                ["CVSS Score",     f"{f.get('cvss_score', 0)} ({f.get('cvss_vector','N/A')})"],
                ["Composite Score",f"{f.get('composite_score', 0)} (asset × exploit weight applied)"],
                ["Exploit Status", f.get("exploit_status", "N/A")],
                ["CVE IDs",        ", ".join(f.get("cve_ids", [])) or "None"],
            ]
            det = Table(details_data, colWidths=[4*cm, 12*cm])
            det.setStyle(TableStyle([
                ("FONTNAME",      (0,0), (0,-1),  "Helvetica-Bold"),
                ("FONTNAME",      (1,0), (1,-1),  "Helvetica"),
                ("FONTSIZE",      (0,0), (-1,-1), 9),
                ("TOPPADDING",    (0,0), (-1,-1), 4),
                ("BOTTOMPADDING", (0,0), (-1,-1), 4),
                ("ROWBACKGROUNDS",(0,0), (-1,-1), [colors.white, colors.HexColor("#F8F9FA")]),
                ("GRID",          (0,0), (-1,-1), 0.3, colors.HexColor("#DEE2E6")),
            ]))
            elems.append(det)
            elems.append(Spacer(1, 0.2*cm))

            # Description + Evidence + Remediation
            for label, key in [
                ("Description", "description"),
                ("Evidence",    "evidence"),
                ("Remediation", "remediation"),
            ]:
                text = f.get(key, "")
                if text:
                    elems.append(Paragraph(f"<b>{label}:</b> {text}", styles["body_small"]))

            # References
            refs = f.get("references", [])
            if refs:
                elems.append(Paragraph(
                    "<b>References:</b> " + " | ".join(refs[:3]),
                    styles["body_small"]
                ))

            elems.append(Spacer(1, 0.6*cm))

        return elems

    # ── Remediation Table ─────────────────────────────────────────────────────

    def _remediation_table(self, styles) -> list:
        risk_scores = self.results.get("risk_scores", [])
        elems = []
        elems.append(Paragraph("3. Remediation Summary", styles["h1"]))
        elems.append(Spacer(1, 0.3*cm))
        elems.append(Paragraph(
            "The following table summarises all findings ranked by composite risk score "
            "and their recommended remediation actions.",
            styles["body"]
        ))
        elems.append(Spacer(1, 0.5*cm))

        header = ["#", "Finding", "Risk", "Score", "Remediation (summary)"]
        rows   = [header]

        for i, f in enumerate(risk_scores, 1):
            rem = f.get("remediation", "")
            if len(rem) > 80:
                rem = rem[:77] + "..."
            rows.append([
                str(i),
                f.get("title", "")[:50],
                f.get("risk_level", ""),
                str(f.get("composite_score", 0)),
                rem,
            ])

        t = Table(rows, colWidths=[0.8*cm, 5.5*cm, 1.8*cm, 1.4*cm, 6.5*cm])
        ts = TableStyle([
            ("BACKGROUND",    (0,0), (-1,0),  colors.HexColor("#2C3E50")),
            ("TEXTCOLOR",     (0,0), (-1,0),  colors.white),
            ("FONTNAME",      (0,0), (-1,0),  "Helvetica-Bold"),
            ("FONTNAME",      (0,1), (-1,-1), "Helvetica"),
            ("FONTSIZE",      (0,0), (-1,-1), 8),
            ("GRID",          (0,0), (-1,-1), 0.3, colors.HexColor("#DEE2E6")),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [colors.white, colors.HexColor("#F8F9FA")]),
            ("TOPPADDING",    (0,0), (-1,-1), 4),
            ("BOTTOMPADDING", (0,0), (-1,-1), 4),
            ("VALIGN",        (0,0), (-1,-1), "TOP"),
        ])
        # Colour severity cells
        for i, f in enumerate(risk_scores, 1):
            sev    = f.get("risk_level", "INFO")
            colour = SEVERITY_COLOURS.get(sev, colors.grey)
            txtc   = SEVERITY_TEXT_COLOURS.get(sev, colors.white)
            ts.add("BACKGROUND", (2, i), (2, i), colour)
            ts.add("TEXTCOLOR",  (2, i), (2, i), txtc)
            ts.add("FONTNAME",   (2, i), (2, i), "Helvetica-Bold")
        t.setStyle(ts)
        elems.append(t)
        return elems

    # ── Appendix ──────────────────────────────────────────────────────────────

    def _appendix_recon(self, styles) -> list:
        recon  = self.results.get("recon", {})
        elems  = []
        elems.append(Paragraph("Appendix A — Reconnaissance Data", styles["h1"]))
        elems.append(Spacer(1, 0.3*cm))

        services = recon.get("open_services", [])
        if services:
            elems.append(Paragraph("Discovered Services", styles["h2"]))
            rows = [["IP", "Port", "Protocol", "Service", "Product", "Version"]]
            for s in services:
                rows.append([
                    s.get("ip",""), str(s.get("port","")),
                    s.get("protocol",""), s.get("service",""),
                    s.get("product",""), s.get("version",""),
                ])
            t = Table(rows, colWidths=[3*cm, 2*cm, 2.5*cm, 3*cm, 3*cm, 2.5*cm])
            t.setStyle(TableStyle([
                ("BACKGROUND",    (0,0), (-1,0),  colors.HexColor("#2C3E50")),
                ("TEXTCOLOR",     (0,0), (-1,0),  colors.white),
                ("FONTNAME",      (0,0), (-1,0),  "Helvetica-Bold"),
                ("FONTNAME",      (0,1), (-1,-1), "Helvetica"),
                ("FONTSIZE",      (0,0), (-1,-1), 8),
                ("GRID",          (0,0), (-1,-1), 0.3, colors.HexColor("#DEE2E6")),
                ("ROWBACKGROUNDS",(0,1), (-1,-1), [colors.white, colors.HexColor("#F8F9FA")]),
                ("TOPPADDING",    (0,0), (-1,-1), 3),
                ("BOTTOMPADDING", (0,0), (-1,-1), 3),
            ]))
            elems.append(t)
            elems.append(Spacer(1, 0.5*cm))

        dns = recon.get("dns_records", {})
        if dns:
            elems.append(Paragraph("DNS Records", styles["h2"]))
            for rtype, vals in dns.items():
                if rtype != "subdomains" and vals:
                    elems.append(Paragraph(
                        f"<b>{rtype}:</b> {', '.join(vals)}", styles["body_small"]
                    ))
            subs = dns.get("subdomains", [])
            if subs:
                elems.append(Paragraph(
                    "<b>Subdomains:</b> " + ", ".join(s["subdomain"] for s in subs),
                    styles["body_small"]
                ))

        return elems

    # ── Text fallback ─────────────────────────────────────────────────────────

    def _write_text_fallback(self, path: str):
        with open(path, "w", encoding="utf-8") as f:
            f.write("AutoVAPT Report (Text Fallback — install ReportLab for PDF)\n")
            f.write("=" * 70 + "\n\n")
            summary = self.results.get("summary", {})
            f.write(f"Target        : {self.results.get('target')}\n")
            f.write(f"Scan ID       : {self.scan_id}\n")
            f.write(f"Timestamp     : {self.results.get('timestamp')}\n")
            f.write(f"Overall Risk  : {summary.get('overall_risk')}\n")
            f.write(f"Total Findings: {summary.get('total', 0)}\n\n")
            for i, r in enumerate(self.results.get("risk_scores", []), 1):
                f.write(f"[{i}] {r.get('title')} — {r.get('risk_level')} "
                        f"(Score: {r.get('composite_score')})\n")
                f.write(f"     {r.get('description','')[:120]}\n")
                f.write(f"     Remediation: {r.get('remediation','')[:120]}\n\n")

    # ── Style builder ─────────────────────────────────────────────────────────

    @staticmethod
    def _build_styles() -> dict:
        base = getSampleStyleSheet()

        def _style(name, parent="Normal", **kwargs):
            return ParagraphStyle(name, parent=base[parent], **kwargs)

        return {
            "cover_title":    _style("cover_title",    fontName="Helvetica-Bold",
                                     fontSize=32, textColor=colors.HexColor("#2C3E50"),
                                     alignment=TA_CENTER),
            "cover_subtitle": _style("cover_subtitle", fontName="Helvetica",
                                     fontSize=13, textColor=colors.HexColor("#7F8C8D"),
                                     alignment=TA_CENTER),
            "h1":             _style("h1", fontName="Helvetica-Bold",
                                     fontSize=14, textColor=colors.HexColor("#2C3E50"),
                                     spaceBefore=12, spaceAfter=6,
                                     borderPad=4),
            "h2":             _style("h2", fontName="Helvetica-Bold",
                                     fontSize=11, textColor=colors.HexColor("#34495E"),
                                     spaceBefore=8, spaceAfter=4),
            "body":           _style("body",       fontName="Helvetica", fontSize=10,
                                     leading=14),
            "body_small":     _style("body_small", fontName="Helvetica", fontSize=8,
                                     leading=12, textColor=colors.HexColor("#555555")),
            "centred":        _style("centred",    fontName="Helvetica-Bold", fontSize=10,
                                     alignment=TA_CENTER),
        }
