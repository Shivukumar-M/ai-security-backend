import os
from datetime import datetime
from typing import Dict, Any, List, Union

from reportlab.lib.pagesizes import letter
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    Image, HRFlowable,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib import colors
from reportlab.pdfgen import canvas

LOGO_PATH = os.path.join(os.getcwd(), "backend", "app", "static", "logo.png")

PAGE_W = letter[0]         # 612 pts
L_MARGIN = R_MARGIN = 40
USABLE_W = PAGE_W - L_MARGIN - R_MARGIN   # 532 pts

# FRONTEND COLOR-THEME MATCH
THEME_COLORS = {
    "malicious":  colors.HexColor("#c0392b"),
    "suspicious": colors.HexColor("#e67e22"),
    "harmless":   colors.HexColor("#27ae60"),
    "clean":      colors.HexColor("#27ae60"),
    "undetected": colors.HexColor("#7f8c8d"),
    "unrated":    colors.HexColor("#7f8c8d"),
    "unknown":    colors.HexColor("#7f8c8d"),
}

HEADER_BG   = colors.HexColor("#1a2c42")   # dark navy for table headers
ROW_ALT     = colors.HexColor("#f4f6f9")   # alternating row tint


class PDFGenerator:
    def __init__(self, filename: str, topic_title: str = "AI Security Platform"):
        self.filename = filename
        self.topic_title = topic_title

        self.styles = getSampleStyleSheet()

        self.title_style = ParagraphStyle(
            name="TitleStyle",
            parent=self.styles["Title"],
            alignment=TA_CENTER,
            fontSize=20,
            textColor=colors.HexColor("#1a2c42"),
            spaceAfter=4,
        )

        self.subtitle_style = ParagraphStyle(
            name="SubtitleStyle",
            parent=self.styles["Normal"],
            alignment=TA_CENTER,
            fontSize=9,
            textColor=colors.HexColor("#7f8c8d"),
            spaceAfter=10,
        )

        self.section_header = ParagraphStyle(
            name="SectionHeader",
            parent=self.styles["Heading2"],
            fontSize=12,
            textColor=colors.HexColor("#1a2c42"),
            leading=16,
            spaceAfter=4,
            spaceBefore=14,
            borderPad=(0, 0, 2, 0),
        )

        self.normal = ParagraphStyle(
            name="NormalText",
            parent=self.styles["BodyText"],
            fontSize=9,
            textColor=colors.HexColor("#2c3e50"),
            leading=13,
        )

        self.cell_style = ParagraphStyle(
            name="CellText",
            parent=self.styles["BodyText"],
            fontSize=8,
            textColor=colors.HexColor("#2c3e50"),
            leading=12,
        )

        self.bullet = ParagraphStyle(
            name="BulletText",
            parent=self.styles["BodyText"],
            fontSize=9,
            textColor=colors.HexColor("#2c3e50"),
            leading=13,
            leftIndent=14,
            bulletIndent=6,
        )


    # ------------------------------------------------------------
    def _footer(self, canvas_obj: canvas.Canvas, doc):
        canvas_obj.saveState()
        canvas_obj.setFont("Helvetica", 7)
        canvas_obj.setFillColor(colors.HexColor("#7f8c8d"))
        footer_text = (
            f"AI Security Platform  •  Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}"
            f"  •  Page {doc.page}"
        )
        canvas_obj.drawCentredString(PAGE_W / 2, 18, footer_text)
        canvas_obj.restoreState()

    # helper: wrap text in cell paragraph
    def _cell(self, text):
        if text is None:
            text = "N/A"
        return Paragraph(str(text).replace("\n", "<br/>"), self.cell_style)

    def wrap_par(self, text):
        if text is None:
            text = "N/A"
        return Paragraph(str(text).replace("\n", "<br/>"), self.normal)

    def _divider(self):
        return HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#d5dde5"), spaceAfter=4)

    # ------------------------------------------------------------
    def _metadata_table(self, meta: Dict[str, Any]):
        rows = []
        fields = [
            ("Target",          meta.get("target")),
            ("Verdict",         meta.get("verdict")),
            ("ML Score",        meta.get("ml_score")),
            ("External Status", meta.get("urlhaus")),
            ("Hash",            meta.get("hash")),
            ("Scan Date",       meta.get("scan_date")),
        ]
        for label, val in fields:
            if val not in (None, "", "N/A", "None"):
                rows.append([self._cell(f"<b>{label}</b>"), self._cell(val)])

        if not rows:
            return Paragraph("No metadata available.", self.normal)

        col1 = USABLE_W * 0.28
        col2 = USABLE_W - col1
        table = Table(rows, colWidths=[col1, col2])
        table.setStyle(TableStyle([
            ("GRID",        (0, 0), (-1, -1), 0.3,  colors.HexColor("#d5dde5")),
            ("BACKGROUND",  (0, 0), (0, -1),  colors.HexColor("#eef2f7")),
            ("VALIGN",      (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING",  (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING",(0, 0), (-1, -1), 8),
        ]))
        return table

    # ------------------------------------------------------------
    def _severity_block(self, verdict: str):
        v = (verdict or "unknown").lower()
        bg = THEME_COLORS.get(v, colors.HexColor("#7f8c8d"))
        lbl = verdict.upper() if verdict else "UNKNOWN"
        return Table(
            [[Paragraph(f"<b>Threat Verdict: {lbl}</b>", ParagraphStyle(
                "SevText", parent=self.styles["Normal"],
                fontSize=11, textColor=colors.white, alignment=TA_CENTER,
            ))]],
            colWidths=[USABLE_W],
            style=[
                ("BACKGROUND",    (0, 0), (-1, -1), bg),
                ("TOPPADDING",    (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("ROUNDEDCORNERS", [4]),
            ]
        )

    # ------------------------------------------------------------
    def _engine_results_table(self, engine_results, verdict):
        """Two-column table: Engine | Result  (Details column removed — always empty)"""
        if not engine_results:
            return Paragraph("No engine results available.", self.normal)

        header_bg = THEME_COLORS.get((verdict or "unknown").lower(), HEADER_BG)

        col1 = USABLE_W * 0.45
        col2 = USABLE_W - col1

        rows = [[
            Paragraph("<b>Engine</b>",  ParagraphStyle("Hdr", parent=self.cell_style, textColor=colors.white)),
            Paragraph("<b>Result</b>",  ParagraphStyle("Hdr", parent=self.cell_style, textColor=colors.white)),
        ]]

        for i, (engine, data) in enumerate(engine_results.items()):
            result = (
                data.get("result")
                or data.get("category")
                or data.get("status")
                or "—"
            )
            bg = ROW_ALT if i % 2 == 0 else colors.white
            rows.append([self._cell(engine), self._cell(result)])

        tbl = Table(rows, colWidths=[col1, col2], repeatRows=1)
        style = TableStyle([
            # Header row
            ("BACKGROUND",    (0, 0), (-1, 0),  header_bg),
            ("TEXTCOLOR",     (0, 0), (-1, 0),  colors.white),
            # Alternating rows
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [ROW_ALT, colors.white]),
            # Grid
            ("GRID",          (0, 0), (-1, -1), 0.3, colors.HexColor("#d5dde5")),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
        ])
        tbl.setStyle(style)
        return tbl

    # ------------------------------------------------------------
    # VirusTotal Summary
    # ------------------------------------------------------------
    def _vt_summary_block(self, vt_details: dict, verdict: str):
        if not vt_details:
            return None

        malicious   = vt_details.get("malicious_count", 0)
        suspicious  = vt_details.get("suspicious_count", 0)
        harmless    = vt_details.get("harmless_count", 0)
        undetected  = vt_details.get("undetected", 0)
        total       = vt_details.get("total_engines", 0)

        ts = vt_details.get("scan_date")
        if isinstance(ts, int):
            scan_date = datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M UTC")
        else:
            scan_date = str(ts) if ts else "N/A"

        rows = [
            [self._cell("<b>Malicious</b>"),   self._cell(str(malicious))],
            [self._cell("<b>Suspicious</b>"),  self._cell(str(suspicious))],
            [self._cell("<b>Harmless</b>"),    self._cell(str(harmless))],
            [self._cell("<b>Undetected</b>"),  self._cell(str(undetected))],
            [self._cell("<b>Total Engines</b>"),self._cell(str(total))],
            [self._cell("<b>Scan Date</b>"),   self._cell(scan_date)],
        ]

        col1 = USABLE_W * 0.28
        col2 = USABLE_W - col1
        table = Table(rows, colWidths=[col1, col2])
        table.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (0, -1),  colors.HexColor("#eef2f7")),
            ("ROWBACKGROUNDS",(0, 0), (-1, -1), [ROW_ALT, colors.white]),
            ("GRID",         (0, 0), (-1, -1), 0.3, colors.HexColor("#d5dde5")),
            ("VALIGN",       (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING",   (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
            ("LEFTPADDING",  (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ]))
        return table

    # ------------------------------------------------------------
    def _mitre_table(self, mitre_list):
        if not mitre_list:
            return None

        col1 = USABLE_W * 0.22
        col2 = USABLE_W - col1

        rows = [[
            Paragraph("<b>Technique ID</b>",   ParagraphStyle("Hdr", parent=self.cell_style, textColor=colors.white)),
            Paragraph("<b>Technique Name</b>", ParagraphStyle("Hdr", parent=self.cell_style, textColor=colors.white)),
        ]]
        for m in mitre_list:
            rows.append([self._cell(m.get("id", "—")), self._cell(m.get("name", "—"))])

        tbl = Table(rows, colWidths=[col1, col2], repeatRows=1)
        tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0),  HEADER_BG),
            ("TEXTCOLOR",     (0, 0), (-1, 0),  colors.white),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [ROW_ALT, colors.white]),
            ("GRID",          (0, 0), (-1, -1), 0.3, colors.HexColor("#d5dde5")),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
        ]))
        return tbl


    # ------------------------------------------------------------
    # FINAL PDF BUILD
    # ------------------------------------------------------------
    def generate_report(self, title: str, data: Dict[str, Any]):

        doc = SimpleDocTemplate(
            self.filename,
            pagesize=letter,
            leftMargin=L_MARGIN, rightMargin=R_MARGIN,
            topMargin=56, bottomMargin=44,
        )
        Story = []

        # ---- HEADER LOGO + TITLE -----------------------------------
        if os.path.exists(LOGO_PATH):
            Story.append(Image(LOGO_PATH, width=48, height=48))
            Story.append(Spacer(1, 6))

        Story.append(Paragraph(self.topic_title, self.title_style))
        Story.append(Paragraph(
            f"Generated {datetime.utcnow().strftime('%B %d, %Y  %H:%M UTC')}",
            self.subtitle_style,
        ))
        Story.append(self._divider())
        Story.append(Spacer(1, 6))

        meta    = data.get("metadata", {})
        verdict = (meta.get("verdict") or "unknown").strip()
        vt_details = data.get("vt_details", {})

        # ---- VERDICT BANNER ----------------------------------------
        Story.append(self._severity_block(verdict))
        Story.append(Spacer(1, 12))

        # ---- SCAN METADATA -----------------------------------------
        Story.append(Paragraph("Scan Metadata", self.section_header))
        Story.append(self._divider())
        Story.append(self._metadata_table(meta))
        Story.append(Spacer(1, 12))

        # ---- VIRUSTOTAL SUMMARY ------------------------------------
        if verdict.lower() in ("malicious", "suspicious") and vt_details:
            block = self._vt_summary_block(vt_details, verdict)
            if block:
                Story.append(Paragraph("VirusTotal Detection Summary", self.section_header))
                Story.append(self._divider())
                Story.append(block)
                Story.append(Spacer(1, 12))

        # ---- AI SUMMARY --------------------------------------------
        ai_sum = data.get("ai_summary")
        if ai_sum:
            Story.append(Paragraph("AI Summary", self.section_header))
            Story.append(self._divider())
            Story.append(Paragraph(ai_sum.replace("\n", "<br/>"), self.normal))
            Story.append(Spacer(1, 12))

        # ---- AI FULL EXPLANATION -----------------------------------
        ai_full = data.get("ai_full")
        if ai_full:
            Story.append(Paragraph("AI Explanation", self.section_header))
            Story.append(self._divider())
            Story.append(Paragraph(ai_full.replace("\n", "<br/>"), self.normal))
            Story.append(Spacer(1, 12))

        # ---- ENGINE RESULTS (2-column, no empty Details col) -------
        engine_results = data.get("engine_results") or {}
        if engine_results:
            Story.append(Paragraph("Engine Results", self.section_header))
            Story.append(self._divider())
            Story.append(self._engine_results_table(engine_results, verdict))
            Story.append(Spacer(1, 12))

        # ---- MITRE ATT&CK ------------------------------------------
        mitre = data.get("mitre") or []
        if mitre:
            Story.append(Paragraph("MITRE ATT&CK Techniques", self.section_header))
            Story.append(self._divider())
            mt = self._mitre_table(mitre)
            if mt:
                Story.append(mt)
                Story.append(Spacer(1, 12))

        doc.build(Story, onFirstPage=self._footer, onLaterPages=self._footer)
        return self.filename
