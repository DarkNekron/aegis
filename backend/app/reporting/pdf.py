"""PDF renderer (ReportLab platypus).

SECURITY: ReportLab ``Paragraph`` interprets an XML-like markup (<b>, <font>, <a href>, <img>...).
Directory data is attacker-controllable, so every value passes through ``esc()`` before it reaches a
Paragraph; only the fixed markup written in this module is ever interpreted.
"""

from __future__ import annotations

import io
import logging
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.shapes import Drawing
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    KeepTogether,
    ListFlowable,
    ListItem,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

logger = logging.getLogger(__name__)
INK = colors.HexColor("#1b2430")
ACCENT = colors.HexColor("#1f5fbf")
LINE = colors.HexColor("#d9dee5")
BG = colors.HexColor("#f2f5f9")
SEVERITY_COLOURS = {"Critical": colors.HexColor("#c62828"), "High": colors.HexColor("#e65100"),
                    "Medium": colors.HexColor("#b28704"), "Low": colors.HexColor("#2e7d32")}


# Unicode TrueType fonts (directory names may be Cyrillic, Greek, CJK...). The standard PDF fonts only
# cover Latin-1, so a TTF is registered when one is available; otherwise symbols degrade to ASCII.
_FONT_CANDIDATES = [
    ("C:/Windows/Fonts/arial.ttf", "C:/Windows/Fonts/arialbd.ttf", "C:/Windows/Fonts/consola.ttf"),
    ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
     "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"),
]
_ASCII = {"→": "->", "≥": ">=", "—": "-", "·": "|", "•": "*"}


def _register_fonts() -> tuple[str, str, str, bool]:
    for regular, bold, mono in _FONT_CANDIDATES:
        if all(Path(f).is_file() for f in (regular, bold, mono)):
            try:
                pdfmetrics.registerFont(TTFont("AegisSans", regular))
                pdfmetrics.registerFont(TTFont("AegisSans-Bold", bold))
                pdfmetrics.registerFont(TTFont("AegisMono", mono))
                pdfmetrics.registerFontFamily("AegisSans", normal="AegisSans", bold="AegisSans-Bold",
                                              italic="AegisSans", boldItalic="AegisSans-Bold")
                return "AegisSans", "AegisSans-Bold", "AegisMono", True
            except Exception:  # unreadable font file: try the next candidate
                logger.warning("Could not load report font %s; trying the next candidate", regular, exc_info=True)
                continue
    return "Helvetica", "Helvetica-Bold", "Courier", False


FONT, FONT_BOLD, FONT_MONO, UNICODE_FONTS = _register_fonts()


def esc(value: Any) -> str:
    """Escape untrusted text for ReportLab markup (and degrade symbols if no Unicode font is available)."""
    text = "" if value is None else str(value)
    if not UNICODE_FONTS:
        for symbol, ascii_text in _ASCII.items():
            text = text.replace(symbol, ascii_text)
    return escape(text)


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    body = ParagraphStyle("body", parent=base["BodyText"], fontName=FONT, fontSize=9.5, leading=13,
                          textColor=INK)
    return {
        "body": body,
        "small": ParagraphStyle("small", parent=body, fontSize=8, leading=10),
        "mono": ParagraphStyle("mono", parent=body, fontName=FONT_MONO, fontSize=7.5, leading=9.5),
        "h1": ParagraphStyle("h1", parent=base["Heading1"], fontName=FONT_BOLD, fontSize=24, leading=28,
                             textColor=INK, spaceAfter=6),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], fontName=FONT_BOLD, fontSize=15, leading=19,
                             textColor=ACCENT, spaceBefore=10, spaceAfter=6),
        "h3": ParagraphStyle("h3", parent=base["Heading3"], fontName=FONT_BOLD, fontSize=11, leading=14,
                             textColor=INK, spaceBefore=6),
        "brand": ParagraphStyle("brand", parent=body, fontName=FONT_BOLD, fontSize=11, textColor=ACCENT,
                                alignment=TA_CENTER, spaceAfter=40),
        "center": ParagraphStyle("center", parent=body, alignment=TA_CENTER),
    }


class _Renderer:
    def __init__(self, report: dict[str, Any]):
        self.r = report
        self.st = _styles()
        self.story: list[Any] = []

    # ------------------------------------------------------------------ helpers
    def p(self, text: str, style: str = "body", *, raw: bool = False) -> Paragraph:
        """``raw=True`` only for markup written in this module (its dynamic parts already passed through esc)."""
        if raw and not UNICODE_FONTS:
            for symbol, ascii_text in _ASCII.items():
                text = text.replace(symbol, ascii_text)
        return Paragraph(text if raw else esc(text), self.st[style])

    def table(self, header: list[str], rows: list[list[Any]], widths: list[float] | None = None,
              severity_col: int | None = None) -> Table:
        data = [[self.p(h, "small") for h in header]]
        for row in rows:
            cells = []
            for col, cell in enumerate(row):
                colour = SEVERITY_COLOURS.get(str(cell)) if col == severity_col else None
                if isinstance(cell, Paragraph):
                    cells.append(cell)
                elif colour is not None:  # colour must be set on the Paragraph; TEXTCOLOR does not reach it
                    cells.append(self.p(f'<font color="#{colour.hexval()[2:]}"><b>{esc(cell)}</b></font>', "small",
                                        raw=True))
                else:
                    cells.append(self.p(cell, "small"))
            data.append(cells)
        t = Table(data, colWidths=widths, repeatRows=1)
        t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, LINE), ("BACKGROUND", (0, 0), (-1, 0), BG),
                               ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 4),
                               ("RIGHTPADDING", (0, 0), (-1, -1), 4)]))
        return t

    def bullets(self, items: list[str]) -> ListFlowable:
        return ListFlowable([ListItem(self.p(i), leftIndent=10) for i in items], bulletType="bullet",
                            start="•" if UNICODE_FONTS else "-", bulletFontName=FONT, leftIndent=12)

    def add(self, *flowables: Any) -> None:
        self.story.extend(flowables)

    # ------------------------------------------------------------------ document
    def build(self) -> bytes:
        meta = self.r["meta"]
        self.cover(meta)
        for number, key in enumerate(meta["sections"], start=1):
            self.add(self.p(f"{number}. {meta['section_titles'][key]}", "h2"))
            getattr(self, f"section_{key}")()
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=20 * mm,
                                bottomMargin=18 * mm, title=meta["title"], author="AEGIS",
                                subject=meta["snapshot"]["name"],
                                creator=f"AEGIS {meta['product_version']}")

        def decorate(canvas, document) -> None:
            canvas.saveState()
            canvas.setFont(FONT, 7.5)
            canvas.setFillColor(colors.grey)
            canvas.drawString(18 * mm, 10 * mm, f"AEGIS {'·' if UNICODE_FONTS else '|'} {meta['classification']}")
            canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {document.page}")
            if document.page > 1:
                canvas.drawString(18 * mm, A4[1] - 12 * mm, meta["title"][:90])
            canvas.restoreState()

        doc.build(self.story, onFirstPage=decorate, onLaterPages=decorate)
        return buffer.getvalue()

    def cover(self, meta: dict[str, Any]) -> None:
        env = self.r["executive_summary"]["environment_risk"]
        self.add(Spacer(1, 50 * mm), self.p("A E G I S", "brand"), self.p(meta["title"], "h1"),
                 self.p(meta["snapshot"]["name"], "h3"), Spacer(1, 6 * mm),
                 self.p(f"Analysis #{meta['analysis_id']} · generated {meta['generated_at'][:19].replace('T', ' ')} UTC"
                        + (f" by {meta['generated_by']}" if meta.get("generated_by") else ""), "body"),
                 self.p(f"Environment risk: {env.get('score', 0)} ({env.get('severity', 'Low')})", "h3"),
                 Spacer(1, 10 * mm),
                 self.p(f"<b>{esc(meta['classification'])}</b>: contains a map of privilege-escalation paths.",
                        "body", raw=True))
        if meta["sample_data"]:
            self.add(Spacer(1, 4 * mm), self.p("<b>SAMPLE DATA</b>: generated from AEGIS's synthetic dataset; it does "
                                               "not describe a real organisation.", "body", raw=True))
        self.add(PageBreak())

    # ------------------------------------------------------------------ sections
    def section_executive_summary(self) -> None:
        ex = self.r["executive_summary"]
        self.add(self.bullets(ex["messages"]))
        if ex["top_findings"]:
            self.add(self.p("Most significant findings", "h3"),
                     self.table(["Severity", "Score", "Route"], [[f["severity"], f["score"], f["route"]]
                                                                 for f in ex["top_findings"]],
                                [22 * mm, 16 * mm, 136 * mm], severity_col=0))
        self.add(self.severity_chart())

    def severity_chart(self) -> Drawing:
        counts = self.r["attack_paths"]["by_severity"]
        drawing = Drawing(170 * mm, 55 * mm)
        chart = VerticalBarChart()
        chart.x, chart.y, chart.width, chart.height = 15 * mm, 8 * mm, 140 * mm, 40 * mm
        chart.data = [[counts[s] for s in SEVERITY_COLOURS]]
        chart.categoryAxis.categoryNames = list(SEVERITY_COLOURS)
        chart.valueAxis.valueMin = 0
        chart.valueAxis.valueMax = max(1, *chart.data[0])
        chart.bars[0].fillColor = ACCENT
        for i, colour in enumerate(SEVERITY_COLOURS.values()):
            chart.bars[(0, i)].fillColor = colour
        drawing.add(chart)
        return drawing

    def section_scope(self) -> None:
        sc = self.r["scope"]
        params = sc["analysis"]["parameters"]
        self.add(self.table(["Item", "Value"], [
            ["Snapshot", sc["snapshot"]], ["Collection time", sc["collected_at"] or "not recorded"],
            ["Source", sc["source_kind"] or "-"],
            ["Analysis", f"#{sc['analysis']['id']} · depth {params['max_depth']} · "
                         f"{params['alternatives_per_source']} route(s) per identity"]], [40 * mm, 134 * mm]))
        self.add(self.p("Data sources", "h3"),
                 self.table(["File", "Format", "Status", "SHA-256"],
                            [[d["file"], d["format"], d["status"], self.p(d["sha256"], "mono")]
                             for d in sc["data_sources"]], [44 * mm, 38 * mm, 18 * mm, 74 * mm]),
                 self.p("Out of scope", "h3"), self.bullets(sc["out_of_scope"]))

    def section_methodology(self) -> None:
        m = self.r["methodology"]
        self.add(self.bullets(m["approach"]), self.p("Path classifications", "h3"),
                 self.table(["Classification", "Meaning"], [[k, v] for k, v in m["classifications"].items()],
                            [55 * mm, 119 * mm]),
                 self.p("Limitations", "h3"), self.bullets(m["limitations"]))

    def section_environment(self) -> None:
        e = self.r["environment"]
        self.add(self.p("Domains: " + (", ".join(e["domains"]) or "none collected")),
                 self.table(["Object type", "Count"], [[k, v] for k, v in sorted(e["objects_by_kind"].items())],
                            [80 * mm, 30 * mm]))

    def section_directory_statistics(self) -> None:
        d = self.r["directory_statistics"]
        self.add(self.table(["Measure", "Value"], [
            ["Objects", d["objects_total"]],
            ["Accounts enabled / disabled", f"{d['accounts']['enabled']} / {d['accounts']['disabled']}"],
            ["Service accounts", d["service_accounts"]], ["Relationships", d["relationships_total"]],
            ["Collection gaps (placeholders)", d["collection_gaps"]]], [80 * mm, 40 * mm]),
            self.p("Relationships by type", "h3"),
            self.table(["Type", "Count"], [[k, v] for k, v in d["relationships_by_kind"].items()],
                       [80 * mm, 30 * mm]))

    def section_privileged_exposure(self) -> None:
        pe = self.r["privileged_exposure"]
        self.add(self.p(f"{pe['tier0_total']} tier-0 objects ({pe['tier0_accounts']} accounts). "
                        f"{pe['exposed_identities']} of {pe['starting_identities']} identities can reach tier-0."),
                 self.p("Exposed privileged targets", "h3"),
                 self.table(["Target", "Type", "Identities"], [[t["name"], t["kind"], t["identities"]]
                                                                for t in pe["exposed_targets"]] or [["None", "", ""]],
                            [100 * mm, 34 * mm, 30 * mm]),
                 self.p("Tier-0 inventory", "h3"),
                 self.table(["Object", "Type", "Why it is tier-0"], [[o["name"], o["kind"], o["reason"]]
                                                                      for o in pe["objects"]],
                            [62 * mm, 26 * mm, 86 * mm]))

    def section_attack_paths(self) -> None:
        ap = self.r["attack_paths"]
        self.add(self.p(f"{ap['total']} paths; the {ap['listed']} highest-risk are listed."),
                 self.table(["#", "Severity", "Score", "Hops", "Route"],
                            [[i, p["severity"], p["score"], p["hops"], p["route"]]
                             for i, p in enumerate(ap["paths"], 1)],
                            [8 * mm, 18 * mm, 14 * mm, 11 * mm, 123 * mm], severity_col=1))

    def section_critical_findings(self) -> None:
        findings = self.r["critical_findings"]
        if not findings:
            self.add(self.p("No Critical or High findings."))
        for i, f in enumerate(findings, 1):
            colour = SEVERITY_COLOURS.get(f["severity"], INK).hexval()[2:]
            block = [self.p(f'F{i}. <font color="#{colour}">{esc(f["severity"])}</font> ({esc(f["score"])}) — '
                            f'{esc(f["source"])} → {esc(f["target"])}', "h3", raw=True),
                     self.p(f["summary"]),
                     self.bullets([f"{s['from']} -[{s['kind']}]-> {s['to']}: {s['technique']}"
                                   + (f" (also: {', '.join(s['alternatives'])})" if s["alternatives"] else "")
                                   for s in f["steps"]])]
            if f["conditions"]:
                block += [self.p("<b>Conditions to validate</b>", raw=True), self.bullets(f["conditions"])]
            block.append(self.table(["Score factor", "Value", "Points", "Reason"],
                                    [[b["factor"], b["value"], b["points"], b["why"]] for b in f["score_breakdown"]],
                                    [36 * mm, 16 * mm, 16 * mm, 106 * mm]))
            self.add(KeepTogether(block[:3]), *block[3:], Spacer(1, 4 * mm))

    def section_technical_evidence(self) -> None:
        if not self.r["technical_evidence"]:
            self.add(self.p("No findings require evidence listing."))
        for i, e in enumerate(self.r["technical_evidence"], 1):
            rows = [[s["relationship"], r["kind"], self.p(f"{r['source_file']} · {r['field']} · {r['data_source']}",
                                                         "mono"), r["confidence"]]
                    for s in e["steps"] for r in s["records"]]
            self.add(self.p(f"F{i}: {e['route']}", "h3"),
                     self.table(["Relationship", "Recorded as", "Source", "Confidence"], rows,
                                [62 * mm, 26 * mm, 66 * mm, 20 * mm]))

    def section_risk_assessment(self) -> None:
        ra = self.r["risk_assessment"]
        env = ra["environment"]
        comp = env.get("components", {})
        self.add(self.p(f"Environment risk {env.get('score', 0)} ({env.get('severity', 'Low')}) = 0.5 × worst path "
                        f"{comp.get('worst_path', 0)} + 0.3 × exposure mass {comp.get('exposure_mass', 0)} + "
                        f"0.2 × breadth {comp.get('breadth', 0)}."),
                 self.table(["Factor", "Weight"], [[k.replace("_", " "), f"{v:.2f}"] for k, v in ra["weights"].items()],
                            [70 * mm, 30 * mm]),
                 self.p(f"Bands: Critical ≥ {ra['bands']['Critical']}, High ≥ {ra['bands']['High']}, Medium ≥ "
                        f"{ra['bands']['Medium']}. Unvalidated conditional paths are capped at "
                        f"{ra['conditional_cap']}.", "small"),
                 self.p("Choke points", "h3"),
                 self.table(["Relationship", "Paths"], [[f"{c['from']} -[{', '.join(c['kinds'])}]-> {c['to']}",
                                                         c["paths"]] for c in ra["choke_points"]] or [["None", ""]],
                            [150 * mm, 24 * mm]))

    def section_recommendations(self) -> None:
        rec = self.r["recommendations"]
        self.add(self.p(f"Priority actions: the minimum cut of {rec['minimum_cut_size']} change(s)", "h3"),
                 self.table(["#", "Relationship", "Action"],
                            [[i, a["relationship"], a["action"]] for i, a in enumerate(rec["priority_actions"], 1)]
                            or [["", "No action required", ""]], [8 * mm, 70 * mm, 96 * mm]),
                 self.p("Techniques observed", "h3"),
                 self.table(["Technique", "Path steps", "Relationship types"],
                            [[t["technique"], t["paths"], ", ".join(t["relationship_kinds"])]
                             for t in rec["by_technique"]], [70 * mm, 22 * mm, 82 * mm]),
                 self.p("Structural measures", "h3"), self.bullets(rec["general"]))

    def section_simulations(self) -> None:
        sims = self.r["simulations"]
        items = ([sims["minimum_cut"]] if sims["minimum_cut"] else []) + sims["saved"]
        if not items:
            self.add(self.p("No simulations were run."))
        for s in items:
            changes = [f"remove {r}" for r in s["removed"]] + [f"disable {d}" for d in s["disabled"]]
            self.add(self.p(s["title"], "h3"), self.table(["Measure", "Before → after"], [
                ["Attack paths", f"{s['paths_before']} → {s['paths_after']}"],
                ["Exposed identities", f"{s['exposed_before']} → {s['exposed_after']}"],
                ["Environment risk", f"{s['risk_before']} → {s['risk_after']}"],
                ["Changes simulated", self.p("<br/>".join(esc(c) for c in changes) or "-", "mono", raw=True)]],
                [45 * mm, 129 * mm]))
        self.add(self.p("Simulations run on an isolated in-memory copy; the directory was not modified.", "small"))

    def section_changes(self) -> None:
        self.add(self.bullets(self.r["changes"]["summary"]))

    def section_conclusion(self) -> None:
        for line in self.r["conclusion"]:
            self.add(self.p(line))
        self.add(Spacer(1, 6 * mm), self.p(self.r["meta"]["disclaimer"], "small"))


def render_pdf(report: dict[str, Any]) -> bytes:
    return _Renderer(report).build()
