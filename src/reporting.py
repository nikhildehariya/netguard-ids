from datetime import datetime
import csv

import pandas as pd

from pathlib import Path

from config import ALERT_CONFIDENCE_THRESHOLD, LOG_PATH, REPORTS_DIR
from detections_db import migrate_csv_to_sqlite, load_detections

LOG_COLUMNS = ["timestamp", "prediction", "confidence", "severity", "source_ip", "flow_id", "mode"]


def load_history(limit: int | None = None, mode: str = "live", path: str | Path | None = None,
                 hours: float | None = None, start: str | None = None, end: str | None = None) -> pd.DataFrame:
    """Load detections from SQLite."""
    from datetime import timedelta
    rows = load_detections(limit=50000, mode=mode)
    if not rows:
        return pd.DataFrame(columns=LOG_COLUMNS)
    df = pd.DataFrame(rows)
    for col in LOG_COLUMNS:
        if col not in df.columns:
            df[col] = ""
    df["confidence"] = pd.to_numeric(df["confidence"], errors="coerce").fillna(0.0)
    df["actionable"] = (
        (df["prediction"] != "NORMAL")
        & (df["severity"].fillna("none") != "none")
        & (df["confidence"] >= ALERT_CONFIDENCE_THRESHOLD)
    )
    df["triage_status"] = "normal"
    df.loc[(df["prediction"] != "NORMAL") & ~df["actionable"], "triage_status"] = "review"
    df.loc[df["actionable"], "triage_status"] = "actionable"
    if hours or start or end:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        df = df.dropna(subset=["timestamp"])
        if hours:
            cutoff = datetime.now() - timedelta(hours=hours)
            df = df[df["timestamp"] >= cutoff]
        else:
            if start:
                df = df[df["timestamp"] >= pd.to_datetime(start)]
            if end:
                df = df[df["timestamp"] <= pd.to_datetime(end)]
    if limit:
        df = df.tail(limit)
    return df


def report_summary(limit: int = 200, hours: float | None = None,
                   start: str | None = None, end: str | None = None) -> dict:
    df = load_history(limit, mode="all", hours=hours, start=start, end=end)
    if df.empty:
        return {
            "total_events": 0,
            "attack_rate": 0.0,
            "raw_non_normal_rate": 0.0,
            "by_prediction": {},
            "by_severity": {},
            "by_triage_status": {},
            "top_sources": {},
        }

    total = len(df)
    raw_non_normal = df[df["prediction"] != "NORMAL"]
    actionable = df[df["actionable"]]
    attack_rate = round((len(actionable) / total) * 100, 2) if total else 0.0
    raw_non_normal_rate = round((len(raw_non_normal) / total) * 100, 2) if total else 0.0
    by_prediction = df["prediction"].value_counts().to_dict()
    by_severity = df["severity"].value_counts().to_dict()
    by_triage_status = df["triage_status"].value_counts().to_dict()
    top_sources = df["source_ip"].fillna("unknown").value_counts().head(5).to_dict()
    return {
        "total_events": int(total),
        "attack_rate": attack_rate,
        "raw_non_normal_rate": raw_non_normal_rate,
        "by_prediction": by_prediction,
        "by_severity": by_severity,
        "by_triage_status": by_triage_status,
        "top_sources": top_sources,
    }


def build_pdf_report(limit: int = 200, hours: float | None = None, start: str | None = None, end: str | None = None) -> str:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    )
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    summary = report_summary(limit, hours=hours, start=start, end=end)
    df = load_history(limit, mode="all", hours=hours, start=start, end=end)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = REPORTS_DIR / f"netguard_report_{timestamp}.pdf"

    # ── Color palette ──────────────────────────────────────────
    C_BG        = colors.HexColor("#020810")
    C_PANEL     = colors.HexColor("#0a1628")
    C_BORDER    = colors.HexColor("#1e3a5f")
    C_ACCENT    = colors.HexColor("#0ea5e9")
    C_GREEN     = colors.HexColor("#22d3a0")
    C_RED       = colors.HexColor("#ef4444")
    C_ORANGE    = colors.HexColor("#f97316")
    C_PURPLE    = colors.HexColor("#a78bfa")
    C_PINK      = colors.HexColor("#ec4899")
    C_WHITE     = colors.HexColor("#f1f5f9")
    C_MUTED     = colors.HexColor("#64748b")
    C_SUBTEXT   = colors.HexColor("#94a3b8")

    ATTACK_COLORS = {
        "NORMAL":       C_GREEN,
        "BRUTE_FORCE":  C_ORANGE,
        "DOS_DDOS":     C_RED,
        "WEB_ATTACK":   C_PURPLE,
        "INFILTRATION": C_PINK,
    }
    SEV_COLORS = {
        "critical": C_RED,
        "high":     C_ORANGE,
        "none":     C_GREEN,
    }

    # ── Styles ─────────────────────────────────────────────────
    def S(name, **kw):
        return ParagraphStyle(name, **kw)

    sTitle = S("Title",
        fontSize=26, textColor=C_WHITE, fontName="Helvetica-Bold",
        leading=32, alignment=TA_LEFT)

    sSubtitle = S("Subtitle",
        fontSize=11, textColor=C_MUTED, fontName="Helvetica",
        leading=16, alignment=TA_LEFT)

    sSectionHeader = S("SectionHeader",
        fontSize=13, textColor=C_ACCENT, fontName="Helvetica-Bold",
        leading=18, spaceBefore=8, spaceAfter=4,
        letterSpacing=1)

    sBody = S("Body",
        fontSize=10, textColor=C_SUBTEXT, fontName="Helvetica",
        leading=15)

    sTableHeader = S("TableHeader",
        fontSize=9, textColor=C_MUTED, fontName="Helvetica-Bold",
        leading=12, alignment=TA_CENTER)

    sTableCell = S("TableCell",
        fontSize=9, textColor=C_WHITE, fontName="Helvetica",
        leading=12, alignment=TA_LEFT)

    sTableCellCenter = S("TableCellC",
        fontSize=9, textColor=C_WHITE, fontName="Helvetica",
        leading=12, alignment=TA_CENTER)

    sFooter = S("Footer",
        fontSize=8, textColor=C_MUTED, fontName="Helvetica",
        leading=12, alignment=TA_CENTER)

    sStatLabel = S("StatLabel",
        fontSize=8, textColor=C_MUTED, fontName="Helvetica-Bold",
        leading=11, alignment=TA_CENTER, letterSpacing=0.5)

    sStatValue = S("StatValue",
        fontSize=22, textColor=C_WHITE, fontName="Helvetica-Bold",
        leading=26, alignment=TA_CENTER)

    # ── Doc setup ──────────────────────────────────────────────
    doc = SimpleDocTemplate(
        str(path), pagesize=A4,
        leftMargin=18*mm, rightMargin=18*mm,
        topMargin=16*mm, bottomMargin=16*mm,
        title="NetGuard IDS Report",
        author="NetGuard IDS v2.0",
    )
    W = A4[0] - 36*mm   # usable width
    story = []

    # ── Helper: horizontal rule ────────────────────────────────
    def hr(color=C_BORDER, thickness=0.5):
        return HRFlowable(width="100%", thickness=thickness, color=color, spaceAfter=6, spaceBefore=6)

    # ── Helper: hex color string ───────────────────────────────
    def _hex(c):
        r, g, b = int(c.red*255), int(c.green*255), int(c.blue*255)
        return f"#{r:02x}{g:02x}{b:02x}"

    # ── Helper: colored pill paragraph ────────────────────────
    def pill(text, color):
        hex_c = color.hexval() if hasattr(color, 'hexval') else "#0ea5e9"
        return Paragraph(
            f'<font color="{hex_c}"><b>{text}</b></font>',
            sTableCell
        )

    # ══════════════════════════════════════════════════════════
    # PAGE 1 — HEADER BANNER
    # ══════════════════════════════════════════════════════════

    # Dark header banner via table
    now_str = datetime.now().strftime("%B %d, %Y  •  %H:%M:%S")
    header_data = [[
        Paragraph("NetGuard IDS", S("H1", fontSize=22, textColor=C_WHITE,
                  fontName="Helvetica-Bold", leading=26)),
        Paragraph(
            f'<font color="#64748b">IoT Intrusion Detection System</font><br/>'
            f'<font color="#0ea5e9" size="9">v2.0  •  XGBoost Classifier  •  CIC-IDS2018</font>',
            S("H2", fontSize=10, textColor=C_MUTED, fontName="Helvetica", leading=15, alignment=TA_RIGHT)
        ),
    ]]
    header_tbl = Table(header_data, colWidths=[W*0.55, W*0.45])
    header_tbl.setStyle(TableStyle([
        ("BACKGROUND",  (0,0), (-1,-1), C_PANEL),
        ("ROWBACKGROUNDS", (0,0), (-1,-1), [C_PANEL]),
        ("BOX",         (0,0), (-1,-1), 1, C_BORDER),
        ("LEFTPADDING",  (0,0), (-1,-1), 14),
        ("RIGHTPADDING", (0,0), (-1,-1), 14),
        ("TOPPADDING",   (0,0), (-1,-1), 14),
        ("BOTTOMPADDING",(0,0), (-1,-1), 14),
        ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
    ]))
    story.append(header_tbl)
    story.append(Spacer(1, 4*mm))

    # Report metadata row
    meta_data = [[
        Paragraph(f'<font color="#64748b">INCIDENT REPORT</font>', sStatLabel),
        Paragraph(f'<font color="#64748b">GENERATED</font>', sStatLabel),
        Paragraph(f'<font color="#64748b">EVENTS ANALYZED</font>', sStatLabel),
        Paragraph(f'<font color="#64748b">CLASSIFICATION MODEL</font>', sStatLabel),
    ],[
        Paragraph(f'<font color="#0ea5e9">Security Operations</font>',
                  S("mv", fontSize=11, textColor=C_ACCENT, fontName="Helvetica-Bold",
                    leading=14, alignment=TA_CENTER)),
        Paragraph(now_str,
                  S("mv2", fontSize=9, textColor=C_WHITE, fontName="Helvetica",
                    leading=14, alignment=TA_CENTER)),
        Paragraph(str(summary["total_events"]),
                  S("mv3", fontSize=18, textColor=C_WHITE, fontName="Helvetica-Bold",
                    leading=22, alignment=TA_CENTER)),
        Paragraph("XGBoost  F1=0.9025",
                  S("mv4", fontSize=10, textColor=C_GREEN, fontName="Helvetica-Bold",
                    leading=14, alignment=TA_CENTER)),
    ]]
    meta_tbl = Table(meta_data, colWidths=[W/4]*4)
    meta_tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,-1), C_BG),
        ("BOX",          (0,0), (-1,-1), 0.5, C_BORDER),
        ("INNERGRID",    (0,0), (-1,-1), 0.3, C_BORDER),
        ("TOPPADDING",   (0,0), (-1,-1), 8),
        ("BOTTOMPADDING",(0,0), (-1,-1), 8),
        ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
    ]))
    story.append(meta_tbl)
    story.append(Spacer(1, 6*mm))

    # ══════════════════════════════════════════════════════════
    # STAT CARDS ROW
    # ══════════════════════════════════════════════════════════
    story.append(Paragraph("EXECUTIVE SUMMARY", sSectionHeader))
    story.append(hr(C_ACCENT, 1))

    total     = summary["total_events"]
    a_rate    = summary["attack_rate"]
    n_attacks = sum(v for k, v in summary["by_prediction"].items() if k != "NORMAL")
    n_normal  = summary["by_prediction"].get("NORMAL", 0)

    def stat_card(label, value, color=C_WHITE):
        return [
            Paragraph(label, sStatLabel),
            Paragraph(f'<font color="{_hex(color)}">{value}</font>', sStatValue),
        ]

    cards_data = [
        [Paragraph("TOTAL FLOWS", sStatLabel),
         Paragraph("NORMAL TRAFFIC", sStatLabel),
         Paragraph("THREATS DETECTED", sStatLabel),
         Paragraph("ATTACK RATE", sStatLabel)],
        [Paragraph(str(total),    S("sv", fontSize=24, textColor=C_WHITE,  fontName="Helvetica-Bold", leading=28, alignment=TA_CENTER)),
         Paragraph(str(n_normal), S("sv", fontSize=24, textColor=C_GREEN,  fontName="Helvetica-Bold", leading=28, alignment=TA_CENTER)),
         Paragraph(str(n_attacks),S("sv", fontSize=24, textColor=C_RED if n_attacks > 0 else C_GREEN, fontName="Helvetica-Bold", leading=28, alignment=TA_CENTER)),
         Paragraph(f"{a_rate}%",  S("sv", fontSize=24, textColor=C_ORANGE if a_rate > 1 else C_GREEN, fontName="Helvetica-Bold", leading=28, alignment=TA_CENTER))],
    ]
    cards_tbl = Table(cards_data, colWidths=[W/4]*4)
    cards_tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,-1), C_PANEL),
        ("BOX",          (0,0), (-1,-1), 0.5, C_BORDER),
        ("INNERGRID",    (0,0), (-1,-1), 0.3, C_BORDER),
        ("TOPPADDING",   (0,0), (-1,-1), 10),
        ("BOTTOMPADDING",(0,0), (-1,-1), 10),
        ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
        ("LINEABOVE",    (0,0), (-1,0),  2, C_ACCENT),
    ]))
    story.append(cards_tbl)
    story.append(Spacer(1, 6*mm))

    # ══════════════════════════════════════════════════════════
    # ATTACK CLASSIFICATION TABLE
    # ══════════════════════════════════════════════════════════
    story.append(Paragraph("THREAT CLASSIFICATION BREAKDOWN", sSectionHeader))
    story.append(hr(C_ACCENT, 1))

    cls_header = [
        Paragraph("ATTACK CLASS",  sTableHeader),
        Paragraph("COUNT",         sTableHeader),
        Paragraph("% OF TOTAL",    sTableHeader),
        Paragraph("RISK LEVEL",    sTableHeader),
    ]
    RISK = {
        "NORMAL":       ("NONE",     C_GREEN),
        "BRUTE_FORCE":  ("HIGH",     C_ORANGE),
        "DOS_DDOS":     ("CRITICAL", C_RED),
        "WEB_ATTACK":   ("HIGH",     C_PURPLE),
        "INFILTRATION": ("MEDIUM",   C_PINK),
    }
    cls_rows = [cls_header]
    for cls, cnt in sorted(summary["by_prediction"].items(), key=lambda x: -x[1]):
        pct = round(cnt / total * 100, 1) if total else 0
        risk_label, risk_color = RISK.get(cls, ("UNKNOWN", C_MUTED))
        cls_rows.append([
            Paragraph(cls.replace("_", " "), sTableCell),
            Paragraph(str(cnt), sTableCellCenter),
            Paragraph(f"{pct}%", sTableCellCenter),
            Paragraph(f'<font color="{_hex(risk_color)}"><b>{risk_label}</b></font>', sTableCellCenter),
        ])

    cls_tbl = Table(cls_rows, colWidths=[W*0.35, W*0.2, W*0.2, W*0.25])
    cls_style = [
        ("BACKGROUND",   (0,0), (-1,0),  C_BG),
        ("BACKGROUND",   (0,1), (-1,-1), C_PANEL),
        ("ROWBACKGROUNDS",(0,1),(-1,-1), [C_PANEL, colors.HexColor("#0d1f35")]),
        ("BOX",          (0,0), (-1,-1), 0.5, C_BORDER),
        ("INNERGRID",    (0,0), (-1,-1), 0.3, C_BORDER),
        ("LINEBELOW",    (0,0), (-1,0),  1,   C_ACCENT),
        ("TOPPADDING",   (0,0), (-1,-1), 8),
        ("BOTTOMPADDING",(0,0), (-1,-1), 8),
        ("LEFTPADDING",  (0,0), (-1,-1), 10),
        ("RIGHTPADDING", (0,0), (-1,-1), 10),
        ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
    ]
    cls_tbl.setStyle(TableStyle(cls_style))
    story.append(cls_tbl)
    story.append(Spacer(1, 6*mm))

    # ══════════════════════════════════════════════════════════
    # SEVERITY + TRIAGE SIDE BY SIDE
    # ══════════════════════════════════════════════════════════
    story.append(Paragraph("SEVERITY & TRIAGE STATUS", sSectionHeader))
    story.append(hr(C_ACCENT, 1))

    def mini_table(title, data_dict, color_map):
        rows = [[Paragraph("CATEGORY", sTableHeader), Paragraph("COUNT", sTableHeader)]]
        for k, v in data_dict.items():
            c = color_map.get(k.lower(), C_SUBTEXT)
            rows.append([
                Paragraph(f'<font color="{_hex(c)}">{k.upper()}</font>', sTableCell),
                Paragraph(str(v), sTableCellCenter),
            ])
        t = Table(rows, colWidths=[W*0.20, W*0.12])
        t.setStyle(TableStyle([
            ("BACKGROUND",   (0,0), (-1,0),  C_BG),
            ("BACKGROUND",   (0,1), (-1,-1), C_PANEL),
            ("BOX",          (0,0), (-1,-1), 0.5, C_BORDER),
            ("INNERGRID",    (0,0), (-1,-1), 0.3, C_BORDER),
            ("LINEBELOW",    (0,0), (-1,0),  1,   C_ACCENT),
            ("TOPPADDING",   (0,0), (-1,-1), 6),
            ("BOTTOMPADDING",(0,0), (-1,-1), 6),
            ("LEFTPADDING",  (0,0), (-1,-1), 8),
            ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
        ]))
        return t

    sev_tbl    = mini_table("Severity",      summary["by_severity"],      {"critical": C_RED, "high": C_ORANGE, "none": C_GREEN})
    triage_tbl = mini_table("Triage Status", summary["by_triage_status"], {"actionable": C_RED, "review": C_ORANGE, "normal": C_GREEN})

    combo = Table([[sev_tbl, Spacer(6*mm, 1), triage_tbl]], colWidths=[W*0.33, 6*mm, W*0.33])
    combo.setStyle(TableStyle([("VALIGN", (0,0), (-1,-1), "TOP")]))
    story.append(combo)
    story.append(Spacer(1, 6*mm))

    # ══════════════════════════════════════════════════════════
    # TOP SOURCE IPs
    # ══════════════════════════════════════════════════════════
    story.append(Paragraph("TOP SOURCE IP ADDRESSES", sSectionHeader))
    story.append(hr(C_ACCENT, 1))

    ip_header = [
        Paragraph("RANK", sTableHeader),
        Paragraph("SOURCE IP", sTableHeader),
        Paragraph("EVENT COUNT", sTableHeader),
        Paragraph("% SHARE", sTableHeader),
    ]
    ip_rows = [ip_header]
    for rank, (ip, cnt) in enumerate(summary["top_sources"].items(), 1):
        pct = round(cnt / total * 100, 1) if total else 0
        ip_rows.append([
            Paragraph(f"#{rank}", sTableCellCenter),
            Paragraph(ip or "unknown", sTableCell),
            Paragraph(str(cnt), sTableCellCenter),
            Paragraph(f"{pct}%", sTableCellCenter),
        ])

    ip_tbl = Table(ip_rows, colWidths=[W*0.1, W*0.4, W*0.25, W*0.25])
    ip_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0),  C_BG),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),  [C_PANEL, colors.HexColor("#0d1f35")]),
        ("BOX",           (0,0), (-1,-1), 0.5, C_BORDER),
        ("INNERGRID",     (0,0), (-1,-1), 0.3, C_BORDER),
        ("LINEBELOW",     (0,0), (-1,0),  1,   C_ACCENT),
        ("TOPPADDING",    (0,0), (-1,-1), 8),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
        ("LEFTPADDING",   (0,0), (-1,-1), 10),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ("BACKGROUND",    (0,1), (0,-1),  colors.HexColor("#0d1f35")),
    ]))
    story.append(ip_tbl)
    story.append(Spacer(1, 6*mm))

    # ══════════════════════════════════════════════════════════
    # RECENT ATTACK EVENTS TABLE (up to 20)
    # ══════════════════════════════════════════════════════════
    if not df.empty:
        attack_df = df[df["prediction"] != "NORMAL"].tail(20)
        if not attack_df.empty:
            story.append(Paragraph("RECENT ATTACK EVENTS", sSectionHeader))
            story.append(hr(C_ACCENT, 1))

            ev_header = [
                Paragraph("TIMESTAMP",  sTableHeader),
                Paragraph("SOURCE IP",  sTableHeader),
                Paragraph("PREDICTION", sTableHeader),
                Paragraph("CONFIDENCE", sTableHeader),
                Paragraph("SEVERITY",   sTableHeader),
            ]
            ev_rows = [ev_header]
            for _, row in attack_df.iterrows():
                pred  = str(row.get("prediction", ""))
                sev   = str(row.get("severity", "none")).lower()
                conf  = float(row.get("confidence", 0))
                p_col = ATTACK_COLORS.get(pred, C_SUBTEXT)
                s_col = SEV_COLORS.get(sev, C_SUBTEXT)
                ts    = str(row.get("timestamp", ""))[:19].replace("T", " ")
                ev_rows.append([
                    Paragraph(ts,   sTableCell),
                    Paragraph(str(row.get("source_ip", "unknown") or "unknown"), sTableCell),
                    Paragraph(f'<font color="{_hex(p_col)}"><b>{pred.replace("_"," ")}</b></font>', sTableCell),
                    Paragraph(f"{conf:.1%}", sTableCellCenter),
                    Paragraph(f'<font color="{_hex(s_col)}"><b>{sev.upper()}</b></font>', sTableCellCenter),
                ])

            ev_tbl = Table(ev_rows, colWidths=[W*0.25, W*0.22, W*0.22, W*0.16, W*0.15])
            ev_tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0,0), (-1,0),  C_BG),
                ("ROWBACKGROUNDS",(0,1),(-1,-1),  [C_PANEL, colors.HexColor("#0d1f35")]),
                ("BOX",           (0,0), (-1,-1), 0.5, C_BORDER),
                ("INNERGRID",     (0,0), (-1,-1), 0.3, C_BORDER),
                ("LINEBELOW",     (0,0), (-1,0),  1,   C_ACCENT),
                ("TOPPADDING",    (0,0), (-1,-1), 6),
                ("BOTTOMPADDING", (0,0), (-1,-1), 6),
                ("LEFTPADDING",   (0,0), (-1,-1), 8),
                ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
            ]))
            story.append(ev_tbl)
            story.append(Spacer(1, 6*mm))

    # ══════════════════════════════════════════════════════════
    # SYSTEM INFO & FOOTER
    # ══════════════════════════════════════════════════════════
    story.append(Paragraph("SYSTEM INFORMATION", sSectionHeader))
    story.append(hr(C_ACCENT, 1))

    sys_data = [
        [Paragraph("PARAMETER", sTableHeader), Paragraph("VALUE", sTableHeader)],
        [Paragraph("System",           sTableCell), Paragraph("NetGuard IDS v2.0",          sTableCell)],
        [Paragraph("Model",            sTableCell), Paragraph("XGBoost Classifier",          sTableCell)],
        [Paragraph("Training Dataset", sTableCell), Paragraph("CIC-IDS2018 (8.2M flows)",    sTableCell)],
        [Paragraph("Features",         sTableCell), Paragraph("80 network flow features",    sTableCell)],
        [Paragraph("F1 Score",         sTableCell), Paragraph("0.9025",                      sTableCell)],
        [Paragraph("Attack Classes",   sTableCell), Paragraph("NORMAL / BRUTE_FORCE / DOS_DDOS / WEB_ATTACK / INFILTRATION", sTableCell)],
        [Paragraph("Report Period",    sTableCell), Paragraph(
                    (f"Last {hours}h" if hours else
                     (f"{start} to {end}" if start and end else
                      (f"From {start}" if start else
                       (f"Until {end}" if end else f"Last {limit} events")))),
                    sTableCell)],
        [Paragraph("Report Generated", sTableCell), Paragraph(datetime.now().isoformat(timespec="seconds"), sTableCell)],
    ]
    sys_tbl = Table(sys_data, colWidths=[W*0.35, W*0.65])
    sys_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0),  C_BG),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),  [C_PANEL, colors.HexColor("#0d1f35")]),
        ("BOX",           (0,0), (-1,-1), 0.5, C_BORDER),
        ("INNERGRID",     (0,0), (-1,-1), 0.3, C_BORDER),
        ("LINEBELOW",     (0,0), (-1,0),  1,   C_ACCENT),
        ("TOPPADDING",    (0,0), (-1,-1), 7),
        ("BOTTOMPADDING", (0,0), (-1,-1), 7),
        ("LEFTPADDING",   (0,0), (-1,-1), 10),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
    ]))
    story.append(sys_tbl)
    story.append(Spacer(1, 8*mm))

    # Footer
    footer_data = [[
        Paragraph(
            f'NetGuard IDS  •  Confidential Security Report  •  Generated {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}',
            sFooter
        )
    ]]
    footer_tbl = Table(footer_data, colWidths=[W])
    footer_tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,-1), C_PANEL),
        ("BOX",          (0,0), (-1,-1), 0.5, C_BORDER),
        ("LINEABOVE",    (0,0), (-1,0),  1,   C_ACCENT),
        ("TOPPADDING",   (0,0), (-1,-1), 8),
        ("BOTTOMPADDING",(0,0), (-1,-1), 8),
        ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
    ]))
    story.append(footer_tbl)

    # ── Build ──────────────────────────────────────────────────
    doc.build(story)
    return str(path)