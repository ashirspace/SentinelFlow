"""CSV + PDF report generators for SentinelFlow.

- Alerts + incidents grouped by severity within a date range.
- Uses reportlab for PDF (single-file, no external services).
"""
import csv
import io
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
)


SEVERITY_ORDER = ["Likely malicious", "Suspicious", "Informational"]
SEVERITY_COLOR = {
    "Likely malicious": colors.HexColor("#ef4444"),
    "Suspicious": colors.HexColor("#f59e0b"),
    "Informational": colors.HexColor("#06b6d4"),
}


def _esc(s: Any) -> str:
    """Escape XML entities for reportlab Paragraph."""
    if s is None:
        return ""
    return (str(s).replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;"))


def _parse_date(s: Optional[str], default: datetime) -> datetime:
    if not s:
        return default
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return default


def parse_range(start: Optional[str], end: Optional[str]):
    now = datetime.now(timezone.utc)
    end_dt = _parse_date(end, now)
    start_dt = _parse_date(start, end_dt.replace(hour=0, minute=0, second=0, microsecond=0))
    return start_dt, end_dt


async def collect_alerts(db, start_iso: str, end_iso: str) -> List[Dict[str, Any]]:
    q = {"created_at": {"$gte": start_iso, "$lte": end_iso}}
    return await db.alerts.find(q, {"_id": 0}).sort("created_at", 1).to_list(20000)


async def collect_incidents(db, start_iso: str, end_iso: str) -> List[Dict[str, Any]]:
    q = {"opened_at": {"$gte": start_iso, "$lte": end_iso}}
    return await db.incidents.find(q, {"_id": 0, "timeline": 0}).sort("opened_at", 1).to_list(5000)


def _group_by_sev(items: List[dict], sev_key: str = "severity") -> Dict[str, List[dict]]:
    g: Dict[str, List[dict]] = defaultdict(list)
    for i in items:
        sev = i.get(sev_key) or "Informational"
        g[sev].append(i)
    return g


def alerts_csv(alerts: List[dict]) -> str:
    buf = io.StringIO()
    cols = ["severity", "rule_id", "rule_name", "status", "created_at",
            "src_ip", "user", "explanation", "id"]
    w = csv.writer(buf)
    w.writerow(cols)
    grouped = _group_by_sev(alerts)
    for sev in SEVERITY_ORDER:
        for a in grouped.get(sev, []):
            kf = a.get("key_fields") or {}
            w.writerow([
                sev, a.get("rule_id"), a.get("rule_name"), a.get("status"),
                a.get("created_at"),
                kf.get("src_ip") or "", kf.get("user") or "",
                (a.get("explanation") or "").replace("\n", " "),
                a.get("id"),
            ])
    return buf.getvalue()


def incidents_csv(incidents: List[dict]) -> str:
    buf = io.StringIO()
    cols = ["severity", "status", "title", "opened_at", "opened_by",
            "alerts", "events", "root_cause", "id"]
    w = csv.writer(buf)
    w.writerow(cols)
    grouped = _group_by_sev(incidents)
    for sev in SEVERITY_ORDER:
        for i in grouped.get(sev, []):
            w.writerow([
                sev, i.get("status"), i.get("title"),
                i.get("opened_at"), i.get("opened_by"),
                len(i.get("alert_ids") or []),
                len(i.get("evidence_event_ids") or []),
                (i.get("root_cause") or "").replace("\n", " "),
                i.get("id"),
            ])
    return buf.getvalue()


def summary_counts(alerts: List[dict], incidents: List[dict]) -> Dict[str, Any]:
    alert_by_sev = Counter(a.get("severity") or "Informational" for a in alerts)
    inc_by_sev = Counter(i.get("severity") or "Informational" for i in incidents)
    inc_by_status = Counter(i.get("status") or "Open" for i in incidents)
    return {
        "alerts_total": len(alerts),
        "alerts_by_severity": {s: alert_by_sev.get(s, 0) for s in SEVERITY_ORDER},
        "incidents_total": len(incidents),
        "incidents_by_severity": {s: inc_by_sev.get(s, 0) for s in SEVERITY_ORDER},
        "incidents_by_status": dict(inc_by_status),
    }


def combined_pdf(start_dt: datetime, end_dt: datetime,
                  alerts: List[dict], incidents: List[dict],
                  generated_by: str) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=LETTER,
        leftMargin=0.6 * inch, rightMargin=0.6 * inch,
        topMargin=0.6 * inch, bottomMargin=0.6 * inch,
        title="SentinelFlow Security Report",
    )
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="Mono", fontName="Courier", fontSize=8, leading=10))
    styles.add(ParagraphStyle(name="Sub", fontName="Helvetica", fontSize=9,
                              textColor=colors.HexColor("#6b7280"), leading=11))
    styles.add(ParagraphStyle(name="H1x", fontName="Helvetica-Bold", fontSize=18, leading=22))
    styles.add(ParagraphStyle(name="H2x", fontName="Helvetica-Bold", fontSize=13,
                              leading=16, spaceBefore=8, spaceAfter=4))

    story = []
    story.append(Paragraph("SentinelFlow — Security Report", styles["H1x"]))
    story.append(Paragraph(
        f"Range: {start_dt.strftime('%Y-%m-%d %H:%M UTC')} → {end_dt.strftime('%Y-%m-%d %H:%M UTC')}<br/>"
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} by {generated_by}",
        styles["Sub"],
    ))
    story.append(Spacer(1, 12))

    # Summary table
    s = summary_counts(alerts, incidents)
    story.append(Paragraph("Summary", styles["H2x"]))
    data = [
        ["Metric", "Count"],
        ["Alerts (total)", str(s["alerts_total"])],
    ]
    for sev in SEVERITY_ORDER:
        data.append([f"  · {sev}", str(s["alerts_by_severity"][sev])])
    data.append(["Incidents (total)", str(s["incidents_total"])])
    for sev in SEVERITY_ORDER:
        data.append([f"  · {sev}", str(s["incidents_by_severity"][sev])])
    for st, n in s["incidents_by_status"].items():
        data.append([f"  Incidents ({st})", str(n)])
    t = Table(data, colWidths=[3.2 * inch, 1.2 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d1d5db")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
    ]))
    story.append(t)
    story.append(Spacer(1, 14))

    # Alerts by severity
    story.append(Paragraph("Alerts by severity", styles["H2x"]))
    alerts_by = _group_by_sev(alerts)
    for sev in SEVERITY_ORDER:
        sev_alerts = alerts_by.get(sev, [])
        if not sev_alerts:
            continue
        story.append(Paragraph(f"{sev} — {len(sev_alerts)}",
                               ParagraphStyle(name="sev", fontName="Helvetica-Bold",
                                              fontSize=11, textColor=SEVERITY_COLOR[sev],
                                              spaceBefore=6, spaceAfter=4)))
        rows = [["When", "Rule", "Src IP / User", "Status", "Explanation"]]
        for a in sev_alerts[:200]:
            kf = a.get("key_fields") or {}
            target = kf.get("src_ip") or kf.get("user") or "—"
            rows.append([
                (a.get("created_at") or "")[:19],
                a.get("rule_id") or "",
                str(target)[:24],
                a.get("status") or "",
                Paragraph(_esc((a.get("explanation") or ""))[:400], styles["Mono"]),
            ])
        tbl = Table(rows, colWidths=[1.15 * inch, 0.55 * inch, 1.1 * inch, 0.85 * inch, 3.65 * inch])
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d1d5db")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(tbl)
        story.append(Spacer(1, 6))

    story.append(PageBreak())

    # Incidents by severity
    story.append(Paragraph("Incidents by severity", styles["H2x"]))
    inc_by = _group_by_sev(incidents)
    for sev in SEVERITY_ORDER:
        sev_inc = inc_by.get(sev, [])
        if not sev_inc:
            continue
        story.append(Paragraph(f"{sev} — {len(sev_inc)}",
                               ParagraphStyle(name="sev", fontName="Helvetica-Bold",
                                              fontSize=11, textColor=SEVERITY_COLOR[sev],
                                              spaceBefore=6, spaceAfter=4)))
        rows = [["Opened", "Status", "Title", "Alerts", "Root cause"]]
        for i in sev_inc:
            rows.append([
                (i.get("opened_at") or "")[:19],
                i.get("status") or "",
                Paragraph(_esc((i.get("title") or ""))[:180], styles["Mono"]),
                str(len(i.get("alert_ids") or [])),
                Paragraph(_esc((i.get("root_cause") or "—"))[:400], styles["Mono"]),
            ])
        tbl = Table(rows, colWidths=[1.15 * inch, 0.9 * inch, 2.3 * inch, 0.55 * inch, 2.4 * inch])
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d1d5db")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(tbl)
        story.append(Spacer(1, 6))

    if not alerts and not incidents:
        story.append(Paragraph("No data in the selected range.", styles["Sub"]))

    doc.build(story)
    return buf.getvalue()
