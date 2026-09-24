"""Security report generation endpoints (CSV & PDF)."""
from typing import Optional
from fastapi import APIRouter, Depends, Response
from fastapi.responses import StreamingResponse

import reports as _reports
from core.database import db
from core.deps import current_user, audit

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/summary")
async def reports_summary(
    start: Optional[str] = None,
    end: Optional[str] = None,
    _: dict = Depends(current_user),
):
    start_dt, end_dt = _reports.parse_range(start, end)
    alerts = await _reports.collect_alerts(db, start_dt.isoformat(), end_dt.isoformat())
    incidents = await _reports.collect_incidents(db, start_dt.isoformat(), end_dt.isoformat())
    return {
        "start": start_dt.isoformat(),
        "end": end_dt.isoformat(),
        **_reports.summary_counts(alerts, incidents),
    }


@router.get("/alerts.csv")
async def reports_alerts_csv(
    start: Optional[str] = None,
    end: Optional[str] = None,
    user: dict = Depends(current_user),
):
    start_dt, end_dt = _reports.parse_range(start, end)
    alerts = await _reports.collect_alerts(db, start_dt.isoformat(), end_dt.isoformat())
    csv_text = _reports.alerts_csv(alerts)
    await audit(
        user["email"], "report_export", target="alerts.csv",
        meta={"count": len(alerts), "start": start_dt.isoformat(), "end": end_dt.isoformat()},
    )
    return StreamingResponse(
        iter([csv_text]), media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=sentinelflow_alerts.csv"},
    )


@router.get("/incidents.csv")
async def reports_incidents_csv(
    start: Optional[str] = None,
    end: Optional[str] = None,
    user: dict = Depends(current_user),
):
    start_dt, end_dt = _reports.parse_range(start, end)
    incidents = await _reports.collect_incidents(db, start_dt.isoformat(), end_dt.isoformat())
    csv_text = _reports.incidents_csv(incidents)
    await audit(
        user["email"], "report_export", target="incidents.csv",
        meta={"count": len(incidents), "start": start_dt.isoformat(), "end": end_dt.isoformat()},
    )
    return StreamingResponse(
        iter([csv_text]), media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=sentinelflow_incidents.csv"},
    )


@router.get("/combined.pdf")
async def reports_combined_pdf(
    start: Optional[str] = None,
    end: Optional[str] = None,
    user: dict = Depends(current_user),
):
    start_dt, end_dt = _reports.parse_range(start, end)
    alerts = await _reports.collect_alerts(db, start_dt.isoformat(), end_dt.isoformat())
    incidents = await _reports.collect_incidents(db, start_dt.isoformat(), end_dt.isoformat())
    pdf_bytes = _reports.combined_pdf(start_dt, end_dt, alerts, incidents, user["email"])
    await audit(
        user["email"], "report_export", target="combined.pdf",
        meta={"alerts": len(alerts), "incidents": len(incidents),
              "start": start_dt.isoformat(), "end": end_dt.isoformat()},
    )
    return Response(
        content=pdf_bytes, media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=sentinelflow_report.pdf"},
    )
