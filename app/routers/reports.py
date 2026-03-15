# backend/app/routers/reports.py
import logging
import os
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse, StreamingResponse
from sqlalchemy import func, or_
from sqlmodel import select

from app.dependencies import DBSession, CurrentUser
from app.utils.csv_exporter import CSVExporter
from app.utils.pdf_generator import PDFGenerator

from app.models.urlscan_model import URLScanResult
from app.models.idsscan_model import IDSScanResult
from app.models.filescan_model import FileScanResult

logger = logging.getLogger("app.reports")
logger.setLevel(logging.INFO)

router = APIRouter(prefix="/reports", tags=["Reporting & Analytics"])


def _make_pdf_path(uid: int, suffix: Optional[str] = None):
    base = f"report_{uid}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    if suffix:
        base = f"{base}_{suffix}"
    fn = base + ".pdf"
    pdf_dir = os.path.join(os.getcwd(), "backend", "app", "media", "reports")
    os.makedirs(pdf_dir, exist_ok=True)
    return os.path.join(pdf_dir, fn), fn


# ---------------------------
# Lookup (autocomplete) endpoint
# ---------------------------
@router.get("/lookup")
def lookup_scans(
    q: str = Query(..., min_length=1),
    kind: str = Query("url", regex="^(url|file|ids)$"),
    db: DBSession = None,
    current_user: CurrentUser = None,
):
    """
    Safe lookup that:
    - Searches ONLY string/text fields
    - Never compares text to integer ID
    - Checks ID ONLY when q.isdigit()
    """
    from urllib.parse import unquote_plus
    from sqlalchemy import or_, func

    try:
        q = unquote_plus(q).strip()
        q_lower = q.lower()

        is_int = q.isdigit()   # Only numeric → valid for ID search
        results = []

        # -------------------------------------------------------------------
        # URL LOOKUP
        # -------------------------------------------------------------------
        if kind == "url":
            url_fields = []

            # dynamically detect possible URL fields
            for field in ("url", "target_url", "target", "scanned_url"):
                if hasattr(URLScanResult, field):
                    url_fields.append(getattr(URLScanResult, field))

            where_clauses = [func.lower(col).like(f"%{q_lower}%") for col in url_fields]

            # ID search only when q is numeric
            if is_int:
                where_clauses.append(URLScanResult.id == int(q))

            stmt = (
                select(URLScanResult)
                .where(
                    (URLScanResult.user_id == current_user.id)
                    & or_(*where_clauses)
                )
            )

            rows = db.exec(stmt).all()

            for r in rows:
                label = (
                    getattr(r, "url", None)
                    or getattr(r, "target_url", None)
                    or getattr(r, "target", None)
                    or f"Scan {r.id}"
                )
                results.append({
                    "id": r.id,
                    "label": label,
                    "scan_date": getattr(r, "scan_time", None)
                })

            return {"results": results}

        # -------------------------------------------------------------------
        # FILE LOOKUP
        # -------------------------------------------------------------------
        if kind == "file":
            file_fields = []

            for field in ("filename", "hash"):
                if hasattr(FileScanResult, field):
                    file_fields.append(getattr(FileScanResult, field))

            where_clauses = [func.lower(col).like(f"%{q_lower}%") for col in file_fields]

            if is_int:
                where_clauses.append(FileScanResult.id == int(q))

            stmt = (
                select(FileScanResult)
                .where(
                    (FileScanResult.user_id == current_user.id)
                    & or_(*where_clauses)
                )
            )

            rows = db.exec(stmt).all()

            for r in rows:
                label = f"{r.filename} ({r.hash[:12]})"
                results.append({
                    "id": r.id,
                    "label": label,
                    "scan_date": getattr(r, "scan_date", None)
                })
            return {"results": results}

        # -------------------------------------------------------------------
        # IDS LOOKUP
        # -------------------------------------------------------------------
        if kind == "ids":
            ids_fields = []

            # detect text-searchable fields
            for field in ("attack_type_summary", "signature", "category"):
                if hasattr(IDSScanResult, field):
                    ids_fields.append(getattr(IDSScanResult, field))

            where_clauses = [func.lower(col).like(f"%{q_lower}%") for col in ids_fields]

            if is_int:
                where_clauses.append(IDSScanResult.id == int(q))

            stmt = (
                select(IDSScanResult)
                .where(
                    (IDSScanResult.user_id == current_user.id)
                    & or_(*where_clauses)
                )
            )

            rows = db.exec(stmt).all()

            for r in rows:
                label = getattr(r, "attack_type_summary", f"IDS {r.id}")
                results.append({
                    "id": r.id,
                    "label": label,
                    "scan_date": getattr(r, "scan_time", None)
                })
            return {"results": results}

        return {"results": []}

    except Exception as e:
        logger.exception("Lookup failed")
        raise HTTPException(status_code=500, detail=f"Lookup failed: {str(e)}")


# ---------------------------
# CSV exporter (kept for compatibility)
# ---------------------------
@router.get("/export/csv/{report_type}")
def export_csv_report(report_type: str, db: DBSession = None, current_user: CurrentUser = None):
    exporter = CSVExporter()
    if report_type == "url_history":
        data = db.exec(select(URLScanResult).where(URLScanResult.user_id == current_user.id)).all()
        csv = exporter.export_data([d.model_dump() for d in data], "url_history.csv")
        return StreamingResponse(csv, media_type="text/csv",
                                headers={"Content-Disposition": "attachment; filename=url_history.csv"})
    if report_type == "ids_history":
        data = db.exec(select(IDSScanResult).where(IDSScanResult.user_id == current_user.id)).all()
        csv = exporter.export_data([d.model_dump() for d in data], "ids_history.csv")
        return StreamingResponse(csv, media_type="text/csv",
                                headers={"Content-Disposition": "attachment; filename=ids_history.csv"})
    if report_type == "file_history":
        data = db.exec(select(FileScanResult).where(FileScanResult.user_id == current_user.id)).all()
        csv = exporter.export_data([d.model_dump() for d in data], "file_history.csv")
        return StreamingResponse(csv, media_type="text/csv",
                                headers={"Content-Disposition": "attachment; filename=file_history.csv"})
    raise HTTPException(status_code=404, detail="Invalid report type")


# ---------------------------
# Executive PDF (aggregate)
# ---------------------------
@router.get("/generate/pdf")
def generate_pdf_report(db: DBSession = None, current_user: CurrentUser = None):
    from app.routers.dashboard import get_dashboard_metrics
    metrics = get_dashboard_metrics(db=db, current_user=current_user)

    sections = [
        {
            "header": "Overall Threat Summary",
            "type": "paragraph",
            "content": f"""
Your environment processed:
- {metrics.get('total_url_scans', 0)} URL Scans
- {metrics.get('total_ids_scans', 0)} IDS Scans
- {metrics.get('total_file_scans', 0)} File Scans

Total Critical Threats: {metrics.get('total_threats_detected')}
            """,
        },
        {
            "header": "URL Verdict Breakdown",
            "type": "table",
            "content": [["Verdict", "Count"]] +
                       list(metrics.get("url_verdict_distribution", {}).items()),
        },
        {
            "header": "IDS Severity Overview",
            "type": "table",
            "content": [["Severity", "Count"]] +
                       list(metrics.get("ids_severity_distribution", {}).items()),
        },
    ]

    path, fname = _make_pdf_path(current_user.id, suffix="executive")
    pdf = PDFGenerator(path, topic_title="AI Security Platform — Executive Summary")
    pdf.generate_report("Executive Summary", sections)
    return FileResponse(path, media_type="application/pdf", filename=fname)


# ---------------------------
# Single-scan PDF generator
# ---------------------------
@router.get("/generate/pdf/scan")
def generate_scan_pdf(
    scan_type: str = Query(..., regex="^(url|file|ids)$"),
    scan_id: str = Query(..., min_length=1),
    db: DBSession = None,
    current_user: CurrentUser = None,
):
    """
    GET /reports/generate/pdf/scan?scan_type=url&scan_id=<id_or_text>
    scan_type = url | file | ids
    scan_id = the model id (primary key) or a text/hash/filename/url to search by
    """
    try:
        from urllib.parse import unquote_plus

        sid_raw = scan_id.strip()
        try:
            sid = unquote_plus(sid_raw)
        except Exception:
            sid = sid_raw

        context = {}

        if scan_type == "url":
            # Try primary key
            row = db.get(URLScanResult, sid)
            if not row:
                # try by common URL columns:
                stmt = select(URLScanResult).where(
                    (URLScanResult.user_id == current_user.id) &
                    or_(
                        (getattr(URLScanResult, "url", None) == sid),
                        (getattr(URLScanResult, "target_url", None) == sid),
                        (getattr(URLScanResult, "target", None) == sid),
                    )
                )
                row = db.exec(stmt).first()

            if not row:
                raise HTTPException(status_code=404, detail="URL scan not found")

            context = {
                "metadata": {
                    "title": "URL Analysis Report",
                    "target": getattr(row, "url", None) or getattr(row, "target_url", None) or getattr(row, "target", None),
                    "verdict": getattr(row, "final_verdict", getattr(row, "final", None)),
                    "ml_score": getattr(row, "ml_score", None),
                    "urlhaus": getattr(row, "urlhaus_status", None),
                    "scan_date": getattr(row, "scan_time", None),
                },
                "engine_results": getattr(row, "engine_results", {}) or {},
                "ai_summary": getattr(row, "ai_summary", None),
                "ai_full": getattr(row, "ai_full", None),
                "mitre": getattr(row, "mitre_techniques", []) or [],
            }

        elif scan_type == "file":
            row = db.get(FileScanResult, sid)
            if not row:
                stmt = select(FileScanResult).where(
                    (FileScanResult.user_id == current_user.id) &
                    or_(
                        (getattr(FileScanResult, "hash", None) == sid),
                        (getattr(FileScanResult, "filename", None) == sid),
                        (FileScanResult.id == sid)
                    )
                )
                row = db.exec(stmt).first()

            if not row:
                raise HTTPException(status_code=404, detail="File scan not found")

            context = {
                "metadata": {
                    "title": "File Analysis Report",
                    "target": getattr(row, "filename", None),
                    "hash": getattr(row, "hash", None),
                    "verdict": getattr(row, "verdict", None),
                    "scan_date": getattr(row, "scan_date", None),
                },
                "engine_results": getattr(row, "engine_results", {}) or {},
                "ai_summary": getattr(row, "ai_summary", None),
                "ai_full": getattr(row, "ai_full", None),
                "mitre": getattr(row, "ai_mitre", []) or [],
            }

        else:  # ids
            row = db.get(IDSScanResult, sid)
            if not row:
                stmt = select(IDSScanResult).where(
                    (IDSScanResult.user_id == current_user.id) &
                    or_(
                        (getattr(IDSScanResult, "attack_type_summary", None) == sid),
                        (IDSScanResult.id == sid)
                    )
                )
                row = db.exec(stmt).first()

            if not row:
                raise HTTPException(status_code=404, detail="IDS scan not found")

            context = {
                "metadata": {
                    "title": "IDS Analysis Report",
                    "target": getattr(row, "attack_type_summary", None) or str(row.id),
                    "verdict": getattr(row, "overall_severity", None),
                    "scan_date": getattr(row, "scan_time", None),
                },
                "engine_results": {},
                "ai_summary": getattr(row, "ai_summary", None),
                "ai_full": getattr(row, "ai_full", None),
                "mitre": getattr(row, "ai_mitre", []) or [],
            }

        # Build PDF
        # safe suffix: take first 8 chars of id/hash for file name
        suffix = f"{scan_type}_{str(scan_id)[:8]}"
        path, fname = _make_pdf_path(current_user.id, suffix=suffix)
        pdf = PDFGenerator(path, topic_title=context["metadata"].get("title", "Threat Report"))
        pdf.generate_report(context["metadata"].get("title", "Threat Report"), context)

        return FileResponse(path, media_type="application/pdf", filename=fname)

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("generate_scan_pdf failed")
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {str(e)}")
