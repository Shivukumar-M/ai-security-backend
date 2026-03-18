from fastapi import APIRouter
from app.dependencies import DBSession, CurrentUser
from app.models.urlscan_model import URLScanResult
from app.models.idsscan_model import IDSScanResult
from app.models.filescan_model import FileScanResult

from sqlmodel import select
from typing import Dict, Any
from datetime import datetime, timedelta
import pandas as pd

router = APIRouter(prefix="/dashboard", tags=["Dashboard Metrics"])


@router.get("/metrics", response_model=Dict[str, Any])
def get_dashboard_metrics(
    db: DBSession,
    current_user: CurrentUser
):

    # ============================================================
    # 1) URL SCANS
    # ============================================================
    url_results = db.exec(
        select(URLScanResult).where(URLScanResult.user_id == current_user.id)
    ).all()

    df_url = pd.DataFrame(
        [(u.id, u.final_verdict, u.target_url, u.scan_time) for u in url_results],
        columns=["id", "verdict", "url", "scan_time"],
    )

    url_verdict_counts = df_url["verdict"].value_counts().to_dict()
    total_url_scans = len(df_url)

    threat_url_count = url_verdict_counts.get("Threat Detected", 0)
    safe_url_count = total_url_scans - threat_url_count


    # ============================================================
    # 2) IDS SCANS
    # ============================================================
    ids_results = db.exec(
        select(IDSScanResult).where(IDSScanResult.user_id == current_user.id)
    ).all()

    df_ids = pd.DataFrame(
        [(i.id, i.overall_severity, i.scan_time) for i in ids_results],
        columns=["id", "severity", "scan_time"],
    )

    ids_severity_counts = df_ids["severity"].value_counts().to_dict()


    # ============================================================
    # 3) FILE SCANS
    # ============================================================
    file_results = db.exec(
        select(FileScanResult).where(FileScanResult.user_id == current_user.id)
    ).all()

    df_files = pd.DataFrame(
        [(f.id, f.verdict, f.filename, f.scan_date) for f in file_results],
        columns=["id", "verdict", "filename", "scan_date"],
    )

    total_file_scans = len(file_results)
    safe_file_count = sum(1 for f in file_results if f.verdict != "Malicious")


    # ============================================================
    # 4) 7-DAY UNIFIED TREND
    # ============================================================
    today = datetime.utcnow()
    traffic_trend = []

    for i in range(7):
        day = today - timedelta(days=i)
        d = day.date()

        url_count = df_url[df_url["scan_time"].dt.date == d].shape[0] if not df_url.empty else 0
        ids_count = df_ids[df_ids["scan_time"].dt.date == d].shape[0] if not df_ids.empty else 0
        file_count = df_files[df_files["scan_date"].dt.date == d].shape[0] if not df_files.empty else 0

        traffic_trend.append({
            "time": day.strftime("%Y-%m-%d"),
            "count": url_count + ids_count + file_count
        })

    traffic_trend.reverse()


    # ============================================================
    # 5) RECENT ACTIVITY (Top 5)
    # ============================================================
    activity = []

    for u in url_results:
        activity.append((u.scan_time, f"URL scanned: {u.target_url} → {u.final_verdict}"))

    for i in ids_results:
        activity.append((i.scan_time, f"IDS alert: {i.overall_severity} severity"))

    for f in file_results:
        activity.append((f.scan_date, f"File scanned: {f.filename} → {f.verdict}"))

    recent_activity = [
        msg for _, msg in sorted(activity, key=lambda x: x[0], reverse=True)[:5]
    ]


    # ============================================================
    # 6) LIVE THREAT ALERTS — NOW WITH ID + TYPE + DETAIL
    # ============================================================
    alerts = []

    # URL Threats
    for u in url_results:
        if u.final_verdict == "Threat Detected":
            alerts.append({
                "id": u.id,
                "type": "url",
                "datetime": u.scan_time,
                "time": u.scan_time.strftime("%H:%M:%S"),
                "level": "CRITICAL",
                "color": "red-400",
                "message": "Malicious URL detected",
                "detail": u.target_url
            })

    # IDS High Severity Alerts
    for i in ids_results:
        if i.overall_severity == "High":
            alerts.append({
                "id": i.id,
                "type": "ids",
                "datetime": i.scan_time,
                "time": i.scan_time.strftime("%H:%M:%S"),
                "level": "HIGH",
                "color": "yellow-400",
                "message": "High severity IDS alert",
                "detail": getattr(i, "signature", "Unknown signature")
            })

    # Malware Files
    for f in file_results:
        if f.verdict == "Malicious":
            alerts.append({
                "id": f.id,
                "type": "file",
                "datetime": f.scan_date,
                "time": f.scan_date.strftime("%H:%M:%S"),
                "level": "CRITICAL",
                "color": "red-500",
                "message": "Malware detected in file",
                "detail": f.filename
            })

    # Sort by REAL datetime
    alerts = sorted(alerts, key=lambda x: x["datetime"], reverse=True)

    live_alerts = alerts[:5]


    # ============================================================
    # 7) TOTAL THREATS
    # ============================================================
    total_threats_detected = (
        threat_url_count +
        ids_severity_counts.get("High", 0) +
        sum(1 for f in file_results if f.verdict == "Malicious")
    )

    # ============================================================
    # 8) FINAL RETURN
    # ============================================================
    return {
        "total_url_scans": total_url_scans,
        "safe_url_count": safe_url_count,

        "total_file_scans": total_file_scans,
        "safe_file_count": safe_file_count,

        "url_verdict_distribution": url_verdict_counts,
        "ids_severity_distribution": ids_severity_counts,

        "total_threats_detected": total_threats_detected,

        "traffic_trend": traffic_trend,
        "recent_activity": recent_activity,
        "live_alerts": live_alerts,
    }
