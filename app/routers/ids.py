# backend/app/routers/ids.py

from fastapi import APIRouter, UploadFile, File, HTTPException, Form, Query
from typing import Optional
from sqlmodel import select

from app.dependencies import DBSession, CurrentUser
from app.services.ids_engine import IDSEngineService
from app.schemas.ids_schema import IDSScanResponse
from app.models.idsscan_model import IDSScanResult

import json

router = APIRouter(prefix="/ids", tags=["IDS & Network Analysis"])
ids_engine_service = IDSEngineService()


# ==========================================================
# 1) UPLOAD + ANALYZE LOG FILE (POST /ids/analyze)
# ==========================================================
@router.post("/analyze", response_model=IDSScanResponse)
async def analyze_network_data(
    db: DBSession,                   # dependency first
    current_user: CurrentUser,       # dependency second

    file: Optional[UploadFile] = File(None),
    log_type: Optional[str] = Form(None),
    count: Optional[int] = Form(None)
):
    """Upload CSV log file OR generate logs automatically."""

    # ----------------------------------------------------------------------
    # MODE A — UPLOADED FILE
    # ----------------------------------------------------------------------
    if file and file.filename:
        if not file.filename.lower().endswith(".csv"):
            raise HTTPException(status_code=400, detail="Only CSV files are supported.")
        
        analysis = await ids_engine_service.analyze_uploaded_file(file)
        file_name = file.filename
        source_type = "UPLOADED"

    # ----------------------------------------------------------------------
    # MODE B — AUTO-GENERATED LOG ANALYSIS (Form version)
    # ----------------------------------------------------------------------
    elif log_type:
        count = count or 1000

        analysis = await ids_engine_service.generate_and_analyze(log_type, count)
        file_name = analysis["file_name"]
        source_type = "GENERATED"

    # ----------------------------------------------------------------------
    # MODE C — INVALID REQUEST
    # ----------------------------------------------------------------------
    else:
        raise HTTPException(
            status_code=400,
            detail="Upload a file OR specify log_type for auto-generation."
        )

    # ----------------------------------------------------------------------
    # SAVE SCAN RESULT IN DATABASE
    # ----------------------------------------------------------------------
    entry = IDSScanResult(
        user_id=current_user.id,
        source_type=source_type,
        file_name=file_name,
        file_path=analysis.get("file_path"),
        total_packets=analysis["total_packets"],
        malicious_packets=analysis["malicious_packets"],
        normal_packets=analysis["normal_packets"],
        overall_severity=analysis["overall_severity"],
        attack_type_summary=json.dumps(analysis["attack_breakdown"]),
        engine_results=json.dumps(analysis["engine_results"]),  # 🔥 ADD THIS

    )

    db.add(entry)
    db.commit()
    db.refresh(entry)

    return IDSScanResponse(
        id=entry.id,
        file_name=entry.file_name,
        scan_time=entry.scan_time,
        total_packets=entry.total_packets,
        malicious_packets=entry.malicious_packets,
        normal_packets=entry.normal_packets,
        overall_severity=entry.overall_severity,
        attack_breakdown=analysis["attack_breakdown"],

        # 🔥 MUST PASS THESE AS LISTS
        engine_results=analysis.get("engine_results", []),
        mitre_techniques=analysis.get("mitre_techniques", []),
        confidence=None,
        correlated_attack=False,
    )



# ==========================================================
# 2) AUTO-GENERATE LOGS (GET /ids/generate)
# ==========================================================
@router.get("/generate")
async def generate_logs(
    db: DBSession,                       # MUST BE FIRST
    current_user: CurrentUser,           # MUST BE SECOND
    type: str = Query(..., description="Mixed, DoS, PortScan, Normal"),
    count: int = Query(1000)
):
    
    """
    Generate synthetic IDS logs for testing/training.
    Example:
    GET /ids/generate?type=Mixed&count=1000
    """
    summary = await ids_engine_service.generate_and_analyze(type, count)
    return summary


# ==========================================================
# 3) HISTORY (GET /ids/history)
# ==========================================================
@router.get("/history")
def get_ids_history(db: DBSession, current_user: CurrentUser):
    scans = db.exec(
        select(IDSScanResult)
        .where(IDSScanResult.user_id == current_user.id)
        .order_by(IDSScanResult.scan_time.desc())
    ).all()

    # REBUILD full result for frontend
    full_history = []
    for s in scans:
        full_history.append({
            "id": s.id,
            "file_name": s.file_name,
            "scan_time": s.scan_time,
            "total_packets": s.total_packets,
            "malicious_packets": s.malicious_packets,
            "normal_packets": s.normal_packets,
            "overall_severity": s.overall_severity,
            "attack_breakdown": json.loads(s.attack_type_summary or "[]"),
            "engine_results": json.loads(s.engine_results or "[]"),
            "mitre_techniques": json.loads(s.mitre_techniques or "[]"),
            "source_type": s.source_type,
            "file_path": s.file_path,
        })

    return full_history


@router.delete("/delete/{scan_id}")
def delete_scan(scan_id: int, db: DBSession, current_user: CurrentUser):
    scan = db.get(IDSScanResult, scan_id)

    if not scan or scan.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Scan not found")

    db.delete(scan)
    db.commit()
    return {"message": "Scan deleted"}


@router.delete("/delete_all")
def delete_all_scans(db: DBSession, current_user: CurrentUser):
    scans = db.exec(
        select(IDSScanResult).where(IDSScanResult.user_id == current_user.id)
    ).all()

    for scan in scans:
        db.delete(scan)

    db.commit()
    return {"message": "All scans cleared"}
