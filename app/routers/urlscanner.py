# backend/app/routers/urlscanner.py

from fastapi import APIRouter, HTTPException
from typing import List
from sqlmodel import select, desc

from app.dependencies import DBSession, CurrentUser
from app.services.url_analyzer import URLAnalyzerService
from app.schemas.urlscan_schema import (
    URLScanRequest,
    URLScanResponse,
    URLScanHistory
)
from app.models.urlscan_model import URLScanResult

from app.rag_engine.rag_utils import RAGUtility

router = APIRouter(prefix="/urlscan", tags=["URL Scanner"])

service = URLAnalyzerService()
rag = RAGUtility()


# -----------------------------------------------------------
# POST /urlscan/
# -----------------------------------------------------------
@router.post("/", response_model=URLScanResponse)
async def scan_url(scan: URLScanRequest, db: DBSession, current_user: CurrentUser):
    try:
        # Run analyzer
        result: URLScanResult = await service.scan_and_analyze(
            url=str(scan.url),
            user_id=current_user.id,
            db=db
        )

        # Build AI context
        context = {
            "url": result.target_url,
            "ml_score": result.ml_score,
            "verdict": result.final_verdict,
            "urlhaus_status": result.urlhaus_status,
            "scan_time": str(result.scan_time),
            "vt_details": result.vt_details,
            "engine_results": result.engine_results,
        }

        # Generate RAG explanation
        ai_output = rag.generate_explanation("URL", context)

        # Store AI fields ONLY
        result.ai_summary = ai_output.summary
        result.ai_full = ai_output.full_explanation

        # ---------- FIX 1: DO NOT overwrite MITRE if RAG gives none ----------
                # ONLY attach MITRE if threat detected
        if result.final_verdict == "Threat Detected":
            rag_mitre = [m.model_dump() for m in ai_output.mitre_techniques]
            if rag_mitre:
                result.mitre_techniques = rag_mitre
        else:
            result.mitre_techniques = []   # 🔥 FORCE EMPTY

        # else: KEEP analyzer MITRE

        # ---------- FIX 2: Save theme but do NOT touch engine_results -----------
        if hasattr(ai_output, "theme_color"):
            result.theme_color = ai_output.theme_color
        if hasattr(ai_output, "theme_icon"):
            result.theme_icon = ai_output.theme_icon

        db.add(result)
        db.commit()
        db.refresh(result)

        return result

    except Exception as e:
        raise HTTPException(500, f"URL scan failed: {e}")


# ===========================================================
# HISTORY
# ===========================================================
@router.get("/history/", response_model=List[URLScanHistory])
def history(db: DBSession, current_user: CurrentUser, limit: int = 50):
    stmt = (
        select(URLScanResult)
        .where(URLScanResult.user_id == current_user.id)
        .order_by(desc(URLScanResult.scan_time))
        .limit(limit)
    )
    return db.exec(stmt).all()


# ===========================================================
# SINGLE SCAN
# ===========================================================
@router.get("/{scan_id}", response_model=URLScanResponse)
def single(scan_id: int, db: DBSession, current_user: CurrentUser):
    scan = db.get(URLScanResult, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan.user_id != current_user.id:
        raise HTTPException(403, "Not authorized")
    return scan


# ===========================================================
# DELETE ONE
# ===========================================================
@router.delete("/delete/{scan_id}")
def delete_one(scan_id: int, db: DBSession, current_user: CurrentUser):
    scan = db.get(URLScanResult, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan.user_id != current_user.id:
        raise HTTPException(403, "Not authorized")

    db.delete(scan)
    db.commit()

    return {"message": f"Scan {scan_id} deleted successfully"}


# ===========================================================
# DELETE ALL
# ===========================================================
@router.delete("/delete_all")
def delete_all(db: DBSession, current_user: CurrentUser):
    scans = db.exec(select(URLScanResult).where(URLScanResult.user_id == current_user.id)).all()

    for scan in scans:
        db.delete(scan)

    db.commit()

    return {"message": "All scans deleted successfully"}
