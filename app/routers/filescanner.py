# backend/app/routers/filescanner.py

from fastapi import (
    APIRouter,
    UploadFile,
    File,
    HTTPException,
    BackgroundTasks
)
import hashlib
import logging
import math
from datetime import datetime
from collections import Counter

from app.dependencies import DBSession, CurrentUser
from app.services.virustotal_service import VirusTotalService
from app.models.filescan_model import FileScanResult

# RAG ENGINE (Gemini+OpenAI hybrid)
from app.rag_engine.rag_utils import RAGUtility

router = APIRouter(prefix="/filescan", tags=["File Malware Scanner"])

vt_service = VirusTotalService()
rag_engine = RAGUtility()

logger = logging.getLogger(__name__)


# ============================================================
# LOCAL STATIC ANALYSIS
# ============================================================
def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = Counter(data)
    entropy = 0.0
    for count in freq.values():
        p = count / len(data)
        entropy -= p * math.log2(p)
    return entropy


SUSPICIOUS_KEYWORDS = [
    b"GetAsyncKeyState", b"SetWindowsHookEx", b"CreateRemoteThread",
    b"SendInput", b"keylogger", b"keystroke", b"keyboard_event",
    b"OpenProcess", b"WriteProcessMemory", b"ReadProcessMemory",
    b"AutoHotkey", b"shellcode", b"WM_KEYDOWN", b"VirtualAllocEx",
    b"RegisterHotKey", b"InternetOpen", b"InternetOpenUrl"
]


def local_static_analysis(content: bytes):
    """Detect malware patterns instantly."""
    entropy = shannon_entropy(content)

    found = []
    lower = content.lower()
    for kw in SUSPICIOUS_KEYWORDS:
        if kw.lower() in lower:
            found.append(kw.decode(errors="ignore"))

    malicious = (entropy > 7.4) or len(found) > 0

    return {
        "category": "malicious" if malicious else "harmless",
        "result": "malicious" if malicious else "clean",
        "details": {
            "entropy": round(entropy, 3),
            "suspicious_strings": found,
            "reason": (
                "High entropy or suspicious code patterns detected"
                if malicious else "No suspicious patterns detected"
            )
        }
    }


# ============================================================
# BACKGROUND VT LOOKUP
# ============================================================
async def vt_background(scan_id: str, sha256: str, db):
    """Refresh VT results without slowing down the UI."""
    try:
        vt = await vt_service.scan_file_hash(sha256)
        if not vt:
            return

        scan = db.get(FileScanResult, scan_id)
        if not scan:
            return

        # merge engines
        for engine, data in vt.get("engine_results", {}).items():
            scan.engine_results[engine] = data

        scan.malicious_count += vt.get("malicious_count", 0)
        scan.total_engines = max(scan.total_engines, vt.get("total_engines", 0))
        scan.vt_ready = True

        db.add(scan)
        db.commit()

        logger.info(f"[VT] Updated VT results for {scan_id}")

    except Exception as e:
        logger.error(f"[VT BACKGROUND ERROR] {e}")


# ============================================================
# POST /filescan  — MAIN FAST SCAN
# ============================================================
@router.post("/")
async def scan_file(
    background: BackgroundTasks,
    db: DBSession,
    current_user: CurrentUser,
    file: UploadFile = File(...)
):
    content = await file.read()
    if not content:
        raise HTTPException(400, "Empty file")

    sha256 = hashlib.sha256(content).hexdigest()

    # 🔥 UNIQUE ID FIX (prevents duplicate PK errors)
    unique_id = f"{sha256}-{int(datetime.utcnow().timestamp() * 1000)}"

    # ---------- Local instant analysis ----------
    local = local_static_analysis(content)

    scan = FileScanResult(
        id=unique_id,          # ⭐ unique
        user_id=current_user.id,
        filename=file.filename,
        hash=sha256,
        file_size=len(content),
        verdict="Malicious" if local["category"] == "malicious" else "Suspicious",
        malicious_count=1 if local["category"] == "malicious" else 0,
        total_engines=1,
        type_description=local["details"]["reason"],
        engine_results={"LocalStatic": local},
        file_properties={"entropy": local["details"]["entropy"]},
        vt_ready=False,
    )

    db.add(scan)
    db.commit()
    db.refresh(scan)

    # ---------- Background VirusTotal fetch ----------
    background.add_task(vt_background, unique_id, sha256, db)

    # ---------- RAG AI Explanation ----------
    rag_payload = {
        "threat_type": "Malicious File" if local["category"] == "malicious" else "Suspicious File",
        "context_data": {
            "filename": scan.filename,
            "hash": scan.hash,
            "entropy": scan.file_properties["entropy"],
            "local_result": local,
            "verdict": scan.verdict,
            "malicious_count": scan.malicious_count,
        },
    }

    rag = rag_engine.generate_explanation(
        rag_payload["threat_type"],
        rag_payload["context_data"]
    )

    scan.ai_summary = rag.summary
    scan.ai_full = rag.full_explanation
    scan.ai_mitre = [t.model_dump() for t in rag.mitre_techniques]
    scan.ai_theme_icon = getattr(rag, "theme_icon", "🛡")
    scan.ai_theme_color = getattr(rag, "theme_color", "#00eaff")

    db.add(scan)
    db.commit()
    db.refresh(scan)

    # ---------- Instant Response ----------
    return {
        "id": scan.id,
        "filename": scan.filename,
        "hash": scan.hash,
        "vt_ready": scan.vt_ready,
        "analysis": {
            "verdict": scan.verdict,
            "malicious_count": scan.malicious_count,
            "total_engines": scan.total_engines,
            "type_description": scan.type_description,
            "scan_date": scan.scan_date,
            "engine_results": scan.engine_results,
        },
        "ai": {
            "summary": scan.ai_summary,
            "full": scan.ai_full,
            "mitre": scan.ai_mitre,
            "icon": scan.ai_theme_icon,
            "color": scan.ai_theme_color,
        },
    }


# ============================================================
# GET /filescan/{scan_id}
# ============================================================
@router.get("/{scan_id}")
async def get_file(scan_id: str, db: DBSession):
    scan = db.get(FileScanResult, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")

    return {
        "id": scan.id,
        "filename": scan.filename,
        "hash": scan.hash,
        "vt_ready": scan.vt_ready,
        "analysis": {
            "verdict": scan.verdict,
            "malicious_count": scan.malicious_count,
            "total_engines": scan.total_engines,
            "type_description": scan.type_description,
            "scan_date": scan.scan_date,
            "engine_results": scan.engine_results,
        },
        "ai": {
            "summary": scan.ai_summary,
            "full": scan.ai_full,
            "mitre": scan.ai_mitre,
            "icon": scan.ai_theme_icon,
            "color": scan.ai_theme_color,
        },
    }


# ============================================================
# GET /filescan?hash=sha256
# ============================================================
@router.get("")
async def get_file_query(hash: str, db: DBSession):
    # Query by hash returns all scans with same file hash
    results = db.exec(
        FileScanResult.select().where(FileScanResult.hash == hash)
    ).all()

    if not results:
        raise HTTPException(404, "Scan not found")

    return results
