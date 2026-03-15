# backend/app/schemas/urlscan_schema.py

from pydantic import BaseModel, HttpUrl
from typing import Optional, Dict, Any, List
from datetime import datetime


# ------------------------------
# Input Request
# ------------------------------
class URLScanRequest(BaseModel):
    url: HttpUrl


# ------------------------------
# Base shared fields
# ------------------------------
class URLScanBase(BaseModel):
    target_url: str
    ml_verdict: Optional[str] = None
    ml_score: Optional[float] = None
    final_verdict: Optional[str] = None

    class Config:
        from_attributes = True


# ------------------------------
# Full Response (Details + PDF)
# ------------------------------
class URLScanResponse(URLScanBase):
    id: int
    scan_time: datetime

    urlhaus_status: Optional[str] = None
    vt_details: Optional[Dict[str, Any]] = None

    resolved_ip: Optional[str] = None
    http_status_code: Optional[int] = None
    url_reachable: Optional[bool] = None


    # ⭐ LIST of DICTS (MUST MATCH DB)
    mitre_techniques: Optional[List[Dict[str, Any]]] = None

    engine_results: Optional[Dict[str, Any]] = None

    ai_summary: Optional[str] = None
    ai_full: Optional[str] = None

    theme_color: Optional[str] = None
    theme_icon: Optional[str] = None


# ------------------------------
# History Table Response
# ------------------------------
class URLScanHistory(URLScanBase):
    id: int
    scan_time: datetime

    urlhaus_status: Optional[str] = None
    vt_details: Optional[Dict[str, Any]] = None

    resolved_ip: Optional[str] = None
    http_status_code: Optional[int] = None
    url_reachable: Optional[bool] = None

    mitre_techniques: Optional[List[Dict[str, Any]]] = None

    engine_results: Optional[Dict[str, Any]] = None
