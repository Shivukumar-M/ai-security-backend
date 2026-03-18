# backend/app/models/urlscan_model.py

from typing import Optional, Dict, Any, List
from datetime import datetime
from sqlmodel import SQLModel, Field, Column, JSON


class URLScanResult(SQLModel, table=True):

    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(index=True, foreign_key="user.id")

    target_url: str = Field(index=True, max_length=500)
    scan_time: datetime = Field(default_factory=datetime.utcnow)

    ml_verdict: str
    ml_score: float

    urlhaus_status: Optional[str] = None

    # VirusTotal + enrichment metadata
    vt_details: Dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON)
    )

    # Final decision
    final_verdict: str

    # VT engine results
    engine_results: Dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON)
    )

    # ✅ REQUIRED (you already use this in service + frontend)
    engine_explanations: Dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON)
    )

    # AI fields
    ai_summary: Optional[str] = None
    ai_full: Optional[str] = None

    # UI theme
    theme_color: Optional[str] = None
    theme_icon: Optional[str] = None

    # MITRE techniques
    mitre_techniques: List[Dict[str, Any]] = Field(
        default_factory=list,
        sa_column=Column(JSON)
    )

    # Flags
    vt_ready: bool = Field(default=False)
    explanation_generated_at: Optional[datetime] = None
    rag_explanation_id: Optional[int] = None

    # ✅ METADATA FIELDS (used by Metadata tab)
    resolved_ip: Optional[str] = Field(default=None)
    http_status_code: Optional[int] = None
    url_reachable: bool = Field(default=False)
