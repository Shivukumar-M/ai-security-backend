# backend/app/models/filescan_model.py

from sqlmodel import SQLModel, Field, Column, JSON
from typing import Optional, Dict, Any, List
from datetime import datetime


class FileScanResult(
    SQLModel,
    table=True,
    table_name="file_scan_result"
):
    # -------------------------
    # PRIMARY & BASIC FIELDS
    # -------------------------
    id: str = Field(primary_key=True)  # sha256 or sha256 + timestamp
    user_id: int = Field(foreign_key="user.id")

    filename: Optional[str] = None
    hash: str
    file_size: Optional[int] = None

    verdict: str = "Unknown"
    malicious_count: int = 0
    total_engines: int = 0
    type_description: Optional[str] = None

    scan_date: datetime = Field(default_factory=datetime.utcnow)

    # -------------------------
    # VIRUSTOTAL & LOCAL ANALYSIS
    # -------------------------
    engine_results: Dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON)
    )

    file_properties: Dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON)
    )

    vt_ready: bool = Field(default=False)

    # -------------------------
    # USER NOTES
    # -------------------------
    notes: Optional[str] = None

    # -------------------------
    # ⭐ AI / RAG OUTPUT FIELDS ⭐
    # -------------------------
    ai_summary: Optional[str] = None
    ai_full: Optional[str] = None

    # MITRE techniques stored as list of:
    # [{ "id": "T1055", "name": "Process Injection" }]
    ai_mitre: List[Dict[str, str]] = Field(
        default_factory=list,
        sa_column=Column(JSON)
    )

    ai_theme_icon: Optional[str] = None
    ai_theme_color: Optional[str] = None
