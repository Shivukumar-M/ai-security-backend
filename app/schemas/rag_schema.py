# ============================================================
# RAG SCHEMA (Dual Engine Support + Severity + Modes)
# ============================================================

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime


# -----------------------------
# MITRE Technique Schema
# -----------------------------
class MITRETechnique(BaseModel):
    id: str
    name: str
    description: Optional[str] = None


# -----------------------------
# Request Schema
# -----------------------------
class RAGExplanationRequest(BaseModel):
    """
    Schema for requesting a threat explanation from RAG.
    """
    threat_type: str = Field(
        ..., 
        description="Example: 'Malicious URL', 'Malicious File', etc."
    )

    context_data: Dict[str, Any] = Field(
        ..., 
        description="Scan metadata (VT results, ML score, file hash, etc.)"
    )

    mode: str = Field(
        default="human",
        description="Explanation style: 'human' (simple) or 'analyst' (deep SOC report)"
    )


# -----------------------------
# Response Schema
# -----------------------------
class RAGExplanationResponse(BaseModel):
    explanation_id: Optional[int] = None         # if you choose to store RAG history later
    generated_at: datetime

    # ⭐ NEW FIELD → 2-LINE SUMMARY FOR UI
    short_summary: str = Field(
        ..., 
        description="Very short 1–2 line summary for UI preview"
    )

    # Long summary (2–3 sentences)
    summary: str

    # Full RAG explanation (long text)
    full_explanation: str

    # Severity score (keep your original requirement)
    severity: int = Field(
        ..., 
        description="0–100 threat severity score"
    )

    # MITRE techniques
    mitre_techniques: List[MITRETechnique] = Field(
        default=[],
        description="List of mapped MITRE ATT&CK techniques"
    )

    class Config:
        from_attributes = True  # For Pydantic v2 ORM support
