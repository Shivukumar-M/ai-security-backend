# backend/app/schemas/ids_schema.py

from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime


# -------------------------------------------------
# REQUEST SCHEMA
# -------------------------------------------------

class LogGenerationRequest(BaseModel):
    """Schema for requesting simulated log generation."""
    log_type: str = Field(..., description="Type of logs to generate (DoS, PortScan, Mixed, Normal).")
    record_count: int = Field(..., gt=0, description="Number of log records to generate.")


# -------------------------------------------------
# RESPONSE SCHEMAS
# -------------------------------------------------

class AttackSummary(BaseModel):
    attack_type: str
    count: int
    severity: str


class MitreTechnique(BaseModel):
    tactic: str
    technique_id: str
    technique: str


class IDSScanResponse(BaseModel):
    """Complete schema for returning a single IDS scan result."""
    id: int
    file_name: str
    scan_time: datetime

    # Packet statistics
    total_packets: int
    malicious_packets: int
    normal_packets: int

    overall_severity: str

    # Attack analysis
    attack_breakdown: List[AttackSummary]

    # 🔥 NEW FIELDS (IDS v3)
    mitre_techniques: Optional[List[MitreTechnique]] = []
    confidence: Optional[float] = None
    correlated_attack: Optional[bool] = False

    class Config:
        from_attributes = True


class LogGenerationResponse(BaseModel):
    success: bool = True
    message: str
    file_name: str
    record_count: int
    generation_time: datetime
