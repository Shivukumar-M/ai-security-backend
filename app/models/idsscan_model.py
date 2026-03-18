from typing import Optional
from datetime import datetime
from sqlmodel import Field, SQLModel


class IDSScanResult(SQLModel, table=True):
    """
    Stores the summary result of an IDS analysis
    (uploaded logs or generated traffic).
    """

    # -------------------------------------------------
    # Primary & Relations
    # -------------------------------------------------
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(index=True, foreign_key="user.id")

    # -------------------------------------------------
    # Source Metadata
    # -------------------------------------------------
    source_type: str = Field(
        max_length=20,
        description="UPLOADED or GENERATED"
    )

    # -------------------------------------------------
    # File & Time
    # -------------------------------------------------
    file_name: str = Field(max_length=255)
    file_path: Optional[str] = Field(default=None, max_length=500)
    scan_time: datetime = Field(default_factory=datetime.utcnow, nullable=False)

    # -------------------------------------------------
    # Packet Statistics
    # -------------------------------------------------
    total_packets: int
    malicious_packets: int
    normal_packets: int

    # -------------------------------------------------
    # Analysis Results (Stored as JSON strings)
    # -------------------------------------------------
    attack_type_summary: str = Field(
        description="JSON string of attack breakdown"
    )

    engine_results: Optional[str] = Field(
        default=None,
        description="JSON string of detection engine results"
    )

    mitre_techniques: Optional[str] = Field(
        default=None,
        description="JSON string of MITRE ATT&CK mappings"
    )

    # -------------------------------------------------
    # Severity
    # -------------------------------------------------
    overall_severity: str = Field(
        max_length=20,
        description="Low / Medium / High / Critical"
    )

    class Config:
        schema_extra = {
            "example": {
                "user_id": 1,
                "source_type": "UPLOADED",
                "file_name": "network_log_20231026.csv",
                "file_path": "/media/uploads/network_log_20231026.csv",
                "total_packets": 10000,
                "malicious_packets": 170,
                "normal_packets": 9830,
                "overall_severity": "High",
                "attack_type_summary": "[{'attack_type': 'SQL Injection', 'count': 120, 'severity': 'High'}]",
                "engine_results": "[{'engine': 'ML Behavior Engine', 'verdict': 'Malicious', 'score': 0.87}]",
                "mitre_techniques": "[{'tactic': 'Initial Access', 'technique_id': 'T1190', 'technique': 'Exploit Public-Facing Application'}]"
            }
        }
