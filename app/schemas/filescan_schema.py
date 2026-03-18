# backend/app/schemas/filescan_schema.py
from pydantic import BaseModel
from typing import Optional, Dict
from datetime import datetime


class FileScanResponse(BaseModel):
    id: str
    filename: Optional[str]
    hash: str
    verdict: str
    malicious_count: int
    total_engines: int
    type_description: Optional[str]
    scan_date: datetime
    engine_results: Dict
    file_properties: Dict


class FileScanHistory(BaseModel):
    id: str
    filename: Optional[str]
    verdict: str
    scan_date: datetime
