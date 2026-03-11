# backend/app/models/apikeys_model.py
from typing import Optional
from datetime import datetime
from sqlmodel import Field, SQLModel

class APIKey(SQLModel, table=True):
    """
    Stores user-provided external API keys, linked to the User model.
    NOTE: In a production system, these keys MUST be encrypted at rest.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(unique=True, foreign_key="user.id") # One-to-one relationship with User
    
    # --- API Key Storage ---
    apivoid_key: Optional[str] = None
    ipqs_key: Optional[str] = None
    gsb_key: Optional[str] = None
    
    # --- Audit ---
    last_updated: datetime = Field(default_factory=datetime.utcnow, nullable=False)
    
    class Config:
        schema_extra = {
            "example": {
                "user_id": 1,
                "apivoid_key": "user_api_key_12345",
            }
        }