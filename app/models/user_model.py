from typing import Optional
from datetime import datetime
from sqlmodel import Field, SQLModel


class User(SQLModel, table=True):
    """
    Represents a user in the application.
    Stores authentication credentials, profile information,
    analyst metadata, and external API keys.
    """

    # -------------------------------------------------
    # PRIMARY KEY
    # -------------------------------------------------
    id: Optional[int] = Field(default=None, primary_key=True)

    # -------------------------------------------------
    # AUTHENTICATION FIELDS
    # -------------------------------------------------
    username: str = Field(
        index=True,
        unique=True,
        min_length=3,
        max_length=50,
        description="Unique username for login"
    )

    email: str = Field(
        index=True,
        unique=True,
        description="User email address"
    )

    hashed_password: str

    is_active: bool = Field(
        default=True,
        description="Indicates if the user account is active"
    )

    is_superuser: bool = Field(
        default=False,
        description="Admin / superuser flag"
    )

    # -------------------------------------------------
    # PROFILE INFORMATION (EDITABLE FROM PROFILE PAGE)
    # -------------------------------------------------
    full_name: Optional[str] = Field(
        default=None,
        description="Full display name of the user"
    )

    role: str = Field(
        default="SOC Analyst (Tier-1)",
        description="User role / designation"
    )

    location: str = Field(
        default="India",
        description="User geographic location"
    )

    threat_exposure: str = Field(
        default="Moderate",
        description="Risk exposure level: Low | Moderate | High"
    )

    avatar_url: Optional[str] = Field(
        default=None,
        description="Profile image URL or file path"
    )

    # -------------------------------------------------
    # AUDIT FIELDS
    # -------------------------------------------------
    created_at: datetime = Field(
        default_factory=datetime.utcnow,
        nullable=False
    )

    last_login_at: Optional[datetime] = Field(
        default=None,
        description="Last login timestamp"
    )

    # -------------------------------------------------
    # EXTERNAL API KEYS (USER-OWNED)
    # -------------------------------------------------
    # ⚠️ In production, encrypt these values
    custom_apivoid_key: Optional[str] = Field(
        default=None,
        description="User-provided APIVoid API key"
    )

    custom_ipqs_key: Optional[str] = Field(
        default=None,
        description="User-provided IPQualityScore API key"
    )

    # -------------------------------------------------
    # CONFIG
    # -------------------------------------------------
    class Config:
        schema_extra = {
            "example": {
                "username": "cyber_analyst",
                "email": "analyst@example.com",
                "hashed_password": "hashed_secret_password",
                "full_name": "Dark Hunter",
                "role": "SOC Analyst (Tier-1)",
                "location": "India",
                "threat_exposure": "Moderate",
            }
        }
