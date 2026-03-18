# backend/app/schemas/user_schema.py
from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime

# --- Base Schema ---
class UserBase(BaseModel):
    """Base Pydantic model for User data."""
    username: str
    email: EmailStr
    full_name: Optional[str] = None

# --- Create Schema ---
class UserCreate(UserBase):
    """Schema for creating a new user (requires password)."""
    password: str

# --- Response Schema ---
class UserResponse(UserBase):
    """Schema for user response (excludes password)."""
    id: int
    is_active: bool
    is_superuser: bool
    role: Optional[str] = None
    location: Optional[str] = None
    threat_exposure: Optional[str] = None
    avatar_url: Optional[str] = None
    created_at: datetime
    last_login_at: Optional[datetime] = None

    class Config:
        from_attributes = True # Allows ORM model conversion

# --- Update Schema (Optional) ---
class UserUpdate(BaseModel):
    """Schema for updating user details."""
    full_name: Optional[str] = None
    role: Optional[str] = None
    location: Optional[str] = None
    threat_exposure: Optional[str] = None

# --- Password Change Schema ---
class PasswordChange(BaseModel):
    current_password: str
    new_password: str