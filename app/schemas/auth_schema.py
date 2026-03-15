# backend/app/schemas/auth_schema.py
from pydantic import BaseModel, EmailStr
from typing import Optional

# --- Request Schemas ---

class UserCreate(BaseModel):
    """Schema for user registration."""
    username: str
    email: EmailStr
    password: str
    full_name: Optional[str] = None
    
class UserLogin(BaseModel):
    """Schema for user login."""
    username: str
    password: str

class Token(BaseModel):
    """Schema for the returned JWT token."""
    access_token: str
    token_type: str = "bearer"

class TokenPayload(BaseModel):
    """Internal schema for decoding JWT payload."""
    sub: Optional[int] = None # User ID
    exp: Optional[int] = None # Expiration timestamp
    
# --- Response Schemas ---

class UserResponse(BaseModel):
    """Schema for returning non-sensitive user data."""
    id: int
    username: str
    email: EmailStr
    full_name: Optional[str] = None
    role: Optional[str] = None
    location: Optional[str] = None
    threat_exposure: Optional[str] = None
    avatar_url: Optional[str] = None
    is_active: bool
    is_superuser: bool
    
    class Config:
        from_attributes = True # Essential for SQLModel compatibility