# backend/app/utils/security.py
from datetime import datetime, timedelta, timezone
from typing import Optional

from passlib.context import CryptContext
from jose import jwt, JWTError

from app.config import settings
from app.schemas.auth_schema import TokenPayload
from app.models.user_model import User
from app.schemas.auth_schema import UserResponse

# Passlib setup for password hashing (using bcrypt)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --- Password Hashing Utilities ---

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain password against a hashed password."""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Generates a secure hash for the given password."""
    return pwd_context.hash(password)

# --- JWT Token Utilities ---

def create_access_token(subject: int) -> str:
    """Creates a JWT access token for a given user ID (subject)."""
    # Define token expiration time
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode = {"exp": expire, "sub": str(subject)}
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str) -> Optional[TokenPayload]:
    """Decodes and validates a JWT access token, returning the payload if valid."""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        # Validate payload structure (will raise error if invalid)
        return TokenPayload(**payload)
    except JWTError:
        # If token is invalid (expired, wrong signature, etc.)
        return None