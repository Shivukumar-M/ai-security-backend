"""
Security utilities for password hashing and verification.
Used by auth, profile, and user management.
"""

from passlib.context import CryptContext

# --------------------------------------------------
# PASSWORD CONTEXT
# --------------------------------------------------
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)

# --------------------------------------------------
# HASH PASSWORD
# --------------------------------------------------
def get_password_hash(password: str) -> str:
    """
    Hash a plain-text password using bcrypt.
    """
    return pwd_context.hash(password)

# --------------------------------------------------
# VERIFY PASSWORD
# --------------------------------------------------
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain password against a hashed password.
    """
    return pwd_context.verify(plain_password, hashed_password)
