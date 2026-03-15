from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlmodel import Session
from typing import Annotated, TypeAlias

from app.database import get_session
from app.models.user_model import User
from app.utils.security import decode_access_token

# OAuth2 token extractor
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")

# Database session annotation
DBSession: TypeAlias = Annotated[Session, Depends(get_session)]



# ------------------------------------------------------------
#  CURRENT USER DEPENDENCY (FULLY FIXED)
# ------------------------------------------------------------
async def get_current_user(
    db: DBSession,
    token: Annotated[str, Depends(oauth2_scheme)]
) -> User:

    # Standard auth error response
    credentials_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"}
    )

    # 1️⃣ Decode token
    payload = decode_access_token(token)
    if payload is None or payload.sub is None:
        raise credentials_error

    user_id = int(payload.sub)

    # 2️⃣ Fetch from DB
    user = db.get(User, user_id)       # ⭐ CORRECT SQLModel usage

    if not user:
        raise credentials_error

    # 3️⃣ Optional: User active check
    if hasattr(user, "is_active") and not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")

    return user


# Shorthand alias
CurrentUser: TypeAlias = Annotated[User, Depends(get_current_user)]
