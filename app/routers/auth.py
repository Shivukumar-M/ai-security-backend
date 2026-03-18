# backend/app/routers/auth.py
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import select, Session # Need Session for explicit annotation
from typing import Annotated # Need Annotated for explicit dependency injection

# Import required base dependencies (get_session and CurrentUser)
from app.dependencies import get_session, CurrentUser 

from app.utils.security import get_password_hash, verify_password, create_access_token
from app.models.user_model import User
from app.schemas.auth_schema import UserCreate, Token, UserResponse

router = APIRouter(prefix="/auth", tags=["Authentication"])

# --- Define the explicit dependency type for readability and stability ---
# We use this local alias for cleaner function signatures below
DatabaseDep = Annotated[Session, Depends(get_session)]

# --- User Registration Endpoint ---
@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
# FIX: Use the explicit Annotated dependency definition
def register_user(user_in: UserCreate, db: DatabaseDep): 
    # Check if user already exists
    existing_user = db.exec(
        select(User).where((User.username == user_in.username) | (User.email == user_in.email))
    ).first()
    
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already registered."
        )

    # Hash the password
    hashed_password = get_password_hash(user_in.password)
    
    # Create the User model instance
    db_user = User(
        username=user_in.username,
        email=user_in.email,
        full_name=user_in.full_name,
        hashed_password=hashed_password
    )
    
    # Save to database
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    return db_user

# --- User Login Endpoint (Token Generation) ---
@router.post("/token", response_model=Token)
def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: DatabaseDep
):
    # form_data.username holds the email address submitted from the login form
    user = db.exec(select(User).where(User.email == form_data.username)).first()

    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User is inactive"
        )
    
    # Generate the access token using the user's ID as the subject
    access_token = create_access_token(subject=user.id)
    
    return {"access_token": access_token, "token_type": "bearer"}

# --- Protected Endpoint Example (Get Current User) ---
@router.get("/me", response_model=UserResponse)
def read_users_me(current_user: CurrentUser):
    """Get the currently logged-in user's details."""
    return current_user