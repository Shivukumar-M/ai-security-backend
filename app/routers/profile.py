from fastapi import APIRouter, HTTPException, status, UploadFile, File
from typing import Dict, Any
from pathlib import Path
import uuid

from app.dependencies import DBSession, CurrentUser
from app.schemas.user_schema import (
    UserResponse,
    UserUpdate,
    PasswordChange,
)
from app.security import verify_password, get_password_hash
from app.routers.dashboard import get_dashboard_metrics

router = APIRouter(
    prefix="/profile",
    tags=["User Profile & Security"]
)

# Create avatars directory if it doesn't exist
AVATARS_DIR = Path("app/media/avatars")
AVATARS_DIR.mkdir(parents=True, exist_ok=True)

# ============================================================
# GET PROFILE
# ============================================================
@router.get("/me", response_model=UserResponse)
def get_my_profile(current_user: CurrentUser):
    return current_user


# ============================================================
# UPDATE PROFILE
# ============================================================
@router.put("/me", response_model=UserResponse)
def update_my_profile(
    payload: UserUpdate,
    db: DBSession,
    current_user: CurrentUser,
):
    """Update user profile (name, role, location, threat_exposure)"""
    
    if payload.full_name is not None:
        current_user.full_name = payload.full_name

    if payload.role is not None:
        current_user.role = payload.role

    if payload.location is not None:
        current_user.location = payload.location

    if payload.threat_exposure is not None:
        current_user.threat_exposure = payload.threat_exposure

    db.add(current_user)
    db.commit()
    db.refresh(current_user)

    return current_user


# ============================================================
# UPLOAD AVATAR
# ============================================================
@router.post("/avatar", response_model=UserResponse)
async def upload_avatar(
    db: DBSession,
    current_user: CurrentUser,
    file: UploadFile = File(...),
):
    """Upload user avatar image"""
    
    # Validate file type
    allowed_types = {"image/jpeg", "image/png", "image/gif", "image/webp"}
    if file.content_type not in allowed_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only JPEG, PNG, GIF, and WebP images are allowed"
        )
    
    # Validate file size (max 5MB)
    max_size = 5 * 1024 * 1024
    content = await file.read()
    if len(content) > max_size:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File size must not exceed 5MB"
        )
    
    # Delete old avatar file if exists
    if current_user.avatar_url:
        old_name = Path(current_user.avatar_url).name
        old_path = AVATARS_DIR / old_name
        if old_path.exists():
            try:
                old_path.unlink()
            except Exception:
                pass
    
    # Generate filename
    safe_name = Path(file.filename).name.replace(" ", "_")
    filename = f"{current_user.id}_{uuid.uuid4().hex}_{safe_name}"
    filepath = AVATARS_DIR / filename
    
    # Save file
    try:
        filepath.write_bytes(content)
        avatar_url = f"/api/media/avatars/{filename}"
        current_user.avatar_url = avatar_url
        
        db.add(current_user)
        db.commit()
        db.refresh(current_user)
        
        return current_user
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to save avatar: {str(e)}"
        )


# ============================================================
# CHANGE PASSWORD
# ============================================================
@router.put("/change-password")
def change_password(
    payload: PasswordChange,
    db: DBSession,
    current_user: CurrentUser,
):
    if not verify_password(payload.current_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )

    current_user.hashed_password = get_password_hash(payload.new_password)
    db.add(current_user)
    db.commit()

    return {"message": "Password updated successfully"}


# ============================================================
# SECURITY SUMMARY (FROM DASHBOARD)
# ============================================================
@router.get("/security-summary", response_model=Dict[str, Any])
def get_profile_security_summary(
    db: DBSession,
    current_user: CurrentUser,
):
    metrics = get_dashboard_metrics(db=db, current_user=current_user)

    ids_events = sum(metrics.get("ids_severity_distribution", {}).values())
    total_threats = metrics.get("total_threats_detected", 0)

    if total_threats == 0:
        exposure = "Minimal"
    elif total_threats <= 3:
        exposure = "Low"
    elif total_threats <= 10:
        exposure = "Moderate"
    else:
        exposure = "High"

    return {
        "urls_scanned": metrics.get("total_url_scans", 0),
        "files_scanned": metrics.get("total_file_scans", 0),
        "ids_events": ids_events,
        "total_threats": total_threats,
        "exposure_level": exposure,
        "recent_activity": metrics.get("recent_activity", [])[:3],
        "live_alert_count": len(metrics.get("live_alerts", [])),
    }
