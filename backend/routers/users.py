from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from backend.database import get_db
from backend.models import User
from backend.schemas import UserResponse, UserRoleUpdate
from backend.dependencies import require_admin
from backend.utils.helpers import get_logger

logger = get_logger("SentinelDLP.UsersRouter")
router = APIRouter(prefix="/users", tags=["User Management"])

@router.get("", response_model=List[UserResponse])
def list_users(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_admin)
):
    """List all registered system users (Administrator only)."""
    users = db.query(User).offset(skip).limit(limit).all()
    return users

@router.patch("/{user_id}", response_model=UserResponse)
def update_user_role(
    user_id: int,
    update_data: UserRoleUpdate,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_admin)
):
    """Update user role or active status (Administrator only)."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    # Prevent admin from deactivating themselves
    if user.id == admin_user.id and update_data.is_active is False:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot deactivate your own admin account")

    user.role = update_data.role
    if update_data.is_active is not None:
        user.is_active = update_data.is_active
        
    db.commit()
    db.refresh(user)
    logger.info(f"Admin {admin_user.username} updated User {user.username} (role={user.role}, active={user.is_active})")
    return user
