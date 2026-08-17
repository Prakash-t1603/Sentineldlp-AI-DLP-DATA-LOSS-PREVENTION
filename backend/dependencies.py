from fastapi import Depends, HTTPException, status, Header, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from typing import Optional, List
from backend.database import get_db
from backend.models import User
from backend.utils.security import decode_access_token
from backend.config import settings

security_bearer = HTTPBearer(auto_error=False)

def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer),
    db: Session = Depends(get_db)
) -> User:
    """Validate Bearer JWT token and return active User."""
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials were not provided",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    payload = decode_access_token(credentials.credentials)
    if not payload or "sub" not in payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    username = payload.get("sub")
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User associated with token no longer exists",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated",
        )
    
    return user


def get_optional_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer),
    token: Optional[str] = None,
    db: Session = Depends(get_db)
) -> Optional[User]:
    """Validate optional Bearer JWT token or query parameter token."""
    raw_token = credentials.credentials if credentials and credentials.credentials else token
    if not raw_token:
        return None
    
    payload = decode_access_token(raw_token)
    if not payload or "sub" not in payload:
        return None
    
    username = payload.get("sub")
    user = db.query(User).filter(User.username == username).first()
    if user and user.is_active:
        return user
    return None


def require_roles(allowed_roles: List[str]):
    """Role-based access control dependency factory."""
    def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Requires one of roles: {', '.join(allowed_roles)}",
            )
        return current_user
    return role_checker

require_admin = require_roles(["admin"])
require_analyst_or_admin = require_roles(["admin", "security_analyst"])


def verify_agent_token(
    x_agent_secret: Optional[str] = Header(None, alias="X-Agent-Secret")
) -> bool:
    """Validate endpoint monitoring agent secret header."""
    if not x_agent_secret or x_agent_secret != settings.AGENT_SECRET_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing Agent authorization secret",
        )
    return True


def get_current_user_or_agent(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer),
    x_agent_secret: Optional[str] = Header(None, alias="X-Agent-Secret"),
    db: Session = Depends(get_db)
) -> Optional[User]:
    """Allows either a valid JWT User or an authorized Endpoint Agent."""
    if x_agent_secret and x_agent_secret == settings.AGENT_SECRET_KEY:
        return None  # Authorized as agent
    
    if credentials and credentials.credentials:
        payload = decode_access_token(credentials.credentials)
        if payload and "sub" in payload:
            user = db.query(User).filter(User.username == payload["sub"]).first()
            if user and user.is_active:
                return user

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Unauthorized. Provide valid JWT Bearer token or Agent secret header",
    )
