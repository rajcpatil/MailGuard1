"""User authentication, server-side session management, and FastAPI security dependencies."""

import secrets
import logging
from datetime import datetime, timedelta
from typing import Optional

from fastapi import Request, Response, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models import User, UserSession
from backend.config import settings

logger = logging.getLogger(__name__)


def create_user_session(db: Session, user: User) -> str:
    """Create a persistent server-side session for an authenticated user."""
    token = secrets.token_hex(32)
    expires_at = datetime.utcnow() + timedelta(seconds=settings.SESSION_MAX_AGE_SECONDS)

    session_record = UserSession(
        session_token=token,
        user_id=user.id,
        expires_at=expires_at,
        created_at=datetime.utcnow(),
    )
    db.add(session_record)
    user.last_login_at = datetime.utcnow()
    db.commit()
    return token


def get_user_from_session_token(db: Session, token: Optional[str]) -> Optional[User]:
    """Retrieve the user associated with a valid, non-expired session token."""
    if not token:
        return None

    session_record = (
        db.query(UserSession)
        .filter(UserSession.session_token == token, UserSession.expires_at > datetime.utcnow())
        .first()
    )
    if not session_record:
        return None

    return db.query(User).filter(User.id == session_record.user_id, User.is_active == True).first()


def invalidate_user_session(db: Session, token: Optional[str]) -> None:
    """Delete a user session on logout."""
    if not token:
        return
    db.query(UserSession).filter(UserSession.session_token == token).delete()
    db.commit()


def set_session_cookie(response: Response, session_token: str) -> None:
    """Set secure HttpOnly session cookie on response."""
    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=session_token,
        max_age=settings.SESSION_MAX_AGE_SECONDS,
        httponly=True,
        samesite="lax",
        secure=settings.COOKIE_SECURE,
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    """Clear session cookie from user browser."""
    response.delete_cookie(
        key=settings.SESSION_COOKIE_NAME,
        path="/",
        httponly=True,
        samesite="lax",
    )


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    """FastAPI dependency: require an authenticated user or raise 401 Unauthorized."""
    token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    user = get_user_from_session_token(db, token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please log in.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def get_optional_current_user(request: Request, db: Session = Depends(get_db)) -> Optional[User]:
    """FastAPI dependency: return the user if logged in, otherwise None."""
    token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    return get_user_from_session_token(db, token)
