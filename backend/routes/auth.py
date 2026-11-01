"""Authentication routes for Google OAuth 2.0 login, signup, sessions, and logout."""

import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Response, Query, status
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.config import settings
from backend.models import User, GmailConnection
from backend.services.auth_service import (
    create_user_session,
    get_user_from_session_token,
    invalidate_user_session,
    set_session_cookie,
    clear_session_cookie,
    get_current_user,
)
from backend.services.google_auth import (
    get_login_authorization_url,
    validate_oauth_state,
    exchange_code_for_tokens,
    get_google_user_info,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/auth", tags=["Authentication"])


@router.get("/google/login", summary="Initiate Google OAuth 2.0 login or signup")
def google_login(db: Session = Depends(get_db)):
    """Generate CSRF-protected state and redirect user to Google's sign-in screen."""
    if not settings.is_google_oauth_configured:
        # Redirect to login page with clear notification instead of raw JSON error
        return RedirectResponse(url="/login?error=credentials_needed", status_code=status.HTTP_303_SEE_OTHER)
    auth_url = get_login_authorization_url(db)
    return RedirectResponse(url=auth_url, status_code=status.HTTP_307_TEMPORARY_REDIRECT)


@router.get("/demo-login", summary="Quick Development / Demo Authentication")
def demo_login(response: Response, db: Session = Depends(get_db)):
    """Logs in with a demo security analyst account for local testing before Google Cloud is configured."""
    demo_sub = "mailguard-demo-user-sub-001"
    user = db.query(User).filter(User.google_sub == demo_sub).first()
    if not user:
        user = User(
            google_sub=demo_sub,
            email="demo.analyst@gmail.com",
            name="Demo Security Analyst",
            picture=None,
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    # Automatically attach demo Gmail connection
    from backend.services.crypto import encrypt_token
    conn = db.query(GmailConnection).filter(GmailConnection.user_id == user.id).first()
    if not conn:
        conn = GmailConnection(
            user_id=user.id,
            gmail_address="demo.analyst@gmail.com",
            encrypted_refresh_token=encrypt_token("demo_refresh_token"),
            access_token="demo_access_token",
            status="connected",
        )
        db.add(conn)
        db.commit()

    session_token = create_user_session(db, user)
    redirect = RedirectResponse(url="/?login_success=1", status_code=status.HTTP_303_SEE_OTHER)
    set_session_cookie(redirect, session_token)
    return redirect


@router.get("/google/callback", summary="Google OAuth 2.0 callback endpoint")
async def google_callback(
    response: Response,
    code: Optional[str] = Query(None, description="Google authorization code"),
    state: Optional[str] = Query(None, description="OAuth state parameter"),
    error: Optional[str] = Query(None, description="OAuth error code"),
    db: Session = Depends(get_db),
):
    """Handle callback from Google, verify identity, create session, and redirect to dashboard."""
    if error:
        logger.warning(f"Google login returned error: {error}")
        return RedirectResponse(url=f"/login?error={error}", status_code=status.HTTP_303_SEE_OTHER)

    if not code or not state:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing code or state parameter.")

    # 1. Validate CSRF state
    state_record = validate_oauth_state(db, state_token=state, expected_flow="login")
    if not state_record:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired OAuth state parameter.")

    try:
        # 2. Exchange code for tokens
        token_data = await exchange_code_for_tokens(code, redirect_uri=settings.GOOGLE_REDIRECT_URI)
        access_token = token_data.get("access_token")
        if not access_token:
            raise ValueError("No access token in Google token response.")

        # 3. Retrieve verified Google profile
        user_info = await get_google_user_info(access_token)
        google_sub = user_info.get("sub")
        email = user_info.get("email")
        name = user_info.get("name")
        picture = user_info.get("picture")

        if not google_sub or not email:
            raise ValueError("Google userinfo did not contain verified sub or email.")

        # 4. Find or create user (enforcing uniqueness on google_sub)
        user = db.query(User).filter(User.google_sub == google_sub).first()
        if not user:
            # Check by email to prevent duplicate accounts
            user = db.query(User).filter(User.email == email).first()
            if user:
                user.google_sub = google_sub
            else:
                user = User(
                    google_sub=google_sub,
                    email=email,
                    name=name,
                    picture=picture,
                )
                db.add(user)
                db.commit()
                db.refresh(user)
        else:
            # Update latest profile details
            user.name = name or user.name
            user.picture = picture or user.picture
            db.commit()

        # 5. Create server-side session and set HttpOnly cookie
        session_token = create_user_session(db, user)
        redirect = RedirectResponse(url="/?login_success=1", status_code=status.HTTP_303_SEE_OTHER)
        set_session_cookie(redirect, session_token)
        return redirect

    except Exception as exc:
        logger.error(f"Failed in Google login callback: {exc}", exc_info=True)
        return RedirectResponse(url="/login?error=auth_failed", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/me", summary="Get currently authenticated user profile")
def get_me(request: Request, db: Session = Depends(get_db)):
    """Fetch current user identity and Gmail connection status."""
    token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    user = get_user_from_session_token(db, token)
    if not user:
        return {"authenticated": False, "user": None}

    conn = db.query(GmailConnection).filter(GmailConnection.user_id == user.id).first()
    return {
        "authenticated": True,
        "user": {
            "id": user.id,
            "email": user.email,
            "name": user.name or user.email.split("@")[0],
            "picture": user.picture,
            "created_at": user.created_at,
        },
        "gmail": {
            "connected": bool(conn and conn.status == "connected"),
            "email": conn.gmail_address if conn else None,
            "status": conn.status if conn else "not_connected",
            "last_sync": conn.last_sync_at if conn else None,
        },
    }


@router.post("/logout", summary="Log out authenticated user")
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    """Invalidate server-side session and remove session cookie."""
    token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    invalidate_user_session(db, token)
    clear_session_cookie(response)
    return {"status": "success", "message": "Logged out successfully."}
