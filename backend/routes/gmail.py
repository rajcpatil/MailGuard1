"""Gmail integration routes for connecting, disconnecting, and scanning Gmail mailboxes."""

import logging
from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import RedirectResponse
from sqlalchemy import desc
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.config import settings
from backend.models import User, GmailConnection
from backend.services.auth_service import get_current_user, get_optional_current_user
from backend.services.crypto import encrypt_token, decrypt_token
from backend.services.google_auth import (
    get_gmail_authorization_url,
    validate_oauth_state,
    exchange_code_for_tokens,
    get_google_user_info,
    revoke_google_token,
)
from backend.services.gmail_service import scan_user_gmail

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/gmail", tags=["Gmail Integration"])


@router.get("/connect", summary="Initiate Gmail read-only authorization flow")
def connect_gmail(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Start OAuth 2.0 flow requesting gmail.readonly permission for the authenticated user."""
    if not settings.is_google_oauth_configured:
        # Enable demo connection for local development testing
        conn = db.query(GmailConnection).filter(GmailConnection.user_id == user.id).first()
        if not conn:
            conn = GmailConnection(
                user_id=user.id,
                gmail_address=user.email,
                encrypted_refresh_token=encrypt_token("demo_refresh_token"),
                access_token="demo_access_token",
                status="connected",
                connected_at=datetime.utcnow(),
            )
            db.add(conn)
        else:
            conn.status = "connected"
            conn.gmail_address = user.email
        db.commit()
        return RedirectResponse(url="/?gmail_connected=1", status_code=status.HTTP_303_SEE_OTHER)

    auth_url = get_gmail_authorization_url(db, user_id=user.id)
    return RedirectResponse(url=auth_url, status_code=status.HTTP_307_TEMPORARY_REDIRECT)


@router.get("/callback", summary="Gmail OAuth 2.0 authorization callback")
async def gmail_callback(
    code: Optional[str] = Query(None, description="Google authorization code"),
    state: Optional[str] = Query(None, description="OAuth state parameter"),
    error: Optional[str] = Query(None, description="OAuth error code"),
    db: Session = Depends(get_db),
):
    """Validate Gmail authorization response, encrypt refresh token, and link to user account."""
    if error:
        logger.warning(f"Gmail authorization returned error: {error}")
        return RedirectResponse(url=f"/?gmail_error={error}", status_code=status.HTTP_303_SEE_OTHER)

    if not code or not state:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing code or state parameter.")

    # 1. Validate state and retrieve associated user_id
    state_record = validate_oauth_state(db, state_token=state, expected_flow="gmail")
    if not state_record or not state_record.user_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired OAuth state for Gmail.")

    user_id = state_record.user_id
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User account not found.")

    try:
        # 2. Exchange authorization code for tokens
        token_data = await exchange_code_for_tokens(code, redirect_uri=settings.GOOGLE_GMAIL_REDIRECT_URI)
        access_token = token_data.get("access_token")
        refresh_token = token_data.get("refresh_token")
        expires_in = token_data.get("expires_in", 3600)

        # 3. Get profile email to detect account mismatch
        user_info = await get_google_user_info(access_token)
        gmail_address = user_info.get("email") or user.email

        # 4. Encrypt refresh token before at-rest SQLite storage
        encrypted_refresh = encrypt_token(refresh_token) if refresh_token else None

        # 5. Upsert GmailConnection record
        conn = db.query(GmailConnection).filter(GmailConnection.user_id == user.id).first()
        if not conn:
            conn = GmailConnection(
                user_id=user.id,
                gmail_address=gmail_address,
                encrypted_refresh_token=encrypted_refresh,
                access_token=access_token,
                token_expiry=datetime.utcnow() + timedelta(seconds=expires_in),
                status="connected",
                connected_at=datetime.utcnow(),
            )
            db.add(conn)
        else:
            conn.gmail_address = gmail_address
            if encrypted_refresh:
                conn.encrypted_refresh_token = encrypted_refresh
            conn.access_token = access_token
            conn.token_expiry = datetime.utcnow() + timedelta(seconds=expires_in)
            conn.status = "connected"
            conn.connected_at = datetime.utcnow()

        db.commit()
        logger.info(f"Gmail account {gmail_address} connected for user_id={user.id}")
        return RedirectResponse(url="/?gmail_connected=1", status_code=status.HTTP_303_SEE_OTHER)

    except Exception as exc:
        logger.error(f"Failed to process Gmail callback: {exc}", exc_info=True)
        return RedirectResponse(url="/?gmail_error=connection_failed", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/status", summary="Check Gmail connection status for authenticated user")
def get_gmail_status(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Return whether the current user has connected their Gmail account."""
    conn = db.query(GmailConnection).filter(GmailConnection.user_id == user.id).first()
    if not conn or conn.status != "connected":
        return {
            "connected": False,
            "status": conn.status if conn else "not_connected",
            "email": None,
            "last_sync": None,
        }

    return {
        "connected": True,
        "status": conn.status,
        "email": conn.gmail_address,
        "last_sync": conn.last_sync_at,
    }


@router.post("/disconnect", summary="Disconnect Gmail and revoke OAuth access")
async def disconnect_gmail(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Revoke Google permissions, delete stored tokens, and set status to disconnected."""
    conn = db.query(GmailConnection).filter(GmailConnection.user_id == user.id).first()
    if not conn:
        return {"status": "success", "message": "Gmail was not connected."}

    # Revoke with Google servers
    raw_refresh = decrypt_token(conn.encrypted_refresh_token) if conn.encrypted_refresh_token else None
    token_to_revoke = raw_refresh or conn.access_token
    if token_to_revoke:
        await revoke_google_token(token_to_revoke)

    # Delete connection record
    db.delete(conn)
    db.commit()
    return {"status": "success", "message": "Gmail disconnected successfully and tokens deleted."}


@router.post("/scan", summary="Fetch and scan recent Gmail emails for threats")
def scan_my_gmail(
    max_results: int = Query(25, ge=1, le=100, description="Number of recent messages to analyze"),
    user: Optional[User] = Depends(get_optional_current_user),
    db: Session = Depends(get_db),
):
    """Retrieve recent emails from user's authorized Gmail account and run threat detection."""
    effective_user = user
    if not effective_user:
        active_conn = (
            db.query(GmailConnection)
            .filter(
                GmailConnection.status == "connected",
                GmailConnection.access_token != "demo_access_token",
                GmailConnection.access_token != "demo_token",
            )
            .order_by(desc(GmailConnection.connected_at))
            .first()
        )
        if active_conn:
            effective_user = db.query(User).filter(User.id == active_conn.user_id).first()

    if not effective_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please connect your Gmail account.",
        )

    try:
        result = scan_user_gmail(db, effective_user, max_results=max_results)
        return result
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))
    except Exception as exc:
        logger.error(f"Error scanning Gmail for user {effective_user.id}: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while scanning your mailbox: {str(exc)}",
        )
