"""Google OAuth 2.0 and OpenID Connect authorization service."""

import secrets
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Tuple
from urllib.parse import urlencode
import httpx
from sqlalchemy.orm import Session

from backend.config import settings
from backend.models import OAuthState

logger = logging.getLogger(__name__)

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"
GOOGLE_REVOKE_URL = "https://oauth2.googleapis.com/revoke"

LOGIN_SCOPES = ["openid", "email", "profile"]
GMAIL_SCOPES = [
    "openid",
    "email",
    "https://www.googleapis.com/auth/gmail.readonly",
]


def create_oauth_state(db: Session, flow_type: str, user_id: Optional[int] = None) -> str:
    """Generate a cryptographic random state parameter and store it with 10-minute validity."""
    state_token = secrets.token_urlsafe(32)
    record = OAuthState(
        state_token=state_token,
        flow_type=flow_type,
        user_id=user_id,
        created_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(minutes=10),
    )
    db.add(record)
    db.commit()
    return state_token


def validate_oauth_state(db: Session, state_token: str, expected_flow: str) -> Optional[OAuthState]:
    """Validate and consume the OAuth state token to protect against CSRF attacks."""
    if not state_token:
        return None

    record = (
        db.query(OAuthState)
        .filter(
            OAuthState.state_token == state_token,
            OAuthState.flow_type == expected_flow,
            OAuthState.expires_at > datetime.utcnow(),
        )
        .first()
    )
    if record:
        # Delete consumed state token immediately
        db.delete(record)
        db.commit()
        return record
    return None


def get_login_authorization_url(db: Session) -> str:
    """Generate Google OAuth 2.0 authorization URL for user login and signup."""
    state = create_oauth_state(db, flow_type="login")
    params = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": " ".join(LOGIN_SCOPES),
        "state": state,
        "prompt": "select_account",
    }
    return f"{GOOGLE_AUTH_URL}?{urlencode(params)}"


def get_gmail_authorization_url(db: Session, user_id: int) -> str:
    """Generate Google OAuth 2.0 authorization URL for read-only Gmail access."""
    state = create_oauth_state(db, flow_type="gmail", user_id=user_id)
    params = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "redirect_uri": settings.GOOGLE_GMAIL_REDIRECT_URI,
        "response_type": "code",
        "scope": " ".join(GMAIL_SCOPES),
        "state": state,
        "access_type": "offline",  # Requests refresh_token for background synchronization
        "prompt": "consent",        # Forces consent screen to ensure refresh_token is returned
    }
    return f"{GOOGLE_AUTH_URL}?{urlencode(params)}"


async def exchange_code_for_tokens(code: str, redirect_uri: str) -> Dict[str, Any]:
    """Exchange authorization code for access and refresh tokens with Google servers."""
    payload = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "client_secret": settings.GOOGLE_CLIENT_SECRET,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": redirect_uri,
    }

    async with httpx.AsyncClient(timeout=15.0) as client:
        response = await client.post(GOOGLE_TOKEN_URL, data=payload)
        if response.status_code != 200:
            logger.error(f"Google token exchange failed ({response.status_code}): {response.text}")
            raise ValueError(f"Failed to exchange authorization code: {response.text}")
        return response.json()


async def get_google_user_info(access_token: str) -> Dict[str, Any]:
    """Fetch verified Google user profile using the access token."""
    headers = {"Authorization": f"Bearer {access_token}"}
    async with httpx.AsyncClient(timeout=15.0) as client:
        response = await client.get(GOOGLE_USERINFO_URL, headers=headers)
        if response.status_code != 200:
            logger.error(f"Failed to fetch Google userinfo ({response.status_code}): {response.text}")
            raise ValueError("Failed to retrieve Google user profile")
        return response.json()


async def revoke_google_token(token: str) -> bool:
    """Revoke a token with Google when user disconnects."""
    if not token:
        return True
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(f"{GOOGLE_REVOKE_URL}?token={token}")
            return resp.status_code == 200
    except Exception as e:
        logger.warning(f"Error revoking token with Google: {e}")
        return False
