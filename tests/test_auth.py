"""Automated tests for user authentication and Google OAuth flows."""

from datetime import datetime, timedelta
from unittest.mock import patch
from backend.models import User, UserSession, OAuthState
from backend.config import settings
from backend.services.auth_service import create_user_session, get_user_from_session_token


def test_auth_me_unauthenticated(client):
    """Unauthenticated users should receive authenticated=False."""
    response = client.get("/api/auth/me")
    assert response.status_code == 200
    data = response.json()
    assert data["authenticated"] is False
    assert data["user"] is None


def test_login_missing_credentials(client):
    """If Google OAuth credentials are not set, redirect to /login with setup guidance."""
    with patch.object(settings, "GOOGLE_CLIENT_ID", ""):
        response = client.get("/api/auth/google/login", follow_redirects=False)
        assert response.status_code == 303
        assert "/login?error=credentials_needed" in response.headers["location"]


def test_demo_login_flow(client, db_session):
    """Demo login allows immediate testing and session creation without Google Cloud setup."""
    response = client.get("/api/auth/demo-login", follow_redirects=False)
    assert response.status_code == 303
    assert "/?login_success=1" in response.headers["location"]
    assert "mailguard_session" in response.cookies
    token = response.cookies["mailguard_session"]

    # Verify session and user
    user = get_user_from_session_token(db_session, token)
    assert user is not None
    assert user.email == "demo.analyst@gmail.com"


def test_login_redirect_with_state(client, db_session):
    """When configured, login generates OAuth state and redirects to Google."""
    with patch.object(settings, "GOOGLE_CLIENT_ID", "test-client-id"), \
         patch.object(settings, "GOOGLE_CLIENT_SECRET", "test-secret"):
        response = client.get("/api/auth/google/login", follow_redirects=False)
        assert response.status_code == 307
        location = response.headers["location"]
        assert "accounts.google.com" in location
        assert "client_id=test-client-id" in location
        assert "state=" in location

        # Verify state saved in database
        state_count = db_session.query(OAuthState).filter(OAuthState.flow_type == "login").count()
        assert state_count >= 1


def test_callback_invalid_state(client):
    """Invalid or expired state parameter should be rejected with HTTP 400."""
    response = client.get("/api/auth/google/callback?code=fake_code&state=nonexistent_state")
    assert response.status_code == 400
    assert "Invalid or expired" in response.json()["detail"]


def test_successful_google_login_flow(client, db_session):
    """Simulate successful Google OAuth callback, user creation, and session persistence."""
    # 1. Create valid state
    state_rec = OAuthState(
        state_token="valid_test_state_123",
        flow_type="login",
        created_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(minutes=10),
    )
    db_session.add(state_rec)
    db_session.commit()

    mock_tokens = {"access_token": "mock_access_token_abc", "expires_in": 3600}
    mock_userinfo = {
        "sub": "google-user-id-998877",
        "email": "security.analyst@example.com",
        "name": "Jane Analyst",
        "picture": "https://example.com/avatar.jpg",
    }

    with patch("backend.routes.auth.exchange_code_for_tokens", return_value=mock_tokens), \
         patch("backend.routes.auth.get_google_user_info", return_value=mock_userinfo):
        response = client.get(
            "/api/auth/google/callback?code=mock_code&state=valid_test_state_123",
            follow_redirects=False,
        )

        assert response.status_code == 303
        assert "/?login_success=1" in response.headers["location"]

        # Verify session cookie was set
        assert "mailguard_session" in response.cookies
        session_token = response.cookies["mailguard_session"]

        # Verify user was created in database
        user = db_session.query(User).filter(User.google_sub == "google-user-id-998877").first()
        assert user is not None
        assert user.email == "security.analyst@example.com"
        assert user.name == "Jane Analyst"

        # Verify session token in database
        session_rec = db_session.query(UserSession).filter(UserSession.session_token == session_token).first()
        assert session_rec is not None
        assert session_rec.user_id == user.id

        # Verify /api/auth/me now returns authenticated user
        client.cookies.set("mailguard_session", session_token)
        me_res = client.get("/api/auth/me")
        assert me_res.status_code == 200
        me_data = me_res.json()
        assert me_data["authenticated"] is True
        assert me_data["user"]["email"] == "security.analyst@example.com"


def test_repeat_google_login_no_duplicate(client, db_session):
    """Repeat login for same Google account should not create duplicate users."""
    existing_user = User(
        google_sub="repeat-user-sub-1122",
        email="repeat@example.com",
        name="Repeat User",
    )
    db_session.add(existing_user)
    db_session.commit()

    state_rec = OAuthState(
        state_token="repeat_state_456",
        flow_type="login",
        created_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(minutes=10),
    )
    db_session.add(state_rec)
    db_session.commit()

    mock_tokens = {"access_token": "mock_token_repeat"}
    mock_userinfo = {
        "sub": "repeat-user-sub-1122",
        "email": "repeat@example.com",
        "name": "Repeat User Updated",
    }

    with patch("backend.routes.auth.exchange_code_for_tokens", return_value=mock_tokens), \
         patch("backend.routes.auth.get_google_user_info", return_value=mock_userinfo):
        response = client.get(
            "/api/auth/google/callback?code=mock_code&state=repeat_state_456",
            follow_redirects=False,
        )
        assert response.status_code == 303

        # Assert only 1 user exists
        total_matching = db_session.query(User).filter(User.google_sub == "repeat-user-sub-1122").count()
        assert total_matching == 1


def test_logout(client, db_session):
    """Logout should invalidate the session in database and clear the cookie."""
    user = User(google_sub="logout-user", email="logout@example.com")
    db_session.add(user)
    db_session.commit()

    token = create_user_session(db_session, user)
    client.cookies.set("mailguard_session", token)

    # Perform logout
    res = client.post("/api/auth/logout")
    assert res.status_code == 200
    assert res.json()["status"] == "success"

    # Verify session removed from database
    session_rec = db_session.query(UserSession).filter(UserSession.session_token == token).first()
    assert session_rec is None
