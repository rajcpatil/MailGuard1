"""Automated tests for Gmail OAuth connection, token encryption, and message analysis."""

import base64
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

from backend.models import User, GmailConnection, OAuthState, ScanRecord
from backend.services.auth_service import create_user_session
from backend.services.crypto import encrypt_token, decrypt_token
from backend.services.gmail_service import _extract_body_and_attachments, scan_user_gmail
from backend.config import settings


def test_token_encryption_at_rest():
    """Verify refresh tokens are properly encrypted and decrypted via Fernet."""
    secret_token = "1//04test_google_refresh_token_very_sensitive_998877"
    encrypted = encrypt_token(secret_token)
    assert encrypted != secret_token
    assert "gAAAAA" in encrypted  # Standard Fernet prefix

    decrypted = decrypt_token(encrypted)
    assert decrypted == secret_token


def test_connect_gmail_unauthenticated(client):
    """Connecting Gmail requires an active user session."""
    response = client.get("/api/gmail/connect")
    assert response.status_code == 401


def test_connect_gmail_redirect(client, db_session):
    """Authenticated user gets redirected to Google with gmail.readonly scope."""
    user = User(google_sub="sub-gmail-test", email="user@gmail.com")
    db_session.add(user)
    db_session.commit()

    token = create_user_session(db_session, user)
    client.cookies.set("mailguard_session", token)

    with patch.object(settings, "GOOGLE_CLIENT_ID", "mock-client-id"), \
         patch.object(settings, "GOOGLE_CLIENT_SECRET", "mock-secret"):
        response = client.get("/api/gmail/connect", follow_redirects=False)
        assert response.status_code == 307
        loc = response.headers["location"]
        assert "gmail.readonly" in loc
        assert "access_type=offline" in loc


def test_gmail_callback_and_token_storage(client, db_session):
    """Verify Gmail callback securely stores encrypted refresh token and links to user."""
    user = User(google_sub="sub-callback-test", email="owner@gmail.com")
    db_session.add(user)
    db_session.commit()

    state_rec = OAuthState(
        state_token="gmail_state_test_789",
        flow_type="gmail",
        user_id=user.id,
        created_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(minutes=10),
    )
    db_session.add(state_rec)
    db_session.commit()

    mock_tokens = {
        "access_token": "mock_gmail_access_token",
        "refresh_token": "mock_real_refresh_token_123",
        "expires_in": 3600,
    }
    mock_userinfo = {"email": "owner@gmail.com"}

    with patch("backend.routes.gmail.exchange_code_for_tokens", return_value=mock_tokens), \
         patch("backend.routes.gmail.get_google_user_info", return_value=mock_userinfo):
        response = client.get(
            "/api/gmail/callback?code=mock_auth_code&state=gmail_state_test_789",
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert "/?gmail_connected=1" in response.headers["location"]

        # Verify database record
        conn = db_session.query(GmailConnection).filter(GmailConnection.user_id == user.id).first()
        assert conn is not None
        assert conn.status == "connected"
        assert conn.gmail_address == "owner@gmail.com"
        # Confirm token is encrypted
        assert conn.encrypted_refresh_token != "mock_real_refresh_token_123"
        assert decrypt_token(conn.encrypted_refresh_token) == "mock_real_refresh_token_123"


def test_gmail_status_and_disconnect(client, db_session):
    """Test checking Gmail status and disconnecting."""
    user = User(google_sub="sub-status-test", email="disconnect@gmail.com")
    db_session.add(user)
    db_session.commit()

    conn = GmailConnection(
        user_id=user.id,
        gmail_address="disconnect@gmail.com",
        encrypted_refresh_token=encrypt_token("some_refresh_token"),
        access_token="some_access",
        status="connected",
    )
    db_session.add(conn)
    db_session.commit()

    token = create_user_session(db_session, user)
    client.cookies.set("mailguard_session", token)

    # Check status
    res = client.get("/api/gmail/status")
    assert res.status_code == 200
    assert res.json()["connected"] is True
    assert res.json()["email"] == "disconnect@gmail.com"

    # Disconnect
    with patch("backend.routes.gmail.revoke_google_token", return_value=True):
        disc_res = client.post("/api/gmail/disconnect")
        assert disc_res.status_code == 200
        assert disc_res.json()["status"] == "success"

        # Verify connection removed from database
        check_conn = db_session.query(GmailConnection).filter(GmailConnection.user_id == user.id).first()
        assert check_conn is None


def test_mime_body_and_attachment_parsing():
    """Verify safe MIME parsing for text/plain and text/html bodies."""
    plain_text = "Dear customer, your account is suspended. Click immediately."
    encoded_plain = base64.urlsafe_b64encode(plain_text.encode("utf-8")).decode("ASCII")

    mock_payload = {
        "mimeType": "multipart/mixed",
        "parts": [
            {
                "mimeType": "text/plain",
                "body": {"data": encoded_plain},
            },
            {
                "filename": "invoice_statement.html",
                "body": {"attachmentId": "att123"},
            },
        ],
    }

    body, attachment = _extract_body_and_attachments(mock_payload)
    assert "account is suspended" in body
    assert attachment == "invoice_statement.html"


def test_scan_user_gmail_messages(db_session):
    """Test fetching and scanning Gmail messages with threat detector."""
    user = User(google_sub="scan-user-sub", email="scanner@gmail.com")
    db_session.add(user)
    db_session.commit()

    mock_messages = [
        {
            "gmail_id": "msg_001",
            "from": "hr@company.com",
            "replyTo": None,
            "subject": "Interview reminder",
            "body": "Hi there, your interview is scheduled for Friday at 10 AM.",
            "attach": None,
            "date": "Mon, 18 Oct 2026 10:00:00 GMT",
        },
        {
            "gmail_id": "msg_002",
            "from": "security@secure-bank-verify.xyz",
            "replyTo": None,
            "subject": "Urgent verification",
            "body": "Dear customer, your bank account is suspended. Update KYC and OTP immediately at http://secure-bank-verify.xyz",
            "attach": "verify.html",
            "date": "Mon, 18 Oct 2026 10:05:00 GMT",
        },
    ]

    with patch("backend.services.gmail_service.fetch_recent_gmail_messages", return_value=mock_messages):
        result = scan_user_gmail(db_session, user, max_results=2)
        assert result["status"] == "success"
        assert result["total_fetched"] == 2
        assert result["threats_blocked"] == 1
        assert result["safe_delivered"] == 1

        # Verify scans are persisted in database and linked to user.id
        scans = db_session.query(ScanRecord).filter(ScanRecord.user_id == user.id).all()
        assert len(scans) == 2
        phish_scan = next(s for s in scans if s.gmail_message_id == "msg_002")
        assert phish_scan.verdict_type == "fraud"
        assert phish_scan.action == "blocked"
