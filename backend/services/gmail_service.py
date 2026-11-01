"""Google Gmail API integration service.

Fetches recent email messages using the official Gmail API (gmail.readonly scope),
decodes and sanitizes MIME structures, and runs security analysis via MailGuard's detector.
"""

import base64
import re
import html
import time
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional, Tuple

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from sqlalchemy.orm import Session

from backend.config import settings
from backend.models import User, GmailConnection, ScanRecord
from backend.services.crypto import encrypt_token, decrypt_token
from backend.services.detector import detector
from backend.services.scan_service import scan_and_save

logger = logging.getLogger(__name__)


def get_user_gmail_credentials(db: Session, user_id: int) -> Optional[Credentials]:
    """Retrieve and refresh official Google Credentials for an authorized user."""
    conn = db.query(GmailConnection).filter(GmailConnection.user_id == user_id).first()
    if not conn or conn.status != "connected":
        return None

    decrypted_refresh = decrypt_token(conn.encrypted_refresh_token) if conn.encrypted_refresh_token else None

    creds = Credentials(
        token=conn.access_token,
        refresh_token=decrypted_refresh,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=settings.GOOGLE_CLIENT_ID,
        client_secret=settings.GOOGLE_CLIENT_SECRET,
        scopes=["https://www.googleapis.com/auth/gmail.readonly"],
    )

    # Check if access token is expired or close to expiry (within 5 minutes)
    need_refresh = False
    if conn.token_expiry and conn.token_expiry <= datetime.utcnow() + timedelta(minutes=5):
        need_refresh = True
    elif not conn.access_token:
        need_refresh = True

    if need_refresh and decrypted_refresh:
        try:
            creds.refresh(Request())
            conn.access_token = creds.token
            if creds.expiry:
                conn.token_expiry = creds.expiry.replace(tzinfo=None) if hasattr(creds.expiry, "tzinfo") and creds.expiry.tzinfo else creds.expiry
            conn.status = "connected"
            db.commit()
            logger.info(f"Refreshed Gmail access token for user_id={user_id}")
        except Exception as e:
            logger.error(f"Failed to refresh Gmail token for user_id={user_id}: {e}")
            conn.status = "expired"
            db.commit()
            return None

    return creds


def _extract_body_and_attachments(payload: Dict[str, Any]) -> Tuple[str, Optional[str]]:
    """Recursively parse Gmail message MIME parts and extract sanitized text and attachment names."""
    body_text = ""
    attachments: List[str] = []

    def walk_parts(part: Dict[str, Any]):
        nonlocal body_text
        mime_type = part.get("mimeType", "")
        filename = part.get("filename", "")
        if filename:
            attachments.append(filename)

        body_data = part.get("body", {}).get("data")
        if body_data:
            try:
                decoded = base64.urlsafe_b64decode(body_data.encode("ASCII")).decode("utf-8", errors="replace")
                if mime_type == "text/plain":
                    body_text += "\n" + decoded
                elif mime_type == "text/html" and not body_text:
                    # Strip HTML tags safely for heuristic analysis
                    cleaned = re.sub(r"<[^>]+>", " ", decoded)
                    body_text += "\n" + html.unescape(cleaned)
            except Exception as err:
                logger.warning(f"Failed to decode part data: {err}")

        for sub_part in part.get("parts", []):
            walk_parts(sub_part)

    walk_parts(payload)
    first_attachment = attachments[0] if attachments else None
    return body_text.strip(), first_attachment


def fetch_recent_gmail_messages(
    db: Session,
    user_id: int,
    max_results: int = 25,
) -> Tuple[List[Dict[str, Any]], int]:
    """Fetch recent messages from the user's Gmail mailbox using the Gmail API.
    Critically optimizes Google API quota by checking existing scanned IDs first,
    skipping expensive messages.get calls for emails already analyzed.
    """
    conn = db.query(GmailConnection).filter(GmailConnection.user_id == user_id).first()
    if not conn or conn.status != "connected":
        raise ValueError("Gmail account is not connected. Please click 'Connect Gmail' first.")

    # If Google OAuth credentials are not configured yet, provide simulated messages for local testing
    if not settings.is_google_oauth_configured or conn.access_token == "demo_access_token" or conn.access_token == "demo_token":
        from backend.services.scan_service import SAMPLES
        conn.last_sync_at = datetime.utcnow()
        db.commit()
        demo_messages = []
        for i, s in enumerate(SAMPLES[:max_results]):
            demo_messages.append({
                "gmail_id": f"demo_msg_{i+1}",
                "from": s["from"],
                "from_raw": s["from"],
                "replyTo": s.get("replyTo"),
                "subject": s["subject"],
                "body": s["body"],
                "attach": s.get("attach"),
                "date": datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT"),
                "internal_date": datetime.utcnow(),
            })
        return demo_messages, len(demo_messages)

    creds = get_user_gmail_credentials(db, user_id)
    if not creds:
        raise ValueError("Gmail account is not connected or token has expired. Please connect Gmail.")

    try:
        service = build("gmail", "v1", credentials=creds, cache_discovery=False)
        # Fetch list of recent message metadata (costs only 5 quota units)
        results = service.users().messages().list(userId="me", maxResults=max_results).execute()
        messages_meta = results.get("messages", [])
        total_in_mailbox = len(messages_meta)

        # Pre-query existing message IDs in the database to avoid redundant messages.get() calls
        existing_ids = set(
            r[0]
            for r in db.query(ScanRecord.gmail_message_id)
            .filter(
                ScanRecord.user_id == user_id,
                ScanRecord.gmail_message_id.isnot(None),
            )
            .all()
        )

        parsed_messages: List[Dict[str, Any]] = []

        for m_meta in messages_meta:
            msg_id = m_meta["id"]

            # If already scanned, skip the expensive messages.get call completely!
            if msg_id in existing_ids:
                continue

            # Small delay between gets to avoid bursting against per-second rate limits
            time.sleep(0.05)

            try:
                msg_data = service.users().messages().get(userId="me", id=msg_id, format="full").execute()
            except HttpError as get_err:
                if get_err.resp.status in (429, 403) or "quota" in str(get_err).lower():
                    logger.warning(f"Reached quota limit on message {msg_id}; stopping batch.")
                    break
                raise

            payload = msg_data.get("payload", {})
            headers = {h["name"].lower(): h["value"] for h in payload.get("headers", [])}

            from_addr = headers.get("from", "Unknown <unknown@example.com>")
            subject = headers.get("subject", "(No Subject)")
            date_str = headers.get("date", "")
            reply_to = headers.get("reply-to", None)

            # Clean sender email
            email_match = re.search(r"<([^>]+)>", from_addr)
            clean_from = email_match.group(1) if email_match else from_addr.strip()

            body_content, attachment_name = _extract_body_and_attachments(payload)
            if not body_content:
                body_content = msg_data.get("snippet", "(No message body content)")

            internal_date_ms = msg_data.get("internalDate")
            msg_dt = (
                datetime.fromtimestamp(int(internal_date_ms) / 1000, tz=timezone.utc).replace(tzinfo=None)
                if internal_date_ms
                else None
            )

            parsed_messages.append({
                "gmail_id": msg_id,
                "from": clean_from,
                "from_raw": from_addr,
                "replyTo": reply_to,
                "subject": subject,
                "body": body_content,
                "attach": attachment_name,
                "date": date_str,
                "internal_date": msg_dt,
            })

        # Update last sync timestamp
        conn = db.query(GmailConnection).filter(GmailConnection.user_id == user_id).first()
        if conn:
            conn.last_sync_at = datetime.utcnow()
            db.commit()

        return parsed_messages, total_in_mailbox

    except HttpError as error:
        logger.error(f"Gmail API HTTP error: {error}")
        reason = error._get_reason() if hasattr(error, "_get_reason") else str(error)
        if error.resp.status == 401:
            conn = db.query(GmailConnection).filter(GmailConnection.user_id == user_id).first()
            if conn:
                conn.status = "expired"
                db.commit()
            raise ValueError("Gmail authorization expired. Please reconnect your account.")
        elif error.resp.status in (429, 403) or "quota" in str(error).lower() or "limit" in str(error).lower():
            logger.warning(f"Google quota rate limit hit: {error}")
            raise ValueError("Google rate limit reached. Your scanned emails are safe; please wait a minute before scanning again.")
        raise ValueError(f"Gmail API error: {reason}")
    except Exception as err:
        logger.error(f"Error fetching Gmail messages: {err}", exc_info=True)
        err_msg = str(err)
        if "ServerNotFoundError" in type(err).__name__ or "no such host" in err_msg.lower() or "connection" in err_msg.lower():
            raise ValueError("Unable to reach Google servers. Please check your internet connection and try again.")
        raise ValueError(f"Failed to retrieve Gmail messages: {err_msg}")


def scan_user_gmail(
    db: Session,
    user: User,
    max_results: int = 25,
) -> Dict[str, Any]:
    res = fetch_recent_gmail_messages(db, user.id, max_results=max_results)
    if isinstance(res, tuple):
        new_messages, total_in_mailbox = res
    elif isinstance(res, list):
        new_messages = res
        total_in_mailbox = len(res)
    else:
        new_messages = []
        total_in_mailbox = 0

    scanned_results: List[Dict[str, Any]] = []
    blocked_count = 0
    flagged_count = 0
    safe_count = 0

    for msg in new_messages:
        # Run detector
        record = scan_and_save(
            db=db,
            from_addr=msg["from"],
            reply_to=msg["replyTo"],
            subject=msg["subject"],
            body=msg["body"],
            attachment=msg["attach"],
            created_at=msg.get("internal_date"),
        )
        record.user_id = user.id
        record.gmail_message_id = msg["gmail_id"]
        db.commit()
        db.refresh(record)

        if record.action == "blocked":
            blocked_count += 1
        elif record.action == "flagged":
            flagged_count += 1
        else:
            safe_count += 1

        scanned_results.append({
            "id": record.id,
            "gmail_id": msg["gmail_id"],
            "from": record.sender,
            "subject": record.subject,
            "type": record.verdict_type,
            "action": record.action,
            "conf": record.confidence,
            "already_scanned": False,
        })

    return {
        "status": "success",
        "total_fetched": total_in_mailbox,
        "newly_scanned": len(new_messages),
        "threats_blocked": blocked_count,
        "threats_flagged": flagged_count,
        "safe_delivered": safe_count,
        "scans": scanned_results,
    }
