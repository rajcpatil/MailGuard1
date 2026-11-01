"""SQLAlchemy models for MailGuard1."""

from datetime import datetime
from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    Boolean,
    Text,
    DateTime,
    JSON,
    Index,
    ForeignKey,
)
from sqlalchemy.orm import relationship
from backend.database import Base


class User(Base):
    """Authenticated user account via Google OAuth."""

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    google_sub = Column(String(255), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    name = Column(String(255), nullable=True)
    picture = Column(String(500), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_login_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    sessions = relationship("UserSession", back_populates="user", cascade="all, delete-orphan")
    gmail_connection = relationship("GmailConnection", back_populates="user", uselist=False, cascade="all, delete-orphan")
    scans = relationship("ScanRecord", back_populates="user")


class UserSession(Base):
    """Server-side session record tied to an HttpOnly cookie."""

    __tablename__ = "user_sessions"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    session_token = Column(String(64), unique=True, index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    expires_at = Column(DateTime, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User", back_populates="sessions")


class GmailConnection(Base):
    """Connected Gmail account metadata and securely encrypted OAuth token."""

    __tablename__ = "gmail_connections"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), unique=True, nullable=False, index=True)
    gmail_address = Column(String(255), nullable=True)
    encrypted_refresh_token = Column(Text, nullable=True)
    access_token = Column(Text, nullable=True)
    token_expiry = Column(DateTime, nullable=True)
    scope = Column(String(255), default="https://www.googleapis.com/auth/gmail.readonly", nullable=False)
    status = Column(String(20), default="connected", nullable=False)  # 'connected', 'disconnected', 'revoked', 'expired'
    connected_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_sync_at = Column(DateTime, nullable=True)

    user = relationship("User", back_populates="gmail_connection")


class OAuthState(Base):
    """Short-lived state tokens for CSRF protection in OAuth flows."""

    __tablename__ = "oauth_states"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    state_token = Column(String(64), unique=True, index=True, nullable=False)
    flow_type = Column(String(20), nullable=False)  # 'login' or 'gmail'
    user_id = Column(Integer, nullable=True)  # Associated user for gmail connection flow
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False, index=True)


class ScanRecord(Base):
    """Stores email scans and verdicts."""

    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    gmail_message_id = Column(String(255), nullable=True, index=True)

    sender = Column(String(255), nullable=False, index=True)
    sender_domain = Column(String(255), nullable=False, index=True)
    reply_to = Column(String(255), nullable=True)
    subject = Column(String(500), nullable=False, default="")
    body = Column(Text, nullable=False, default="")
    attachment = Column(String(255), nullable=True)

    # Detection outputs
    verdict_type = Column(String(20), nullable=False, index=True)  # 'safe', 'spam', 'fraud'
    score = Column(Float, nullable=False, default=0.0)
    confidence = Column(Integer, nullable=False, default=0)
    action = Column(String(20), nullable=False, index=True)  # 'delivered', 'flagged', 'blocked'
    reasons = Column(JSON, nullable=False, default=list)  # list of {bad: bool, msg: str}
    keyword_flag = Column(Boolean, nullable=False, default=False)
    latency_ms = Column(Float, nullable=False, default=0.0)
    detection_version = Column(String(50), nullable=False, default="heuristic-baseline-1.0")

    # Status / Management
    is_restored = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    user = relationship("User", back_populates="scans")

    __table_args__ = (
        Index("ix_scans_action_created", "action", "created_at"),
        Index("ix_scans_domain_action", "sender_domain", "action"),
    )


class AppConfig(Base):
    """Key-value application settings such as sensitivity threshold."""

    __tablename__ = "app_config"

    key = Column(String(50), primary_key=True, index=True)
    value = Column(String(255), nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
