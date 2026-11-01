"""Cryptographic utilities for encrypting and decrypting sensitive tokens at rest."""

import base64
import hashlib
import logging
from cryptography.fernet import Fernet
from backend.config import settings

logger = logging.getLogger(__name__)


def _get_fernet_key() -> bytes:
    """Derive a stable 32-byte base64 key for Fernet from configuration."""
    raw_key = settings.TOKEN_ENCRYPTION_KEY or settings.SESSION_SECRET or "mailguard_default_secret_key"
    # Create deterministic 32-byte key via SHA-256
    digest = hashlib.sha256(raw_key.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


def encrypt_token(plain_token: str) -> str:
    """Encrypt a sensitive OAuth refresh token for secure at-rest database storage."""
    if not plain_token:
        return ""
    fernet = Fernet(_get_fernet_key())
    encrypted = fernet.encrypt(plain_token.encode("utf-8"))
    return encrypted.decode("utf-8")


def decrypt_token(cipher_text: str) -> str:
    """Decrypt an encrypted refresh token from database storage."""
    if not cipher_text:
        return ""
    try:
        fernet = Fernet(_get_fernet_key())
        decrypted = fernet.decrypt(cipher_text.encode("utf-8"))
        return decrypted.decode("utf-8")
    except Exception as e:
        logger.error(f"Failed to decrypt token: {e}")
        return ""
