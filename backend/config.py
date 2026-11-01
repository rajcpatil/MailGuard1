"""Application configuration using Pydantic Settings."""

from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    APP_NAME: str = "MailGuard"
    APP_ENV: str = "development"
    DEBUG: bool = True
    HOST: str = "127.0.0.1"
    PORT: int = 8000
    DATABASE_URL: str = "sqlite:///./mailguard.db"
    DEFAULT_THRESHOLD: float = 0.5
    CORS_ORIGINS: str = (
        "http://localhost:8000,http://127.0.0.1:8000,http://localhost:3000,http://127.0.0.1:5500,null"
    )

    # Google OAuth 2.0 Settings
    GOOGLE_CLIENT_ID: str = ""
    GOOGLE_CLIENT_SECRET: str = ""
    GOOGLE_REDIRECT_URI: str = "http://127.0.0.1:8000/api/auth/google/callback"
    GOOGLE_GMAIL_REDIRECT_URI: str = "http://127.0.0.1:8000/api/gmail/callback"

    # Session & Token Security
    SESSION_SECRET: str = "mailguard_dev_session_secret_key_change_in_production"
    SESSION_COOKIE_NAME: str = "mailguard_session"
    SESSION_MAX_AGE_SECONDS: int = 60 * 60 * 24 * 7  # 7 days
    TOKEN_ENCRYPTION_KEY: str = ""  # Fernet key (auto-derived from SESSION_SECRET if not provided)
    COOKIE_SECURE: bool = False  # Set to True in production with HTTPS
    FRONTEND_URL: str = "http://127.0.0.1:8000"

    @property
    def cors_origin_list(self) -> List[str]:
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]

    @property
    def is_google_oauth_configured(self) -> bool:
        cid = (self.GOOGLE_CLIENT_ID or "").strip()
        secret = (self.GOOGLE_CLIENT_SECRET or "").strip()
        if not cid or not secret:
            return False
        if "your_google_client_id_here" in cid or "your_google_client_secret_here" in secret:
            return False
        return True


settings = Settings()
