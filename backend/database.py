"""Database configuration and session management with SQLAlchemy."""

import logging
from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker
from backend.config import settings

logger = logging.getLogger(__name__)

connect_args = {"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    echo=False,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """Dependency to provide a transactional database session per request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Initialize database tables and perform non-destructive schema migrations."""
    import backend.models  # Register models with metadata
    Base.metadata.create_all(bind=engine)

    # Safe SQLite migration: ensure user_id and gmail_message_id exist on scans table
    if settings.DATABASE_URL.startswith("sqlite"):
        try:
            with engine.connect() as conn:
                res = conn.execute(text("PRAGMA table_info(scans)")).fetchall()
                existing_cols = {col[1] for col in res}
                if "user_id" not in existing_cols:
                    logger.info("Migrating schema: adding 'user_id' column to scans table.")
                    conn.execute(text("ALTER TABLE scans ADD COLUMN user_id INTEGER REFERENCES users(id)"))
                    conn.commit()
                if "gmail_message_id" not in existing_cols:
                    logger.info("Migrating schema: adding 'gmail_message_id' column to scans table.")
                    conn.execute(text("ALTER TABLE scans ADD COLUMN gmail_message_id VARCHAR(255)"))
                    conn.commit()
        except Exception as e:
            logger.warning(f"Schema check error (non-fatal): {e}")
