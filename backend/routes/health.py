"""Health check endpoint."""

from fastapi import APIRouter
from backend.config import settings

router = APIRouter(prefix="/api", tags=["Health"])


@router.get("/health", summary="API Health Check")
def get_health():
    """Verify backend API is active and functioning."""
    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "environment": settings.APP_ENV,
        "version": "1.0.0",
    }
