"""Dashboard statistics and sensitivity configuration endpoints."""

import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models import User
from backend.schemas import DashboardStats, UpdateThresholdRequest
from backend.services.auth_service import get_optional_current_user
from backend.services.scan_service import (
    get_dashboard_metrics,
    set_current_threshold,
    get_current_threshold,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


@router.get("/stats", response_model=DashboardStats, summary="Get dashboard KPIs, trends, and threat breakdown")
def get_stats(
    user: Optional[User] = Depends(get_optional_current_user),
    db: Session = Depends(get_db),
):
    """Fetch live aggregated threat intelligence metrics and 7-day trend data."""
    try:
        user_id = user.id if user else None
        return get_dashboard_metrics(db, user_id=user_id)
    except Exception as exc:
        logger.error(f"Error fetching dashboard metrics: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve dashboard statistics.",
        )


@router.put("/threshold", summary="Update blocking sensitivity threshold")
def update_threshold(payload: UpdateThresholdRequest, db: Session = Depends(get_db)):
    """Update global email threat blocking threshold (e.g. 0.5 = 50%)."""
    new_thr = set_current_threshold(db, payload.threshold)
    return {"message": "Sensitivity threshold updated successfully", "threshold": new_thr}


@router.get("/threshold", summary="Get current blocking sensitivity threshold")
def get_threshold(db: Session = Depends(get_db)):
    """Retrieve the current sensitivity threshold setting."""
    return {"threshold": get_current_threshold(db)}
