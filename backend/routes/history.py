"""Scan history endpoints."""

import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models import User
from backend.schemas import HistoryResponse
from backend.services.scan_service import get_scan_history, delete_scan
from backend.services.auth_service import get_optional_current_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/history", tags=["History"])


@router.get("", response_model=HistoryResponse, summary="Get scan history for Inbox or Quarantine")
def list_history(
    box: str = Query("all", pattern="^(inbox|quar|all)$", description="Folder partition ('inbox', 'quar', or 'all')"),
    limit: int = Query(100, ge=1, le=500, description="Page size limit"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    user: Optional[User] = Depends(get_optional_current_user),
    db: Session = Depends(get_db),
):
    """Retrieve list of scanned emails and folder counts from SQLite, filtered by user if logged in."""
    user_id = user.id if user else None
    emails, n_in, n_q = get_scan_history(db=db, box=box, limit=limit, offset=offset, user_id=user_id)
    return {
        "emails": emails,
        "nIn": n_in,
        "nQ": n_q,
    }


@router.delete("/{scan_id}", summary="Delete a scan record from history")
def delete_history_item(
    scan_id: int,
    user: Optional[User] = Depends(get_optional_current_user),
    db: Session = Depends(get_db),
):
    """Delete a specific email scan from the user's scan history."""
    user_id = user.id if user else None
    deleted = delete_scan(db=db, scan_id=scan_id, user_id=user_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan record not found or access denied.",
        )
    return {"status": "success", "message": f"Scan {scan_id} deleted successfully."}
