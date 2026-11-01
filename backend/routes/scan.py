"""Email scan and verdict endpoints."""

import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.schemas import EmailScanRequest, ScanResponse
from backend.services.scan_service import (
    scan_and_save,
    receive_next_sample,
    restore_scan,
    record_to_dict,
)
from backend.models import ScanRecord, User
from backend.services.auth_service import get_optional_current_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/scan", tags=["Scanning"])


@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED, summary="Scan an email")
def scan_email(
    payload: EmailScanRequest,
    user: Optional[User] = Depends(get_optional_current_user),
    db: Session = Depends(get_db),
):
    """Analyze email content for spam and phishing threats and persist the result."""
    try:
        record = scan_and_save(
            db=db,
            from_addr=payload.from_addr,
            reply_to=payload.reply_to,
            subject=payload.subject,
            body=payload.body,
            attachment=payload.attachment,
            threshold=payload.threshold,
        )
        if user:
            record.user_id = user.id
            db.commit()
            db.refresh(record)
        return record_to_dict(record)
    except Exception as exc:
        logger.error(f"Error during email scan: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while analyzing the email. Please try again.",
        )


@router.post("/receive", response_model=ScanResponse, summary="Receive and scan next incoming sample email")
def receive_email(
    sample_index: Optional[int] = Query(None, description="Optional sample index override"),
    db: Session = Depends(get_db),
):
    """Simulate receiving and analyzing an incoming email for the inbox view."""
    try:
        record = receive_next_sample(db=db, sample_index=sample_index)
        return record_to_dict(record)
    except Exception as exc:
        logger.error(f"Error processing incoming sample: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to process incoming sample email.",
        )


@router.get("/{scan_id}", response_model=ScanResponse, summary="Get details of a specific scan")
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    """Fetch stored scan verdict and detailed diagnostic reasons by ID."""
    record = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan record with ID {scan_id} not found.",
        )
    return record_to_dict(record)


@router.post("/{scan_id}/restore", response_model=ScanResponse, summary="Restore quarantined email")
def restore_quarantined_email(scan_id: int, db: Session = Depends(get_db)):
    """Mark a quarantined email as safe/restored and deliver to Inbox."""
    record = restore_scan(db=db, scan_id=scan_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Quarantined record with ID {scan_id} not found.",
        )
    return record_to_dict(record)
