"""Pydantic schemas for request and response serialization and validation."""

from datetime import datetime
from typing import List, Optional, Dict
from pydantic import BaseModel, Field, ConfigDict, field_validator


class ReasonItem(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    bad: bool
    msg: str


class EmailScanRequest(BaseModel):
    """Payload to scan an email."""
    model_config = ConfigDict(populate_by_name=True)

    from_addr: str = Field(..., alias="from", min_length=3, max_length=255, description="Sender email address")
    reply_to: Optional[str] = Field(None, alias="replyTo", max_length=255, description="Optional Reply-To address")
    subject: str = Field(default="", max_length=500, description="Email subject line")
    body: str = Field(default="", max_length=50000, description="Email body content")
    attachment: Optional[str] = Field(None, alias="attach", max_length=255, description="Optional attachment name")
    threshold: Optional[float] = Field(default=None, ge=0.1, le=0.99, description="Sensitivity threshold")

    @field_validator("from_addr")
    @classmethod
    def validate_from_addr(cls, v: str) -> str:
        v = v.strip()
        if not v or "@" not in v:
            raise ValueError("Sender must be a valid email address containing '@'")
        return v


class ScanResponse(BaseModel):
    """Scan result returned to frontend matching existing JavaScript model."""
    model_config = ConfigDict(populate_by_name=True, from_attributes=True)

    id: int
    from_addr: str = Field(..., alias="from")
    from_name: Optional[str] = None
    reply_to: Optional[str] = Field(None, alias="replyTo")
    subject: str
    body: str
    attachment: Optional[str] = Field(None, alias="attach")
    score: float
    type: str  # 'safe', 'spam', 'fraud'
    conf: int
    why: List[ReasonItem]
    ms: str
    kwFlag: bool
    action: str  # 'delivered', 'flagged', 'blocked'
    time: str
    created_at: Optional[datetime] = None


class HistoryResponse(BaseModel):
    """Inbox and Quarantine records for the list view."""
    model_config = ConfigDict(populate_by_name=True)

    emails: List[ScanResponse]
    nIn: int
    nQ: int


class DashboardStats(BaseModel):
    """Aggregated stats for the Dashboard view."""
    model_config = ConfigDict(populate_by_name=True)

    scanned: int
    threats_blocked_7d: int
    fraud_pct: int
    avg_latency_ms: Optional[str] = None
    days: List[List[int]]  # 7 days, each [spam_count, fraud_count]
    offenders: Dict[str, int]
    threat_mix: Dict[str, int]  # {"spam": count, "fraud": count}
    threshold: float


class UpdateThresholdRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    threshold: float = Field(..., ge=0.1, le=0.99)
