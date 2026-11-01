"""Database services for scans, history, samples, and dashboard metrics."""

from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

from backend.models import ScanRecord, AppConfig, GmailConnection
from backend.services.detector import detector
from backend.config import settings

SAMPLES = [
    {
        "from": "hr@company.com",
        "subject": "Interview schedule for Thursday",
        "body": "Hi Aarav,\nThanks for applying. We would like to invite you for an interview on Thursday at 11 am.\nRegards,\nPriya (HR)",
    },
    {
        "from": "alerts@hdfcbank.com",
        "subject": "Your monthly statement is ready",
        "body": "Your statement for August is available. Log in at https://www.hdfcbank.com to view it. We never ask for your PIN or OTP by email.",
    },
    {
        "from": "offers@deals-mart.biz",
        "subject": "MEGA SALE: 70% off, limited time!",
        "body": "Buy now and get 70% off everything. Limited time offer. Unsubscribe at http://deals-mart.biz/unsub",
    },
    {
        "from": "security@secure-bank-verify.xyz",
        "subject": "Account will be suspended",
        "body": "Dear customer, your account will be suspended. Click http://secure-bank-verify.xyz to update KYC immediately.",
    },
    {
        "from": "accounts@micros0ft-support.com",
        "replyTo": "m.support77@gmail.com",
        "subject": "Invoice #4471 for your review",
        "body": "Hello,\nPlease find the invoice attached. Sign in to your Microsoft account to confirm the payment details within 24 hours.",
        "attach": "invoice.html",
    },
    {
        "from": "claims@prize-claim.top",
        "subject": "You won ₹50 lakh!",
        "body": "Congratulations winner! You won ₹50 lakh in our lottery. Send your details and card number to claim your prize.",
    },
    {
        "from": "rahul@company.com",
        "subject": "Team lunch tomorrow",
        "body": "Hey, lunch at 1 pm tomorrow near the office. Let me know if you are joining.",
    },
]

# No baseline constants — dashboard shows only real data from the database.


def get_current_threshold(db: Session) -> float:
    """Retrieve the currently configured sensitivity threshold."""
    cfg = db.query(AppConfig).filter(AppConfig.key == "threshold").first()
    if cfg:
        try:
            return float(cfg.value)
        except ValueError:
            pass
    return settings.DEFAULT_THRESHOLD


def set_current_threshold(db: Session, threshold: float) -> float:
    """Persist sensitivity threshold."""
    cfg = db.query(AppConfig).filter(AppConfig.key == "threshold").first()
    if not cfg:
        cfg = AppConfig(key="threshold", value=str(threshold))
        db.add(cfg)
    else:
        cfg.value = str(threshold)
    db.commit()
    return threshold


def scan_and_save(
    db: Session,
    from_addr: str,
    reply_to: Optional[str],
    subject: str,
    body: str,
    attachment: Optional[str] = None,
    threshold: Optional[float] = None,
    created_at: Optional[datetime] = None,
) -> ScanRecord:
    """Run detection heuristics, save record to database, and update domain reputation."""
    eff_threshold = threshold if threshold is not None else get_current_threshold(db)

    result = detector.analyze(
        from_addr=from_addr,
        reply_to=reply_to,
        subject=subject,
        body=body,
        attachment=attachment,
        threshold=eff_threshold,
    )

    domain = from_addr.strip().lower().split("@")[-1] if "@" in from_addr else "unknown"

    record = ScanRecord(
        sender=from_addr.strip(),
        sender_domain=domain,
        reply_to=reply_to.strip() if reply_to else None,
        subject=subject,
        body=body,
        attachment=attachment.strip() if attachment else None,
        verdict_type=result["type"],
        score=result["score"],
        confidence=result["conf"],
        action=result["action"],
        reasons=result["why"],
        keyword_flag=result["kwFlag"],
        latency_ms=result["latency_ms_num"],
        detection_version=result["detection_version"],
        is_restored=False,
        created_at=created_at or datetime.utcnow(),
    )

    db.add(record)
    db.commit()
    db.refresh(record)

    # If blocked, increment offender report count in detector for suspicious third-party domains
    KNOWN_MAJOR = ("google.com", "replit.com", "openai.com", "render.com", "supabase.com", "mcdonalds.com", "canva.com", "epicgames.com", "pinterest.com", "claude.com", "meister.co")
    if record.action == "blocked" and not any(domain.endswith(k) for k in KNOWN_MAJOR):
        detector.update_reputation(domain, add_reports=1)

    return record


def seed_initial_samples_if_empty(db: Session) -> None:
    """Populate database with initial 3 samples on first run if empty."""
    count = db.query(ScanRecord).count()
    if count == 0:
        for sample in SAMPLES[:3]:
            scan_and_save(
                db=db,
                from_addr=sample["from"],
                reply_to=sample.get("replyTo"),
                subject=sample["subject"],
                body=sample["body"],
                attachment=sample.get("attach"),
            )


def receive_next_sample(db: Session, sample_index: Optional[int] = None) -> ScanRecord:
    """Simulate receiving a new incoming email from the sample pool."""
    total_count = db.query(ScanRecord).count()
    idx = sample_index if sample_index is not None else total_count % len(SAMPLES)
    sample = SAMPLES[idx % len(SAMPLES)]

    return scan_and_save(
        db=db,
        from_addr=sample["from"],
        reply_to=sample.get("replyTo"),
        subject=sample["subject"],
        body=sample["body"],
        attachment=sample.get("attach"),
    )


def record_to_dict(record: ScanRecord) -> Dict[str, Any]:
    """Convert ScanRecord ORM entity to API response format matching frontend expectations."""
    formatted_time = ""
    if record.created_at:
        now = datetime.utcnow()
        if record.created_at.date() == now.date():
            formatted_time = record.created_at.strftime("%I:%M %p")
        else:
            formatted_time = record.created_at.strftime("%b %d")

    # Extract clean human-friendly sender name
    sender_raw = record.sender or "Unknown"
    from_name = sender_raw
    if "<" in sender_raw:
        display_part = sender_raw.split("<")[0].strip().strip('"').strip("'")
        if display_part:
            from_name = display_part
    else:
        domain = record.sender_domain or (sender_raw.split("@")[-1] if "@" in sender_raw else "")
        domain_sld = domain.split(".")[-2] if "." in domain else domain
        brand_map = {
            "replit": "Replit",
            "mcdonalds": "McDonald's",
            "render": "Render",
            "openai": "ChatGPT",
            "google": "Google",
            "supabase": "Supabase",
            "lovable": "Lovable",
            "canva": "Canva",
            "pinterest": "Pinterest",
            "epicgames": "Epic Games",
            "claude": "Claude",
            "meister": "MindMeister",
            "manus": "Manus",
        }
        from_name = brand_map.get(domain_sld.lower(), domain_sld.capitalize() if domain_sld else sender_raw.split("@")[0])

    return {
        "id": record.id,
        "from": record.sender,
        "from_name": from_name,
        "replyTo": record.reply_to,
        "subject": record.subject,
        "body": record.body,
        "attach": record.attachment,
        "score": record.score,
        "type": record.verdict_type,
        "conf": record.confidence,
        "why": record.reasons,
        "ms": f"{record.latency_ms:.1f}",
        "kwFlag": record.keyword_flag,
        "action": record.action,
        "time": formatted_time,
        "created_at": record.created_at,
    }


def _build_scoped_scan_query(db: Session, user_id: Optional[int] = None):
    """Build a ScanRecord query scoped to the authenticated or active connected Gmail user."""
    base_query = db.query(ScanRecord)

    effective_user_id = user_id
    if effective_user_id is None:
        # If no user session passed, check if there is an active real Gmail connection
        active_conn = (
            db.query(GmailConnection)
            .filter(
                GmailConnection.status == "connected",
                GmailConnection.access_token != "demo_access_token",
                GmailConnection.access_token != "demo_token",
            )
            .order_by(desc(GmailConnection.connected_at))
            .first()
        )
        if active_conn:
            effective_user_id = active_conn.user_id

    if effective_user_id is not None:
        gmail_scans_exist = (
            db.query(ScanRecord)
            .filter(
                ScanRecord.user_id == effective_user_id,
                ScanRecord.gmail_message_id.isnot(None),
                ~ScanRecord.gmail_message_id.like("demo_msg_%"),
            )
            .count()
            > 0
        )
        if gmail_scans_exist:
            return base_query.filter(
                ScanRecord.user_id == effective_user_id,
                ScanRecord.gmail_message_id.isnot(None),
                ~ScanRecord.gmail_message_id.like("demo_msg_%"),
            )
        return base_query.filter(ScanRecord.user_id == effective_user_id)

    # Fallback when no user is specified: return real Gmail scans if available
    real_scans = base_query.filter(
        ScanRecord.gmail_message_id.isnot(None),
        ~ScanRecord.gmail_message_id.like("demo_msg_%"),
    )
    if real_scans.count() > 0:
        return real_scans

    return base_query


def get_scan_history(
    db: Session,
    box: str = "all",
    limit: int = 100,
    offset: int = 0,
    user_id: Optional[int] = None,
) -> Tuple[List[Dict[str, Any]], int, int]:
    """Retrieve emails partitioned into Inbox (delivered/flagged) and Quarantine (blocked).
    Scoped strictly to the connected Gmail user's real emails when available.
    """
    base_query = _build_scoped_scan_query(db, user_id=user_id)

    inbox_count = base_query.filter(ScanRecord.action != "blocked").count()
    quar_count = base_query.filter(ScanRecord.action == "blocked").count()

    query = base_query
    if box == "quar":
        query = query.filter(ScanRecord.action == "blocked")
    elif box == "inbox":
        query = query.filter(ScanRecord.action != "blocked")

    records = query.order_by(desc(ScanRecord.created_at), desc(ScanRecord.id)).offset(offset).limit(limit).all()
    emails = [record_to_dict(r) for r in records]

    return emails, inbox_count, quar_count


def delete_scan(db: Session, scan_id: int, user_id: Optional[int] = None) -> bool:
    """Delete a scan record with user ownership protection."""
    query = db.query(ScanRecord).filter(ScanRecord.id == scan_id)
    if user_id is not None:
        query = query.filter((ScanRecord.user_id == user_id) | (ScanRecord.user_id == None))
    record = query.first()
    if not record:
        return False
    db.delete(record)
    db.commit()
    return True


def restore_scan(db: Session, scan_id: int) -> Optional[ScanRecord]:
    """Restore a quarantined email to the Inbox."""
    record = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not record:
        return None

    record.action = "delivered"
    record.is_restored = True
    db.commit()
    db.refresh(record)
    return record


def get_dashboard_metrics(db: Session, user_id: Optional[int] = None) -> Dict[str, Any]:
    """Calculate dashboard metrics entirely from real database scan records for the connected user."""
    now = datetime.utcnow()
    # 7-slot list: index 0 = 6 days ago, index 6 = today, each [spam_blocked, fraud_blocked]
    days: List[List[int]] = [[0, 0] for _ in range(7)]
    offenders: Dict[str, int] = {}
    spam_total = 0
    fraud_total = 0

    records = _build_scoped_scan_query(db, user_id=user_id).all()
    blocked_offenders: Dict[str, int] = {}
    all_threat_offenders: Dict[str, int] = {}

    for r in records:
        if r.verdict_type != "safe":
            if r.verdict_type == "fraud":
                fraud_total += 1
            else:
                spam_total += 1
            dom = r.sender_domain
            all_threat_offenders[dom] = all_threat_offenders.get(dom, 0) + 1

            # Place scan in the 7-day chart bucket
            rec_date = r.created_at or now
            delta_days = (now.date() - rec_date.date()).days
            bucket = 6 - delta_days  # today = bucket 6, yesterday = bucket 5, etc.
            if 0 <= bucket <= 6:
                if r.verdict_type == "fraud":
                    days[bucket][1] += 1
                else:
                    days[bucket][0] += 1

        if r.action == "blocked":
            dom = r.sender_domain
            blocked_offenders[dom] = blocked_offenders.get(dom, 0) + 1

    total_scanned = len(records)
    threats_sum = spam_total + fraud_total
    threats_7d = sum(d[0] + d[1] for d in days)
    offenders = blocked_offenders if blocked_offenders else all_threat_offenders

    fraud_pct = int(round((fraud_total / threats_sum * 100))) if threats_sum > 0 else 0

    return {
        "scanned": total_scanned,
        "threats_blocked_7d": threats_7d,
        "fraud_pct": fraud_pct,
        "days": days,
        "offenders": dict(sorted(offenders.items(), key=lambda x: x[1], reverse=True)[:5]),
        "threat_mix": {"spam": spam_total, "fraud": fraud_total},
        "threshold": get_current_threshold(db),
    }
