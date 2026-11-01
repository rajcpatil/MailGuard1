"""Unit tests for the email security heuristic detector."""

from backend.services.detector import HeuristicBaselineDetector


def test_safe_email_detection():
    detector = HeuristicBaselineDetector()
    result = detector.analyze(
        from_addr="hr@company.com",
        reply_to=None,
        subject="Interview schedule for Thursday",
        body="Hi Aarav, Thanks for applying. We would like to invite you for an interview on Thursday at 11 am.",
        attachment=None,
        threshold=0.5,
    )
    assert result["type"] == "safe"
    assert result["action"] == "delivered"
    assert result["score"] < 0.3
    assert result["conf"] >= 70
    assert any("normal" in item["msg"].lower() for item in result["why"])


def test_fraud_phishing_detection():
    detector = HeuristicBaselineDetector()
    result = detector.analyze(
        from_addr="security@secure-bank-verify.xyz",
        reply_to=None,
        subject="Account will be suspended",
        body="Dear customer, your account will be suspended. Click http://secure-bank-verify.xyz to update KYC immediately.",
        attachment=None,
        threshold=0.5,
    )
    assert result["type"] == "fraud"
    assert result["action"] == "blocked"
    assert result["score"] >= 0.5
    assert len(result["why"]) >= 2
    # Check for specific diagnostic reasons
    reasons_text = " ".join(item["msg"] for item in result["why"])
    assert "urgent" in reasons_text.lower() or "act fast" in reasons_text.lower()
    assert "credentials" in reasons_text.lower() or "kyc" in reasons_text.lower()


def test_spam_detection():
    detector = HeuristicBaselineDetector()
    result = detector.analyze(
        from_addr="offers@deals-mart.biz",
        reply_to=None,
        subject="MEGA SALE: 70% off, limited time!",
        body="Buy now and get 70% off everything. Limited time offer. Unsubscribe at http://deals-mart.biz/unsub",
        attachment=None,
        threshold=0.5,
    )
    assert result["type"] == "spam"
    reasons_text = " ".join(item["msg"] for item in result["why"])
    assert "promotional" in reasons_text.lower() or "bulk spam" in reasons_text.lower()


def test_risky_attachment_and_reply_to_mismatch():
    detector = HeuristicBaselineDetector()
    result = detector.analyze(
        from_addr="accounts@micros0ft-support.com",
        reply_to="m.support77@gmail.com",
        subject="Invoice #4471 for your review",
        body="Hello, Please find the invoice attached. Sign in to your Microsoft account to confirm the payment details within 24 hours.",
        attachment="invoice.html",
        threshold=0.5,
    )
    assert result["type"] == "fraud"
    reasons_text = " ".join(item["msg"] for item in result["why"])
    assert "attachment" in reasons_text.lower()
    assert "reply-to" in reasons_text.lower()
