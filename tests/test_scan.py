"""Tests for scan API endpoints."""

from backend.models import ScanRecord


def test_scan_email_success(client, db_session):
    payload = {
        "from": "security@secure-bank-verify.xyz",
        "replyTo": "",
        "subject": "Account will be suspended",
        "body": "Dear customer, your account will be suspended. Click http://secure-bank-verify.xyz to update KYC immediately.",
        "attach": "",
    }
    response = client.post("/api/scan", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["type"] == "fraud"
    assert data["action"] == "blocked"
    assert data["score"] >= 0.5
    assert len(data["why"]) > 0
    assert "id" in data

    # Verify database persistence
    db_record = db_session.query(ScanRecord).filter(ScanRecord.id == data["id"]).first()
    assert db_record is not None
    assert db_record.verdict_type == "fraud"
    assert db_record.sender == "security@secure-bank-verify.xyz"


def test_scan_email_invalid_input(client):
    # Invalid sender (missing '@')
    payload = {
        "from": "invalid-sender",
        "subject": "Hello",
        "body": "Test message",
    }
    response = client.post("/api/scan", json=payload)
    assert response.status_code == 422


def test_scan_receive_sample(client, db_session):
    response = client.post("/api/scan/receive?sample_index=0")
    assert response.status_code == 200
    data = response.json()
    assert data["from"] == "hr@company.com"
    assert data["type"] == "safe"
    assert data["action"] == "delivered"


def test_get_scan_detail_and_restore(client, db_session):
    # First create a blocked scan
    payload = {
        "from": "phish@secure-bank-verify.xyz",
        "subject": "Urgent verification required",
        "body": "Verify your password and otp immediately or be blocked within 24 hours.",
    }
    res = client.post("/api/scan", json=payload)
    scan_id = res.json()["id"]

    # Fetch scan detail
    detail_res = client.get(f"/api/scan/{scan_id}")
    assert detail_res.status_code == 200
    assert detail_res.json()["action"] == "blocked"

    # Restore scan
    restore_res = client.post(f"/api/scan/{scan_id}/restore")
    assert restore_res.status_code == 200
    assert restore_res.json()["action"] == "delivered"

    # Verify updated in database
    updated = db_session.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    assert updated.action == "delivered"
    assert updated.is_restored is True


def test_get_nonexistent_scan(client):
    response = client.get("/api/scan/999999")
    assert response.status_code == 404
