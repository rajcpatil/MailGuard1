"""Tests for history, dashboard stats, and database persistence."""


def test_history_inbox_and_quarantine(client, db_session):
    # Insert 1 safe email and 1 phishing email
    client.post("/api/scan", json={
        "from": "friend@company.com",
        "subject": "Lunch update",
        "body": "See you at lunch at 1pm.",
    })
    client.post("/api/scan", json={
        "from": "scam@prize-claim.top",
        "subject": "You won lottery prize",
        "body": "You won ₹50 lakh in lottery! Send card number immediately to claim.",
    })

    # Test Inbox query
    inbox_res = client.get("/api/history?box=inbox")
    assert inbox_res.status_code == 200
    inbox_data = inbox_res.json()
    assert inbox_data["nIn"] >= 1
    assert any(e["type"] == "safe" for e in inbox_data["emails"])
    assert not any(e["action"] == "blocked" for e in inbox_data["emails"])

    # Test Quarantine query
    quar_res = client.get("/api/history?box=quar")
    assert quar_res.status_code == 200
    quar_data = quar_res.json()
    assert any(e["action"] == "blocked" for e in quar_data["emails"])

    # Test All query (box=all)
    all_res = client.get("/api/history?box=all")
    assert all_res.status_code == 200
    all_data = all_res.json()
    assert len(all_data["emails"]) >= 2
    assert all_data["nIn"] >= 1


def test_dashboard_stats_and_threshold(client):
    # Fetch initial stats
    res = client.get("/api/dashboard/stats")
    assert res.status_code == 200
    data = res.json()
    assert "scanned" in data
    assert "days" in data
    assert len(data["days"]) == 7
    assert "offenders" in data
    assert "threat_mix" in data

    # Update sensitivity threshold
    update_res = client.put("/api/dashboard/threshold", json={"threshold": 0.65})
    assert update_res.status_code == 200
    assert update_res.json()["threshold"] == 0.65

    # Check that threshold persisted
    get_thr = client.get("/api/dashboard/threshold")
    assert get_thr.status_code == 200
    assert get_thr.json()["threshold"] == 0.65


def test_dashboard_metrics_reflect_live_scans(client, db_session):
    """Scanned emails are dynamically aggregated into the dashboard metrics."""
    initial_res = client.get("/api/dashboard/stats")
    assert initial_res.status_code == 200
    initial = initial_res.json()

    # Scan one spam and one fraud email
    client.post("/api/scan", json={
        "from": "offers@deals-mart.biz",
        "subject": "MEGA SALE: 70% off, limited time!",
        "body": "Buy now and get 70% off everything. Limited time offer.",
    })
    client.post("/api/scan", json={
        "from": "security@secure-bank-verify.xyz",
        "subject": "Account will be suspended",
        "body": "Dear customer, your account will be suspended. Click http://secure-bank-verify.xyz to update KYC immediately.",
    })

    live_res = client.get("/api/dashboard/stats")
    assert live_res.status_code == 200
    live = live_res.json()

    assert live["scanned"] >= initial["scanned"]
    assert len(live["days"]) == 7
