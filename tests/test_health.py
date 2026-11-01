"""Tests for the health check and root endpoints."""


def test_health_check(client):
    """Ensure /api/health returns HTTP 200 and healthy status."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "MailGuard"
    assert data["version"] == "1.0.0"


def test_api_root(client):
    """Ensure /api returns HTTP 200 and available endpoints."""
    response = client.get("/api")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "online"
    assert "endpoints" in data
    assert "health" in data["endpoints"]
    assert "scan" in data["endpoints"]


def test_frontend_serving(client):
    """Ensure / serves the MailGuard HTML file."""
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")
    assert "<title>MailGuard</title>" in response.text


def test_companion_js_serving(client):
    """Ensure /mailguard-api.js serves the companion integration script."""
    response = client.get("/mailguard-api.js")
    assert response.status_code == 200
    assert "javascript" in response.headers.get("content-type", "")
    assert "checkBackend" in response.text
