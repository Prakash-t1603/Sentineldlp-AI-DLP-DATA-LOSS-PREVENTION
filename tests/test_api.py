import pytest
from fastapi.testclient import TestClient
from backend.main import app, init_database

@pytest.fixture(scope="module")
def client():
    init_database()
    with TestClient(app) as c:
        yield c

def test_health_check(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "HEALTHY"

def test_admin_login(client):
    resp = client.post("/api/v1/auth/login", json={
        "username_or_email": "admin@sentineldlp.io",
        "password": "Admin@123456"
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["user"]["role"] == "admin"

def test_dashboard_summary_with_token(client):
    # 1. Login
    login_resp = client.post("/api/v1/auth/login", json={
        "username_or_email": "admin@sentineldlp.io",
        "password": "Admin@123456"
    })
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Query Dashboard
    dash_resp = client.get("/api/v1/dashboard/summary", headers=headers)
    assert dash_resp.status_code == 200
    dash_data = dash_resp.json()
    assert "stats" in dash_data
    assert "risk_distribution" in dash_data
    assert "alerts_by_severity" in dash_data

def test_reports_summary_with_token(client):
    login_resp = client.post("/api/v1/auth/login", json={
        "username_or_email": "admin@sentineldlp.io",
        "password": "Admin@123456"
    })
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    rep_resp = client.get("/api/v1/reports/summary", headers=headers)
    assert rep_resp.status_code == 200
    data = rep_resp.json()
    assert "metrics" in data

def test_upload_scan_unregistered_employee(client):
    login_resp = client.post("/api/v1/auth/login", json={
        "username_or_email": "admin@sentineldlp.io",
        "password": "Admin@123456"
    })
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    file_content = b"Govt of India Aadhaar Number: 5489 1234 8901 Name: Test User"
    files = {"file": ("test_aadhaar_doc.txt", file_content, "text/plain")}
    data = {"employee_id": "EMP-PREFLIGHT-USER"}

    resp = client.post("/api/v1/files/upload-scan", headers=headers, files=files, data=data)
    assert resp.status_code == 200
    res_data = resp.json()
    assert res_data["classification"] == "HIGHLY_CONFIDENTIAL"
    assert res_data["sensitivity_score"] >= 90.0
    assert any(e["entity_type"] == "AADHAAR_NUMBER" for e in res_data["detected_entities"])

def test_export_alerts_csv(client):
    # Direct endpoint
    resp1 = client.get("/reports/export/alerts.csv")
    assert resp1.status_code == 200
    assert "text/csv" in resp1.headers["content-type"]
    assert "Alert ID" in resp1.text

    # API prefixed endpoint
    resp2 = client.get("/api/v1/reports/export/alerts.csv")
    assert resp2.status_code == 200
    assert "text/csv" in resp2.headers["content-type"]
    assert "Alert ID" in resp2.text

def test_export_activities_csv(client):
    resp = client.get("/reports/export/activities.csv")
    assert resp.status_code == 200
    assert "text/csv" in resp.headers["content-type"]
    assert "Log ID" in resp.text

