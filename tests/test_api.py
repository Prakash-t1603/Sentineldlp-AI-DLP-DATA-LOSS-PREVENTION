import pytest
from fastapi.testclient import TestClient
from backend.main import app, init_database

@pytest.fixture(scope="module")
def client():
    init_database()
    from run import seed_demo_data
    seed_demo_data()
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

def test_upload_scan_registered_employee(client):
    login_resp = client.post("/api/v1/auth/login", json={
        "username_or_email": "admin@sentineldlp.io",
        "password": "Admin@123456"
    })
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    file_content = b"Govt of India Aadhaar Number: 5489 1234 8901 Name: Test User"
    files = {"file": ("test_aadhaar_doc.txt", file_content, "text/plain")}
    data = {"employee_id": "EMP-DEV-01"}

    resp = client.post("/api/v1/files/upload-scan", headers=headers, files=files, data=data)
    assert resp.status_code == 200
    res_data = resp.json()
    assert res_data["classification"] == "HIGHLY_CONFIDENTIAL"
    assert res_data["sensitivity_score"] >= 90.0
    assert any(e["entity_type"] == "AADHAAR_NUMBER" for e in res_data["detected_entities"])

def test_upload_scan_unregistered_employee_rejected(client):
    login_resp = client.post("/api/v1/auth/login", json={
        "username_or_email": "admin@sentineldlp.io",
        "password": "Admin@123456"
    })
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    file_content = b"Govt of India Aadhaar Number: 5489 1234 8901 Name: Test User"
    files = {"file": ("test_aadhaar_doc.txt", file_content, "text/plain")}
    data = {"employee_id": "EMP-NONEXISTENT-PREFLIGHT"}

    resp = client.post("/api/v1/files/upload-scan", headers=headers, files=files, data=data)
    assert resp.status_code == 404

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

def test_delete_single_alert_and_bulk_delete(client):
    # 1. Login
    login_resp = client.post("/api/v1/auth/login", json={
        "username_or_email": "admin@sentineldlp.io",
        "password": "Admin@123456"
    })
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Create test alerts
    created_ids = []
    for i in range(3):
        res = client.post("/api/v1/alerts", headers=headers, json={
            "employee_id": "EMP-DEV-01",
            "alert_type": f"TEST_ALERT_{i}",
            "severity": "LOW",
            "risk_score": 10.0,
            "description": f"Test alert for deletion #{i}",
            "source": "TEST_RUNNER"
        })
        assert res.status_code == 201
        created_ids.append(res.json()["id"])

    # 3. Test delete single alert
    del_id = created_ids.pop(0)
    del_resp = client.delete(f"/api/v1/alerts/{del_id}", headers=headers)
    assert del_resp.status_code == 200
    assert del_resp.json()["alert_id"] == del_id

    # 4. Verify deleted alert is not found
    get_del = client.get(f"/api/v1/alerts/{del_id}", headers=headers)
    assert get_del.status_code == 404

    # 5. Test bulk delete remaining test alerts
    bulk_resp = client.post("/api/v1/alerts/bulk-delete", headers=headers, json={
        "alert_ids": created_ids
    })
    assert bulk_resp.status_code == 200
    bulk_data = bulk_resp.json()
    assert bulk_data["deleted_count"] == len(created_ids)
    assert set(bulk_data["deleted_ids"]) == set(created_ids)

def test_bulk_delete_employees_api(client):
    login_resp = client.post("/api/v1/auth/login", json={
        "username_or_email": "admin@sentineldlp.io",
        "password": "Admin@123456"
    })
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Create 2 temporary employees
    for emp_id in ["EMP-BULK-1", "EMP-BULK-2"]:
        client.delete(f"/api/v1/employees/{emp_id}?hard_delete=true", headers=headers)
        res = client.post("/api/v1/employees", headers=headers, json={
            "employee_id": emp_id,
            "username": f"bulk_user_{emp_id.lower()}",
            "full_name": f"Bulk User {emp_id}"
        })
        assert res.status_code == 201

    # Bulk delete (deactivate)
    bulk_res = client.post("/api/v1/employees/bulk-delete", headers=headers, json={
        "employee_ids": ["EMP-BULK-1", "EMP-BULK-2"],
        "hard_delete": False
    })
    assert bulk_res.status_code == 200
    assert bulk_res.json()["deleted_count"] == 2

    # Clean up with hard delete
    hard_res = client.post("/api/v1/employees/bulk-delete", headers=headers, json={
        "employee_ids": ["EMP-BULK-1", "EMP-BULK-2"],
        "hard_delete": True
    })
    assert hard_res.status_code == 200
    assert hard_res.json()["deleted_count"] == 2

def test_bulk_delete_files_api(client, tmp_path):
    login_resp = client.post("/api/v1/auth/login", json={
        "username_or_email": "admin@sentineldlp.io",
        "password": "Admin@123456"
    })
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Create 2 temporary files
    f1 = tmp_path / "test_file_bulk_1.txt"
    f2 = tmp_path / "test_file_bulk_2.txt"
    f1.write_text("Confidential financial report details")
    f2.write_text("Internal engineering documentation")

    # Scan 2 files
    res1 = client.post("/api/v1/files/scan", headers=headers, json={
        "filepath": str(f1),
        "employee_id": "EMP-DEV-01"
    })
    res2 = client.post("/api/v1/files/scan", headers=headers, json={
        "filepath": str(f2),
        "employee_id": "EMP-DEV-01"
    })
    assert res1.status_code == 200
    assert res2.status_code == 200

    # List files to get IDs
    files_list = client.get("/api/v1/files", headers=headers).json()
    test_file_ids = [f["id"] for f in files_list if "test_file_bulk" in f["filepath"]]
    assert len(test_file_ids) >= 2

    # Bulk delete files
    bulk_res = client.post("/api/v1/files/bulk-delete", headers=headers, json={
        "file_ids": test_file_ids
    })
    assert bulk_res.status_code == 200
    assert bulk_res.json()["deleted_count"] == len(test_file_ids)




