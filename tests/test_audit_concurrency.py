import pytest
import concurrent.futures
from fastapi.testclient import TestClient
from backend.main import app, init_database
from backend.models import Employee, Device, Alert
from backend.database import SessionLocal

@pytest.fixture(scope="module")
def client():
    init_database()
    with TestClient(app) as c:
        yield c

@pytest.fixture(scope="module")
def auth_headers(client):
    login_resp = client.post("/api/v1/auth/login", json={
        "username_or_email": "admin@sentineldlp.io",
        "password": "Admin@123456"
    })
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

def test_concurrent_agent_events(client, auth_headers):
    db = SessionLocal()
    
    # EMP-001 (Prakash T)
    emp1 = db.query(Employee).filter_by(employee_id="EMP-001").first()
    if not emp1:
        emp1 = Employee(employee_id="EMP-001", full_name="Prakash T", username="prakash", status="ONLINE", active=True, risk_score=0.0)
        db.add(emp1)
    else:
        emp1.full_name = "Prakash T"

    # EMP-002 (Dhya P)
    emp2 = db.query(Employee).filter_by(employee_id="EMP-002").first()
    if not emp2:
        emp2 = Employee(employee_id="EMP-002", full_name="Dhya P", username="dhya", status="ONLINE", active=True, risk_score=0.0)
        db.add(emp2)
    else:
        emp2.full_name = "Dhya P"
        
    db.commit()
    db.close()

    def register_and_send(employee_id, device_id, username, hostname):
        reg_resp = client.post("/api/v1/agents/register", json={
            "machine_id": device_id,
            "hostname": hostname,
            "ip_address": f"192.168.1.{len(employee_id)}",
            "username": username, "employee_id": employee_id,
            "os_info": "Windows",
            "agent_version": "1.0.0"
        })
        assert reg_resp.status_code == 201, f"Register failed: {reg_resp.text}"
        token = reg_resp.json()["device_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        alert_payload = {
            "employee_id": employee_id,
            "device_id": device_id,
            "alert_type": "EXFILTRATION_CLIPBOARD_LEAK",
            "severity": "CRITICAL",
            "risk_score": 95.0,
            "description": f"🚨 CONFIDENTIAL DATA from {employee_id}",
            "source": "CLIPBOARD_MONITOR",
            "status": "OPEN"
        }
        resp = client.post("/api/v1/alerts", json=alert_payload, headers=headers)
        return resp.status_code, resp.json()

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        f1 = executor.submit(register_and_send, "EMP-001", "EMP-PC-DEVIL", "prakash", "EMP-PC-DEVIL")
        f2 = executor.submit(register_and_send, "EMP-002", "EMP-PC-WIN", "dhya", "EMP-PC-WIN")

        r1_status, r1_data = f1.result()
        r2_status, r2_data = f2.result()

    print("\n--- Concurrency Test Results ---")
    print(f"EMP-001 Request Data Sent: EMP-001")
    print(f"EMP-001 DB Attribution Received: {r1_data.get('employee_id')} | {r1_data.get('employee_name')} | Device: {r1_data.get('device_id')}")
    print(f"EMP-002 Request Data Sent: EMP-002")
    print(f"EMP-002 DB Attribution Received: {r2_data.get('employee_id')} | {r2_data.get('employee_name')} | Device: {r2_data.get('device_id')}")
    print("--------------------------------")

    assert r1_data["employee_id"] == "EMP-001", f"Expected EMP-001, got {r1_data.get('employee_id')}"
    assert r1_data["employee_name"] == "Prakash T", f"Expected Prakash T, got {r1_data.get('employee_name')}"
    assert "EMP-001" in r1_data["description"], f"Alert desc corrupted: {r1_data['description']}"

    assert r2_data["employee_id"] == "EMP-002", f"Expected EMP-002, got {r2_data.get('employee_id')}"
    assert r2_data["employee_name"] == "Dhya P", f"Expected Dhya P, got {r2_data.get('employee_name')}"
    assert "EMP-002" in r2_data["description"], f"Alert desc corrupted: {r2_data['description']}"
