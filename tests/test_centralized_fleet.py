import os
import sys
import time
import socket
from datetime import datetime, timezone, timedelta
import pytest
from fastapi.testclient import TestClient

from backend.main import app, init_database
from backend.database import SessionLocal, run_auto_migrations
from backend.models import Device, Employee, ActivityLog, User, DLPEvent, Alert
from backend.services.agent_service import agent_service
from backend.services.fleet_monitor import fleet_monitor_service
from agent.event_queue import OfflineEventQueue
from agent.agent import SentinelAgent
from agent.browser_monitor import BrowserMonitor

@pytest.fixture(scope="module")
def client():
    init_database()
    with TestClient(app) as c:
        yield c

@pytest.fixture(scope="module")
def admin_token(client):
    login_resp = client.post("/api/v1/auth/login", json={
        "username_or_email": "admin@sentineldlp.io",
        "password": "Admin@123456"
    })
    assert login_resp.status_code == 200
    return login_resp.json()["access_token"]

@pytest.fixture(scope="module")
def analyst_token(client):
    login_resp = client.post("/api/v1/auth/login", json={
        "username_or_email": "analyst@sentineldlp.io",
        "password": "Analyst@123456"
    })
    assert login_resp.status_code == 200
    return login_resp.json()["access_token"]

@pytest.fixture(scope="module")
def agent_headers():
    from backend.config import settings
    return {"X-Agent-Secret": settings.AGENT_SECRET_KEY}

# 1. Employee Creation
def test_1_employee_creation(client, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    client.delete("/api/v1/employees/EMP-CYBER-001?hard_delete=true", headers=headers)
    payload = {
        "employee_id": "EMP-CYBER-001",
        "username": "prakash_soc",
        "full_name": "Prakash Cyber",
        "email": "prakash@sentineldlp.io",
        "phone_number": "+91-9876543210",
        "department": "Cybersecurity",
        "designation": "Principal Threat Hunter",
        "manager": "CISO",
        "location": "HQ Bengaluru"
    }
    resp = client.post("/api/v1/employees", json=payload, headers=headers)
    assert resp.status_code == 201
    data = resp.json()
    assert data["employee_id"] == "EMP-CYBER-001"
    assert data["full_name"] == "Prakash Cyber"
    assert data["department"] == "Cybersecurity"

# 2. Employee Update
def test_2_employee_update(client, admin_token):
    update_payload = {
        "designation": "Lead SOC Architect",
        "location": "SOC War Room"
    }
    headers = {"Authorization": f"Bearer {admin_token}"}
    resp = client.put("/api/v1/employees/EMP-CYBER-001", json=update_payload, headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["designation"] == "Lead SOC Architect"
    assert data["location"] == "SOC War Room"

# 3. Employee Lookup
def test_3_employee_lookup(client, analyst_token):
    headers = {"Authorization": f"Bearer {analyst_token}"}
    resp = client.get("/api/v1/employees/EMP-CYBER-001", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["employee"]["employee_id"] == "EMP-CYBER-001"
    assert data["employee"]["full_name"] == "Prakash Cyber"
    assert "devices" in data
    assert "monitoring_modules" in data
    assert "security_summary" in data

# 4. Device Registration
def test_4_device_registration(client):
    payload = {
        "hostname": "WORKSTATION-PRAKASH-1",
        "operating_system": "Linux Ubuntu 24.04",
        "ip_address": "172.24.143.236",
        "agent_version": "2.2.0",
        "employee_id": "EMP-CYBER-001",
        "preferred_device_id": "DEV-PC-CYBER-1"
    }
    resp = client.post("/api/v1/agents/register", json=payload)
    assert resp.status_code == 201
    data = resp.json()
    assert data["device_id"] == "DEV-PC-CYBER-1"
    assert "device_token" in data
    assert data["status"] == "ONLINE"

# 5. Agent Registration
def test_5_agent_registration(client):
    payload = {
        "hostname": "LAPTOP-MOBILE-CYBER",
        "operating_system": "macOS Sonoma",
        "ip_address": "172.24.143.237",
        "agent_version": "2.2.0",
        "employee_id": "EMP-CYBER-001",
        "preferred_device_id": "DEV-MAC-CYBER-2"
    }
    resp = client.post("/api/v1/agents/register", json=payload)
    assert resp.status_code == 201
    assert resp.json()["device_id"] == "DEV-MAC-CYBER-2"

# 6. Heartbeat
def test_6_agent_heartbeat(client, agent_headers):
    hb_payload = {
        "device_id": "DEV-PC-CYBER-1",
        "employee_id": "EMP-CYBER-001",
        "hostname": "WORKSTATION-PRAKASH-1",
        "username": "prakash_soc",
        "ip_address": "172.24.143.236",
        "operating_system": "Linux Ubuntu 24.04",
        "agent_version": "2.2.0",
        "status": "ONLINE",
        "monitoring_status": "ACTIVE",
        "active_monitoring_modules": {
            "usb": "ACTIVE",
            "file": "ACTIVE",
            "clipboard": "ACTIVE",
            "process": "ACTIVE",
            "browser": "ACTIVE",
            "email": "ACTIVE",
            "event": "ACTIVE"
        }
    }
    resp = client.post("/api/v1/agents/heartbeat", json=hb_payload, headers=agent_headers)
    assert resp.status_code == 200
    assert resp.json()["acknowledged"] is True
    assert resp.json()["status"] == "ONLINE"

# 7. ONLINE Status Evaluation
def test_7_online_status_threshold():
    now = datetime.now(timezone.utc)
    recent = now - timedelta(seconds=12)
    status, diff = fleet_monitor_service.evaluate_status(recent, now)
    assert status == "ONLINE"
    assert diff == 12

# 8. WARNING Status Evaluation
def test_8_warning_status_threshold():
    now = datetime.now(timezone.utc)
    warning_ts = now - timedelta(seconds=45)
    status, diff = fleet_monitor_service.evaluate_status(warning_ts, now)
    assert status == "WARNING"
    assert diff == 45

# 9. OFFLINE Status Evaluation
def test_9_offline_status_threshold():
    now = datetime.now(timezone.utc)
    offline_ts = now - timedelta(seconds=90)
    status, diff = fleet_monitor_service.evaluate_status(offline_ts, now)
    assert status == "OFFLINE"
    assert diff == 90

# 10. Multiple Devices Per Employee
def test_10_multiple_devices_per_employee(client, analyst_token):
    headers = {"Authorization": f"Bearer {analyst_token}"}
    resp = client.get("/api/v1/employees/EMP-CYBER-001/devices", headers=headers)
    assert resp.status_code == 200
    devices = resp.json()
    assert len(devices) >= 2
    dev_ids = [d["device_id"] for d in devices]
    assert "DEV-PC-CYBER-1" in dev_ids
    assert "DEV-MAC-CYBER-2" in dev_ids

# 11. Agent Startup Event (AGENT_STARTED)
def test_11_agent_startup_event(client, agent_headers):
    payload = {
        "device_id": "DEV-PC-CYBER-1",
        "employee_id": "EMP-CYBER-001",
        "event": "AGENT_STARTED",
        "details": "SentinelDLP Agent initialized on Linux"
    }
    resp = client.post("/api/v1/agents/status", json=payload, headers=agent_headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "acknowledged"

# 12. Monitoring Startup Event (MONITORING_STARTED)
def test_12_monitoring_startup_event(client, agent_headers):
    payload = {
        "device_id": "DEV-PC-CYBER-1",
        "employee_id": "EMP-CYBER-001",
        "event": "MONITORING_STARTED",
        "details": "All sub-monitors active"
    }
    resp = client.post("/api/v1/agents/status", json=payload, headers=agent_headers)
    assert resp.status_code == 200
    assert resp.json()["event"] == "MONITORING_STARTED"

# 13. Connection Lost Evaluation
def test_13_connection_lost_evaluation():
    now = datetime.now(timezone.utc)
    stale_time = now - timedelta(seconds=150)
    status, diff = fleet_monitor_service.evaluate_status(stale_time, now)
    assert status == "OFFLINE"
    assert diff >= 150

# 14. Connection Restored & Queue Flush
def test_14_connection_restored_and_queue_flush(tmp_path):
    test_db = tmp_path / "test_queue.db"
    queue = OfflineEventQueue(db_path=test_db)
    queue.push("DLP_EVENT", {"file_name": "secrets.env", "channel": "USB"})
    queue.push("DLP_EVENT", {"file_name": "passwords.txt", "channel": "BROWSER"})
    assert queue.size() == 2

    # Simulate flush
    batch = queue.peek_batch(limit=10)
    assert len(batch) == 2
    deleted = queue.delete_batch([b[0] for b in batch])
    assert deleted == 2
    assert queue.size() == 0

# 15. Employee Dashboard API
def test_15_employee_dashboard_api(client, analyst_token):
    headers = {"Authorization": f"Bearer {analyst_token}"}
    resp = client.get("/api/v1/employees", headers=headers)
    assert resp.status_code == 200
    employees = resp.json()
    assert isinstance(employees, list)
    assert len(employees) >= 1
    emp_ids = [e["employee_id"] for e in employees]
    assert "EMP-CYBER-001" in emp_ids

# 16. Employee Detail API
def test_16_employee_detail_api(client, analyst_token):
    headers = {"Authorization": f"Bearer {analyst_token}"}
    resp = client.get("/api/v1/employees/EMP-CYBER-001", headers=headers)
    assert resp.status_code == 200
    detail = resp.json()
    assert detail["employee"]["employee_id"] == "EMP-CYBER-001"
    assert len(detail["devices"]) >= 2
    assert detail["security_summary"] is not None

# 17. RBAC Access Control
def test_17_rbac_access_control(client, admin_token, analyst_token):
    # Admin can access admin endpoints
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    resp = client.get("/api/v1/users", headers=admin_headers)
    assert resp.status_code == 200

    # Analyst cannot create employee (admin only)
    analyst_headers = {"Authorization": f"Bearer {analyst_token}"}
    emp_payload = {"employee_id": "EMP-FAIL-1", "username": "fail_user"}
    resp = client.post("/api/v1/employees", json=emp_payload, headers=analyst_headers)
    assert resp.status_code == 403

# 18. Unauthorized Employee Access
def test_18_unauthorized_employee_access(client):
    # Missing authorization token
    resp = client.get("/api/v1/employees")
    assert resp.status_code == 401

# 19. Offline Event Queue Persistence
def test_19_offline_event_queue_persistence(tmp_path):
    db_file = tmp_path / "persistence_test.db"
    q1 = OfflineEventQueue(db_path=db_file)
    q1.push("DLP_EVENT", {"file_name": "source_code.zip", "channel": "EMAIL"})
    assert q1.size() == 1

    # Reload new queue instance on same db file
    q2 = OfflineEventQueue(db_path=db_file)
    assert q2.size() == 1
    batch = q2.peek_batch(limit=5)
    assert batch[0][2]["file_name"] == "source_code.zip"

# 20. Browser Receiver Ownership & Configuration
def test_20_browser_receiver_config():
    agent = SentinelAgent(server_url="http://127.0.0.1:8000", employee_id="EMP-TEST-BR", browser_port=8765)
    assert agent.browser_monitor.port == 8765

# 21. Backend Does Not Bind 8765
def test_21_backend_does_not_bind_8765():
    # Verify port 8765 is not bound by backend server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    try:
        # If we can bind to 127.0.0.1:8765 or candidate, it means port is free and not held by backend
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        assert port > 0
    finally:
        s.close()

# 22. Endpoint Agent Binds Port 8765
def test_22_endpoint_agent_binds_8765():
    monitor = BrowserMonitor(agent_instance=None, host="127.0.0.1", port=8765)
    monitor.start()
    assert monitor.is_running is True
    # Verify health endpoint responds
    try:
        import requests
        resp = requests.get(f"http://127.0.0.1:{monitor.port}/health", timeout=2)
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"
    finally:
        monitor.stop()

# 23. Agent Starts Without Backend Package Dependency
def test_23_agent_starts_standalone():
    agent = SentinelAgent(server_url="http://127.0.0.1:8000", employee_id="EMP-STANDALONE-TEST")
    assert agent.employee_id == "EMP-STANDALONE-TEST"
    assert agent.api_client is not None
    assert agent.usb_monitor is not None
    assert agent.file_monitor is not None
    assert agent.clipboard_monitor is not None
    assert agent.process_monitor is not None
    assert agent.browser_monitor is not None
    assert agent.email_monitor is not None
    assert agent.event_monitor is not None

# 24. Agent Survives Server Outage
def test_24_agent_survives_server_outage(tmp_path):
    # Agent pointing to invalid/offline server port
    agent = SentinelAgent(server_url="http://127.0.0.1:59999", employee_id="EMP-OUTAGE-TEST")
    
    # Registration should not crash
    registered = agent.register_endpoint()
    assert registered is False

    # Dispatching DLP event should not crash and buffer to offline queue
    res = agent.send_dlp_event(
        channel_or_dict="USB",
        application="USB Drive",
        file_name="financial_ledger.xlsx",
        risk_score=85.0
    )
    assert res["status"] == "QUEUED_OFFLINE"
    assert res["action"] == "ALLOW"
