"""
SentinelDLP - Comprehensive Employee & Device Isolation Test Suite
===================================================================
Validates strict endpoint-to-employee identity isolation across the full stack:
Agent -> API Client -> FastAPI Backend -> Database -> DLP Engine -> Alerts -> Incidents -> SOC Profile.

Fleet Configuration:
- EMP-001 = Prakash T = EMP-PC-TEST01 = Linux
- EMP-002 = Dhya P = EMP-PC-WIN = Windows
- EMP-003 = Dhya P = EMP-PC-WIN03 = Windows 11
"""

import os
import json
import base64
import tempfile
import pytest
from pathlib import Path
from fastapi.testclient import TestClient

from backend.main import app, init_database
from backend.database import SessionLocal, Base, engine
from backend.models import Employee, Device, DLPEvent, Alert, Incident, ActivityLog, User
from backend.services.alert_service import alert_service
from backend.services.agent_service import agent_service
from backend.config import settings
from agent.config import (
    get_configured_employee_id, _is_generated_employee_id,
    normalize_employee_id, validate_employee_id, normalize_server_url,
    get_or_generate_stable_device_id
)
from agent.agent import SentinelAgent, run_agent
from agent.api_client import AgentAPIClient
from agent.browser_monitor import BrowserMonitor

TEST_DATA_DIR = Path(__file__).parent / "test_data"

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

@pytest.fixture(autouse=True)
def setup_fleet():
    """Ensure baseline fleet is seeded before each test."""
    db = SessionLocal()
    try:
        # Clear events, alerts, incidents
        db.query(Incident).delete()
        db.query(Alert).delete()
        db.query(DLPEvent).delete()

        # Seed EMP-001 (Prakash T)
        emp1 = db.query(Employee).filter(Employee.employee_id == "EMP-001").first()
        if not emp1:
            emp1 = Employee(
                employee_id="EMP-001",
                username="prakash",
                full_name="Prakash T",
                email="prakash@sentineldlp.io",
                department="Engineering",
                designation="Security Lead",
                hostname="EMP-PC-TEST01",
                operating_system="Linux",
                ip_address="172.24.143.236",
                status="ONLINE",
                active=True,
                risk_score=0.0
            )
            db.add(emp1)
        else:
            emp1.full_name = "Prakash T"
            emp1.active = True
            emp1.risk_score = 0.0

        # Seed EMP-002 (Dhya P)
        emp2 = db.query(Employee).filter(Employee.employee_id == "EMP-002").first()
        if not emp2:
            emp2 = Employee(
                employee_id="EMP-002",
                username="dhya",
                full_name="Dhya P",
                email="dhya@sentineldlp.io",
                department="Finance",
                designation="Financial Analyst",
                hostname="EMP-PC-WIN",
                operating_system="Windows 11",
                ip_address="192.168.1.150",
                status="ONLINE",
                active=True,
                risk_score=0.0
            )
            db.add(emp2)
        else:
            emp2.full_name = "Dhya P"
            emp2.active = True
            emp2.risk_score = 0.0

        # Seed EMP-003 (Dhya P)
        emp3 = db.query(Employee).filter(Employee.employee_id == "EMP-003").first()
        if not emp3:
            emp3 = Employee(
                employee_id="EMP-003",
                username="dhya_cs",
                full_name="Dhya P",
                email="dhya.p@sentineldlp.io",
                department="CS",
                designation="Software Engineer",
                hostname="EMP-PC-WIN03",
                operating_system="Windows 11",
                ip_address="192.168.1.155",
                status="ONLINE",
                active=True,
                risk_score=0.0
            )
            db.add(emp3)
        else:
            emp3.full_name = "Dhya P"
            emp3.department = "CS"
            emp3.active = True
            emp3.risk_score = 0.0

        # Seed Devices
        dev1 = db.query(Device).filter(Device.device_id == "EMP-PC-TEST01").first()
        if not dev1:
            dev1 = Device(
                device_id="EMP-PC-TEST01",
                hostname="EMP-PC-TEST01",
                employee_id="EMP-001",
                username="prakash",
                operating_system="Linux",
                device_token="dev-tok-emp-pc-test01",
                status="ONLINE",
                is_active=True
            )
            db.add(dev1)
        else:
            dev1.employee_id = "EMP-001"

        dev2 = db.query(Device).filter(Device.device_id == "EMP-PC-WIN").first()
        if not dev2:
            dev2 = Device(
                device_id="EMP-PC-WIN",
                hostname="EMP-PC-WIN",
                employee_id="EMP-002",
                username="dhya",
                operating_system="Windows 11",
                device_token="dev-tok-emp-pc-win",
                status="ONLINE",
                is_active=True
            )
            db.add(dev2)
        else:
            dev2.employee_id = "EMP-002"

        db.commit()
    finally:
        db.close()


# ==============================================================================
# 1. BOM Normalization Tests
# ==============================================================================
def test_1_bom_normalization_decoded_artifacts():
    assert normalize_employee_id("ï»¿EMP-003") == "EMP-003"
    assert normalize_employee_id("ï»¿EMP-WIN-01") == "EMP-WIN-01"

def test_2_bom_normalization_unicode_character():
    assert normalize_employee_id("\ufeffEMP-003") == "EMP-003"
    assert normalize_employee_id("\ufeff\ufeffEMP-003") == "EMP-003"

def test_3_whitespace_normalization():
    assert normalize_employee_id("  EMP-003  ") == "EMP-003"
    assert normalize_employee_id("\t\nEMP-003\r\n") == "EMP-003"
    assert validate_employee_id("EMP-003") is True
    assert validate_employee_id("ï»¿EMP-003") is False


# ==============================================================================
# 2. Server URL Normalization Tests
# ==============================================================================
def test_4_server_url_normalization_without_scheme():
    assert normalize_server_url("172.24.143.236:8000") == "http://172.24.143.236:8000"
    assert normalize_server_url("localhost:8000") == "http://localhost:8000"
    assert normalize_server_url("172.24.143.236:8000/api/v1") == "http://172.24.143.236:8000"

def test_5_server_url_normalization_with_scheme():
    assert normalize_server_url("http://172.24.143.236:8000") == "http://172.24.143.236:8000"
    assert normalize_server_url("http://172.24.143.236:8000/") == "http://172.24.143.236:8000"
    assert normalize_server_url("https://172.24.143.236:8000") == "https://172.24.143.236:8000"
    assert normalize_server_url("https://172.24.143.236:8000/api") == "https://172.24.143.236:8000"


# ==============================================================================
# 3. CLI Precedence & Agent APIClient Propagation Tests
# ==============================================================================
def test_6_cli_employee_id_overrides_env_and_file(tmp_path, monkeypatch):
    emp_file = tmp_path / ".employee_id"
    emp_file.write_text("EMP-001")
    monkeypatch.setattr("agent.config.EMPLOYEE_ID_FILE", emp_file)
    monkeypatch.setenv("SENTINEL_EMPLOYEE_ID", "EMP-WIN-01")

    # Pass --employee-id EMP-003
    agent = SentinelAgent(employee_id="EMP-003", server_url="172.24.143.236:8000")
    assert agent.employee_id == "EMP-003"
    assert agent.server_url == "http://172.24.143.236:8000"
    assert agent.api_client.employee_id == "EMP-003"
    assert agent.api_client.server_url == "http://172.24.143.236:8000"

def test_7_agent_api_client_uses_instance_employee_id(tmp_path):
    client_inst = AgentAPIClient(
        server_url="172.24.143.236:8000",
        employee_id="ï»¿EMP-003",
        device_id="DEV-TEST-WIN03"
    )
    assert client_inst.employee_id == "EMP-003"
    assert client_inst.server_url == "http://172.24.143.236:8000"
    assert client_inst.api_base == "http://172.24.143.236:8000/api/v1"
    headers = client_inst._get_headers()
    assert headers["X-Employee-Id"] == "EMP-003"
    assert headers["X-Device-Id"] == "DEV-TEST-WIN03"


# ==============================================================================
# 4. Device ID Stability & Separation Tests
# ==============================================================================
def test_8_device_id_remains_stable_after_restart(tmp_path, monkeypatch):
    dev_config_file = tmp_path / ".device_config.json"
    monkeypatch.setattr("agent.config.DEVICE_CONFIG_FILE", dev_config_file)

    dev_id1 = get_or_generate_stable_device_id()
    assert dev_id1.startswith("EMP-PC-")

    # Simulate restart
    dev_id2 = get_or_generate_stable_device_id()
    assert dev_id1 == dev_id2


# ==============================================================================
# 5. Device Collision Prevention (HTTP 409 Conflict)
# ==============================================================================
def test_9_device_belonging_to_emp001_cannot_be_registered_by_emp003(client, auth_headers):
    # EMP-PC-TEST01 is already registered to EMP-001.
    # Attempting to register EMP-PC-TEST01 under EMP-003 must be rejected with HTTP 409.
    payload = {
        "hostname": "EMP-PC-TEST01",
        "operating_system": "Windows 11",
        "ip_address": "192.168.1.155",
        "username": "dhya",
        "full_name": "Dhya P",
        "email": "dhya.p@sentineldlp.io",
        "department": "CS",
        "designation": "Software Engineer",
        "agent_version": "2.1.0",
        "employee_id": "EMP-003",
        "preferred_device_id": "EMP-PC-TEST01"  # Collision!
    }

    resp = client.post("/api/v1/agents/register", json=payload, headers=auth_headers)
    assert resp.status_code == 409
    detail = resp.json()["detail"]
    assert detail["error"] == "DEVICE_ALREADY_REGISTERED"
    assert "already registered to employee 'EMP-001'" in detail["message"]

    # Verify device in DB is still registered to EMP-001 (not hijacked)
    db = SessionLocal()
    try:
        dev = db.query(Device).filter(Device.device_id == "EMP-PC-TEST01").first()
        assert dev.employee_id == "EMP-001"
    finally:
        db.close()


# ==============================================================================
# 6. EMP-003 Windows Event & SOC Isolation Tests
# ==============================================================================
def test_10_emp003_windows_event_creates_alert_for_emp003(client, auth_headers):
    payload = {
        "channel": "BROWSER",
        "application": "Chrome Browser",
        "domain": "transfer.example.com",
        "file_name": "q4_financial_report.xlsx",
        "file_size": 2048,
        "extracted_text": "CONFIDENTIAL FINANCIAL REPORT: PAN ABCDE1234F, Aadhaar 5489 1234 8901",
        "employee_id": "EMP-003",
        "device_id": "EMP-PC-WIN03"
    }

    resp = client.post("/api/v1/dlp/browser-event", json=payload, headers=auth_headers)
    assert resp.status_code == 200
    res_data = resp.json()
    assert res_data["action"] in ("BLOCK", "WARN")
    assert res_data["alert_created"] is True

    db = SessionLocal()
    try:
        # Check Alert for EMP-003
        alerts = db.query(Alert).filter(Alert.employee_id == "EMP-003").all()
        assert len(alerts) >= 1
        assert alerts[0].employee.full_name == "Dhya P"
        assert alerts[0].employee.department == "CS"

        # Check Incident for EMP-003
        incidents = db.query(Incident).filter(Incident.employee_id == "EMP-003").all()
        assert len(incidents) >= 1
        assert incidents[0].employee_id == "EMP-003"

        # EMP-001 (Prakash T) must have 0 events, 0 alerts, 0 incidents
        emp1_alerts = db.query(Alert).filter(Alert.employee_id == "EMP-001").count()
        emp1_incidents = db.query(Incident).filter(Incident.employee_id == "EMP-001").count()
        emp1_events = db.query(DLPEvent).filter(DLPEvent.employee_id == "EMP-001").count()
        emp1 = db.query(Employee).filter(Employee.employee_id == "EMP-001").first()

        assert emp1_alerts == 0
        assert emp1_incidents == 0
        assert emp1_events == 0
        assert emp1.risk_score == 0.0
    finally:
        db.close()


# ==============================================================================
# 7. Offline Queue Identity Preservation
# ==============================================================================
def test_11_offline_queue_preserves_emp003_event(tmp_path, monkeypatch, client, auth_headers):
    from agent.event_queue import OfflineEventQueue
    queue_db = tmp_path / "offline_events.db"
    test_queue = OfflineEventQueue(db_path=queue_db)
    monkeypatch.setattr("agent.api_client.event_queue", test_queue)

    api_client = AgentAPIClient(
        server_url="http://testserver",
        employee_id="EMP-003",
        device_id="EMP-PC-WIN03"
    )

    test_payload = {
        "event_id": "DLP-OFFLINE-003-WIN",
        "employee_id": "EMP-003",
        "device_id": "EMP-PC-WIN03",
        "channel": "BROWSER",
        "application": "Edge",
        "destination": "dropbox.com",
        "file_name": "source_code_archive.zip",
        "file_size": 8192,
        "sensitive_data_detected": True,
        "risk_score": 90.0,
        "risk_level": "CRITICAL",
        "action": "BLOCK",
        "details": "Offline code leak blocked"
    }

    test_queue.push("DLP_EVENT", test_payload)
    batch = test_queue.peek_batch(limit=5)
    assert len(batch) == 1
    assert batch[0][2]["employee_id"] == "EMP-003"
    assert batch[0][2]["device_id"] == "EMP-PC-WIN03"
    assert batch[0][2]["event_id"] == "DLP-OFFLINE-003-WIN"

    # Flush to server
    resp = client.post("/api/v1/dlp/events", json=batch[0][2], headers=auth_headers)
    assert resp.status_code == 200

    db = SessionLocal()
    try:
        ev = db.query(DLPEvent).filter(DLPEvent.event_id == "DLP-OFFLINE-003-WIN").first()
        assert ev is not None
        assert ev.employee_id == "EMP-003"
        assert ev.device_id == "EMP-PC-WIN03"
        assert ev.employee.full_name == "Dhya P"
    finally:
        db.close()


# ==============================================================================
# 8. Browser Receiver Localhost Binding
# ==============================================================================
def test_12_browser_monitor_binds_to_localhost_by_default():
    bm = BrowserMonitor(agent_instance=None)
    assert bm.host == "127.0.0.1"
    assert bm.port == 8765
