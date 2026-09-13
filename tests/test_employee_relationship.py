import os
import sys
import time
from datetime import datetime, timezone, timedelta
import pytest
from fastapi.testclient import TestClient

from backend.main import app, init_database
from backend.database import SessionLocal, run_auto_migrations
from backend.models import Device, Employee, ActivityLog, User, DLPEvent, Alert, Incident
from backend.services.agent_service import agent_service
from backend.services.fleet_monitor import fleet_monitor_service

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


# 1. Manual Employee Creation: Starts OFFLINE with NO fake devices or heartbeats
def test_1_manual_employee_creation_offline_unassigned(client, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    client.delete("/api/v1/employees/EMP-REL-001?hard_delete=true", headers=headers)
    
    payload = {
        "employee_id": "EMP-REL-001",
        "username": "rajesh_kumar",
        "full_name": "Rajesh Kumar",
        "email": "rajesh.kumar@sentineldlp.io",
        "phone_number": "+91-9876543299",
        "department": "Engineering",
        "designation": "Backend Lead",
        "manager": "CTO Office",
        "location": "Bengaluru Tech Park"
    }
    resp = client.post("/api/v1/employees", json=payload, headers=headers)
    assert resp.status_code == 201
    data = resp.json()
    assert data["employee_id"] == "EMP-REL-001"
    assert data["full_name"] == "Rajesh Kumar"
    assert data["status"] == "OFFLINE"
    assert data["hostname"] in ["NOT_ASSIGNED", "NOT ASSIGNED"]
    assert data["last_seen"] is None
    assert data["last_seen_seconds_ago"] in [None, 0]


# 2. Strict Agent Registration: Unknown employee ID must return 404 and NOT auto-create employee
def test_2_unknown_employee_registration_rejected(client):
    payload = {
        "hostname": "UNKNOWN-DEV-PC",
        "operating_system": "Windows 11",
        "ip_address": "192.168.1.100",
        "agent_version": "2.2.0",
        "employee_id": "NON_EXISTENT_EMP_999",
        "preferred_device_id": "DEV-PC-ROGUE"
    }
    resp = client.post("/api/v1/agents/register", json=payload)
    assert resp.status_code in [404, 400]
    detail = resp.json().get("detail", {})
    if isinstance(detail, dict):
        assert detail.get("error") == "EMPLOYEE_NOT_REGISTERED"

    # Verify no rogue employee was auto-created
    db = SessionLocal()
    try:
        rogue_emp = db.query(Employee).filter(Employee.employee_id == "NON_EXISTENT_EMP_999").first()
        assert rogue_emp is None
    finally:
        db.close()


# 3. Valid Agent Registration: Links Device to Employee and transitions status to ONLINE
def test_3_valid_agent_registration_links_device_and_sets_online(client):
    payload = {
        "hostname": "DEV-LAPTOP-RAJESH",
        "operating_system": "Linux Ubuntu 24.04",
        "ip_address": "172.24.143.210",
        "agent_version": "2.2.0",
        "employee_id": "EMP-REL-001",
        "preferred_device_id": "DEV-RAJESH-01"
    }
    resp = client.post("/api/v1/agents/register", json=payload)
    assert resp.status_code == 201
    data = resp.json()
    assert data["device_id"] == "DEV-RAJESH-01"
    assert data["employee_id"] == "EMP-REL-001"
    assert data["status"] == "ONLINE"
    assert "device_token" in data

    # Verify Employee record status is now ONLINE and hostname is updated
    db = SessionLocal()
    try:
        emp = db.query(Employee).filter(Employee.employee_id == "EMP-REL-001").first()
        assert emp is not None
        assert emp.status == "ONLINE"
        assert emp.hostname == "DEV-LAPTOP-RAJESH"
        assert emp.ip_address == "172.24.143.210"
        assert emp.last_seen is not None
    finally:
        db.close()


# 4. Agent Heartbeat: Refreshes last_seen for Device and Employee
def test_4_agent_heartbeat_updates_device_and_employee(client, agent_headers):
    hb_payload = {
        "device_id": "DEV-RAJESH-01",
        "employee_id": "EMP-REL-001",
        "hostname": "DEV-LAPTOP-RAJESH",
        "username": "rajesh_kumar",
        "ip_address": "172.24.143.210",
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


# 5. DLP Event Submission: Properly tags employee_id and device_id
def test_5_dlp_event_submission_with_device_correlation(client, agent_headers):
    event_payload = {
        "employee_id": "EMP-REL-001",
        "device_id": "DEV-RAJESH-01",
        "channel": "BROWSER",
        "application": "Google Chrome",
        "destination": "mail.google.com",
        "file_name": "customer_data_export.csv",
        "file_size": 45000,
        "content_summary": "Extracted 150 customer email and Aadhar records from CSV",
        "risk_score": 92.0,
        "risk_level": "CRITICAL",
        "action": "BLOCK",
        "matched_rules": ["PII_EXFILTRATION", "BULK_DATA_EXPORT"],
        "details": {
            "browser": "Chrome 128",
            "url": "https://mail.google.com/upload",
            "detection": "Sensitive Aadhar and credit card numbers found in attachment"
        }
    }
    resp = client.post("/api/v1/dlp/events", json=event_payload, headers=agent_headers)
    assert resp.status_code in [200, 201]
    data = resp.json()
    assert data["employee_id"] == "EMP-REL-001"
    assert data["action"] == "BLOCK"
    assert data["risk_score"] >= 90.0


# 6. High-Risk DLP Event Creates Correlated Alert and Incident
def test_6_correlated_alert_and_incident_creation():
    db = SessionLocal()
    try:
        # Check Alert created for EMP-REL-001
        alert = db.query(Alert).filter(Alert.employee_id == "EMP-REL-001").order_by(Alert.created_at.desc()).first()
        assert alert is not None
        assert alert.employee_id == "EMP-REL-001"
        assert alert.severity in ["CRITICAL", "HIGH"]
        assert alert.device_id == "DEV-RAJESH-01" or alert.device_id is not None

        # Check Incident created for EMP-REL-001
        incident = db.query(Incident).filter(Incident.employee_id == "EMP-REL-001").order_by(Incident.created_at.desc()).first()
        assert incident is not None
        assert incident.employee_id == "EMP-REL-001"
    finally:
        db.close()


# 7. Employee 360° Profile API: Returns complete aggregated data
def test_7_employee_360_profile_endpoint_returns_complete_data(client, analyst_token):
    headers = {"Authorization": f"Bearer {analyst_token}"}
    resp = client.get("/api/v1/employees/EMP-REL-001", headers=headers)
    assert resp.status_code == 200
    data = resp.json()

    # Section A: Employee info
    emp = data["employee"]
    assert emp["employee_id"] == "EMP-REL-001"
    assert emp["full_name"] == "Rajesh Kumar"
    assert emp["status"] == "ONLINE"

    # Section B: Registered Devices
    devices = data["devices"]
    assert len(devices) >= 1
    assert any(d["device_id"] == "DEV-RAJESH-01" for d in devices)

    # Section C: Monitoring Modules
    mods = data["monitoring_modules"]
    assert mods["browser"] == "ACTIVE"
    assert mods["file"] == "ACTIVE"

    # Section D: Security Summary
    sec = data["security_summary"]
    assert sec["total_events"] >= 1
    assert sec["alerts"] >= 1

    # Section E: Alerts list
    alerts = data["alerts"]
    assert len(alerts) >= 1
    assert alerts[0]["employee_id"] == "EMP-REL-001"

    # Section F: Incidents list
    incidents = data["incidents"]
    assert len(incidents) >= 1
    assert incidents[0]["employee_id"] == "EMP-REL-001"

    # Section G: DLP Events list
    events = data["dlp_events"]
    assert len(events) >= 1
    assert events[0]["employee_id"] == "EMP-REL-001"


# 8. Employee Sub-Endpoints
def test_8_employee_sub_endpoints(client, analyst_token):
    headers = {"Authorization": f"Bearer {analyst_token}"}
    
    # 8a. Devices sub-endpoint
    resp_dev = client.get("/api/v1/employees/EMP-REL-001/devices", headers=headers)
    assert resp_dev.status_code == 200
    assert len(resp_dev.json()) >= 1
    assert resp_dev.json()[0]["device_id"] == "DEV-RAJESH-01"

    # 8b. Alerts sub-endpoint
    resp_alt = client.get("/api/v1/employees/EMP-REL-001/alerts", headers=headers)
    assert resp_alt.status_code == 200
    assert len(resp_alt.json()) >= 1
    assert resp_alt.json()[0]["employee_id"] == "EMP-REL-001"

    # 8c. Incidents sub-endpoint
    resp_inc = client.get("/api/v1/employees/EMP-REL-001/incidents", headers=headers)
    assert resp_inc.status_code == 200
    assert len(resp_inc.json()) >= 1

    # 8d. Events sub-endpoint
    resp_ev = client.get("/api/v1/employees/EMP-REL-001/events", headers=headers)
    assert resp_ev.status_code == 200
    assert len(resp_ev.json()) >= 1

    # 8e. Status sub-endpoint
    resp_st = client.get("/api/v1/employees/EMP-REL-001/status", headers=headers)
    assert resp_st.status_code == 200
    st_data = resp_st.json()
    assert st_data["employee_id"] == "EMP-REL-001"
    assert st_data["status"] == "ONLINE"


# 9. Clean Unbound Employee Profile
def test_9_clean_unbound_employee_profile(client, admin_token, analyst_token):
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    analyst_headers = {"Authorization": f"Bearer {analyst_token}"}
    client.delete("/api/v1/employees/EMP-REL-002?hard_delete=true", headers=admin_headers)

    payload = {
        "employee_id": "EMP-REL-002",
        "username": "anita_sharma",
        "full_name": "Anita Sharma",
        "email": "anita@sentineldlp.io",
        "department": "Finance",
        "designation": "Financial Analyst"
    }
    resp = client.post("/api/v1/employees", json=payload, headers=admin_headers)
    assert resp.status_code == 201

    # Fetch 360 profile
    resp_prof = client.get("/api/v1/employees/EMP-REL-002", headers=analyst_headers)
    assert resp_prof.status_code == 200
    prof = resp_prof.json()
    assert prof["employee"]["status"] == "OFFLINE"
    assert prof["devices"] == []
    assert prof["alerts"] == []
    assert prof["incidents"] == []
    assert prof["dlp_events"] == []


# 10. Heartbeat Lifecycle Status Decay (ONLINE -> WARNING -> OFFLINE)
def test_10_heartbeat_decay_evaluation():
    now = datetime.now(timezone.utc)
    
    # < 30 seconds -> ONLINE
    s_online, diff1 = fleet_monitor_service.evaluate_status(now - timedelta(seconds=15), now)
    assert s_online == "ONLINE"
    assert diff1 == 15

    # 30-60 seconds -> WARNING
    s_warn, diff2 = fleet_monitor_service.evaluate_status(now - timedelta(seconds=45), now)
    assert s_warn == "WARNING"
    assert diff2 == 45

    # > 60 seconds -> OFFLINE
    s_offline, diff3 = fleet_monitor_service.evaluate_status(now - timedelta(seconds=120), now)
    assert s_offline == "OFFLINE"
    assert diff3 == 120


# 11. Prevent Auto-Creation of Ghost Employees
def test_11_ghost_employee_emp_browser_01_prevented(client, agent_headers):
    # If someone sends an event with an unknown or ghost ID, verify it doesn't create EMP-BROWSER-01
    bad_payload = {
        "employee_id": "GHOST-NONEXISTENT",
        "channel": "BROWSER",
        "application": "Firefox",
        "file_name": "unknown.pdf",
        "risk_score": 10.0,
        "action": "ALLOW"
    }
    resp = client.post("/api/v1/dlp/events", json=bad_payload, headers=agent_headers)
    assert resp.status_code in [400, 404]
    
    db = SessionLocal()
    try:
        ghost = db.query(Employee).filter(Employee.employee_id == "EMP-BROWSER-01").first()
        assert ghost is None
        ghost2 = db.query(Employee).filter(Employee.employee_id == "GHOST-NONEXISTENT").first()
        assert ghost2 is None
    finally:
        db.close()
