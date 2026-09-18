"""
SentinelDLP - Multi-User Identity Attribution & Alert Isolation Test Suite
===========================================================================
Validates that:
1. When User A (Alice Smith, EMP-USER-A) copies or sends sensitive data (clipboard, USB, file, email, browser),
   alerts are generated strictly under User A's name and ID, and the alert message explicitly names User A.
2. When User B (Bob Jones, EMP-USER-B) copies or sends sensitive data, alerts are generated strictly under
   User B's name and ID, and the alert message explicitly names User B.
3. Admin queries and filters by employee_id strictly separate User A's alerts from User B's alerts.
4. 360° employee profiles, incident records, and UEBA risk scores maintain 100% strict multi-user isolation.
"""

import base64
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from backend.main import app, init_database
from backend.database import SessionLocal
from backend.models import Employee, Device, Alert, Incident, DLPEvent, ActivityLog, User
from agent.clipboard_monitor import scan_clipboard_text

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
def seed_multi_users():
    """Seed User A and User B and clear prior events/alerts before each test."""
    db = SessionLocal()
    try:
        db.query(Incident).delete()
        db.query(Alert).delete()
        db.query(DLPEvent).delete()
        db.query(ActivityLog).delete()

        # Seed User A
        emp_a = db.query(Employee).filter(Employee.employee_id == "EMP-USER-A").first()
        if not emp_a:
            emp_a = Employee(
                employee_id="EMP-USER-A",
                username="alice_smith",
                full_name="Alice Smith",
                email="alice.smith@sentineldlp.io",
                department="Finance",
                designation="Financial Analyst",
                hostname="ALICE-WORKSTATION",
                operating_system="Windows 11",
                ip_address="192.168.10.21",
                status="ONLINE",
                active=True,
                risk_score=0.0
            )
            db.add(emp_a)
        else:
            emp_a.full_name = "Alice Smith"
            emp_a.active = True
            emp_a.risk_score = 0.0

        # Seed User B
        emp_b = db.query(Employee).filter(Employee.employee_id == "EMP-USER-B").first()
        if not emp_b:
            emp_b = Employee(
                employee_id="EMP-USER-B",
                username="bob_jones",
                full_name="Bob Jones",
                email="bob.jones@sentineldlp.io",
                department="Engineering",
                designation="Backend Developer",
                hostname="BOB-WORKSTATION",
                operating_system="Linux",
                ip_address="192.168.10.45",
                status="ONLINE",
                active=True,
                risk_score=0.0
            )
            db.add(emp_b)
        else:
            emp_b.full_name = "Bob Jones"
            emp_b.active = True
            emp_b.risk_score = 0.0

        # Seed Devices for User A and User B
        dev_a = db.query(Device).filter(Device.device_id == "DEV-ALICE-01").first()
        if not dev_a:
            dev_a = Device(
                device_id="DEV-ALICE-01",
                hostname="ALICE-WORKSTATION",
                employee_id="EMP-USER-A",
                username="alice_smith",
                operating_system="Windows 11",
                device_token="tok-alice-01",
                status="ONLINE",
                is_active=True
            )
            db.add(dev_a)
        else:
            dev_a.employee_id = "EMP-USER-A"

        dev_b = db.query(Device).filter(Device.device_id == "DEV-BOB-01").first()
        if not dev_b:
            dev_b = Device(
                device_id="DEV-BOB-01",
                hostname="BOB-WORKSTATION",
                employee_id="EMP-USER-B",
                username="bob_jones",
                operating_system="Linux",
                device_token="tok-bob-01",
                status="ONLINE",
                is_active=True
            )
            db.add(dev_b)
        else:
            dev_b.employee_id = "EMP-USER-B"

        db.commit()
    finally:
        db.close()


def test_1_user_a_copies_sensitive_data_alert_attribution(client, auth_headers):
    """
    Test that when User A (Alice Smith) copies sensitive data (e.g. Credit Card + AWS Keys),
    an alert is generated under User A's name and ID.
    """
    sample_text = "CONFIDENTIAL INTERNAL FINANCIAL REPORT: Credit Card: 4532-1188-9922-3344, AWS Key: AKIAIOSFODNN7EXAMPLE"
    entities, score, classification = scan_clipboard_text(sample_text)
    assert len(entities) >= 1

    # Simulate User A's agent dispatching a clipboard alert
    alert_payload = {
        "employee_id": "EMP-USER-A",
        "device_id": "DEV-ALICE-01",
        "alert_type": "EXFILTRATION_CLIPBOARD_LEAK",
        "severity": "CRITICAL",
        "risk_score": 95.0,
        "description": "🚨 REAL-TIME EXFILTRATION DETECTED: Sensitive data [CREDIT_CARD_NUMBER (x1), AWS_ACCESS_KEY (x1)] copied by Employee 'Alice Smith' (EMP-USER-A) while WhatsApp was active.",
        "source": "CLIPBOARD_MONITOR",
        "status": "OPEN"
    }

    resp = client.post("/api/v1/alerts", json=alert_payload, headers=auth_headers)
    assert resp.status_code == 201
    alert_data = resp.json()

    # Verify Alert is assigned to Alice Smith
    assert alert_data["employee_id"] == "EMP-USER-A"
    assert alert_data["employee_name"] == "Alice Smith"
    assert alert_data["employee_username"] == "alice_smith"
    assert "Alice Smith" in alert_data["description"]
    assert "EMP-USER-A" in alert_data["description"]
    assert alert_data["severity"] == "CRITICAL"


def test_2_user_b_sends_confidential_file_alert_attribution(client, auth_headers):
    """
    Test that when User B (Bob Jones) sends a confidential file via browser/cloud upload,
    an alert is generated under User B's name and ID.
    """
    sensitive_content = (
        "RESTRICTED SOURCE CODE AND CUSTOMER PII DATABASE DUMP\n"
        "Employee Salary Details: CTC $180,000\n"
        "Customer PAN: ABCDE1234F\n"
        "Customer Aadhaar: 9876 5432 1098\n"
    )
    b64_content = base64.b64encode(sensitive_content.encode("utf-8")).decode("utf-8")

    scan_req = {
        "channel": "BROWSER",
        "application": "Google Chrome",
        "destination": "https://wetransfer.com/upload",
        "file_name": "customer_pii_export.csv",
        "file_size": len(sensitive_content),
        "file_content_base64": b64_content,
        "employee_id": "EMP-USER-B",
        "device_id": "DEV-BOB-01"
    }

    resp = client.post("/api/v1/dlp/scan", json=scan_req, headers=auth_headers)
    assert resp.status_code == 200
    scan_data = resp.json()

    assert scan_data["action"] == "BLOCK"
    assert scan_data["alert_created"] is True
    alert_id = scan_data["alert_id"]
    assert alert_id is not None

    # Fetch created alert detail
    alert_resp = client.get(f"/api/v1/alerts/{alert_id}", headers=auth_headers)
    assert alert_resp.status_code == 200
    alert_obj = alert_resp.json()

    # Verify Alert is assigned to Bob Jones
    assert alert_obj["employee_id"] == "EMP-USER-B"
    assert alert_obj["employee_name"] == "Bob Jones"
    assert alert_obj["employee_username"] == "bob_jones"
    assert "Bob Jones" in alert_obj["description"]
    assert "EMP-USER-B" in alert_obj["description"]
    assert "customer_pii_export.csv" in alert_obj["description"]


def test_3_user_a_and_user_b_distinct_email_dlp_alerts(client, auth_headers):
    """
    Test distinct email exfiltration events for User A vs User B:
    - User A sending confidential financial report generates alert in Alice's name.
    - User B sending proprietary source code generates alert in Bob's name.
    """
    # 1. Alice sends finance email
    alice_email = {
        "sender": "alice.smith@sentineldlp.io",
        "recipient": "external-auditor@competitor.com",
        "subject": "Q3 Financial Ledger",
        "body": "Confidential Q3 Financials with employee salary details: CTC $250,000",
        "file_name": "q3_ledger.xlsx",
        "extracted_text": "CONFIDENTIAL FINANCIAL LEDGER: Credit Card: 4111 2222 3333 4444, Salary: $250,000",
        "employee_id": "EMP-USER-A",
        "device_id": "DEV-ALICE-01"
    }
    resp_a = client.post("/api/v1/dlp/email-event", json=alice_email, headers=auth_headers)
    assert resp_a.status_code == 200
    res_a_data = resp_a.json()
    assert res_a_data["action"] == "BLOCK"
    assert res_a_data["alert_created"] is True

    # 2. Bob sends developer email
    bob_email = {
        "sender": "bob.jones@sentineldlp.io",
        "recipient": "bob.personal@gmail.com",
        "subject": "Production Keys Backup",
        "body": "Personal backup of backend keys",
        "file_name": "production_keys.env",
        "extracted_text": "HIGHLY_CONFIDENTIAL AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY and GITHUB_TOKEN=ghp_111122223333444455556666777788889999",
        "employee_id": "EMP-USER-B",
        "device_id": "DEV-BOB-01"
    }
    resp_b = client.post("/api/v1/dlp/email-event", json=bob_email, headers=auth_headers)
    assert resp_b.status_code == 200
    res_b_data = resp_b.json()
    assert res_b_data["action"] == "BLOCK"
    assert res_b_data["alert_created"] is True


def test_4_admin_alert_filtering_isolation(client, auth_headers):
    """
    Test that Admin can query alerts filtered by employee_id and receive strictly isolated results:
    - Filtering by EMP-USER-A returns only User A's alerts.
    - Filtering by EMP-USER-B returns only User B's alerts.
    """
    # 1. Create alert for Alice
    client.post("/api/v1/alerts", json={
        "employee_id": "EMP-USER-A",
        "device_id": "DEV-ALICE-01",
        "alert_type": "EXFILTRATION_CLIPBOARD_LEAK",
        "severity": "CRITICAL",
        "risk_score": 90.0,
        "description": "🚨 Sensitive data copied by Employee 'Alice Smith' (EMP-USER-A)",
        "source": "CLIPBOARD_MONITOR",
        "status": "OPEN"
    }, headers=auth_headers)

    # 2. Create alert for Bob
    client.post("/api/v1/alerts", json={
        "employee_id": "EMP-USER-B",
        "device_id": "DEV-BOB-01",
        "alert_type": "EXFILTRATION_USB_TRANSFER",
        "severity": "CRITICAL",
        "risk_score": 95.0,
        "description": "🚨 Sensitive file copied to USB by Employee 'Bob Jones' (EMP-USER-B)",
        "source": "USB_MONITOR",
        "status": "OPEN"
    }, headers=auth_headers)

    # Query Alice's alerts
    resp_alice = client.get("/api/v1/alerts?employee_id=EMP-USER-A", headers=auth_headers)
    assert resp_alice.status_code == 200
    alice_alerts = resp_alice.json()
    assert len(alice_alerts) == 1
    assert alice_alerts[0]["employee_id"] == "EMP-USER-A"
    assert alice_alerts[0]["employee_name"] == "Alice Smith"
    assert "Alice Smith" in alice_alerts[0]["description"]
    assert "Bob" not in alice_alerts[0]["description"]

    # Query Bob's alerts
    resp_bob = client.get("/api/v1/alerts?employee_id=EMP-USER-B", headers=auth_headers)
    assert resp_bob.status_code == 200
    bob_alerts = resp_bob.json()
    assert len(bob_alerts) == 1
    assert bob_alerts[0]["employee_id"] == "EMP-USER-B"
    assert bob_alerts[0]["employee_name"] == "Bob Jones"
    assert "Bob Jones" in bob_alerts[0]["description"]
    assert "Alice" not in bob_alerts[0]["description"]


def test_5_incident_and_ueba_profile_isolation(client, auth_headers):
    """
    Test that automatic SOC incidents and 360° employee profiles strictly maintain multi-user isolation:
    - Incidents for User A reference Alice Smith and EMP-USER-A.
    - Incidents for User B reference Bob Jones and EMP-USER-B.
    - User A's 360° profile returns only User A's events, alerts, and devices.
    - User B's 360° profile returns only User B's events, alerts, and devices.
    """
    # Create critical alerts triggering automatic incidents
    client.post("/api/v1/alerts", json={
        "employee_id": "EMP-USER-A",
        "device_id": "DEV-ALICE-01",
        "alert_type": "EXFILTRATION_CLIPBOARD_LEAK",
        "severity": "CRITICAL",
        "risk_score": 92.0,
        "description": "🚨 Exfiltration by Employee 'Alice Smith' (EMP-USER-A)",
        "source": "CLIPBOARD_MONITOR",
        "status": "OPEN"
    }, headers=auth_headers)

    client.post("/api/v1/alerts", json={
        "employee_id": "EMP-USER-B",
        "device_id": "DEV-BOB-01",
        "alert_type": "EXFILTRATION_USB_TRANSFER",
        "severity": "CRITICAL",
        "risk_score": 96.0,
        "description": "🚨 Exfiltration by Employee 'Bob Jones' (EMP-USER-B)",
        "source": "USB_MONITOR",
        "status": "OPEN"
    }, headers=auth_headers)

    # 1. Verify Incidents
    inc_resp = client.get("/api/v1/incidents", headers=auth_headers)
    assert inc_resp.status_code == 200
    incidents = inc_resp.json()
    assert len(incidents) >= 2

    alice_incs = [i for i in incidents if i["employee_id"] == "EMP-USER-A"]
    bob_incs = [i for i in incidents if i["employee_id"] == "EMP-USER-B"]

    assert len(alice_incs) > 0
    for i in alice_incs:
        assert "Alice Smith" in i["title"] or "EMP-USER-A" in i["title"]

    assert len(bob_incs) > 0
    for i in bob_incs:
        assert "Bob Jones" in i["title"] or "EMP-USER-B" in i["title"]

    # 2. Verify User A 360° Profile
    prof_a = client.get("/api/v1/employees/EMP-USER-A/profile", headers=auth_headers)
    assert prof_a.status_code == 200
    data_a = prof_a.json()
    assert data_a["employee"]["full_name"] == "Alice Smith"
    assert data_a["employee"]["employee_id"] == "EMP-USER-A"
    for al in data_a["alerts"]:
        assert al["employee_id"] == "EMP-USER-A"
    for dev in data_a["devices"]:
        assert dev["device_id"] == "DEV-ALICE-01"

    # 3. Verify User B 360° Profile
    prof_b = client.get("/api/v1/employees/EMP-USER-B/profile", headers=auth_headers)
    assert prof_b.status_code == 200
    data_b = prof_b.json()
    assert data_b["employee"]["full_name"] == "Bob Jones"
    assert data_b["employee"]["employee_id"] == "EMP-USER-B"
    for bl in data_b["alerts"]:
        assert bl["employee_id"] == "EMP-USER-B"
    for dev in data_b["devices"]:
        assert dev["device_id"] == "DEV-BOB-01"
