import ast
import os
from pathlib import Path
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import inspect

from backend.main import app, init_database
from backend.database import SessionLocal
from backend.models import Device, Employee, DLPEvent, Alert
from backend.schemas import DeviceRegisterRequest, DeviceHeartbeatRequest
from backend.services.agent_service import agent_service


@pytest.fixture(scope="module")
def client():
    init_database()
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def db_session():
    init_database()
    db = SessionLocal()
    yield db
    db.close()


@pytest.fixture(scope="module")
def ensure_emp_win_01(db_session):
    emp = db_session.query(Employee).filter(Employee.employee_id == "EMP-WIN-01").first()
    if not emp:
        now = datetime.now(timezone.utc)
        emp = Employee(
            employee_id="EMP-WIN-01",
            username="prakash_win",
            full_name="Prakash T",
            email="prakash.win@sentineldlp.io",
            department="Cybersecurity",
            designation="Senior SOC Analyst",
            hostname="WORKSTATION-WIN",
            ip_address="192.168.1.150",
            operating_system="Windows 11",
            status="ONLINE",
            last_seen=now,
            created_at=now,
            updated_at=now,
            active=True,
            risk_score=0.0
        )
        db_session.add(emp)
        db_session.commit()
        db_session.refresh(emp)
    return emp


@pytest.fixture(scope="module")
def agent_headers():
    from backend.config import settings
    return {"X-Agent-Secret": settings.AGENT_SECRET_KEY}


# ==============================================================================
# TEST 1: Existing employee EMP-WIN-01 + new device -> registration succeeds
# ==============================================================================
def test_1_existing_employee_new_device_registration_succeeds(client, ensure_emp_win_01):
    payload = {
        "hostname": "DESKTOP-WIN-TEST",
        "operating_system": "Windows 11 Enterprise",
        "ip_address": "192.168.1.155",
        "agent_version": "2.1.0",
        "employee_id": "EMP-WIN-01",
        "preferred_device_id": "DEV-WIN-01-TEST"
    }

    resp = client.post("/api/v1/agents/register", json=payload)
    assert resp.status_code == 201
    data = resp.json()

    assert data["device_id"] == "DEV-WIN-01-TEST"
    assert data["employee_id"] == "EMP-WIN-01"
    assert "device_token" in data
    assert len(data["device_token"]) >= 32
    assert data["status"] == "ONLINE"

    # Verify device in DB
    db = SessionLocal()
    try:
        dev = db.query(Device).filter(Device.device_id == "DEV-WIN-01-TEST").first()
        assert dev is not None
        assert dev.employee_id == "EMP-WIN-01"
        assert dev.hostname == "DESKTOP-WIN-TEST"
        assert dev.operating_system == "Windows 11 Enterprise"
        assert dev.status == "ONLINE"
    finally:
        db.close()


# ==============================================================================
# TEST 2: Unknown employee -> 404/409, never creates Employee
# ==============================================================================
def test_2_unknown_employee_registration_rejected(client):
    payload = {
        "hostname": "ROGUE-PC-999",
        "operating_system": "Windows 11",
        "ip_address": "192.168.1.99",
        "agent_version": "2.1.0",
        "employee_id": "NON_EXISTENT_EMP_UNKNOWN_999",
        "preferred_device_id": "DEV-ROGUE-999",
        "full_name": "Fake Employee",
        "email": "fake@sentineldlp.io"
    }

    resp = client.post("/api/v1/agents/register", json=payload)
    assert resp.status_code in [404, 409]

    # Verify that the employee was NOT created in DB
    db = SessionLocal()
    try:
        emp = db.query(Employee).filter(Employee.employee_id == "NON_EXISTENT_EMP_UNKNOWN_999").first()
        assert emp is None
    finally:
        db.close()


# ==============================================================================
# TEST 3: Existing device heartbeat -> 200 and last_seen updates
# ==============================================================================
def test_3_existing_device_heartbeat_updates_last_seen(client, ensure_emp_win_01, agent_headers):
    db = SessionLocal()
    try:
        dev = db.query(Device).filter(Device.device_id == "DEV-WIN-01-TEST").first()
        assert dev is not None
        initial_last_seen = dev.last_seen
    finally:
        db.close()

    hb_payload = {
        "device_id": "DEV-WIN-01-TEST",
        "employee_id": "EMP-WIN-01",
        "hostname": "DESKTOP-WIN-TEST",
        "username": "prakash_win",
        "ip_address": "192.168.1.155",
        "operating_system": "Windows 11 Enterprise",
        "agent_version": "2.1.0",
        "status": "ONLINE",
        "monitoring_status": "ACTIVE",
        "active_monitoring_modules": {
            "usb": "ACTIVE",
            "file": "ACTIVE",
            "clipboard": "ACTIVE"
        }
    }

    resp = client.post("/api/v1/agents/heartbeat", json=hb_payload, headers=agent_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["acknowledged"] is True
    assert data["device_id"] == "DEV-WIN-01-TEST"
    assert data["status"] == "ONLINE"

    # Verify in DB that last_seen updated
    db = SessionLocal()
    try:
        updated_dev = db.query(Device).filter(Device.device_id == "DEV-WIN-01-TEST").first()
        assert updated_dev is not None
        assert updated_dev.last_seen is not None
        if initial_last_seen:
            assert updated_dev.last_seen >= initial_last_seen
        assert updated_dev.status == "ONLINE"
    finally:
        db.close()


# ==============================================================================
# TEST 4: Heartbeat never creates duplicate Employee
# ==============================================================================
def test_4_heartbeat_never_creates_employee(client, agent_headers):
    db = SessionLocal()
    try:
        employee_count_before = db.query(Employee).count()
    finally:
        db.close()

    # Heartbeat with a non-existent device
    hb_payload_unknown_device = {
        "device_id": "DEV-UNKNOWN-HEARTBEAT-999",
        "employee_id": "EMP-GHOST-999",
        "full_name": "Ghost User",
        "email": "ghost@company.com",
        "hostname": "GHOST-WS",
        "status": "ONLINE"
    }

    resp = client.post("/api/v1/agents/heartbeat", json=hb_payload_unknown_device, headers=agent_headers)
    assert resp.status_code == 404

    # Check total employee count did not increase
    db = SessionLocal()
    try:
        employee_count_after = db.query(Employee).count()
        assert employee_count_after == employee_count_before
        ghost_emp = db.query(Employee).filter(Employee.employee_id == "EMP-GHOST-999").first()
        assert ghost_emp is None
    finally:
        db.close()


# ==============================================================================
# TEST 5: Duplicate device registration is handled safely
# ==============================================================================
def test_5_duplicate_device_registration_handled_safely(client, ensure_emp_win_01):
    payload = {
        "hostname": "DESKTOP-WIN-TEST-RENAMED",
        "operating_system": "Windows 11 Enterprise (Updated)",
        "ip_address": "192.168.1.180",
        "agent_version": "2.2.0",
        "employee_id": "EMP-WIN-01",
        "preferred_device_id": "DEV-WIN-01-TEST"
    }

    resp = client.post("/api/v1/agents/register", json=payload)
    assert resp.status_code == 201
    data = resp.json()
    assert data["device_id"] == "DEV-WIN-01-TEST"

    # Verify DB has exactly 1 device row with this ID, and fields are updated
    db = SessionLocal()
    try:
        devices = db.query(Device).filter(Device.device_id == "DEV-WIN-01-TEST").all()
        assert len(devices) == 1
        assert devices[0].hostname == "DESKTOP-WIN-TEST-RENAMED"
        assert devices[0].operating_system == "Windows 11 Enterprise (Updated)"
        assert devices[0].ip_address == "192.168.1.180"
        assert devices[0].agent_version == "2.2.0"
    finally:
        db.close()


# ==============================================================================
# TEST 6: Database exception causes rollback
# ==============================================================================
def test_6_database_exception_causes_rollback():
    db = SessionLocal()
    try:
        # Mock commit to raise an exception
        mock_db = MagicMock(wraps=db)
        mock_db.commit.side_effect = Exception("Simulated DB commit error")

        req = DeviceRegisterRequest(
            hostname="FAIL-HOST",
            employee_id="EMP-WIN-01",
            preferred_device_id="DEV-FAIL-01"
        )

        with pytest.raises(Exception, match="Simulated DB commit error"):
            agent_service.register_device(mock_db, req)

        # Ensure rollback was called on failure
        mock_db.rollback.assert_called_once()
    finally:
        db.close()


# ==============================================================================
# TEST 7: No Employee constructor contains fields that don't exist in the model
# ==============================================================================
def test_7_no_invalid_employee_constructor_fields():
    # 1. Get all valid attribute and column names on Employee
    employee_mapper = inspect(Employee)
    valid_attributes = set(employee_mapper.columns.keys())
    valid_attributes.update(employee_mapper.relationships.keys())
    # include valid properties/hybrid_properties
    valid_attributes.update(["is_active"])

    assert "risk_level" not in valid_attributes

    # 2. Inspect all python files in backend/ and agent/
    root_dir = Path(__file__).resolve().parent.parent
    scan_dirs = [root_dir / "backend", root_dir / "agent"]

    for scan_dir in scan_dirs:
        for py_file in scan_dir.rglob("*.py"):
            with open(py_file, "r", encoding="utf-8") as f:
                content = f.read()

            try:
                tree = ast.parse(content, filename=str(py_file))
            except SyntaxError:
                continue

            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    # Check if constructor is Employee(...)
                    is_employee_call = False
                    if isinstance(node.func, ast.Name) and node.func.id == "Employee":
                        is_employee_call = True
                    elif isinstance(node.func, ast.Attribute) and node.func.attr == "Employee":
                        is_employee_call = True

                    if is_employee_call:
                        for kw in node.keywords:
                            if kw.arg is not None:
                                assert kw.arg in valid_attributes, (
                                    f"Invalid keyword argument '{kw.arg}' passed to Employee(...) "
                                    f"in {py_file.relative_to(root_dir)}:line {node.lineno}"
                                )
                                assert kw.arg != "risk_level", (
                                    f"Found forbidden 'risk_level' in Employee(...) "
                                    f"in {py_file.relative_to(root_dir)}:line {node.lineno}"
                                )
