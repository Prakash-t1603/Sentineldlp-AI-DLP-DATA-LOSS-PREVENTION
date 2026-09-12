import time
from datetime import datetime, timezone, timedelta
import pytest
from fastapi.testclient import TestClient

from backend.main import app, init_database
from backend.database import SessionLocal
from backend.models import Device, Employee, DLPEvent, Alert
from backend.services.agent_service import agent_service
from agent.event_queue import OfflineEventQueue


@pytest.fixture(scope="module")
def client():
    init_database()
    with TestClient(app) as c:
        yield c


def test_agent_registration_success(client):
    """Verify endpoint agent registration, token issuance, and device persistence."""
    payload = {
        "hostname": "TEST-WORKSTATION-99",
        "operating_system": "Ubuntu 22.04 LTS",
        "ip_address": "192.168.10.99",
        "agent_version": "2.1.0",
        "employee_id": "EMP-TEST-99",
        "preferred_device_id": "EMP-PC-TEST99"
    }

    resp = client.post("/api/v1/agents/register", json=payload)
    assert resp.status_code == 201
    data = resp.json()

    assert data["device_id"] == "EMP-PC-TEST99"
    assert "device_token" in data
    assert len(data["device_token"]) >= 32
    assert data["status"] == "ONLINE"
    assert data["heartbeat_interval_seconds"] == 15


def test_agent_heartbeat_processing(client):
    """Verify heartbeat pings update last_seen and return acknowledged response."""
    # 1. Register device
    reg_payload = {
        "hostname": "TEST-HB-WS",
        "operating_system": "Windows 11",
        "ip_address": "192.168.10.100",
        "agent_version": "2.1.0",
        "employee_id": "EMP-HB-100",
        "preferred_device_id": "EMP-PC-HB100"
    }
    reg_resp = client.post("/api/v1/agents/register", json=reg_payload)
    assert reg_resp.status_code == 201
    token = reg_resp.json()["device_token"]

    # 2. Send Heartbeat with device headers
    hb_payload = {
        "device_id": "EMP-PC-HB100",
        "status": "ONLINE",
        "agent_version": "2.1.0",
        "metrics": {"cpu_percent": 12.5, "memory_percent": 45.0}
    }
    headers = {
        "X-Device-Id": "EMP-PC-HB100",
        "X-Device-Token": token
    }
    hb_resp = client.post("/api/v1/agents/heartbeat", json=hb_payload, headers=headers)
    assert hb_resp.status_code == 200
    hb_data = hb_resp.json()
    assert hb_data["acknowledged"] is True
    assert hb_data["device_id"] == "EMP-PC-HB100"
    assert hb_data["status"] == "ONLINE"


def test_fleet_overview_and_device_detail(client):
    """Verify fleet overview endpoint and individual device detail retrieval."""
    # Login as admin to query fleet
    login_resp = client.post("/api/v1/auth/login", json={
        "username_or_email": "admin@sentineldlp.io",
        "password": "Admin@123456"
    })
    token = login_resp.json()["access_token"]
    auth_headers = {"Authorization": f"Bearer {token}"}

    # 1. Fleet summary
    fleet_resp = client.get("/api/v1/agents", headers=auth_headers)
    assert fleet_resp.status_code == 200
    fleet = fleet_resp.json()
    assert "total_devices" in fleet
    assert "online_devices" in fleet
    assert "devices" in fleet
    assert fleet["total_devices"] >= 1

    # 2. Single device details
    dev_resp = client.get("/api/v1/agents/EMP-PC-HB100", headers=auth_headers)
    assert dev_resp.status_code == 200
    dev_data = dev_resp.json()
    assert dev_data["device_id"] == "EMP-PC-HB100"
    assert dev_data["hostname"] == "TEST-HB-WS"
    assert dev_data["status"] == "ONLINE"
    assert dev_data["last_seen_seconds_ago"] is not None
    assert dev_data["last_seen_seconds_ago"] < 30.0


def test_dynamic_heartbeat_status_evaluation():
    """Verify status transitions: ONLINE (<=30s), WARNING (31s-60s), OFFLINE (>60s)."""
    now = datetime.now(timezone.utc)

    # 1. Seen 5 seconds ago -> ONLINE
    recent = now - timedelta(seconds=5)
    status_recent, diff_recent = agent_service.evaluate_device_status(recent)
    assert status_recent == "ONLINE"
    assert diff_recent <= 10.0

    # 2. Seen 45 seconds ago -> WARNING
    warning_time = now - timedelta(seconds=45)
    status_warn, diff_warn = agent_service.evaluate_device_status(warning_time)
    assert status_warn == "WARNING"
    assert 40.0 <= diff_warn <= 50.0

    # 3. Seen 120 seconds ago -> OFFLINE
    offline_time = now - timedelta(seconds=120)
    status_offline, diff_offline = agent_service.evaluate_device_status(offline_time)
    assert status_offline == "OFFLINE"
    assert diff_offline >= 100.0

    # 4. Never seen -> OFFLINE
    status_none, diff_none = agent_service.evaluate_device_status(None)
    assert status_none == "OFFLINE"
    assert diff_none is None


def test_offline_event_queue_buffering(tmp_path):
    """Verify offline SQLite queue handles buffering, persistence, and batch replay."""
    test_db = tmp_path / "test_offline.db"
    queue = OfflineEventQueue(db_path=test_db)

    assert queue.size() == 0

    # 1. Push events
    success1 = queue.push("DLP_EVENT", {"file_name": "passwords.txt", "channel": "USB"})
    success2 = queue.push("DLP_EVENT", {"file_name": "secrets.env", "channel": "BROWSER"})

    assert success1 is True
    assert success2 is True
    assert queue.size() == 2

    # 2. Peek batch
    batch = queue.peek_batch(limit=10)
    assert len(batch) == 2
    assert batch[0][0] == 1
    assert batch[0][2]["file_name"] == "passwords.txt"
    assert batch[1][2]["file_name"] == "secrets.env"

    # 3. Delete synced batch
    deleted_count = queue.delete_batch([1])
    assert deleted_count == 1
    assert queue.size() == 1

    remaining = queue.peek_batch(limit=10)
    assert len(remaining) == 1
    assert remaining[0][0] == 2


def test_dlp_event_ingestion_from_device(client):
    """Verify endpoint agent can submit multi-channel DLP events and trigger alerts."""
    event_payload = {
        "device_id": "EMP-PC-HB100",
        "employee_id": "EMP-HB-100",
        "channel": "USB",
        "application": "Removable USB Drive",
        "file_name": "customer_pii_database.csv",
        "destination": "F:\\ExtDrive",
        "file_hash": "aabbccddeeff00112233445566778899",
        "file_size": 10240,
        "file_type": ".csv",
        "sensitive_data_detected": True,
        "detection_type": "PII",
        "risk_score": 95.0,
        "risk_level": "CRITICAL",
        "action": "BLOCK",
        "status": "BLOCKED",
        "details": "PII transfer to USB drive blocked by endpoint policy."
    }

    headers = {
        "X-Device-Id": "EMP-PC-HB100",
        "X-Agent-Secret": "sentinel_agent_telemetry_secure_token_key_9981"
    }

    resp = client.post("/api/v1/dlp/events", json=event_payload, headers=headers)
    assert resp.status_code == 200
    data = resp.json()

    assert data["file_name"] == "customer_pii_database.csv"
    assert data["channel"] == "USB"
    assert data["action"] == "BLOCK"
    assert data["risk_score"] == 95.0
