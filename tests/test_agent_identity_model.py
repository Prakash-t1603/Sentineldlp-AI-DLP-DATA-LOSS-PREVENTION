import os
import sys
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from agent.config import (
    get_configured_employee_id,
    save_configured_employee_id,
    _is_generated_employee_id,
    HOSTNAME
)
from agent.agent import SentinelAgent, run_agent
from agent.api_client import AgentAPIClient
from agent.email_monitor import EmailMonitor
from agent.event_queue import event_queue


# ==============================================================================
# TEST 1: _is_generated_employee_id correctly identifies generated strings
# ==============================================================================
def test_generated_employee_id_detection():
    # Auto-generated patterns should be detected
    assert _is_generated_employee_id("EMP-DESKTOP--E7CE4D") is True
    assert _is_generated_employee_id("EMP-DESKTOP-123456") is True
    if HOSTNAME:
        assert _is_generated_employee_id(f"EMP-{HOSTNAME.upper()[:8]}-A1B2C3") is True
    assert _is_generated_employee_id("") is True

    # Real admin-assigned IDs must NOT be marked as generated
    assert _is_generated_employee_id("EMP-WIN-01") is False
    assert _is_generated_employee_id("EMP-001") is False
    assert _is_generated_employee_id("EMP-DEV-02") is False
    assert _is_generated_employee_id("EMP-FIN-99") is False


# ==============================================================================
# TEST 2: Priority: Explicit argument > Configured / Environment
# ==============================================================================
def test_employee_id_precedence(monkeypatch, tmp_path):
    monkeypatch.setenv("EMPLOYEE_ID", "EMP-ENV-01")
    
    # 1. Explicit argument overrides environment
    agent = SentinelAgent(
        server_url="http://127.0.0.1:8000",
        employee_id="EMP-WIN-01"
    )
    assert agent.employee_id == "EMP-WIN-01"
    assert agent.api_client.employee_id == "EMP-WIN-01"
    assert agent.email_monitor.employee_id == "EMP-WIN-01"

    # 2. When explicit argument is omitted, falls back to valid configured ENV
    agent2 = SentinelAgent(
        server_url="http://127.0.0.1:8000"
    )
    assert agent2.employee_id == "EMP-ENV-01"


# ==============================================================================
# TEST 3: Startup fails clearly if no employee ID is assigned
# ==============================================================================
def test_startup_fails_without_employee_id(monkeypatch):
    monkeypatch.delenv("EMPLOYEE_ID", raising=False)
    monkeypatch.delenv("DLP_EMPLOYEE_ID", raising=False)
    
    with patch("agent.agent.get_configured_employee_id", return_value=""), \
         patch("agent.agent.EMPLOYEE_ID", ""), \
         patch("agent.config.get_configured_employee_id", return_value=""):
        
        with pytest.raises(ValueError, match="administrator-assigned Employee ID is required"):
            SentinelAgent(server_url="http://127.0.0.1:8000", employee_id=None)


# ==============================================================================
# TEST 4: Stale generated IDs in .employee_id are ignored
# ==============================================================================
def test_stale_generated_id_ignored(monkeypatch, tmp_path):
    monkeypatch.delenv("EMPLOYEE_ID", raising=False)
    monkeypatch.delenv("DLP_EMPLOYEE_ID", raising=False)
    
    stale_file = tmp_path / ".employee_id"
    stale_file.write_text("EMP-DESKTOP--E7CE4D")
    empty_dev_file = tmp_path / "empty_dev.json"
    
    with patch("agent.config.EMPLOYEE_ID_FILE", stale_file), \
         patch("agent.config.DEVICE_CONFIG_FILE", empty_dev_file):
        configured_id = get_configured_employee_id()
        assert configured_id == ""


# ==============================================================================
# TEST 5: Identity Separation: Employee ID != Device ID != Hostname
# ==============================================================================
def test_identity_separation():
    agent = SentinelAgent(
        server_url="http://127.0.0.1:8000",
        employee_id="EMP-WIN-01",
        device_id="DEV-WIN-01"
    )
    
    assert agent.employee_id == "EMP-WIN-01"
    assert agent.device_id == "DEV-WIN-01"
    assert agent.hostname == HOSTNAME
    assert agent.employee_id != agent.device_id
    assert agent.employee_id != agent.hostname


# ==============================================================================
# TEST 6: All payloads retain authoritative employee_id and device_id
# ==============================================================================
def test_outbound_payloads_contain_authoritative_ids():
    event_queue.clear()
    agent = SentinelAgent(
        server_url="http://127.0.0.1:8000",
        employee_id="EMP-WIN-01",
        device_id="EMP-PC-TEST01"
    )

    with patch("requests.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "device_id": "EMP-PC-TEST01",
            "device_token": "token_123456789012345678901234567890",
            "action": "ALLOW",
            "risk_score": 0.0,
            "status": "ONLINE",
            "acknowledged": True
        }
        mock_post.return_value = mock_resp

        # 1. Registration
        agent.register_endpoint()
        assert mock_post.called
        reg_payload = mock_post.call_args[1]["json"]
        assert reg_payload["employee_id"] == "EMP-WIN-01"
        assert reg_payload["preferred_device_id"] == "EMP-PC-TEST01"

        # 2. Heartbeat
        agent.send_heartbeat()
        hb_payload = mock_post.call_args[1]["json"]
        assert hb_payload["employee_id"] == "EMP-WIN-01"
        assert hb_payload["device_id"] == "EMP-PC-TEST01"

        # 3. Status Event
        agent.api_client.send_status_event("AGENT_STARTED")
        status_payload = mock_post.call_args[1]["json"]
        assert status_payload["employee_id"] == "EMP-WIN-01"
        assert status_payload["device_id"] == "EMP-PC-TEST01"

        # 4. DLP Event
        agent.send_dlp_event(
            channel="USB",
            application="USB Drive",
            file_name="confidential_doc.docx"
        )
        dlp_payload = mock_post.call_args[1]["json"]
        assert dlp_payload["employee_id"] == "EMP-WIN-01"
        assert dlp_payload["device_id"] == "EMP-PC-TEST01"


# ==============================================================================
# TEST 7: Safety assertion fails if mismatched employee_id is injected
# ==============================================================================
def test_safety_assertion_on_employee_id_mismatch():
    client = AgentAPIClient(
        server_url="http://127.0.0.1:8000",
        employee_id="EMP-WIN-01",
        device_id="DEV-01"
    )

    bad_payload = {
        "employee_id": "EMP-DESKTOP--E7CE4D",
        "device_id": "DEV-01",
        "channel": "USB",
        "file_name": "test.txt"
    }

    # Should raise AssertionError due to mismatch
    with pytest.raises(AssertionError, match="employee_id mismatch"):
        client.send_dlp_event(bad_payload)
