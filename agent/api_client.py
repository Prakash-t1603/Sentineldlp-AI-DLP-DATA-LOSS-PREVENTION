import time
import requests
from typing import Dict, Any, Optional, Tuple
from agent.config import (
    API_BASE_URL, SERVER_URL, AGENT_SECRET, HOSTNAME,
    OS_NAME, LOCAL_IP, EMPLOYEE_ID, USERNAME, EMPLOYEE_NAME,
    EMPLOYEE_EMAIL, EMPLOYEE_DEPT, EMPLOYEE_DESIG, EMPLOYEE_PHONE,
    load_device_credentials, save_device_credentials,
    get_configured_employee_id, _is_generated_employee_id,
    normalize_employee_id, validate_employee_id, normalize_server_url,
    get_or_generate_stable_device_id
)
from agent.logger import get_agent_logger
from agent.event_queue import event_queue

logger = get_agent_logger("SentinelDLP.Agent.APIClient")

class AgentAPIClient:
    """
    HTTP API client managing communication between the Endpoint Agent and the Central DLP Server.
    Supports auto-registration, device credential persistence, heartbeats, status events, and offline queue fallback.
    """
    def __init__(
        self,
        server_url: Optional[str] = None,
        employee_id: Optional[str] = None,
        device_id: Optional[str] = None
    ):
        self.server_url = normalize_server_url(server_url or SERVER_URL)
        self.api_base = f"{self.server_url}/api/v1"
        self.agent_secret = AGENT_SECRET

        # Load or initialize device credentials with stable unique device identity
        creds = load_device_credentials()
        self.device_id = get_or_generate_stable_device_id(device_id)
        self.device_token = creds.get("device_token") or ""
        
        # Authoritative employee_id from parameter > valid saved credential > configured EMPLOYEE_ID
        raw_emp = employee_id or creds.get("employee_id") or get_configured_employee_id() or EMPLOYEE_ID or ""
        norm_emp = normalize_employee_id(raw_emp) or ""
        if norm_emp and validate_employee_id(norm_emp) and not _is_generated_employee_id(norm_emp):
            self.employee_id = norm_emp
        else:
            self.employee_id = normalize_employee_id(employee_id) or ""

        self.is_registered = bool(self.device_token)

    def _get_headers(self) -> Dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "X-Agent-Secret": self.agent_secret,
            "X-Device-Id": self.device_id,
            "X-Employee-Id": self.employee_id
        }
        if self.device_token:
            headers["X-Device-Token"] = self.device_token
            headers["Authorization"] = f"Bearer {self.device_token}"
        return headers

    def register(
        self,
        employee_id: Optional[str] = None,
        full_name: Optional[str] = None,
        email: Optional[str] = None,
        department: Optional[str] = None,
        designation: Optional[str] = None,
        phone_number: Optional[str] = None
    ) -> bool:
        """Register the endpoint device with the Central DLP Server."""
        emp_id = (employee_id or self.employee_id).strip()
        if not emp_id:
            logger.error("❌ CRITICAL: Cannot register endpoint device without an assigned Employee ID!")
            return False

        self.employee_id = emp_id
        url = f"{self.api_base}/agents/register"
        payload = {
            "hostname": HOSTNAME,
            "operating_system": OS_NAME,
            "ip_address": LOCAL_IP,
            "username": USERNAME,
            "full_name": full_name or EMPLOYEE_NAME,
            "email": email or EMPLOYEE_EMAIL,
            "department": department or EMPLOYEE_DEPT,
            "designation": designation or EMPLOYEE_DESIG,
            "phone_number": phone_number or EMPLOYEE_PHONE,
            "agent_version": "2.1.0",
            "employee_id": emp_id,
            "preferred_device_id": self.device_id
        }
        assert payload["employee_id"] == self.employee_id, "Registration employee_id mismatch"

        try:
            logger.info(f"Registering endpoint device with Central Server at {url} (Employee: {emp_id})...")
            resp = requests.post(url, json=payload, headers=self._get_headers(), timeout=6)
            if resp.status_code in [200, 201]:
                data = resp.json()
                self.device_id = data.get("device_id", self.device_id)
                self.device_token = data.get("device_token", "")
                self.is_registered = True
                save_device_credentials(self.device_id, self.device_token, self.employee_id)
                logger.info(f"Endpoint registered successfully! Assigned Device ID: {self.device_id}")
                return True
            elif resp.status_code in [404, 409] and "EMPLOYEE_NOT_REGISTERED" in resp.text:
                logger.error(f"❌ Employee ID '{emp_id}' not registered in Central SOC directory. Register employee before activating endpoint.")
                return False
            else:
                logger.warning(f"Registration rejected with status {resp.status_code}: {resp.text}")
                return False
        except requests.exceptions.RequestException as e:
            logger.warning(f"Central DLP Server unavailable for registration ({e}). Running in offline mode.")
            return False

    def send_heartbeat(
        self,
        status: str = "ONLINE",
        employee_id: Optional[str] = None,
        full_name: Optional[str] = None,
        email: Optional[str] = None,
        department: Optional[str] = None,
        designation: Optional[str] = None,
        monitoring_status: str = "ACTIVE",
        active_modules: Optional[Dict[str, str]] = None,
        metrics: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Send periodic heartbeat ping to the Central Server with full telemetry."""
        emp_id = (employee_id or self.employee_id).strip()
        if not emp_id:
            logger.warning("Heartbeat skipped: No Employee ID configured.")
            return False

        self.employee_id = emp_id
        url = f"{self.api_base}/agents/heartbeat"
        payload = {
            "device_id": self.device_id,
            "employee_id": emp_id,
            "hostname": HOSTNAME,
            "username": USERNAME,
            "full_name": full_name or EMPLOYEE_NAME,
            "email": email or EMPLOYEE_EMAIL,
            "department": department or EMPLOYEE_DEPT,
            "designation": designation or EMPLOYEE_DESIG,
            "ip_address": LOCAL_IP,
            "operating_system": OS_NAME,
            "agent_version": "2.1.0",
            "status": status,
            "monitoring_status": monitoring_status,
            "active_monitoring_modules": active_modules or {
                "usb": "ACTIVE",
                "file": "ACTIVE",
                "clipboard": "ACTIVE",
                "process": "ACTIVE",
                "browser": "ACTIVE",
                "email": "ACTIVE",
                "event": "ACTIVE"
            },
            "metrics": metrics or {}
        }
        assert payload["employee_id"] == self.employee_id, "Heartbeat employee_id mismatch"

        try:
            resp = requests.post(url, json=payload, headers=self._get_headers(), timeout=5)
            if resp.status_code == 200:
                # Flush offline queue when connectivity is healthy
                self.flush_offline_queue()
                return True
            return False
        except requests.exceptions.RequestException:
            logger.debug(f"Heartbeat failed: Central Server at {self.server_url} unreachable.")
            return False

    def send_status_event(
        self,
        event: str,
        employee_id: Optional[str] = None,
        details: Optional[str] = None
    ) -> bool:
        """
        Send operational lifecycle event (AGENT_STARTED, MONITORING_STARTED, AGENT_STOPPED).
        """
        emp_id = (employee_id or self.employee_id).strip()
        if not emp_id:
            logger.warning(f"Status event '{event}' skipped: No Employee ID configured.")
            return False

        self.employee_id = emp_id
        url = f"{self.api_base}/agents/status"
        payload = {
            "device_id": self.device_id,
            "employee_id": self.employee_id,
            "event": event,
            "details": details or f"Host: {HOSTNAME} ({LOCAL_IP})"
        }
        assert payload["employee_id"] == self.employee_id, "Status event employee_id mismatch"
        assert payload["device_id"] == self.device_id, "Status event device_id mismatch"

        try:
            resp = requests.post(url, json=payload, headers=self._get_headers(), timeout=5)
            return resp.status_code == 200
        except Exception as e:
            logger.debug(f"Operational event dispatch ({event}) deferred: {e}")
            return False

    def send_dlp_event(self, event_payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send a DLP security event (USB, Browser, Email, File) to the Central Server.
        Automatically queues event locally if the Central Server is unreachable.
        """
        payload_emp = event_payload.get("employee_id")
        if payload_emp and payload_emp != self.employee_id:
            logger.error(f"❌ Rejected DLP event dispatch with inconsistent employee_id '{payload_emp}' (Expected '{self.employee_id}')")
            raise AssertionError(f"DLP event employee_id mismatch: {payload_emp} != {self.employee_id}")

        payload_dev = event_payload.get("device_id")
        if payload_dev and payload_dev != self.device_id:
            logger.error(f"❌ Rejected DLP event dispatch with inconsistent device_id '{payload_dev}' (Expected '{self.device_id}')")
            raise AssertionError(f"DLP event device_id mismatch: {payload_dev} != {self.device_id}")

        # Ensure authoritative device and employee metadata is attached
        event_payload["device_id"] = self.device_id
        event_payload["employee_id"] = self.employee_id
        event_payload.setdefault("source", "endpoint_agent")

        ev_id = event_payload.get("event_id", "new")
        logger.info(f"Creating event {ev_id} for employee {self.employee_id}, device {self.device_id}")

        url = f"{self.api_base}/dlp/events"
        try:
            resp = requests.post(url, json=event_payload, headers=self._get_headers(), timeout=7)
            if resp.status_code in [200, 201]:
                data = resp.json()
                logger.info(f"DLP Event accepted by Central Server -> Policy Action: [{data.get('action', 'ALLOW')}], Risk Score: {data.get('risk_score', 0)}")
                return data
            else:
                logger.warning(f"Central Server rejected DLP event ({resp.status_code}). Buffering to offline queue.")
                event_queue.push("DLP_EVENT", event_payload)
                return {"action": "ALLOW", "status": "QUEUED_OFFLINE", "risk_score": 0.0}
        except requests.exceptions.RequestException as e:
            logger.warning(f"Connection to Central Server failed ({e}). Event saved to offline queue.")
            event_queue.push("DLP_EVENT", event_payload)
            return {"action": "ALLOW", "status": "QUEUED_OFFLINE", "risk_score": 0.0}

    def flush_offline_queue(self, max_items: int = 50) -> int:
        """
        Replay buffered offline events to the Central Server once connection is re-established.
        Preserves original offline event employee_id, device_id, and event_id.
        """
        if event_queue.size() == 0:
            return 0

        batch = event_queue.peek_batch(limit=max_items)
        if not batch:
            return 0

        logger.info(f"Synchronizing {len(batch)} buffered offline events with Central DLP Server...")
        synced_ids = []

        for row_id, event_type, payload in batch:
            # Preserve original queued employee_id and device_id if present; fallback to authoritative instance state
            payload["employee_id"] = payload.get("employee_id") or self.employee_id
            payload["device_id"] = payload.get("device_id") or self.device_id

            headers = {
                "Content-Type": "application/json",
                "X-Agent-Secret": self.agent_secret,
                "X-Device-Id": payload["device_id"],
                "X-Employee-Id": payload["employee_id"]
            }
            if self.device_token:
                headers["X-Device-Token"] = self.device_token
                headers["Authorization"] = f"Bearer {self.device_token}"

            url = f"{self.api_base}/dlp/events"
            try:
                resp = requests.post(url, json=payload, headers=headers, timeout=5)
                if resp.status_code in [200, 201]:
                    synced_ids.append(row_id)
                else:
                    break
            except Exception:
                # Connection dropped again; stop batch and retry on next heartbeat
                break

        if synced_ids:
            event_queue.delete_batch(synced_ids)
            logger.info(f"Successfully synchronized {len(synced_ids)} offline events.")

        return len(synced_ids)
