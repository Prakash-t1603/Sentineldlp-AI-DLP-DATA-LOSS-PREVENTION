import time
import requests
from typing import Dict, Any, Optional, Tuple
from agent.config import (
    API_BASE_URL, SERVER_URL, AGENT_SECRET, HOSTNAME,
    OS_NAME, LOCAL_IP, EMPLOYEE_ID, USERNAME, load_device_credentials, save_device_credentials
)
from agent.logger import get_agent_logger
from agent.event_queue import event_queue

logger = get_agent_logger("SentinelDLP.Agent.APIClient")

class AgentAPIClient:
    """
    HTTP API client managing communication between the Endpoint Agent and the Central DLP Server.
    Supports auto-registration, device credential persistence, heartbeats, status events, and offline queue fallback.
    """
    def __init__(self, server_url: Optional[str] = None):
        self.server_url = (server_url or SERVER_URL).rstrip("/")
        self.api_base = f"{self.server_url}/api/v1"
        self.agent_secret = AGENT_SECRET

        # Load or initialize device credentials
        creds = load_device_credentials()
        self.device_id = creds.get("device_id") or f"EMP-PC-{HOSTNAME.upper()[:6]}"
        self.device_token = creds.get("device_token") or ""
        self.is_registered = bool(self.device_token)

    def _get_headers(self) -> Dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "X-Agent-Secret": self.agent_secret,
            "X-Device-Id": self.device_id
        }
        if self.device_token:
            headers["X-Device-Token"] = self.device_token
            headers["Authorization"] = f"Bearer {self.device_token}"
        return headers

    def register(self, employee_id: Optional[str] = None) -> bool:
        """Register the endpoint device with the Central DLP Server."""
        url = f"{self.api_base}/agents/register"
        payload = {
            "hostname": HOSTNAME,
            "operating_system": OS_NAME,
            "ip_address": LOCAL_IP,
            "username": USERNAME,
            "agent_version": "2.1.0",
            "employee_id": employee_id or EMPLOYEE_ID,
            "preferred_device_id": self.device_id
        }
        try:
            logger.info(f"Registering endpoint device with Central Server at {url}...")
            resp = requests.post(url, json=payload, headers=self._get_headers(), timeout=6)
            if resp.status_code in [200, 201]:
                data = resp.json()
                self.device_id = data.get("device_id", self.device_id)
                self.device_token = data.get("device_token", "")
                self.is_registered = True
                save_device_credentials(self.device_id, self.device_token)
                logger.info(f"Endpoint registered successfully! Assigned Device ID: {self.device_id}")
                return True
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
        monitoring_status: str = "ACTIVE",
        active_modules: Optional[Dict[str, str]] = None,
        metrics: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Send periodic heartbeat ping to the Central Server with full telemetry."""
        url = f"{self.api_base}/agents/heartbeat"
        payload = {
            "device_id": self.device_id,
            "employee_id": employee_id or EMPLOYEE_ID,
            "hostname": HOSTNAME,
            "username": USERNAME,
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
        url = f"{self.api_base}/agents/status"
        payload = {
            "device_id": self.device_id,
            "employee_id": employee_id or EMPLOYEE_ID,
            "event": event,
            "details": details or f"Host: {HOSTNAME} ({LOCAL_IP})"
        }
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
        # Ensure device metadata is attached
        event_payload.setdefault("device_id", self.device_id)
        event_payload.setdefault("employee_id", EMPLOYEE_ID)
        event_payload.setdefault("source", "endpoint_agent")

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
        """
        if event_queue.size() == 0:
            return 0

        batch = event_queue.peek_batch(limit=max_items)
        if not batch:
            return 0

        logger.info(f"Synchronizing {len(batch)} buffered offline events with Central DLP Server...")
        synced_ids = []

        for row_id, event_type, payload in batch:
            url = f"{self.api_base}/dlp/events"
            try:
                resp = requests.post(url, json=payload, headers=self._get_headers(), timeout=5)
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
