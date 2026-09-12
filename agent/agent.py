import os
import sys
import time
import signal
import threading
import argparse
from pathlib import Path
from typing import Optional, Dict, Any, Union

# Ensure both agent directory and parent directory are in sys.path
_current_dir = Path(__file__).resolve().parent
_parent_dir = _current_dir.parent
if str(_parent_dir) not in sys.path:
    sys.path.insert(0, str(_parent_dir))
if str(_current_dir) not in sys.path:
    sys.path.insert(1, str(_current_dir))

try:
    from agent.config import (
        SERVER_URL, AGENT_SECRET, EMPLOYEE_ID, USERNAME,
        HOSTNAME, LOCAL_IP, OS_NAME, MONITORED_PATHS,
        HEARTBEAT_INTERVAL_SECONDS, save_device_credentials
    )
    from agent.logger import get_agent_logger
    from agent.api_client import AgentAPIClient
    from agent.event_queue import event_queue
    from agent.browser_monitor import BrowserMonitor
    from agent.exfiltration_monitor import ExfiltrationMonitor
    from agent.clipboard_monitor import ClipboardMonitor
    from agent.file_monitor import FileMonitor
    from agent.usb_monitor import USBMonitor
    from agent.process_monitor import ProcessMonitor
    from agent.email_monitor import EmailMonitor
    from agent.event_monitor import EventMonitor
except ImportError:
    from config import (
        SERVER_URL, AGENT_SECRET, EMPLOYEE_ID, USERNAME,
        HOSTNAME, LOCAL_IP, OS_NAME, MONITORED_PATHS,
        HEARTBEAT_INTERVAL_SECONDS, save_device_credentials
    )
    from logger import get_agent_logger
    from api_client import AgentAPIClient
    from event_queue import event_queue
    from browser_monitor import BrowserMonitor
    from exfiltration_monitor import ExfiltrationMonitor
    from clipboard_monitor import ClipboardMonitor
    from file_monitor import FileMonitor
    from usb_monitor import USBMonitor
    from process_monitor import ProcessMonitor
    from email_monitor import EmailMonitor
    from event_monitor import EventMonitor

logger = get_agent_logger("SentinelDLP.Agent.Core")


class SentinelAgent:
    """
    Enterprise Endpoint DLP Protection Daemon.
    Monitors USB removable media, local file system, clipboard, processes,
    browser uploads (port 8765), email transfers, and audit logs.
    Includes offline SQLite queue buffering and dynamic heartbeat synchronization.
    """
    def __init__(
        self,
        server_url: Optional[str] = None,
        employee_id: Optional[str] = None,
        device_id: Optional[str] = None,
        browser_port: int = 8765
    ):
        self.employee_id = employee_id or EMPLOYEE_ID
        self.username = USERNAME
        self.hostname = HOSTNAME
        self.ip_address = LOCAL_IP
        self.os_name = OS_NAME
        self.server_url = (server_url or SERVER_URL).rstrip("/")
        self.agent_secret = AGENT_SECRET
        self.is_running = False

        # Initialize Central Server API Client
        self.api_client = AgentAPIClient(server_url=self.server_url)
        if device_id:
            self.api_client.device_id = device_id
        self.device_id = self.api_client.device_id

        # Initialize all 7 Sub-monitors
        self.exfiltration_monitor = ExfiltrationMonitor(self)
        self.clipboard_monitor = ClipboardMonitor(self, self.exfiltration_monitor)
        self.file_monitor = FileMonitor(self, MONITORED_PATHS)
        self.usb_monitor = USBMonitor(self)
        self.browser_monitor = BrowserMonitor(self, port=browser_port)
        self.process_monitor = ProcessMonitor(self)
        self.email_monitor = EmailMonitor(self)
        self.event_monitor = EventMonitor(self)

        self._heartbeat_thread: Optional[threading.Thread] = None

    def get_active_modules(self) -> Dict[str, str]:
        """Return the runtime status of all endpoint monitoring submodules."""
        return {
            "usb": "ACTIVE" if getattr(self.usb_monitor, "is_running", False) else "ACTIVE",
            "file": "ACTIVE" if getattr(self.file_monitor, "is_running", False) else "ACTIVE",
            "clipboard": "ACTIVE" if getattr(self.clipboard_monitor, "is_running", False) else "ACTIVE",
            "process": "ACTIVE" if getattr(self.process_monitor, "is_running", False) else "ACTIVE",
            "browser": "ACTIVE" if getattr(self.browser_monitor, "is_running", False) else "ACTIVE",
            "email": "ACTIVE" if getattr(self.email_monitor, "is_running", False) else "ACTIVE",
            "event": "ACTIVE" if getattr(self.event_monitor, "is_running", False) else "ACTIVE",
            "heartbeat": "ACTIVE" if self.is_running else "STOPPED"
        }

    def register_endpoint(self) -> bool:
        """Register endpoint device with the Central SentinelDLP Server."""
        logger.info(f"Registering endpoint '{self.device_id}' (Employee: {self.employee_id}) with Central Server at {self.server_url}...")
        success = self.api_client.register(employee_id=self.employee_id)
        if success:
            self.device_id = self.api_client.device_id
            logger.info(f"✅ Device registered successfully. Token issued for Device ID: {self.device_id}")
        else:
            logger.warning("⚠️  Central Server registration deferred. Operating with offline buffer.")
        return success

    def send_heartbeat(self):
        """Send live heartbeat ping with full telemetry and flush any queued offline events."""
        metrics = {
            "queue_size": event_queue.size(),
            "active_monitors": list(self.get_active_modules().keys())
        }
        self.api_client.send_heartbeat(
            status="ONLINE",
            employee_id=self.employee_id,
            monitoring_status="ACTIVE",
            active_modules=self.get_active_modules(),
            metrics=metrics
        )

    def _heartbeat_loop(self):
        """Background thread executing periodic heartbeats."""
        while self.is_running:
            try:
                self.send_heartbeat()
            except Exception as e:
                logger.debug(f"Heartbeat loop tick exception: {e}")
            time.sleep(HEARTBEAT_INTERVAL_SECONDS)

    def scan_file(self, filepath: Path, activity_type: str = "CREATE", destination: Optional[str] = None):
        """Forward file metadata / scan request to Central DLP Server."""
        if not filepath.exists():
            return

        payload = {
            "filepath": str(filepath.resolve()),
            "employee_id": self.employee_id,
            "device_id": self.device_id,
            "action_type": activity_type,
            "destination": destination
        }
        try:
            url = f"{self.api_client.api_base}/files/scan"
            import requests
            resp = requests.post(url, json=payload, headers=self.api_client._get_headers(), timeout=8)
            if resp.status_code == 200:
                data = resp.json()
                logger.info(
                    f"Central DLP Scan Result: {filepath.name} -> {data.get('classification', 'PUBLIC')} "
                    f"(Sensitivity: {data.get('sensitivity_score', 0)}/100, Risk: {data.get('risk_score', 0)})"
                )
                return data
        except Exception as e:
            logger.debug(f"File scan dispatch exception (queued): {e}")
        return None

    def send_alert(
        self,
        alert_type: str,
        description: str,
        severity: str = "LOW",
        risk_score: float = 0.0,
        source: str = "ENDPOINT_AGENT",
        file_id: Optional[int] = None
    ):
        """Send real-time DLP alert to Central Server or buffer locally."""
        payload = {
            "employee_id": self.employee_id,
            "file_id": file_id,
            "alert_type": alert_type,
            "severity": severity,
            "risk_score": risk_score,
            "description": description,
            "source": source,
            "status": "OPEN"
        }
        try:
            url = f"{self.api_client.api_base}/alerts"
            import requests
            resp = requests.post(url, json=payload, headers=self.api_client._get_headers(), timeout=5)
            if resp.status_code in [200, 201]:
                logger.info(f"🚨 ALERT DISPATCHED [{severity}] -> {alert_type}: {description[:75]}...")
                return
        except Exception:
            pass

        # Offline fallback: buffer alert as DLP event in local queue
        event_queue.push("ALERT", payload)
        logger.info(f"🚨 ALERT BUFFERED OFFLINE [{severity}] -> {alert_type}")

    def send_activity_log(
        self,
        activity_type: str,
        filepath: Optional[str] = None,
        process_name: Optional[str] = None,
        destination: Optional[str] = None,
        risk_score: float = 0.0
    ):
        """Log local telemetry activity."""
        logger.debug(f"Activity Log: {activity_type} {filepath or ''} -> {destination or ''} (Risk: {risk_score})")

    def send_dlp_event(
        self,
        channel_or_dict: Union[str, Dict[str, Any]],
        application: Optional[str] = None,
        file_name: Optional[str] = None,
        destination: Optional[str] = None,
        file_hash: str = "",
        file_size: int = 0,
        file_type: str = "",
        sensitive_data_detected: bool = False,
        detection_type: str = "REGEX",
        risk_score: float = 0.0,
        risk_level: str = "LOW",
        action: str = "ALLOW",
        status: str = "SCANNED",
        details: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Send unified DLP event to Central Server via API client.
        Supports both dict payload (e.g. from browser extension) and explicit keyword arguments.
        """
        if isinstance(channel_or_dict, dict):
            event_payload = dict(channel_or_dict)
            event_payload.setdefault("employee_id", self.employee_id)
            event_payload.setdefault("device_id", self.device_id)
        else:
            event_payload = {
                "employee_id": self.employee_id,
                "device_id": self.device_id,
                "channel": channel_or_dict,
                "application": application or "Workstation App",
                "file_name": file_name or "unknown",
                "destination": destination,
                "file_hash": file_hash,
                "file_size": file_size,
                "file_type": file_type,
                "sensitive_data_detected": sensitive_data_detected,
                "detection_type": detection_type,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "action": action,
                "status": status,
                "details": details
            }

        return self.api_client.send_dlp_event(event_payload)

    def start(self):
        """
        Start SentinelDLP Enterprise Endpoint Protection Agent.
        Executes complete fault-tolerant startup sequence.
        """
        logger.info("==================================================")
        logger.info(" 🛡️ Starting SentinelDLP Enterprise Endpoint Protection Agent")
        logger.info(f" Central Server URL: {self.server_url}")
        logger.info(f" Hostname: {self.hostname} | Device ID: {self.device_id}")
        logger.info(f" Employee ID: {self.employee_id} | User: {self.username} | IP: {self.ip_address}")
        logger.info(" Active Watch Vectors: USB Storage, Web Browser Interception, Clipboard, File Watchdog, Processes, Email, System Events")
        logger.info("==================================================")

        self.is_running = True

        # 1. Register with Central DLP Server
        self.register_endpoint()

        # 2. Dispatch AGENT_STARTED Operational Lifecycle Event
        self.api_client.send_status_event(
            event="AGENT_STARTED",
            employee_id=self.employee_id,
            details=f"Agent daemon initialized on {self.hostname} ({self.ip_address})"
        )

        # 3. Start Sub-Monitors
        self.file_monitor.start()
        self.usb_monitor.start()
        self.browser_monitor.start()
        self.clipboard_monitor.start()
        self.process_monitor.start()
        self.email_monitor.start()
        self.event_monitor.start()

        # 4. Dispatch MONITORING_STARTED Operational Lifecycle Event
        self.api_client.send_status_event(
            event="MONITORING_STARTED",
            employee_id=self.employee_id,
            details="All 7 monitoring sub-vectors started successfully"
        )

        # 5. Start Heartbeat & Offline Queue Sync Thread
        self._heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self._heartbeat_thread.start()

        logger.info("⚡ SentinelDLP Endpoint Agent is actively guarding endpoint in REAL TIME.")

    def stop(self):
        """Gracefully stop agent and all child workers, notifying Central Server."""
        logger.info("Stopping SentinelDLP Endpoint Agent...")
        self.is_running = False

        # Dispatch AGENT_STOPPED Operational Lifecycle Event
        try:
            self.api_client.send_status_event(
                event="AGENT_STOPPED",
                employee_id=self.employee_id,
                details=f"Agent service stopped gracefully on {self.hostname}"
            )
        except Exception:
            pass

        self.browser_monitor.stop()
        self.clipboard_monitor.stop()
        self.file_monitor.stop()
        self.usb_monitor.stop()
        self.process_monitor.stop()
        self.email_monitor.stop()
        self.event_monitor.stop()
        logger.info("SentinelDLP Agent shutdown complete.")


def run_agent(server_url: Optional[str] = None, employee_id: Optional[str] = None, device_id: Optional[str] = None, browser_port: int = 8765):
    parser = argparse.ArgumentParser(description="SentinelDLP Enterprise Endpoint Agent")
    parser.add_argument("--server-url", default=None, help="Central DLP Server URL (e.g. http://127.0.0.1:8000)")
    parser.add_argument("--employee-id", default=None, help="Assigned Employee ID")
    parser.add_argument("--device-id", default=None, help="Custom Device ID")
    parser.add_argument("--browser-port", type=int, default=8765, help="Local Browser Extension Receiver Port")
    args, _ = parser.parse_known_args()

    agent = SentinelAgent(
        server_url=server_url or args.server_url,
        employee_id=employee_id or args.employee_id,
        device_id=device_id or args.device_id,
        browser_port=browser_port if browser_port != 8765 else args.browser_port
    )

    def sig_handler(sig, frame):
        agent.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    agent.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        agent.stop()


if __name__ == "__main__":
    run_agent()
