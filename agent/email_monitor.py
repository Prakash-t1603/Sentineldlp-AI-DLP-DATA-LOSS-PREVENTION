import os
import sys
import time
import base64
import threading
from pathlib import Path
from typing import Optional, Dict, Any, List
import requests

from agent.config import SERVER_URL, API_BASE_URL, AGENT_SECRET, EMPLOYEE_ID, HOSTNAME
from agent.logger import get_agent_logger as get_logger

logger = get_logger("SentinelDLP.Agent.EmailMonitor")

class EmailMonitor:
    """
    Modular Email DLP Agent component for monitoring, intercepting, and inspecting
    authorized corporate outgoing emails and attachments (Microsoft 365, Gmail, SMTP gateways).
    Communicates strictly via Central Server REST API.
    """
    def __init__(self, agent_instance=None):
        self.agent = agent_instance
        self.employee_id = getattr(agent_instance, "employee_id", EMPLOYEE_ID)
        self.hostname = getattr(agent_instance, "hostname", HOSTNAME)
        self.server_url = getattr(agent_instance, "server_url", SERVER_URL).rstrip("/")
        self.agent_secret = getattr(agent_instance, "agent_secret", AGENT_SECRET)
        self.is_running = False

    def _get_headers(self) -> Dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "X-Agent-Secret": self.agent_secret
        }
        if self.agent and getattr(self.agent, "api_client", None):
            return self.agent.api_client._get_headers()
        return headers

    def inspect_outgoing_email(
        self,
        sender: str,
        recipient: str,
        file_path: Optional[str] = None,
        file_name: Optional[str] = None,
        file_content: Optional[str] = None,
        file_bytes: Optional[bytes] = None,
        subject: str = "",
        body: str = "",
        application: str = "Corporate Mail"
    ) -> Dict[str, Any]:
        """
        Inspect outgoing email and attachment for sensitive data exfiltration via Central DLP API.
        """
        url = f"{self.server_url}/api/v1/dlp/email-event"
        b64_content = None
        if file_bytes:
            b64_content = base64.b64encode(file_bytes).decode("utf-8")
        elif file_content:
            b64_content = base64.b64encode(file_content.encode("utf-8")).decode("utf-8")

        payload = {
            "channel": "EMAIL",
            "application": application,
            "sender": sender,
            "recipient": recipient,
            "file_name": file_name or (Path(file_path).name if file_path else "attachment.dat"),
            "file_size": len(file_bytes) if file_bytes else (len(file_content) if file_content else 0),
            "file_path": file_path,
            "subject": subject,
            "body": body,
            "extracted_text": file_content or "",
            "file_content_base64": b64_content,
            "employee_id": self.employee_id,
            "device_id": self.hostname
        }
        try:
            resp = requests.post(url, json=payload, headers=self._get_headers(), timeout=10)
            if resp.status_code == 200:
                return resp.json()
            else:
                logger.warning(f"Email DLP API returned {resp.status_code}: {resp.text}")
                return {"action": "ALLOW", "risk_score": 0.0, "status": "ERROR"}
        except Exception as e:
            logger.error(f"Error calling Email DLP API: {e}")
            return {"action": "ALLOW", "risk_score": 0.0, "status": "ERROR"}

    def start(self):
        self.is_running = True
        logger.info("Modular Email DLP Agent active.")

    def stop(self):
        self.is_running = False
        logger.info("Modular Email DLP Agent stopped.")

email_monitor = EmailMonitor()
