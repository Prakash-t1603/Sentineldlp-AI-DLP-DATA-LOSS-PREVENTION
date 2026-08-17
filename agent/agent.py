import os
import sys
import time
import signal
import threading
import requests
from pathlib import Path
from typing import Optional, Dict, Any

from agent.config import (
    BACKEND_URL, AGENT_SECRET, EMPLOYEE_ID, USERNAME,
    HOSTNAME, LOCAL_IP, OS_NAME, MONITORED_PATHS,
    HEARTBEAT_INTERVAL_SECONDS
)
from agent.exfiltration_monitor import ExfiltrationMonitor
from agent.clipboard_monitor import ClipboardMonitor
from agent.file_monitor import FileMonitor
from agent.usb_monitor import USBMonitor
from agent.process_monitor import ProcessMonitor
from agent.event_monitor import EventMonitor
from backend.utils.helpers import get_logger

logger = get_logger("SentinelDLP.Agent.Core")

class SentinelAgent:
    def __init__(self):
        self.employee_id = EMPLOYEE_ID
        self.username = USERNAME
        self.hostname = HOSTNAME
        self.ip_address = LOCAL_IP
        self.os_name = OS_NAME
        self.backend_url = BACKEND_URL.rstrip("/")
        self.agent_secret = AGENT_SECRET
        self.is_running = False

        # Initialize Sub-monitors
        self.exfiltration_monitor = ExfiltrationMonitor(self)
        self.clipboard_monitor = ClipboardMonitor(self, self.exfiltration_monitor)
        self.file_monitor = FileMonitor(self, MONITORED_PATHS)
        self.usb_monitor = USBMonitor(self)
        self.process_monitor = ProcessMonitor(self)
        self.event_monitor = EventMonitor(self)

        self._heartbeat_thread = None

    def _get_headers(self) -> Dict[str, str]:
        return {
            "Content-Type": "application/json",
            "X-Agent-Secret": self.agent_secret
        }

    def register_endpoint(self) -> bool:
        """Register or update endpoint device with the SentinelDLP backend."""
        # 1. Direct DB registration if in-process
        try:
            from backend.database import SessionLocal
            from backend.models import Employee
            db = SessionLocal()
            try:
                emp = db.query(Employee).filter(Employee.employee_id == self.employee_id).first()
                if not emp:
                    emp = Employee(
                        employee_id=self.employee_id,
                        username=self.username,
                        hostname=self.hostname,
                        ip_address=self.ip_address,
                        operating_system=self.os_name,
                        status="ONLINE",
                        risk_score=0.0
                    )
                    db.add(emp)
                else:
                    emp.status = "ONLINE"
                    emp.hostname = self.hostname
                    emp.ip_address = self.ip_address
                db.commit()
                logger.info(f"Endpoint registered locally in DB: {self.employee_id}")
                return True
            finally:
                db.close()
        except Exception:
            pass

        # 2. REST API fallback for remote agents
        url = f"{self.backend_url}/employees/register"
        payload = {
            "employee_id": self.employee_id,
            "username": self.username,
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "operating_system": self.os_name
        }
        try:
            logger.info(f"Connecting to SentinelDLP backend at: {self.backend_url}...")
            resp = requests.post(url, json=payload, headers=self._get_headers(), timeout=5)
            if resp.status_code in [200, 201]:
                logger.info(f"Endpoint successfully registered. Employee ID: {self.employee_id}")
                return True
            else:
                logger.warning(f"Registration returned status {resp.status_code}: {resp.text}")
                return False
        except requests.exceptions.ConnectionError:
            logger.warning("Could not connect to SentinelDLP backend. Will retry in background.")
            return False
        except Exception as e:
            logger.error(f"Endpoint registration error: {e}")
            return False

    def send_heartbeat(self):
        """Send periodic heartbeat ping to the backend."""
        try:
            from backend.database import SessionLocal
            from backend.models import Employee
            from datetime import datetime, timezone
            db = SessionLocal()
            try:
                emp = db.query(Employee).filter(Employee.employee_id == self.employee_id).first()
                if emp:
                    emp.last_seen = datetime.now(timezone.utc)
                    emp.status = "ONLINE"
                    db.commit()
                    return
            finally:
                db.close()
        except Exception:
            pass

        url = f"{self.backend_url}/employees/heartbeat/{self.employee_id}"
        try:
            requests.post(url, headers=self._get_headers(), timeout=4)
        except Exception:
            pass

    def _heartbeat_loop(self):
        while self.is_running:
            self.send_heartbeat()
            time.sleep(HEARTBEAT_INTERVAL_SECONDS)

    def scan_file(self, filepath: Path, activity_type: str = "CREATE", destination: Optional[str] = None):
        """Send file inspection request to backend DLP analysis engine."""
        # 1. In-process direct DB indexing
        try:
            from backend.database import SessionLocal
            from backend.models import FileRecord, Employee
            from backend.services.file_analysis_service import file_analysis_service
            from backend.services.classifier_service import classifier_service
            from backend.utils.helpers import compute_file_hash
            from datetime import datetime, timezone

            db = SessionLocal()
            try:
                file_size = filepath.stat().st_size if filepath.exists() else 0
                file_hash = compute_file_hash(filepath)
                ext = filepath.suffix.lower()
                extracted_text, _ = file_analysis_service.extract_text_from_file(filepath)

                clf_result = classifier_service.classify_file(
                    filename=filepath.name,
                    filepath=str(filepath),
                    file_size=file_size,
                    extracted_text=extracted_text,
                    file_hash=file_hash
                )
                classification = clf_result.get("classification", "PUBLIC")
                sensitivity_score = clf_result.get("sensitivity_score", 0.0)

                rec = db.query(FileRecord).filter(
                    (FileRecord.filepath == str(filepath)) & (FileRecord.employee_id == self.employee_id)
                ).first()

                if rec:
                    rec.file_size = file_size
                    rec.hash = file_hash
                    rec.classification = classification
                    rec.sensitivity = sensitivity_score
                    rec.modified_at = datetime.now(timezone.utc)
                else:
                    rec = FileRecord(
                        employee_id=self.employee_id,
                        filename=filepath.name,
                        filepath=str(filepath),
                        extension=ext,
                        file_size=file_size,
                        hash=file_hash,
                        classification=classification,
                        sensitivity=sensitivity_score,
                        created_at=datetime.now(timezone.utc)
                    )
                    db.add(rec)
                db.commit()
                logger.info(f"File indexed locally in DB: {filepath.name} ({classification}, {sensitivity_score}/100)")
                return
            finally:
                db.close()
        except Exception:
            pass

        # 2. REST API fallback for remote agents
        url = f"{self.backend_url}/files/scan"
        payload = {
            "filepath": str(filepath.resolve()),
            "employee_id": self.employee_id,
            "action_type": activity_type
        }
        try:
            resp = requests.post(url, json=payload, headers=self._get_headers(), timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                classification = data.get("classification", "PUBLIC")
                risk_score = data.get("risk_score", 0.0)
                logger.info(
                    f"Scan complete: {filepath.name} -> {classification} "
                    f"(Sensitivity: {data.get('sensitivity_score')}/100, Risk: {risk_score})"
                )
            else:
                logger.warning(f"File scan API returned status {resp.status_code}: {resp.text}")
        except Exception as e:
            logger.error(f"Error scanning file {filepath.name}: {e}")

    def send_alert(
        self,
        alert_type: str,
        description: str,
        severity: str = "LOW",
        risk_score: float = 0.0,
        source: str = "ENDPOINT_AGENT",
        file_id: Optional[int] = None
    ):
        """Send real-time DLP alert to backend or directly record in database."""
        # 1. Direct DB session creation (instant in-process)
        try:
            from backend.database import SessionLocal
            from backend.services.alert_service import alert_service
            db = SessionLocal()
            try:
                alert = alert_service.process_and_create_alert(
                    db=db,
                    employee_id=self.employee_id,
                    alert_type=alert_type,
                    description=description,
                    source=source,
                    file_id=file_id,
                    risk_score=risk_score,
                    severity=severity
                )
                logger.info(f"🚨 REAL-TIME ALERT GENERATED [#{alert.id} - {severity}] -> {alert_type}: {description[:80]}...")
                return
            finally:
                db.close()
        except Exception as e:
            logger.debug(f"Direct DB alert creation bypassed: {e}")

        # 2. REST API fallback for remote agents
        url = f"{self.backend_url}/alerts"
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
            resp = requests.post(url, json=payload, headers=self._get_headers(), timeout=5)
            if resp.status_code in [200, 201]:
                logger.info(f"🚨 ALERT SENT [{severity}] -> {alert_type}: {description[:80]}...")
        except Exception as e:
            logger.error(f"Error transmitting alert: {e}")

    def send_activity_log(
        self,
        activity_type: str,
        filepath: Optional[str] = None,
        process_name: Optional[str] = None,
        destination: Optional[str] = None,
        risk_score: float = 0.0
    ):
        """Send telemetry activity log."""
        try:
            from backend.database import SessionLocal
            from backend.models import ActivityLog
            from datetime import datetime, timezone
            db = SessionLocal()
            try:
                act = ActivityLog(
                    employee_id=self.employee_id,
                    activity_type=activity_type,
                    filepath=filepath,
                    process_name=process_name,
                    destination=destination,
                    risk_score=risk_score,
                    timestamp=datetime.now(timezone.utc)
                )
                db.add(act)
                db.commit()
                return
            finally:
                db.close()
        except Exception:
            pass

        logger.debug(f"Telemetry activity logged: {activity_type} {filepath or ''} -> {destination or ''}")

    def start(self):
        """Start all real-time monitoring threads."""
        logger.info("==================================================")
        logger.info(f" Starting SentinelDLP Real-Time Endpoint Protection Agent")
        logger.info(f" Hostname: {self.hostname} | OS: {self.os_name}")
        logger.info(f" Employee ID: {self.employee_id} | User: {self.username}")
        logger.info(f" Active Watch Vectors: USB, Web Storage, WhatsApp/Chat, Email, Clipboard")
        logger.info(f" Monitored Directories: {MONITORED_PATHS}")
        logger.info("==================================================")

        self.is_running = True
        self.register_endpoint()

        # Start Sub-Monitors
        self.file_monitor.start()
        self.usb_monitor.start()
        self.clipboard_monitor.start()
        self.process_monitor.start()
        self.event_monitor.start()

        # Start Heartbeat
        self._heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self._heartbeat_thread.start()

        logger.info("🛡️  SentinelDLP Agent is actively guarding endpoint in REAL TIME.")

    def stop(self):
        """Gracefully stop agent and all child workers."""
        logger.info("Stopping SentinelDLP Endpoint Agent...")
        self.is_running = False
        self.clipboard_monitor.stop()
        self.file_monitor.stop()
        self.usb_monitor.stop()
        self.process_monitor.stop()
        self.event_monitor.stop()
        logger.info("SentinelDLP Agent shutdown complete.")

def run_agent():
    agent = SentinelAgent()
    
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
