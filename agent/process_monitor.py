import psutil
import threading
import time
from typing import Set, Dict
from agent.config import PROCESS_SCAN_INTERVAL_SECONDS
from backend.utils.helpers import get_logger

logger = get_logger("SentinelDLP.Agent.ProcessMonitor")

# Suspicious tools or high-risk file transfer utilities
WATCHLIST_PROCESSES = {
    "tor.exe": ("ANONYMIZATION_NETWORK", "CRITICAL", 85.0),
    "tor": ("ANONYMIZATION_NETWORK", "CRITICAL", 85.0),
    "nc.exe": ("NETCAT_TUNNEL", "HIGH", 75.0),
    "ncat.exe": ("NETCAT_TUNNEL", "HIGH", 75.0),
    "filezilla.exe": ("FTP_CLIENT", "MEDIUM", 45.0),
    "winscp.exe": ("SFTP_CLIENT", "MEDIUM", 45.0),
    "mega.exe": ("CLOUD_EXFILTRATION_CLIENT", "HIGH", 60.0),
    "dropbox.exe": ("CLOUD_SYNC_CLIENT", "LOW", 25.0),
    "googledrivesync.exe": ("CLOUD_SYNC_CLIENT", "LOW", 20.0),
    "curl.exe": ("DATA_TRANSFER_CLI", "MEDIUM", 35.0),
    "wget.exe": ("DATA_TRANSFER_CLI", "MEDIUM", 35.0),
    "wireshark.exe": ("PACKET_CAPTURE", "MEDIUM", 40.0)
}

class ProcessMonitor:
    def __init__(self, agent_instance):
        self.agent = agent_instance
        self.is_running = False
        self._thread = None
        self._alerted_pids: Set[int] = set()

    def _scan_processes(self):
        """Scan running processes for exfiltration tools."""
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'username']):
                try:
                    pname = proc.info.get('name', '')
                    if not pname:
                        continue
                    pname_lower = pname.lower()
                    pid = proc.info.get('pid', 0)

                    if pname_lower in WATCHLIST_PROCESSES and pid not in self._alerted_pids:
                        category, severity, risk_score = WATCHLIST_PROCESSES[pname_lower]
                        self._alerted_pids.add(pid)

                        logger.warning(f"HIGH-RISK PROCESS DETECTED: {pname} (PID: {pid}) - {category}")
                        self.agent.send_alert(
                            alert_type=f"SUSPICIOUS_PROCESS_{category}",
                            description=(
                                f"High-risk transfer/network process '{pname}' (PID: {pid}) "
                                f"detected on endpoint. Risk Category: {category}."
                            ),
                            severity=severity,
                            risk_score=risk_score,
                            source="PROCESS_MONITOR"
                        )

                        # Send activity log
                        self.agent.send_activity_log(
                            activity_type="PROCESS_SPAWN",
                            process_name=pname,
                            risk_score=risk_score
                        )
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except Exception as e:
            logger.error(f"Process scan error: {e}")

    def _loop(self):
        logger.info(f"ProcessMonitor started (Scanning every {PROCESS_SCAN_INTERVAL_SECONDS}s).")
        while self.is_running:
            self._scan_processes()
            time.sleep(PROCESS_SCAN_INTERVAL_SECONDS)

    def start(self):
        if not self.is_running:
            self.is_running = True
            self._thread = threading.Thread(target=self._loop, daemon=True)
            self._thread.start()

    def stop(self):
        self.is_running = False
        if self._thread:
            self._thread.join(timeout=2.0)
            logger.info("ProcessMonitor stopped.")
