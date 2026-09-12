import sys
import time
import random
import signal
import threading
import argparse
from typing import List, Dict, Any, Optional

from agent.api_client import AgentAPIClient
from agent.logger import get_agent_logger

logger = get_agent_logger("SentinelDLP.FleetSimulator")

SIMULATED_DEVICES = [
    {
        "device_id": "EMP-PC-001",
        "employee_id": "EMP-001",
        "hostname": "FINANCE-WS-01",
        "ip_address": "192.168.1.101",
        "os_name": "Windows 11 Pro",
        "role": "Financial Analyst"
    },
    {
        "device_id": "EMP-PC-002",
        "employee_id": "EMP-002",
        "hostname": "ENGINEERING-WS-02",
        "ip_address": "192.168.1.102",
        "os_name": "Ubuntu 22.04 LTS",
        "role": "Software Engineer"
    },
    {
        "device_id": "EMP-PC-003",
        "employee_id": "EMP-003",
        "hostname": "HR-MACBOOK-03",
        "ip_address": "192.168.1.103",
        "os_name": "macOS Sonoma 14.2",
        "role": "HR Manager"
    }
]

SAMPLE_SIMULATED_EVENTS = [
    {
        "channel": "USB",
        "application": "Removable USB Drive",
        "file_name": "quarterly_financial_q3_confidential.xlsx",
        "destination": "/media/usb/KINGSTON_32GB",
        "file_hash": "a1b2c3d4e5f67890abcdef1234567890",
        "file_size": 2457600,
        "file_type": ".xlsx",
        "sensitive_data_detected": True,
        "detection_type": "FINANCIAL_DATA",
        "risk_score": 92.5,
        "risk_level": "CRITICAL",
        "action": "BLOCK",
        "status": "BLOCKED",
        "details": "High-risk financial statement copied to unauthorized USB storage."
    },
    {
        "channel": "BROWSER",
        "application": "Google Chrome (Google Drive)",
        "file_name": "source_code_auth_service.py",
        "destination": "drive.google.com",
        "file_hash": "f6e5d4c3b2a10987fedcba0987654321",
        "file_size": 34816,
        "file_type": ".py",
        "sensitive_data_detected": True,
        "detection_type": "SOURCE_CODE",
        "risk_score": 85.0,
        "risk_level": "CRITICAL",
        "action": "BLOCK",
        "status": "BLOCKED",
        "details": "Proprietary backend code upload intercepted on personal cloud storage."
    },
    {
        "channel": "EMAIL",
        "application": "Microsoft Outlook",
        "file_name": "employee_payroll_records.csv",
        "destination": "external_recipient@gmail.com",
        "file_hash": "11223344556677889900aabbccddeeff",
        "file_size": 184320,
        "file_type": ".csv",
        "sensitive_data_detected": True,
        "detection_type": "PII",
        "risk_score": 88.0,
        "risk_level": "CRITICAL",
        "action": "BLOCK",
        "status": "BLOCKED",
        "details": "PII payroll data attached to external personal email."
    }
]


class SimulatedEndpointWorker:
    """
    Simulates a distinct endpoint running the SentinelDLP client daemon.
    """
    def __init__(self, device_spec: Dict[str, Any], server_url: str):
        self.spec = device_spec
        self.device_id = device_spec["device_id"]
        self.employee_id = device_spec["employee_id"]
        self.server_url = server_url
        self.api_client = AgentAPIClient(server_url=server_url)
        self.api_client.device_id = self.device_id
        self.is_running = False
        self._thread: Optional[threading.Thread] = None

    def start(self):
        self.is_running = True
        # Register device
        self.api_client.register(employee_id=self.employee_id)
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        logger.info(f"Simulated Endpoint [{self.device_id}] ({self.spec['hostname']}) started.")

    def _run_loop(self):
        loop_count = 0
        while self.is_running:
            try:
                # 1. Heartbeat
                cpu_metric = round(random.uniform(5.0, 35.0), 1)
                mem_metric = round(random.uniform(40.0, 68.0), 1)
                metrics = {"cpu_percent": cpu_metric, "memory_percent": mem_metric}
                
                self.api_client.send_heartbeat(status="ONLINE", metrics=metrics)
                loop_count += 1
            except Exception as e:
                logger.debug(f"Simulator [{self.device_id}] loop error: {e}")

            time.sleep(15)

    def stop(self):
        self.is_running = False


class FleetSimulator:
    def __init__(self, server_url: str = "http://127.0.0.1:8000"):
        self.server_url = server_url
        self.workers: List[SimulatedEndpointWorker] = []

    def start(self):
        logger.info("==================================================")
        logger.info(" 🚀 Launching SentinelDLP Multi-Endpoint Fleet Simulator")
        logger.info(f" Target Central Server: {self.server_url}")
        logger.info(f" Simulating {len(SIMULATED_DEVICES)} endpoints concurrently:")
        for dev in SIMULATED_DEVICES:
            logger.info(f"  - {dev['device_id']} ({dev['hostname']} | {dev['ip_address']} | {dev['os_name']})")
        logger.info("==================================================")

        for dev_spec in SIMULATED_DEVICES:
            worker = SimulatedEndpointWorker(dev_spec, self.server_url)
            worker.start()
            self.workers.append(worker)

    def stop(self):
        logger.info("Stopping Fleet Simulator...")
        for worker in self.workers:
            worker.stop()
        logger.info("Fleet Simulator stopped.")


def run_fleet_simulator(server_url: Optional[str] = None):
    parser = argparse.ArgumentParser(description="SentinelDLP Multi-Endpoint Fleet Simulator")
    parser.add_argument("--server-url", default="http://127.0.0.1:8000", help="Central Server URL")
    args, _ = parser.parse_known_args()

    simulator = FleetSimulator(server_url=server_url or args.server_url)

    def sig_handler(sig, frame):
        simulator.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    simulator.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        simulator.stop()


if __name__ == "__main__":
    run_fleet_simulator()
