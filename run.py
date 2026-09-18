import os
import sys
import time
import argparse
from pathlib import Path

import socket

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

def get_local_ip():
    """Discover host's primary local LAN/WAN IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def start_backend(host: str = None, port: int = None):
    """Launch the FastAPI Uvicorn server accessible via Primary IP and Localhost."""
    import uvicorn
    from backend.config import settings

    target_host = host or settings.API_HOST or "0.0.0.0"
    target_port = port or settings.API_PORT or 8000
    local_ip = get_local_ip()

    print(f"\n=======================================================")
    print(f" [*] Launching {settings.PROJECT_NAME} Central DLP Server...")
    print(f" [*] Network / Primary IP: http://{local_ip}:{target_port}")
    print(f" [*] SOC Dashboard:        http://{local_ip}:{target_port}/dashboard")
    print(f" [*] Employee Portal:      http://{local_ip}:{target_port}/employee-portal")
    print(f" [*] API Documentation:    http://{local_ip}:{target_port}/docs")
    print(f" [*] Localhost Loopback:   http://127.0.0.1:{target_port}")
    print(f"=======================================================\n")
    uvicorn.run("backend.main:app", host=target_host, port=target_port, reload=settings.DEBUG)

def start_agent():
    """Launch the SentinelDLP Endpoint Monitoring Agent."""
    from agent.agent import run_agent
    run_agent()

def start_simulated_fleet():
    """Launch multi-endpoint fleet simulation."""
    from agent.simulated_endpoints import run_fleet_simulator
    run_fleet_simulator()

def run_tests():
    """Execute pytest suite."""
    import pytest
    print("\n[*] Executing SentinelDLP Test Suite...\n")
    pytest.main(["tests/", "-v"])

def seed_demo_data():
    """Seed baseline employees and devices with clean zero risk scores (no fake alerts)."""
    from backend.database import SessionLocal, Base, engine
    from backend.models import Employee, Device, FileRecord, Alert, Incident, ActivityLog, DLPEvent
    from backend.main import init_database

    init_database()
    db = SessionLocal()
    print("\n[*] Seeding baseline employee directory and devices (clean alert baseline)...")

    try:
        # 1. Create Baseline Employees (Risk 0.0)
        employees_data = [
            ("EMP-001", "prakash", "Prakash T", "prakash@sentineldlp.io", "EMP-PC-TEST01", "172.24.143.236", "Linux", 0.0, "Engineering", "Security Lead"),
            ("EMP-002", "dhya", "Dhya P", "dhya@sentineldlp.io", "EMP-PC-WIN", "192.168.1.150", "Windows 11", 0.0, "Finance", "Financial Analyst"),
            ("EMP-DEV-01", "dev_alex", "Alex Rivera", "alex@sentineldlp.io", "WORKSTATION-ALEX", "192.168.1.101", "Windows 11", 0.0, "Engineering", "Software Engineer"),
            ("EMP-FIN-02", "sarah_finance", "Sarah Jenkins", "sarah@sentineldlp.io", "FIN-LAPTOP-02", "192.168.1.102", "Windows 10", 0.0, "Finance", "Accountant"),
            ("EMP-HR-03", "mark_hr", "Mark Vance", "mark@sentineldlp.io", "HR-STATION-03", "192.168.1.103", "macOS Sonoma", 0.0, "HR", "HR Generalist"),
            ("EMP-OPS-04", "elena_devops", "Elena Rostova", "elena@sentineldlp.io", "SRV-ADMIN-04", "192.168.1.104", "Ubuntu Linux 24.04", 0.0, "Operations", "DevOps Engineer"),
            ("EMP-MKT-05", "david_marketing", "David Kim", "david@sentineldlp.io", "MKT-LAPTOP-05", "192.168.1.105", "Windows 11", 0.0, "Marketing", "Marketing Specialist"),
        ]

        for emp_id, uname, fname, email, host, ip, os_name, risk, dept, desig in employees_data:
            existing = db.query(Employee).filter(Employee.employee_id == emp_id).first()
            if not existing:
                emp = Employee(
                    employee_id=emp_id,
                    username=uname,
                    full_name=fname,
                    email=email,
                    department=dept,
                    designation=desig,
                    hostname=host,
                    ip_address=ip,
                    operating_system=os_name,
                    status="ONLINE",
                    risk_score=risk
                )
                db.add(emp)
            else:
                existing.full_name = fname
                existing.email = email
                existing.department = dept
                existing.designation = desig
                existing.hostname = host
                existing.operating_system = os_name
        db.commit()

        # 2. Seed Endpoint Devices
        devices_data = [
            ("EMP-PC-TEST01", "EMP-PC-TEST01", "EMP-001", "prakash", "Linux", "172.24.143.236", "dev-tok-emp-pc-test01"),
            ("EMP-PC-WIN", "EMP-PC-WIN", "EMP-002", "dhya", "Windows 11", "192.168.1.150", "dev-tok-emp-pc-win"),
        ]

        for dev_id, host, emp_id, uname, os_name, ip, tok in devices_data:
            dev = db.query(Device).filter(Device.device_id == dev_id).first()
            if not dev:
                dev = Device(
                    device_id=dev_id,
                    hostname=host,
                    employee_id=emp_id,
                    username=uname,
                    operating_system=os_name,
                    ip_address=ip,
                    device_token=tok,
                    status="ONLINE",
                    monitoring_enabled=True,
                    monitoring_status="ACTIVE",
                    is_active=True
                )
                db.add(dev)
            else:
                dev.employee_id = emp_id
                dev.hostname = host
                dev.operating_system = os_name
                dev.username = uname
        db.commit()

        # Clear any preexisting alerts/incidents to guarantee clean state
        db.query(Incident).delete()
        db.query(Alert).delete()
        db.query(DLPEvent).delete()
        db.commit()

        print("[+] Baseline employee directory and devices seeded with 0.0 risk and 0 alerts.\n")
    except Exception as e:
        db.rollback()
        print(f"[-] Error seeding data: {e}")
    finally:
        db.close()

def clear_alerts():
    """Remove all alert, incident, and DLP event records from the database and reset employee risk scores."""
    from backend.database import SessionLocal
    from backend.models import Alert, Incident, Employee, DLPEvent
    db = SessionLocal()
    print("\n[*] Purging all alert, incident, and DLP event data from database...")
    try:
        events_deleted = db.query(DLPEvent).delete()
        incidents_deleted = db.query(Incident).delete()
        alerts_deleted = db.query(Alert).delete()
        # Reset employee risk scores
        employees = db.query(Employee).all()
        for emp in employees:
            emp.risk_score = 0.0
            emp.status = "ONLINE"
        db.commit()
        print(f"[+] Successfully removed {events_deleted} DLP event(s), {alerts_deleted} alert(s), and {incidents_deleted} incident(s).")
        print("[+] Reset employee risk scores to 0.0 (clean baseline).\n")
    except Exception as e:
        db.rollback()
        print(f"[-] Error clearing alerts: {e}")
    finally:
        db.close()

def reset_database():
    """Remove all seeded files, demo employees, alerts, incidents, DLP events, and activity logs."""
    from backend.database import SessionLocal
    from backend.models import Alert, Incident, Employee, FileRecord, ActivityLog, DLPEvent
    db = SessionLocal()
    print("\n[*] Resetting SentinelDLP database (removing seeded/sample data)...")
    try:
        dlp_cnt = db.query(DLPEvent).delete()
        inc = db.query(Incident).delete()
        alt = db.query(Alert).delete()
        act = db.query(ActivityLog).delete()
        fil = db.query(FileRecord).delete()
        emp = db.query(Employee).delete()
        db.commit()
        print(f"[+] Purged {dlp_cnt} DLP event(s), {fil} file record(s), {alt} alert(s), {inc} incident(s), {act} activity log(s), {emp} employee(s).")
        print("[+] Database is now 100% clean and ready for real-time live monitoring.\n")
    except Exception as e:
        db.rollback()
        print(f"[-] Error resetting database: {e}")
    finally:
        db.close()

def run_dlp_tests():
    """Execute the Unified Multi-Channel DLP test suite."""
    import pytest
    print("\n=======================================================")
    print(" [*] Executing Unified Multi-Channel DLP Test Suite...")
    print(" [*] Testing USB, Browser (Drive/WhatsApp), and Email channels")
    print("=======================================================\n")
    pytest.main(["tests/test_dlp_unified.py", "-v"])

def main():
    parser = argparse.ArgumentParser(description="SentinelDLP AI Platform CLI")
    parser.add_argument(
        "command",
        nargs="?",
        choices=["backend", "agent", "sim-agents", "seed", "test", "dlp-test", "clear-alerts", "reset-db"],
        default="backend",
        help="Component to start: backend, agent, sim-agents, seed, test, dlp-test, clear-alerts, or reset-db"
    )
    parser.add_argument("--host", default=None, help="Host IP to bind backend server (default: 0.0.0.0 for network IP access)")
    parser.add_argument("--port", type=int, default=None, help="Port to bind backend server (default: 8000)")

    args, unknown = parser.parse_known_args()

    if args.command == "backend":
        start_backend(host=args.host, port=args.port)
    elif args.command == "agent":
        start_agent()
    elif args.command == "sim-agents":
        start_simulated_fleet()
    elif args.command == "seed":
        seed_demo_data()
    elif args.command == "test":
        run_tests()
    elif args.command == "dlp-test":
        run_dlp_tests()
    elif args.command == "clear-alerts":
        clear_alerts()
    elif args.command == "reset-db":
        reset_database()

if __name__ == "__main__":
    main()
