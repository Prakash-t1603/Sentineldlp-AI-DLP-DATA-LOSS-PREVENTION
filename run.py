import os
import sys
import time
import argparse
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

def start_backend():
    """Launch the FastAPI Uvicorn dev server."""
    import uvicorn
    from backend.config import settings
    print(f"\n=======================================================")
    print(f" [*] Launching {settings.PROJECT_NAME} Backend Server...")
    print(f" [*] SOC Dashboard:   http://{settings.API_HOST}:{settings.API_PORT}")
    print(f" [*] Employee Portal: http://{settings.API_HOST}:{settings.API_PORT}/employee-portal")
    print(f" [*] API Docs:        http://{settings.API_HOST}:{settings.API_PORT}/docs")
    print(f"=======================================================\n")
    uvicorn.run("backend.main:app", host=settings.API_HOST, port=settings.API_PORT, reload=settings.DEBUG)

def start_agent():
    """Launch the SentinelDLP Endpoint Monitoring Agent."""
    from agent.agent import run_agent
    run_agent()

def run_tests():
    """Execute pytest suite."""
    import pytest
    print("\n[*] Executing SentinelDLP Test Suite...\n")
    pytest.main(["tests/", "-v"])

def seed_demo_data():
    """Seed sample employees, realistic sensitive files, and simulated DLP alerts."""
    from backend.database import SessionLocal, Base, engine
    from backend.models import Employee, FileRecord, Alert, Incident, ActivityLog
    from backend.services.classifier_service import classifier_service
    from backend.services.alert_service import alert_service
    from backend.main import init_database

    init_database()
    db = SessionLocal()
    print("\n[*] Seeding realistic DLP demo simulation data...")

    try:
        # 1. Create Sample Employees
        employees_data = [
            ("EMP-DEV-01", "dev_alex", "WORKSTATION-ALEX", "192.168.1.101", "Windows 11", 15.0),
            ("EMP-FIN-02", "sarah_finance", "FIN-LAPTOP-02", "192.168.1.102", "Windows 10", 78.5),
            ("EMP-HR-03", "mark_hr", "HR-STATION-03", "192.168.1.103", "macOS Sonoma", 35.0),
            ("EMP-OPS-04", "elena_devops", "SRV-ADMIN-04", "192.168.1.104", "Ubuntu Linux 24.04", 88.0),
            ("EMP-MKT-05", "david_marketing", "MKT-LAPTOP-05", "192.168.1.105", "Windows 11", 8.0),
        ]

        for emp_id, uname, host, ip, os_name, risk in employees_data:
            existing = db.query(Employee).filter(Employee.employee_id == emp_id).first()
            if not existing:
                emp = Employee(
                    employee_id=emp_id,
                    username=uname,
                    hostname=host,
                    ip_address=ip,
                    operating_system=os_name,
                    status="ONLINE" if risk < 80 else "SUSPICIOUS",
                    risk_score=risk
                )
                db.add(emp)
        db.commit()

        # 2. Create Sample Monitored File Records
        files_data = [
            ("EMP-FIN-02", "Q3_Salary_and_Bonus_Rollout.docx", "C:/Corporate/Finance/Q3_Salary_and_Bonus_Rollout.docx", ".docx", 45000, "HIGHLY_CONFIDENTIAL", 92.0),
            ("EMP-OPS-04", "production_master_credentials.env", "C:/Deployments/production_master_credentials.env", ".env", 1200, "HIGHLY_CONFIDENTIAL", 98.0),
            ("EMP-HR-03", "Employee_SSN_and_Aadhaar_Directory.csv", "C:/HR/Records/Employee_SSN_and_Aadhaar_Directory.csv", ".csv", 18500, "CONFIDENTIAL", 78.0),
            ("EMP-DEV-01", "architecture_overview.md", "C:/Code/Docs/architecture_overview.md", ".md", 8500, "INTERNAL", 35.0),
            ("EMP-MKT-05", "public_press_release_2026.txt", "C:/Public/Marketing/public_press_release_2026.txt", ".txt", 4200, "PUBLIC", 5.0),
        ]

        for emp_id, fname, fpath, ext, size, cls, sens in files_data:
            existing_f = db.query(FileRecord).filter(FileRecord.filepath == fpath).first()
            if not existing_f:
                f_rec = FileRecord(
                    employee_id=emp_id,
                    filename=fname,
                    filepath=fpath,
                    extension=ext,
                    file_size=size,
                    classification=cls,
                    sensitivity=sens,
                    hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                )
                db.add(f_rec)
        db.commit()

        # 3. Create Sample Alerts & Incidents
        alert_service.process_and_create_alert(
            db=db,
            employee_id="EMP-OPS-04",
            alert_type="SECRET_FILE_EXFILTRATION_RISK",
            description="High risk: 'production_master_credentials.env' accessed by unauthorized process 'curl.exe'. Contains database credentials and API master keys.",
            source="PROCESS_MONITOR",
            risk_score=95.0,
            severity="CRITICAL"
        )

        alert_service.process_and_create_alert(
            db=db,
            employee_id="EMP-FIN-02",
            alert_type="USB_COPY_CONFIDENTIAL_DATA",
            description="File 'Q3_Salary_and_Bonus_Rollout.docx' (HIGHLY_CONFIDENTIAL) copied to external Removable USB device 'E:/'.",
            source="USB_MONITOR",
            risk_score=85.0,
            severity="CRITICAL"
        )

        alert_service.process_and_create_alert(
            db=db,
            employee_id="EMP-HR-03",
            alert_type="PII_BULK_ACCESS",
            description="Bulk access of 200+ Employee PII / National IDs from 'Employee_SSN_and_Aadhaar_Directory.csv'.",
            source="FILE_MONITOR",
            risk_score=68.0,
            severity="HIGH"
        )

        print("[+] Demo simulation data seeded successfully!\n")
    except Exception as e:
        db.rollback()
        print(f"[-] Error seeding data: {e}")
    finally:
        db.close()

def clear_alerts():
    """Remove all alert and incident records from the database and reset employee risk scores."""
    from backend.database import SessionLocal
    from backend.models import Alert, Incident, Employee, ActivityLog
    db = SessionLocal()
    print("\n[*] Purging all alert and incident data from database...")
    try:
        incidents_deleted = db.query(Incident).delete()
        alerts_deleted = db.query(Alert).delete()
        # Reset employee risk scores
        employees = db.query(Employee).all()
        for emp in employees:
            emp.risk_score = 0.0
            emp.status = "ONLINE"
        db.commit()
        print(f"[+] Successfully removed {alerts_deleted} alert(s) and {incidents_deleted} incident(s).")
        print("[+] Reset employee risk scores to 0.0 (clean baseline).\n")
    except Exception as e:
        db.rollback()
        print(f"[-] Error clearing alerts: {e}")
    finally:
        db.close()

def reset_database():
    """Remove all seeded files, demo employees, alerts, incidents, and activity logs."""
    from backend.database import SessionLocal
    from backend.models import Alert, Incident, Employee, FileRecord, ActivityLog
    db = SessionLocal()
    print("\n[*] Resetting SentinelDLP database (removing seeded/sample data)...")
    try:
        inc = db.query(Incident).delete()
        alt = db.query(Alert).delete()
        act = db.query(ActivityLog).delete()
        fil = db.query(FileRecord).delete()
        emp = db.query(Employee).delete()
        db.commit()
        print(f"[+] Purged {fil} file record(s), {alt} alert(s), {inc} incident(s), {act} activity log(s), {emp} employee(s).")
        print("[+] Database is now 100% clean and ready for real-time live monitoring.\n")
    except Exception as e:
        db.rollback()
        print(f"[-] Error resetting database: {e}")
    finally:
        db.close()

def main():
    parser = argparse.ArgumentParser(description="SentinelDLP AI Platform CLI")
    parser.add_argument("command", nargs="?", choices=["backend", "agent", "seed", "test", "clear-alerts", "reset-db"], default="backend",
                        help="Component to start: backend, agent, seed, test, clear-alerts, or reset-db")

    args = parser.parse_args()

    if args.command == "backend":
        start_backend()
    elif args.command == "agent":
        start_agent()
    elif args.command == "seed":
        seed_demo_data()
    elif args.command == "test":
        run_tests()
    elif args.command == "clear-alerts":
        clear_alerts()
    elif args.command == "reset-db":
        reset_database()

if __name__ == "__main__":
    main()


