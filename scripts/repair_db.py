"""
Database repair and identity reconciliation script for SentinelDLP.
- Links Windows endpoint EMP-PC-WIN (win / 10.0.2.15) to EMP-006 (Riya).
- Links Linux endpoint EMP-PC-DEVIL (Devil / 172.24.143.236) to EMP-001 (Prakash T).
- Cleans up demo/mock employees (EMP-DEV-01, EMP-FIN-02, EMP-HR-03, EMP-TEST-99, EMP-HB-100).
- Cleans up demo/mock devices.
- Ensures all alerts and incidents match their underlying event's employee_id and device_id.
"""
import os
import sys
from pathlib import Path
from datetime import datetime, timezone

# Ensure project root is in sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from backend.database import SessionLocal
from backend.models import Employee, Device, DLPEvent, Alert, Incident, ActivityLog, UEBAProfile

def repair_database():
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        print("Starting SentinelDLP Database Repair & Reconciliation...")

        # 1. Purge demo/mock employees
        demo_emp_ids = ["EMP-DEV-01", "EMP-FIN-02", "EMP-HR-03", "EMP-TEST-99", "EMP-HB-100"]
        deleted_emps = db.query(Employee).filter(Employee.employee_id.in_(demo_emp_ids)).delete(synchronize_session=False)
        print(f"Purged {deleted_emps} demo employees ({demo_emp_ids}).")

        # 2. Purge demo/mock devices
        demo_device_ids = ["EMP-PC-001", "EMP-PC-002", "EMP-PC-003", "EMP-PC-TEST99", "EMP-PC-HB100"]
        deleted_devs = db.query(Device).filter(Device.device_id.in_(demo_device_ids)).delete(synchronize_session=False)
        print(f"Purged {deleted_devs} demo devices.")

        # 3. Ensure EMP-001 (Prakash T) exists and is correctly configured
        emp1 = db.query(Employee).filter(Employee.employee_id == "EMP-001").first()
        if not emp1:
            emp1 = Employee(
                employee_id="EMP-001",
                full_name="Prakash T",
                email="prakash@gmail.com",
                department="Cyber Security",
                designation="Security Architect",
                username="prakash",
                hostname="Devil",
                ip_address="172.24.143.236",
                operating_system="Linux 7.0.12+kali-amd64",
                active=True,
                status="ONLINE",
                last_seen=now,
                created_at=now,
                updated_at=now
            )
            db.add(emp1)
        else:
            emp1.hostname = "Devil"
            emp1.ip_address = "172.24.143.236"
            emp1.operating_system = "Linux 7.0.12+kali-amd64"
            emp1.last_seen = now
            emp1.updated_at = now

        # 4. Ensure EMP-002 (Dhya P) exists
        emp2 = db.query(Employee).filter(Employee.employee_id == "EMP-002").first()
        if not emp2:
            emp2 = Employee(
                employee_id="EMP-002",
                full_name="Dhya P",
                email="dhya@gmail.com",
                department="Cyber Security",
                designation="Security Analyst",
                username="dhya",
                hostname="Devil",
                ip_address="172.24.143.236",
                operating_system="Linux 7.0.12+kali-amd64",
                active=True,
                status="OFFLINE",
                created_at=now,
                updated_at=now
            )
            db.add(emp2)

        # 5. Ensure EMP-006 (Riya) exists and is correctly configured
        emp6 = db.query(Employee).filter(Employee.employee_id == "EMP-006").first()
        if not emp6:
            emp6 = Employee(
                employee_id="EMP-006",
                full_name="Riya",
                email="riya@gmail.com",
                department="HR",
                designation="HR Specialist",
                username="riya",
                hostname="win",
                ip_address="10.0.2.15",
                operating_system="Windows 11",
                active=True,
                status="ONLINE",
                last_seen=now,
                created_at=now,
                updated_at=now
            )
            db.add(emp6)
        else:
            emp6.hostname = "win"
            emp6.ip_address = "10.0.2.15"
            emp6.operating_system = "Windows 11"
            emp6.last_seen = now
            emp6.updated_at = now

        db.flush()

        # 6. Ensure Device EMP-PC-DEVIL is assigned exclusively to EMP-001
        import secrets
        dev_devil = db.query(Device).filter(Device.device_id == "EMP-PC-DEVIL").first()
        if not dev_devil:
            dev_devil = Device(
                device_id="EMP-PC-DEVIL",
                employee_id="EMP-001",
                hostname="Devil",
                username="prakash",
                operating_system="Linux 7.0.12+kali-amd64",
                ip_address="172.24.143.236",
                mac_address="02:42:ac:11:00:02",
                agent_version="2.1.0",
                device_token=secrets.token_hex(32),
                status="ONLINE",
                monitoring_enabled=True,
                monitoring_status="ACTIVE",
                is_active=True,
                registered_at=now,
                last_seen=now,
                updated_at=now
            )
            db.add(dev_devil)
        else:
            dev_devil.employee_id = "EMP-001"
            dev_devil.hostname = "Devil"
            dev_devil.ip_address = "172.24.143.236"
            dev_devil.operating_system = "Linux 7.0.12+kali-amd64"
            dev_devil.is_active = True
            dev_devil.last_seen = now
            dev_devil.updated_at = now

        # 7. Ensure Device EMP-PC-WIN is assigned to EMP-006 (Riya)
        dev_win = db.query(Device).filter(Device.device_id == "EMP-PC-WIN").first()
        if not dev_win:
            dev_win = Device(
                device_id="EMP-PC-WIN",
                employee_id="EMP-006",
                hostname="win",
                username="riya",
                operating_system="Windows 11",
                ip_address="10.0.2.15",
                mac_address="08:00:27:12:34:56",
                agent_version="2.1.0",
                device_token=secrets.token_hex(32),
                status="ONLINE",
                monitoring_enabled=True,
                monitoring_status="ACTIVE",
                is_active=True,
                registered_at=now,
                last_seen=now,
                updated_at=now
            )
            db.add(dev_win)
        else:
            dev_win.employee_id = "EMP-006"
            dev_win.hostname = "win"
            dev_win.ip_address = "10.0.2.15"
            dev_win.operating_system = "Windows 11"
            dev_win.is_active = True
            dev_win.last_seen = now
            dev_win.updated_at = now

        db.flush()

        # 8. Reconcile DLP events, alerts, and incidents
        events = db.query(DLPEvent).all()
        for ev in events:
            # If event is from Windows host or EMP-PC-WIN, attribute to EMP-006
            if ev.device_id == "EMP-PC-WIN" or (ev.details and "win" in ev.details.lower()):
                ev.employee_id = "EMP-006"
                ev.device_id = "EMP-PC-WIN"
            elif ev.device_id == "EMP-PC-DEVIL" and ev.employee_id not in ["EMP-001", "EMP-002"]:
                ev.employee_id = "EMP-001"

        db.flush()

        # Reconcile alerts
        alerts = db.query(Alert).all()
        for al in alerts:
            if al.event_id:
                ev = db.query(DLPEvent).filter(DLPEvent.id == al.event_id).first()
                if ev:
                    al.employee_id = ev.employee_id
                    al.device_id = ev.device_id

        # Reconcile incidents
        incidents = db.query(Incident).all()
        for inc in incidents:
            if inc.alert_id:
                al = db.query(Alert).filter(Alert.id == inc.alert_id).first()
                if al:
                    inc.employee_id = al.employee_id

        db.commit()
        print("✅ SentinelDLP Database Repair & Reconciliation completed successfully.")

    except Exception as e:
        db.rollback()
        print(f"❌ Error during database repair: {e}")
        raise
    finally:
        db.close()

if __name__ == "__main__":
    repair_database()
