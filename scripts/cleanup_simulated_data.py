"""
SentinelDLP Database Cleanup & Data Reconciliation Utility
Removes simulated/ghost employee and device records (e.g. EMP-BROWSER-01, drive.google.com),
and reconciles orphaned DLP events, alerts, and incidents to legitimate registered employees.
"""
import os
import sys

# Add project root to python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.database import SessionLocal, run_auto_migrations
from backend.models import Employee, Device, DLPEvent, Alert, Incident, ActivityLog

def cleanup_simulated_data():
    run_auto_migrations()
    db = SessionLocal()
    try:
        print("=== SentinelDLP Data Reconciliation & Ghost Cleanup ===")
        
        # 1. Identify ghost employees
        ghost_ids = ["EMP-BROWSER-01", "EMP-000"]
        ghost_emps = db.query(Employee).filter(Employee.employee_id.in_(ghost_ids)).all()
        
        # Find a primary legitimate employee to re-link events if available
        primary_emp = db.query(Employee).filter(~Employee.employee_id.in_(ghost_ids)).first()
        target_emp_id = primary_emp.employee_id if primary_emp else None
        
        if ghost_emps:
            for ge in ghost_emps:
                print(f"Found ghost employee: {ge.employee_id} ({ge.full_name})")
                
                # Re-link or clean DLP events
                events = db.query(DLPEvent).filter(DLPEvent.employee_id == ge.employee_id).all()
                for ev in events:
                    if target_emp_id:
                        print(f"  Re-linking DLP event {ev.event_id} from {ge.employee_id} -> {target_emp_id}")
                        ev.employee_id = target_emp_id
                    else:
                        print(f"  Deleting orphan DLP event {ev.event_id}")
                        db.delete(ev)
                
                # Re-link or clean Alerts
                alerts = db.query(Alert).filter(Alert.employee_id == ge.employee_id).all()
                for al in alerts:
                    if target_emp_id:
                        print(f"  Re-linking Alert {al.alert_id} from {ge.employee_id} -> {target_emp_id}")
                        al.employee_id = target_emp_id
                    else:
                        print(f"  Deleting orphan Alert {al.alert_id}")
                        db.delete(al)
                
                # Re-link or clean Incidents
                incidents = db.query(Incident).filter(Incident.employee_id == ge.employee_id).all()
                for inc in incidents:
                    if target_emp_id:
                        print(f"  Re-linking Incident {inc.incident_id} from {ge.employee_id} -> {target_emp_id}")
                        inc.employee_id = target_emp_id
                    else:
                        print(f"  Deleting orphan Incident {inc.incident_id}")
                        db.delete(inc)
                
                # Delete ghost employee
                print(f"  Removing ghost employee record {ge.employee_id}")
                db.delete(ge)
        
        # 2. Identify and delete fake device entries (e.g. drive.google.com)
        fake_devices = db.query(Device).filter(
            (Device.hostname.like("%google.com%")) |
            (Device.device_id.like("%google.com%")) |
            (Device.device_id.in_(ghost_ids))
        ).all()
        for fd in fake_devices:
            print(f"Removing fake/ghost device: {fd.device_id} (Host: {fd.hostname})")
            db.delete(fd)
            
        db.commit()
        print("=== Database cleanup and reconciliation completed successfully! ===")
        
    except Exception as e:
        db.rollback()
        print(f"ERROR during database cleanup: {e}")
        raise
    finally:
        db.close()

if __name__ == "__main__":
    cleanup_simulated_data()
