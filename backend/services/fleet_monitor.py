import json
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List, Tuple
from sqlalchemy.orm import Session

from backend.models import Device, Employee, ActivityLog
from backend.utils.helpers import get_logger

logger = get_logger("SentinelDLP.FleetMonitor")

HEARTBEAT_ONLINE_THRESHOLD_SECS = 30
HEARTBEAT_WARNING_THRESHOLD_SECS = 60

class FleetMonitorService:
    """
    Central Fleet Health and Telemetry Engine.
    Tracks active endpoint agents, processes heartbeats, calculates dynamic status
    (ONLINE, WARNING, OFFLINE), manages module statuses, and logs operational audit events.
    """

    @staticmethod
    def evaluate_status(last_seen: Optional[datetime], current_time: Optional[datetime] = None) -> Tuple[str, Optional[int]]:
        """
        Dynamically determine connection status based on heartbeat age in seconds:
        - ONLINE:  last heartbeat <= 30 seconds
        - WARNING: 31-60 seconds
        - OFFLINE: > 60 seconds (or never seen)
        """
        if not last_seen:
            return "OFFLINE", None

        now = current_time or datetime.now(timezone.utc)
        if last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)

        diff = max(0, int((now - last_seen).total_seconds()))
        if diff <= HEARTBEAT_ONLINE_THRESHOLD_SECS:
            return "ONLINE", diff
        elif diff <= HEARTBEAT_WARNING_THRESHOLD_SECS:
            return "WARNING", diff
        else:
            return "OFFLINE", diff

    def record_operational_event(
        self,
        db: Session,
        employee_id: str,
        activity_type: str,
        process_name: Optional[str] = "SentinelAgent",
        destination: Optional[str] = None
    ) -> Optional[ActivityLog]:
        """
        Record operational lifecycle audit event (AGENT_STARTED, MONITORING_STARTED, AGENT_STOPPED, etc.)
        without creating false security alerts or incidents.
        """
        emp = db.query(Employee).filter(Employee.employee_id == employee_id).first()
        if not emp:
            logger.warning(f"Skipping operational event [{activity_type}]: Employee '{employee_id}' not found in database.")
            return None

        now = datetime.now(timezone.utc)
        log = ActivityLog(
            employee_id=emp.employee_id,
            activity_type=activity_type,
            filepath=None,
            process_name=process_name,
            destination=destination,
            timestamp=now,
            risk_score=0.0
        )
        db.add(log)
        db.commit()
        db.refresh(log)
        logger.info(f"Recorded operational event [{activity_type}] for employee {emp.employee_id}")
        return log

    def evaluate_employee_status(self, employee: Employee, db: Session, current_time: Optional[datetime] = None) -> str:
        """
        Evaluate aggregate employee live status across all assigned endpoint devices.
        If any device is ONLINE -> employee is ONLINE (LIVE).
        If no device is ONLINE but a device is in WARNING -> WARNING.
        Otherwise -> OFFLINE.
        """
        now = current_time or datetime.now(timezone.utc)
        devices = db.query(Device).filter(Device.employee_id == employee.employee_id, Device.is_active == True).all()
        
        if not devices:
            # Fallback to employee.last_seen
            status_name, _ = self.evaluate_status(employee.last_seen, now)
            return status_name

        has_warning = False
        latest_last_seen = None

        for d in devices:
            d_status, _ = self.evaluate_status(d.last_seen, now)
            if d.last_seen:
                if latest_last_seen is None or d.last_seen > latest_last_seen:
                    latest_last_seen = d.last_seen

            if d_status == "ONLINE":
                if employee.status != "ONLINE":
                    employee.status = "ONLINE"
                    employee.last_seen = latest_last_seen or now
                return "ONLINE"
            elif d_status == "WARNING":
                has_warning = True

        calculated = "WARNING" if has_warning else "OFFLINE"
        if employee.status != calculated:
            employee.status = calculated
        if latest_last_seen:
            employee.last_seen = latest_last_seen
        return calculated

    def get_fleet_summary(self, db: Session) -> Dict[str, Any]:
        """
        Generate complete fleet overview metrics including device and employee statuses.
        """
        now = datetime.now(timezone.utc)
        employees = db.query(Employee).filter(Employee.active == True).all()
        devices = db.query(Device).filter(Device.is_active == True).all()

        emp_online = 0
        emp_warning = 0
        emp_offline = 0
        monitoring_active_count = 0

        for emp in employees:
            status = self.evaluate_employee_status(emp, db, now)
            if status == "ONLINE":
                emp_online += 1
            elif status == "WARNING":
                emp_warning += 1
            else:
                emp_offline += 1

        dev_online = 0
        dev_warning = 0
        dev_offline = 0

        for d in devices:
            st, _ = self.evaluate_status(d.last_seen, now)
            d.status = st
            if st == "ONLINE":
                dev_online += 1
                if d.monitoring_status == "ACTIVE":
                    monitoring_active_count += 1
            elif st == "WARNING":
                dev_warning += 1
            else:
                dev_offline += 1

        db.commit()

        return {
            "total_employees": len(employees),
            "live_employees": emp_online,
            "warning_employees": emp_warning,
            "offline_employees": emp_offline,
            "monitoring_active_employees": monitoring_active_count,
            "total_devices": len(devices),
            "online_devices": dev_online,
            "warning_devices": dev_warning,
            "offline_devices": dev_offline,
        }

fleet_monitor_service = FleetMonitorService()
