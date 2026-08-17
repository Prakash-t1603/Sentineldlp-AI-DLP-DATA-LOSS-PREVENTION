from datetime import datetime, timezone
from typing import Optional, Dict, Any, Tuple
from sqlalchemy.orm import Session
from backend.models import Alert, Incident, Employee, FileRecord, ActivityLog
from backend.services.risk_service import risk_service
from backend.utils.helpers import get_logger, log_security_event

logger = get_logger("SentinelDLP.AlertService")

class AlertService:
    @staticmethod
    def process_and_create_alert(
        db: Session,
        employee_id: str,
        alert_type: str,
        description: str,
        source: str = "FILE_MONITOR",
        file_id: Optional[int] = None,
        risk_score: float = 0.0,
        severity: Optional[str] = None,
        auto_create_incident: bool = True
    ) -> Alert:
        """
        Create a new security Alert, update employee risk score,
        and automatically open an Incident if severity is HIGH or CRITICAL.
        """
        # Determine severity from risk score if not provided
        if not severity:
            severity = risk_service.get_risk_level(risk_score)

        # 1. Ensure employee exists
        employee = db.query(Employee).filter(Employee.employee_id == employee_id).first()
        if not employee:
            employee = Employee(
                employee_id=employee_id,
                username=employee_id,
                hostname="UNKNOWN_ENDPOINT",
                status="ONLINE",
                risk_score=risk_score
            )
            db.add(employee)
            db.commit()
            db.refresh(employee)

        # 2. Insert Alert
        new_alert = Alert(
            employee_id=employee_id,
            file_id=file_id,
            alert_type=alert_type,
            severity=severity,
            risk_score=round(risk_score, 1),
            description=description,
            source=source,
            status="OPEN",
            created_at=datetime.now(timezone.utc)
        )
        db.add(new_alert)
        db.commit()
        db.refresh(new_alert)

        # 3. Log security event
        log_security_event(
            component=source,
            event=alert_type,
            severity=severity,
            employee_id=employee_id,
            details={
                "alert_id": new_alert.id,
                "file_id": file_id,
                "risk_score": risk_score,
                "description": description
            }
        )

        # 4. If HIGH or CRITICAL, automatically open an Incident for Security Analysts
        if auto_create_incident and severity in ["HIGH", "CRITICAL"]:
            title = f"DLP Violation [{severity}]: {alert_type} on Endpoint {employee_id}"
            incident = Incident(
                alert_id=new_alert.id,
                employee_id=employee_id,
                title=title,
                description=description,
                severity=severity,
                status="OPEN",
                created_at=datetime.now(timezone.utc)
            )
            db.add(incident)
            db.commit()
            logger.info(f"Auto-generated Incident #{incident.id} for Alert #{new_alert.id} ({severity})")

        # 5. Recompute UEBA employee risk
        risk_service.calculate_employee_ueba_risk(db, employee_id)

        return new_alert

    @staticmethod
    def log_activity_and_evaluate(
        db: Session,
        employee_id: str,
        activity_type: str,
        filepath: Optional[str] = None,
        process_name: Optional[str] = None,
        destination: Optional[str] = None,
        sensitivity_score: float = 0.0,
        classification: str = "PUBLIC",
        file_id: Optional[int] = None
    ) -> Tuple[ActivityLog, Optional[Alert]]:
        """
        Record activity log, evaluate risk, and generate alert if threshold is exceeded.
        """
        risk_data = risk_service.calculate_event_risk(
            activity_type=activity_type,
            sensitivity_score=sensitivity_score,
            classification=classification,
            process_name=process_name,
            destination=destination
        )
        
        event_risk = risk_data["risk_score"]
        risk_level = risk_data["risk_level"]

        # Save activity log
        log_entry = ActivityLog(
            employee_id=employee_id,
            activity_type=activity_type,
            filepath=filepath,
            process_name=process_name,
            destination=destination,
            timestamp=datetime.now(timezone.utc),
            risk_score=event_risk
        )
        db.add(log_entry)
        db.commit()
        db.refresh(log_entry)

        # Create alert if risk >= 30 (MEDIUM, HIGH, CRITICAL) or sensitive file accessed
        alert = None
        if event_risk >= 30.0 or classification in ["CONFIDENTIAL", "HIGHLY_CONFIDENTIAL"]:
            filename = filepath.split("/")[-1].split("\\")[-1] if filepath else "Unknown"
            desc = (
                f"Suspicious activity detected: {activity_type} on '{filename}'. "
                f"Classification: {classification}, Destination: {destination or 'Local'}, "
                f"Process: {process_name or 'N/A'}. Calculated Risk: {event_risk} ({risk_level})."
            )
            alert = AlertService.process_and_create_alert(
                db=db,
                employee_id=employee_id,
                alert_type=f"DLP_{activity_type}",
                description=desc,
                source="AGENT_ACTIVITY",
                file_id=file_id,
                risk_score=event_risk,
                severity=risk_level
            )

        return log_entry, alert

alert_service = AlertService()
