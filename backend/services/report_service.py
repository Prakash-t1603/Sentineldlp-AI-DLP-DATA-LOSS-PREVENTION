import csv
import io
from datetime import datetime, timezone
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from sqlalchemy import func
from backend.models import Employee, FileRecord, Alert, Incident, ActivityLog

class ReportService:
    @staticmethod
    def generate_executive_summary(db: Session) -> Dict[str, Any]:
        """Generate comprehensive executive compliance and threat summary."""
        total_employees = db.query(Employee).count()
        total_files = db.query(FileRecord).count()
        sensitive_files = db.query(FileRecord).filter(
            FileRecord.classification.in_(["CONFIDENTIAL", "HIGHLY_CONFIDENTIAL"])
        ).count()
        total_alerts = db.query(Alert).count()
        critical_alerts = db.query(Alert).filter(Alert.severity == "CRITICAL").count()
        high_alerts = db.query(Alert).filter(Alert.severity == "HIGH").count()
        total_incidents = db.query(Incident).count()
        open_incidents = db.query(Incident).filter(Incident.status.in_(["OPEN", "INVESTIGATING"])).count()
        usb_transfers = db.query(ActivityLog).filter(ActivityLog.activity_type == "USB_COPY").count()

        avg_risk = db.query(func.avg(Employee.risk_score)).scalar() or 0.0

        # Top 5 at-risk employees
        top_risk_employees = db.query(Employee).order_by(Employee.risk_score.desc()).limit(5).all()
        employee_data = [
            {
                "employee_id": e.employee_id,
                "username": e.username,
                "hostname": e.hostname,
                "risk_score": e.risk_score,
                "status": e.status
            }
            for e in top_risk_employees
        ]

        # Recent critical alerts
        recent_critical = db.query(Alert).filter(Alert.severity == "CRITICAL").order_by(Alert.created_at.desc()).limit(5).all()
        alerts_data = [
            {
                "id": a.id,
                "employee_id": a.employee_id,
                "alert_type": a.alert_type,
                "description": a.description,
                "risk_score": a.risk_score,
                "created_at": a.created_at.isoformat()
            }
            for a in recent_critical
        ]

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "metrics": {
                "total_endpoints": total_employees,
                "monitored_files": total_files,
                "sensitive_files_detected": sensitive_files,
                "total_dlp_alerts": total_alerts,
                "critical_alerts": critical_alerts,
                "high_alerts": high_alerts,
                "total_incidents": total_incidents,
                "open_incidents": open_incidents,
                "usb_transfers_recorded": usb_transfers,
                "fleet_average_risk_score": round(float(avg_risk), 1)
            },
            "top_risk_endpoints": employee_data,
            "recent_critical_threats": alerts_data
        }

    @staticmethod
    def export_alerts_csv(db: Session) -> str:
        """Export all alerts into formatted CSV data."""
        alerts = db.query(Alert).order_by(Alert.created_at.desc()).all()
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            "Alert ID", "Timestamp (UTC)", "Employee ID", "Alert Type",
            "Severity", "Risk Score", "Status", "Source", "Description"
        ])
        
        for a in alerts:
            writer.writerow([
                a.id,
                a.created_at.isoformat() if a.created_at else "",
                a.employee_id,
                a.alert_type,
                a.severity,
                a.risk_score,
                a.status,
                a.source,
                a.description.replace("\n", " ")
            ])
            
        return output.getvalue()

    @staticmethod
    def export_activity_logs_csv(db: Session) -> str:
        """Export all endpoint activity logs into formatted CSV data."""
        activities = db.query(ActivityLog).order_by(ActivityLog.timestamp.desc()).all()
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            "Log ID", "Timestamp (UTC)", "Employee ID", "Activity Type",
            "File Path", "Process Name", "Destination", "Risk Score"
        ])
        
        for act in activities:
            writer.writerow([
                act.id,
                act.timestamp.isoformat() if act.timestamp else "",
                act.employee_id,
                act.activity_type,
                act.filepath or "",
                act.process_name or "",
                act.destination or "",
                act.risk_score
            ])
            
        return output.getvalue()

report_service = ReportService()
