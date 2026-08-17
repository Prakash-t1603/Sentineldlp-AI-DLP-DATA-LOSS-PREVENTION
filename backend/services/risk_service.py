import numpy as np
from datetime import datetime, timezone, time
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from backend.models import Employee, FileRecord, ActivityLog, Alert
from backend.utils.helpers import get_logger

logger = get_logger("SentinelDLP.RiskService")

# Suspicious processes commonly associated with data exfiltration / stealth copying
SUSPICIOUS_PROCESSES = {
    "cmd.exe": 15.0,
    "powershell.exe": 20.0,
    "pwsh.exe": 20.0,
    "curl.exe": 30.0,
    "wget.exe": 30.0,
    "mega.exe": 40.0,
    "dropbox.exe": 25.0,
    "googledrivesync.exe": 20.0,
    "onedrive.exe": 15.0,
    "filezilla.exe": 35.0,
    "winscp.exe": 35.0,
    "tor.exe": 60.0,
    "7z.exe": 15.0,
    "winrar.exe": 15.0,
    "python.exe": 15.0,
    "nc.exe": 60.0,
    "ncat.exe": 60.0,
}

class RiskService:
    @staticmethod
    def get_risk_level(risk_score: float) -> str:
        """Map numerical score (0-100) to standard DLP risk level."""
        if risk_score >= 80.0:
            return "CRITICAL"
        elif risk_score >= 60.0:
            return "HIGH"
        elif risk_score >= 30.0:
            return "MEDIUM"
        else:
            return "LOW"

    @staticmethod
    def calculate_event_risk(
        activity_type: str,
        sensitivity_score: float,
        classification: str,
        process_name: Optional[str] = None,
        destination: Optional[str] = None,
        timestamp: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Calculate composite risk score for an endpoint activity event.
        Combines content sensitivity, action vector, process threat factor, and temporal anomaly.
        """
        now = timestamp or datetime.now(timezone.utc)
        
        # 1. Action vector scoring
        action_weights = {
            "EXFILTRATION_USB_TRANSFER": 60.0,
            "EXFILTRATION_WEB_STORAGE": 55.0,
            "EXFILTRATION_EMAIL": 50.0,
            "EXFILTRATION_MESSAGING_APP": 55.0,
            "EXFILTRATION_CLIPBOARD_LEAK": 45.0,
            "EXFILTRATION_CLOUD_SYNC": 50.0,
            "USB_COPY": 50.0,
            "CLOUD_SYNC": 40.0,
            "NETWORK_TRANSFER": 45.0,
            "CLIPBOARD_COPY": 35.0,
            "PROCESS_SPAWN": 25.0,
            "MASS_DOWNLOAD": 45.0,
            "RENAME": 15.0,
            "DELETE": 15.0,
            "MODIFY": 20.0,
            "CREATE": 20.0,
            "MANUAL_SCAN": 10.0,
            "UPLOAD_SCAN": 20.0
        }
        action_score = action_weights.get(activity_type.upper(), 15.0)
        
        # If highly confidential file is created, copied, or modified, scale action score
        if classification == "HIGHLY_CONFIDENTIAL" or sensitivity_score >= 85.0:
            action_score = max(action_score, 40.0)
            if activity_type.upper() == "USB_COPY":
                action_score += 35.0

        # 2. Process threat factor
        proc_score = 0.0
        if process_name:
            proc_lower = process_name.lower().split("/")[-1].split("\\")[-1]
            proc_score = SUSPICIOUS_PROCESSES.get(proc_lower, 0.0)

        # 3. After-hours / Weekend temporal anomaly factor
        time_score = 0.0
        hour = now.hour
        if hour < 7 or hour >= 20:
            time_score += 20.0
        if now.weekday() >= 5:
            time_score += 20.0

        # 4. Composite weighting: 50% sensitivity, 30% action, 10% process, 10% temporal
        raw_composite = (
            (sensitivity_score * 0.50) +
            (action_score * 0.30) +
            (proc_score * 0.10) +
            (time_score * 0.10)
        )

        # Base floor if sensitivity is critical
        if sensitivity_score >= 90.0:
            raw_composite = max(raw_composite, 60.0)  # At least HIGH

        final_score = min(100.0, max(0.0, raw_composite))
        risk_level = RiskService.get_risk_level(final_score)

        return {
            "risk_score": round(final_score, 1),
            "risk_level": risk_level,
            "factors": {
                "sensitivity_contribution": round(sensitivity_score * 0.50, 1),
                "action_contribution": round(action_score * 0.30, 1),
                "process_contribution": round(proc_score * 0.10, 1),
                "time_anomaly_contribution": round(time_score * 0.10, 1)
            }
        }

    @staticmethod
    def calculate_employee_ueba_risk(db: Session, employee_id: str) -> Dict[str, Any]:
        """
        User and Entity Behavior Analytics (UEBA).
        Evaluates employee historical activities, mass volume spikes,
        and Isolation Forest anomaly detection when sample size is sufficient.
        """
        activities = db.query(ActivityLog).filter(ActivityLog.employee_id == employee_id).all()
        alerts = db.query(Alert).filter(Alert.employee_id == employee_id).all()
        files = db.query(FileRecord).filter(FileRecord.employee_id == employee_id).all()

        total_activities = len(activities)
        total_alerts = len(alerts)
        sensitive_files_count = sum(1 for f in files if f.classification in ["CONFIDENTIAL", "HIGHLY_CONFIDENTIAL"])
        critical_alerts_count = sum(1 for a in alerts if a.severity == "CRITICAL")
        high_alerts_count = sum(1 for a in alerts if a.severity == "HIGH")

        # Baseline deterministic calculation
        base_score = 0.0
        base_score += (critical_alerts_count * 25.0)
        base_score += (high_alerts_count * 15.0)
        
        if sensitive_files_count > 10:
            base_score += 25.0
        elif sensitive_files_count > 5:
            base_score += 15.0
        elif sensitive_files_count > 0:
            base_score += (sensitive_files_count * 2.0)

        usb_count = sum(1 for a in activities if a.activity_type == "USB_COPY")
        if usb_count > 0:
            base_score += min(30.0, usb_count * 10.0)

        # Isolation Forest Anomaly Detection (>= 20 points)
        anomaly_detected = False
        if total_activities >= 20:
            try:
                from sklearn.ensemble import IsolationForest
                features = []
                for act in activities:
                    hour = act.timestamp.hour if act.timestamp else 12
                    is_usb = 1 if act.activity_type == "USB_COPY" else 0
                    features.append([hour, act.risk_score, is_usb])

                X = np.array(features)
                iso = IsolationForest(contamination=0.1, random_state=42)
                preds = iso.fit_predict(X)
                recent_anomalies = np.sum(preds[-5:] == -1)
                if recent_anomalies >= 2:
                    anomaly_detected = True
                    base_score += 20.0
                    logger.info(f"UEBA: Isolation Forest detected behavioral anomaly for {employee_id}")
            except Exception as e:
                logger.warning(f"UEBA Isolation Forest warning: {e}")

        final_employee_risk = min(100.0, max(0.0, base_score))
        risk_level = RiskService.get_risk_level(final_employee_risk)

        # Update employee risk in DB
        emp = db.query(Employee).filter(Employee.employee_id == employee_id).first()
        if emp:
            emp.risk_score = round(final_employee_risk, 1)
            if final_employee_risk >= 80.0:
                emp.status = "SUSPICIOUS"
            db.commit()

        return {
            "employee_id": employee_id,
            "risk_score": round(final_employee_risk, 1),
            "risk_level": risk_level,
            "anomaly_detected": anomaly_detected,
            "total_activities": total_activities,
            "sensitive_files_count": sensitive_files_count,
            "alert_count": total_alerts
        }

risk_service = RiskService()
