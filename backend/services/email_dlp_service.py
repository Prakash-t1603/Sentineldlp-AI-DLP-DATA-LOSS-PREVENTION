import os
import re
import base64
import tempfile
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.orm import Session

from backend.models import DLPEvent, Employee, FileRecord
from backend.services.classifier_service import classifier_service
from backend.services.file_analysis_service import file_analysis_service
from backend.services.risk_service import risk_service
from backend.services.policy_service import policy_service
from backend.services.alert_service import alert_service
from backend.utils.helpers import compute_file_hash, get_logger

logger = get_logger("SentinelDLP.EmailDLPService")

# Default internal domains for external recipient detection
INTERNAL_DOMAINS = {"sentineldlp.io", "company.com", "corporate.internal", "enterprise.local"}

class EmailDLPService:
    @staticmethod
    def is_external_email(recipient_email: str) -> bool:
        """
        Check if recipient email belongs to an external third-party domain.
        """
        if not recipient_email or "@" not in recipient_email:
            return True
        domain = recipient_email.split("@")[-1].strip().lower()
        return domain not in INTERNAL_DOMAINS

    def process_email_event(
        self,
        db: Session,
        sender: str,
        recipient: str,
        file_name: Optional[str] = None,
        file_size: int = 0,
        file_type: Optional[str] = None,
        subject: Optional[str] = "",
        body: Optional[str] = "",
        extracted_text: Optional[str] = "",
        file_content_base64: Optional[str] = None,
        file_path: Optional[str] = None,
        employee_id: Optional[str] = None,
        device_id: Optional[str] = "WORKSTATION",
        application: str = "Corporate Mail"
    ) -> Dict[str, Any]:
        """
        Inspect outgoing authorized email and attachments for sensitive data exfiltration.
        Unified processing: Centralized Scanner -> Risk Engine -> Policy Engine -> DLP Event Store -> Alerts.
        """
        emp_id = employee_id or sender.split("@")[0]
        # Resolve master employee if exists in database
        emp = db.query(Employee).filter(Employee.employee_id == emp_id).first()
        if not emp:
            emp = db.query(Employee).filter(Employee.email == sender).first()
            if emp:
                emp_id = emp.employee_id
            else:
                # Use first active employee or keep emp_id as identifier without creating ghost record
                first_emp = db.query(Employee).filter(Employee.active == True).first()
                if first_emp:
                    emp_id = first_emp.employee_id

        # 1. Determine destination boundary
        is_external = self.is_external_email(recipient)
        destination_type = "EXTERNAL" if is_external else "INTERNAL"

        # 2. Extract attachment text if file provided
        full_content_text = extracted_text or ""
        attachment_name = file_name or (Path(file_path).name if file_path else "email_attachment.dat")
        ext = file_type or (Path(attachment_name).suffix.lower() if attachment_name else ".txt")
        actual_size = file_size
        file_hash = ""

        # If base64 content provided, decode and parse safely in temp storage
        if file_content_base64:
            try:
                raw_bytes = base64.b64decode(file_content_base64)
                actual_size = len(raw_bytes)
                import hashlib
                file_hash = hashlib.sha256(raw_bytes).hexdigest()

                # Try text decode first
                try:
                    full_content_text = raw_bytes.decode("utf-8")
                except Exception:
                    # Write to temp file and extract via file_analysis_service
                    with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp:
                        tmp.write(raw_bytes)
                        tmp_path = Path(tmp.name)
                    try:
                        extracted, _ = file_analysis_service.extract_text_from_file(tmp_path)
                        full_content_text = extracted or full_content_text
                    finally:
                        try:
                            tmp_path.unlink()
                        except Exception:
                            pass
            except Exception as e:
                logger.warning(f"Error decoding base64 attachment: {e}")

        # If file_path provided and exists
        elif file_path and Path(file_path).exists():
            p = Path(file_path)
            actual_size = p.stat().st_size
            file_hash = compute_file_hash(p)
            attachment_name = p.name
            ext = p.suffix.lower()
            if not full_content_text:
                extracted, _ = file_analysis_service.extract_text_from_file(p)
                full_content_text = extracted

        # Append body text if available
        combined_text = full_content_text
        if body:
            combined_text = f"{body}\n\n{full_content_text}".strip()

        # 3. Run Centralized DLP Scanner
        clf_result = classifier_service.classify_file(
            filename=attachment_name,
            filepath=file_path or attachment_name,
            file_size=actual_size,
            extracted_text=combined_text,
            file_hash=file_hash
        )

        classification = clf_result.get("classification", "PUBLIC")
        sensitivity_score = clf_result.get("sensitivity_score", 0.0)
        detected_entities = clf_result.get("detected_entities", [])
        indicators = clf_result.get("indicators", [])
        total_sensitive_records = sum(e.get("count", 1) for e in detected_entities)
        sensitive_data_detected = sensitivity_score >= 30.0 or len(detected_entities) > 0

        # 4. Centralized Risk Engine Scoring
        has_keywords = any("confidential" in ind.lower() or "proprietary" in ind.lower() for ind in indicators)
        risk_info = risk_service.calculate_dlp_risk(
            channel="EMAIL",
            sensitivity_score=sensitivity_score,
            classification=classification,
            destination=recipient,
            application=application,
            file_size=actual_size,
            sensitive_entities_count=len(detected_entities),
            has_sensitive_keywords=has_keywords,
            is_external_destination=is_external
        )
        risk_score = risk_info["risk_score"]
        risk_level = risk_info["risk_level"]

        # 5. Centralized Policy Engine Evaluation
        policy_decision = policy_service.evaluate_policy(
            db=db,
            channel="EMAIL",
            risk_score=risk_score,
            sensitive_data_detected=sensitive_data_detected,
            destination=recipient,
            destination_type=destination_type
        )
        action = policy_decision["action"]
        policy_name = policy_decision["policy_name"]

        # 6. Format details & reason
        if detected_entities:
            entity_summary = ", ".join([f"{e['entity_type']} (x{e['count']})" for e in detected_entities])
        elif indicators:
            entity_summary = ", ".join(indicators[:3])
        else:
            entity_summary = "No sensitive entities detected"

        details_text = (
            f"Sender: {sender} | Recipient: {recipient} ({destination_type}) | "
            f"Attachment: '{attachment_name}' ({actual_size} bytes) | "
            f"Sensitive Data: {sensitive_data_detected} ({total_sensitive_records} records) | "
            f"Entities: [{entity_summary}] | Policy Applied: '{policy_name}'"
        )

        # 7. Record unified DLPEvent in database
        dlp_event = DLPEvent(
            employee_id=emp_id,
            device_id=device_id or "EMAIL-GATEWAY",
            channel="EMAIL",
            application=application,
            destination=recipient,
            file_name=attachment_name,
            file_hash=file_hash,
            file_size=actual_size,
            file_type=ext,
            sensitive_data_detected=sensitive_data_detected,
            detection_type="PII" if detected_entities else ("CLASSIFIER" if sensitivity_score > 0 else "BENIGN"),
            risk_score=risk_score,
            risk_level=risk_level,
            action=action,
            timestamp=datetime.now(timezone.utc),
            status="BLOCKED" if action == "BLOCK" else ("WARNED" if action == "WARN" else "ALLOWED"),
            details=details_text
        )
        db.add(dlp_event)
        db.commit()
        db.refresh(dlp_event)

        # 8. Real-time Alerting for High / Critical incidents
        alert_id = None
        alert_created = False
        if action == "BLOCK" or risk_score >= 60.0 or policy_decision.get("create_alert", False):
            alert_desc = (
                f"🚨 EMAIL DLP INCIDENT [{action}]: Outgoing email to external recipient '{recipient}' "
                f"contained sensitive attachment '{attachment_name}' ({classification}, Sensitivity: {sensitivity_score}/100). "
                f"Detected: [{entity_summary}]. Risk: {risk_score} ({risk_level})."
            )
            alert = alert_service.process_and_create_alert(
                db=db,
                employee_id=emp_id,
                alert_type="EMAIL_SENSITIVE_ATTACHMENT_EXFILTRATION",
                description=alert_desc,
                source="EMAIL_DLP",
                risk_score=risk_score,
                severity=risk_level
            )
            alert_id = alert.id
            alert_created = True

        logger.info(
            f"📧 Email DLP Scan [{action}]: {sender} -> {recipient} | "
            f"File: '{attachment_name}' | Score: {risk_score} ({risk_level})"
        )

        return {
            "event_id": dlp_event.event_id,
            "channel": "EMAIL",
            "application": application,
            "sender": sender,
            "recipient": recipient,
            "destination_type": destination_type,
            "file_name": attachment_name,
            "file_hash": file_hash,
            "file_size": actual_size,
            "classification": classification,
            "sensitivity_score": sensitivity_score,
            "sensitive_data": sensitive_data_detected,
            "sensitive_data_detected": sensitive_data_detected,
            "sensitive_records_count": total_sensitive_records,
            "detected_entities": detected_entities,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "action": action,
            "policy_name": policy_name,
            "alert_created": alert_created,
            "alert_id": alert_id,
            "status": dlp_event.status,
            "details": details_text,
            "timestamp": dlp_event.timestamp.isoformat()
        }

email_dlp_service = EmailDLPService()
