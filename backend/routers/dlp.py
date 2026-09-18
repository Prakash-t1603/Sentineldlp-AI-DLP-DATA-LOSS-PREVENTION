import os
import json
import base64
import tempfile
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query, UploadFile, File, Form
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

from backend.database import get_db
from backend.models import DLPEvent, DLPPolicy, PolicyRule, Employee, Device, FileRecord, Alert, Incident, User
from backend.schemas import (
    DLPEventResponse, DLPEventCreate, BrowserDLPEventRequest, EmailDLPEventRequest,
    DLPGenericScanRequest, DLPGenericScanResponse, DLPPolicyCreate, DLPPolicyUpdate,
    DLPPolicyResponse, DLPStatisticsResponse, KeyValueCount, PolicyRuleCreate, PolicyRuleResponse
)
from backend.services.classifier_service import classifier_service
from backend.services.file_analysis_service import file_analysis_service
from backend.services.risk_service import risk_service
from backend.services.policy_service import policy_service
from backend.services.email_dlp_service import email_dlp_service
from backend.services.alert_service import alert_service
from backend.utils.helpers import compute_file_hash, get_logger
from backend.dependencies import get_current_user_or_agent, require_analyst_or_admin

logger = get_logger("SentinelDLP.DLPRouter")
router = APIRouter(prefix="/dlp", tags=["Unified Multi-Channel DLP"])

# ==================== Unified DLP Ingestion & Scanning ====================

def _resolve_authoritative_identity(
    db: Session,
    employee_id: Optional[str] = None,
    device_id: Optional[str] = None
) -> Tuple[Employee, Optional[Device], str, str]:
    """
    Authoritatively resolve employee and device relationship:
    1. If device_id is provided, look up registered Device.
    2. If Device exists and has an assigned employee_id:
       - If incoming employee_id differs from Device.employee_id, detect and log mismatch,
         and authoritatively bind to the registered Device.employee_id.
       - Master employee is looked up using Device.employee_id.
    3. If Device is not found or has no employee_id:
       - Look up employee by employee_id.
       - If still not found, fail with 404 (NEVER fall back to first employee).
    """
    clean_emp = (employee_id or "").strip()
    clean_dev = (device_id or "").strip()

    device = None
    target_emp_id = clean_emp

    if clean_dev:
        device = db.query(Device).filter(Device.device_id == clean_dev).first()
        if device and device.employee_id:
            if clean_emp and clean_emp != device.employee_id:
                logger.warning(
                    f"⚠️ Mismatch detected: Ingested event claimed employee_id='{clean_emp}', "
                    f"but authenticated device '{clean_dev}' is registered to employee '{device.employee_id}'. "
                    f"Authoritatively assigning event to '{device.employee_id}'."
                )
            target_emp_id = device.employee_id

    if not target_emp_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "EMPLOYEE_ID_REQUIRED", "message": "Valid Employee ID or registered Device ID is required."}
        )

    emp = db.query(Employee).filter(Employee.employee_id == target_emp_id).first()
    if not emp:
        logger.error(f"❌ Ingestion rejected: Employee '{target_emp_id}' not registered in master directory.")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "EMPLOYEE_NOT_FOUND", "message": f"Employee '{target_emp_id}' does not exist in SOC master directory."}
        )

    effective_dev_id = clean_dev or (device.device_id if device else "WORKSTATION")
    logger.info(f"Authenticated device {effective_dev_id} resolved to employee {emp.employee_id}")

    return emp, device, emp.employee_id, effective_dev_id

@router.post("/scan", response_model=DLPGenericScanResponse)
def scan_dlp_file(
    scan_req: DLPGenericScanRequest,
    db: Session = Depends(get_db),
    auth_caller: Optional[User] = Depends(get_current_user_or_agent)
):
    """
    Centralized DLP Scanner endpoint shared by USB, Browser, Cloud, and Email modules.
    Runs Content OCR -> Extractors -> NLP -> Regex -> Classifier -> UEBA -> Risk Engine -> Policy Engine.
    """
    channel = scan_req.channel.upper()
    destination = scan_req.destination or scan_req.application or "Unknown Destination"
    file_name = scan_req.file_name or "unknown"
    file_size = scan_req.file_size
    raw_bytes: Optional[bytes] = None
    extracted_text = scan_req.extracted_text or ""

    # Authoritatively resolve employee & device identity
    emp, dev, emp_id, dev_id = _resolve_authoritative_identity(
        db=db,
        employee_id=scan_req.employee_id,
        device_id=scan_req.device_id
    )

    # Decode base64 payload if provided
    if scan_req.file_content_base64:
        try:
            raw_bytes = base64.b64decode(scan_req.file_content_base64)
            file_size = len(raw_bytes)
        except Exception as e:
            logger.warning(f"Error decoding base64 file payload: {e}")

    # Read from local filepath if provided and bytes not yet acquired
    elif scan_req.file_path and Path(scan_req.file_path).exists():
        p = Path(scan_req.file_path)
        try:
            file_size = p.stat().st_size
            file_name = p.name
            with open(p, "rb") as f:
                raw_bytes = f.read()
        except Exception as e:
            logger.warning(f"Error reading local file {scan_req.file_path}: {e}")

    # 1. Execute Central AI DLP Pipeline
    from backend.ai.pipeline import dlp_pipeline
    ai_res = dlp_pipeline.analyze_payload(
        db=db,
        content=extracted_text,
        content_bytes=raw_bytes,
        filename=file_name,
        channel=channel,
        destination=destination,
        employee_id=emp_id,
        device_id=dev_id,
        persist=True
    )

    file_hash = ai_res.file_hash
    classification = ai_res.classification
    sensitivity_score = ai_res.sensitivity_score
    risk_score = ai_res.risk_score
    risk_level = ai_res.risk_level
    action = ai_res.policy_action
    detected_entities = ai_res.entities
    sensitive_data_detected = len(detected_entities) > 0 or sensitivity_score >= 30.0 or classification in ("CONFIDENTIAL", "RESTRICTED", "HIGHLY_CONFIDENTIAL")

    # 2. Check Database Policy Rules for any custom overrides
    policy_decision = policy_service.evaluate_policy(
        db=db,
        channel=channel,
        risk_score=risk_score,
        sensitive_data_detected=sensitive_data_detected,
        destination=destination
    )
    policy_name = policy_decision.get("policy_name", "AI Content Policy")
    if policy_decision.get("action") == "BLOCK":
        action = "BLOCK"
    elif policy_decision.get("action") == "WARN" and action == "ALLOW":
        action = "WARN"

    emp.last_seen = datetime.now(timezone.utc)
    emp.status = "ONLINE"
    db.commit()

    # 3. Construct rich, structured Detection Details string
    ext = Path(file_name).suffix.lower() if file_name else ""
    ocr_tag = f"DETECTED ({int(ai_res.confidence_breakdown.get('ocr_confidence', 0.95)*100)}%)" if ai_res.ocr_used else "NONE"
    nlp_tag = f"DETECTED ({len(detected_entities)} entities)" if detected_entities else "CLEAN"
    ml_tag = f"{classification} ({int(ai_res.confidence*100)}%)"
    cat_tag = ai_res.category if ai_res.category != "UNCLASSIFIED" else (detected_entities[0]["category"] if detected_entities else "CLEAN")
    entity_summary = ", ".join([f"{e['entity_type']} (x{e.get('count', 1)})" for e in detected_entities]) if detected_entities else "None"

    if sensitive_data_detected:
        details_str = (
            f"OCR: {ocr_tag} | NLP: {nlp_tag} | ML: {ml_tag} | "
            f"Sensitive Data: {cat_tag} | Entities: [{entity_summary}] | "
            f"Risk: {risk_score} ({risk_level}) | Policy: {action}"
        )
    else:
        details_str = f"OCR: {ocr_tag} | NLP: CLEAN | ML: {ml_tag} | Content Analysis: CLEAN | Risk: {risk_score} ({risk_level}) | Policy: {action}"

    event_status = "BLOCKED" if action == "BLOCK" else ("WARNED" if action == "WARN" else "ALLOWED")

    event = DLPEvent(
        employee_id=emp_id,
        device_id=dev_id,
        channel=channel,
        application=scan_req.application,
        destination=destination,
        file_name=file_name,
        file_hash=file_hash,
        file_size=file_size,
        file_type=ext,
        sensitive_data_detected=sensitive_data_detected,
        detection_type="OCR+AI" if ai_res.ocr_used else ("PII+AI" if detected_entities else ("CLASSIFIER" if sensitivity_score > 0 else "BENIGN")),
        risk_score=risk_score,
        risk_level=risk_level,
        action=action,
        timestamp=datetime.now(timezone.utc),
        status=event_status,
        details=details_str
    )
    db.add(event)
    db.commit()
    db.refresh(event)

    # 4. Real-Time Alerting for HIGH and CRITICAL events (BLOCK, WARN or risk >= 60.0)
    alert_created = False
    alert_id = None
    if action == "BLOCK" or risk_score >= 60.0 or (policy_decision.get("create_alert", False) and action in ["BLOCK", "WARN"]):
        emp_name = emp.full_name or emp.username or emp_id
        alert_desc = (
            f"🚨 DLP INCIDENT [{action}] by Employee '{emp_name}' ({emp_id}) on {channel}: Transfer of '{file_name}' ({classification}, "
            f"Sensitivity: {sensitivity_score}/100) via {scan_req.application} to '{destination}'. "
            f"Detected: [{entity_summary}]. Risk: {risk_score} ({risk_level})."
        )
        alert = alert_service.process_and_create_alert(
            db=db,
            employee_id=emp_id,
            device_id=dev_id,
            event_id=event.event_id,
            alert_type=f"DLP_{channel}_EXFILTRATION_{action}",
            description=alert_desc,
            source=f"{channel}_MONITOR",
            risk_score=risk_score,
            severity=risk_level
        )
        alert_created = True
        alert_id = alert.id

    return DLPGenericScanResponse(
        event_id=event.event_id,
        channel=channel,
        application=scan_req.application,
        destination=destination,
        file_name=file_name,
        file_hash=file_hash,
        file_size=file_size,
        classification=classification,
        sensitivity_score=sensitivity_score,
        sensitive_data_detected=sensitive_data_detected,
        detected_entities=detected_entities,
        detection_type=event.detection_type,
        risk_score=risk_score,
        risk_level=risk_level,
        action=action,
        policy_name=policy_name,
        alert_created=alert_created,
        alert_id=alert_id,
        status=event.status,
        message=f"DLP Scan Completed: Policy decided {action}.",
        ocr={"used": ai_res.ocr_used, "confidence": ai_res.confidence_breakdown.get("ocr_confidence", 0.95)},
        nlp={"used": True, "entity_count": len(detected_entities)},
        ml={"used": True, "classification": classification, "confidence": ai_res.confidence},
        ueba={"anomaly_score": ai_res.ueba_breakdown.get("anomaly_score", 0.0)},
        reasons=ai_res.reasons,
        sensitive_entities=detected_entities
    )

@router.get("/browser-event")
def get_browser_event_info():
    """Service status and health check for the Browser DLP Event endpoint."""
    return {
        "status": "ACTIVE",
        "channel": "BROWSER",
        "service": "SentinelDLP Browser Event Receiver",
        "supported_methods": ["POST", "GET"],
        "description": "Send HTTP POST with file upload interception telemetry to scan files and enforce DLP policy."
    }

@router.post("/browser-event", response_model=DLPGenericScanResponse)
def handle_browser_event(
    req: BrowserDLPEventRequest,
    db: Session = Depends(get_db),
    auth_caller: Optional[User] = Depends(get_current_user_or_agent)
):
    """
    Handle file upload interception events from the Browser DLP extension / web client.
    Supports Google Drive, OneDrive, Dropbox, Gmail Webmail, WhatsApp Web, WeTransfer, etc.
    """
    emp_id = req.employee_id or req.employee
    dev_id = req.device_id or req.device
    dest = req.domain or req.application

    scan_req = DLPGenericScanRequest(
        channel="BROWSER",
        application=req.application or "Web Browser",
        destination=dest,
        file_name=req.file_name,
        file_path=req.file_path,
        file_size=req.file_size,
        extracted_text=req.extracted_text or "",
        file_content_base64=req.file_content_base64,
        employee_id=emp_id,
        device_id=dev_id
    )
    return scan_dlp_file(scan_req=scan_req, db=db, auth_caller=auth_caller)

@router.get("/email-event")
def get_email_event_info():
    """Service status and health check for the Email DLP Event endpoint."""
    return {
        "status": "ACTIVE",
        "channel": "EMAIL",
        "service": "SentinelDLP Email Event Receiver",
        "supported_methods": ["POST", "GET"],
        "description": "Send HTTP POST with email message and MIME attachments to scan and evaluate DLP policy."
    }

@router.post("/email-event")
def handle_email_event(
    req: EmailDLPEventRequest,
    db: Session = Depends(get_db),
    auth_caller: Optional[User] = Depends(get_current_user_or_agent)
):
    """
    Handle email attachment DLP inspection from Outlook / Microsoft 365, Gmail / Google Workspace, or SMTP gateway.
    """
    return email_dlp_service.process_email_event(
        db=db,
        sender=req.sender,
        recipient=req.recipient,
        file_name=req.file_name,
        file_size=req.file_size,
        file_type=req.file_type,
        subject=req.subject,
        body=req.body,
        extracted_text=req.extracted_text,
        file_content_base64=req.file_content_base64,
        file_path=req.file_path,
        employee_id=req.employee_id,
        device_id=req.device_id,
        application=req.application or "Corporate Mail"
    )

@router.post("/events", response_model=DLPEventResponse)
def record_generic_dlp_event(
    event_in: DLPEventCreate,
    db: Session = Depends(get_db),
    auth_caller: Optional[User] = Depends(get_current_user_or_agent)
):
    """Ingest a pre-computed or endpoint-agent generated DLP event with deep content analysis."""
    emp, dev, emp_id, dev_id = _resolve_authoritative_identity(
        db=db,
        employee_id=event_in.employee_id,
        device_id=event_in.device_id
    )

    emp.last_seen = datetime.now(timezone.utc)
    emp.status = "ONLINE"
    db.commit()

    # If event has base64 file content or local file path, run content analysis
    if event_in.file_content_base64 or (event_in.file_path and Path(event_in.file_path).exists()):
        scan_req = DLPGenericScanRequest(
            channel=event_in.channel or "USB",
            application=event_in.application or "Workstation App",
            destination=event_in.destination or "Local",
            file_name=event_in.file_name,
            file_path=event_in.file_path,
            file_size=event_in.file_size or 0,
            extracted_text=event_in.extracted_text or "",
            file_content_base64=event_in.file_content_base64,
            employee_id=emp_id,
            device_id=dev_id
        )
        scan_res = scan_dlp_file(scan_req=scan_req, db=db, auth_caller=auth_caller)
        # Fetch the created DLPEvent
        event = db.query(DLPEvent).filter(DLPEvent.event_id == scan_res.event_id).first()
        if event:
            return event

    event_data = event_in.model_dump(exclude={"file_content_base64", "file_path", "extracted_text"})
    event_data["employee_id"] = emp_id
    event_data["device_id"] = dev_id
    if not event_data.get("event_id"):
        event_data.pop("event_id", None)
    if isinstance(event_data.get("details"), (dict, list)):
        event_data["details"] = json.dumps(event_data["details"])
    event = DLPEvent(**event_data)
    db.add(event)
    db.commit()
    db.refresh(event)

    # If action is BLOCK or (risk >= 60 and not ALLOW), create alert
    if event.action == "BLOCK" or (event.risk_score >= 60.0 and event.action in ["BLOCK", "WARN"]):
        emp_name = emp.full_name or emp.username or emp_id
        alert_desc = f"🚨 DLP Event [{event.action}] by Employee '{emp_name}' ({emp_id}) on {event.channel}: {event.file_name} -> {event.destination} (Risk: {event.risk_score})"
        alert_service.process_and_create_alert(
            db=db,
            employee_id=emp_id,
            device_id=dev_id,
            event_id=event.event_id,
            alert_type=f"DLP_{event.channel}_{event.action}",
            description=alert_desc,
            source=f"{event.channel}_MONITOR",
            risk_score=event.risk_score,
            severity=event.risk_level
        )

    return event

# ==================== DLP Event Queries & Details ====================

@router.get("/events", response_model=List[DLPEventResponse])
def list_dlp_events(
    channel: Optional[str] = Query(None),
    employee_id: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    auth_caller: Optional[User] = Depends(get_current_user_or_agent)
):
    """List DLP events with multi-factor filtering."""
    query = db.query(DLPEvent)
    if channel and channel.upper() != "ALL":
        query = query.filter(DLPEvent.channel == channel.upper())
    if employee_id:
        query = query.filter(DLPEvent.employee_id == employee_id)
    if risk_level:
        query = query.filter(DLPEvent.risk_level == risk_level.upper())
    if action:
        query = query.filter(DLPEvent.action == action.upper())
    if search:
        s = f"%{search}%"
        query = query.filter(
            (DLPEvent.file_name.ilike(s)) |
            (DLPEvent.destination.ilike(s)) |
            (DLPEvent.application.ilike(s)) |
            (DLPEvent.employee_id.ilike(s))
        )

    return query.order_by(DLPEvent.timestamp.desc()).offset(skip).limit(limit).all()

@router.delete("/events/clear-all", status_code=status.HTTP_200_OK)
def clear_all_dlp_events(
    db: Session = Depends(get_db),
    auth_caller: Optional[User] = Depends(get_current_user_or_agent)
):
    """Purge all recorded DLP events from the database."""
    deleted_count = db.query(DLPEvent).delete()
    db.commit()
    logger.info(f"Purged all {deleted_count} DLP events.")
    return {"message": f"Successfully cleared {deleted_count} DLP events", "deleted_count": deleted_count}

@router.delete("/events/{event_id}", status_code=status.HTTP_200_OK)
def delete_single_dlp_event(
    event_id: str,
    db: Session = Depends(get_db),
    auth_caller: Optional[User] = Depends(get_current_user_or_agent)
):
    """Delete a specific DLP event by event_id or numeric ID."""
    if event_id.isdigit():
        event = db.query(DLPEvent).filter((DLPEvent.id == int(event_id)) | (DLPEvent.event_id == event_id)).first()
    else:
        event = db.query(DLPEvent).filter(DLPEvent.event_id == event_id).first()

    if not event:
        raise HTTPException(status_code=404, detail="DLP Event not found")

    ev_id = event.event_id
    db.delete(event)
    db.commit()
    logger.info(f"Deleted DLP event {ev_id}")
    return {"message": f"DLP Event '{ev_id}' deleted successfully", "event_id": ev_id}

@router.get("/events/{event_id}", response_model=DLPEventResponse)
def get_dlp_event_by_id(
    event_id: str,
    db: Session = Depends(get_db),
    auth_caller: Optional[User] = Depends(get_current_user_or_agent)
):
    """Retrieve specific DLP event by event_id or database integer id."""
    if event_id.isdigit():
        event = db.query(DLPEvent).filter((DLPEvent.id == int(event_id)) | (DLPEvent.event_id == event_id)).first()
    else:
        event = db.query(DLPEvent).filter(DLPEvent.event_id == event_id).first()

    if not event:
        raise HTTPException(status_code=404, detail="DLP Event not found")
    return event

# ==================== DLP Statistics & SOC Analytics ====================

@router.get("/statistics", response_model=DLPStatisticsResponse)
def get_dlp_statistics(
    db: Session = Depends(get_db),
    auth_caller: Optional[User] = Depends(get_current_user_or_agent)
):
    """Retrieve comprehensive DLP statistics, channel counts, and threat rankings."""
    total_events = db.query(DLPEvent).count()
    usb_events = db.query(DLPEvent).filter(DLPEvent.channel == "USB").count()
    browser_events = db.query(DLPEvent).filter(DLPEvent.channel == "BROWSER").count()
    email_events = db.query(DLPEvent).filter(DLPEvent.channel == "EMAIL").count()
    cloud_events = db.query(DLPEvent).filter(DLPEvent.channel == "CLOUD").count()

    blocked_transfers = db.query(DLPEvent).filter(DLPEvent.action == "BLOCK").count()
    warned_transfers = db.query(DLPEvent).filter(DLPEvent.action == "WARN").count()
    allowed_transfers = db.query(DLPEvent).filter(DLPEvent.action == "ALLOW").count()
    critical_incidents = db.query(DLPEvent).filter(DLPEvent.risk_level == "CRITICAL").count()

    # Events by channel
    channel_counts = [
        {"label": "USB", "count": usb_events},
        {"label": "Browser", "count": browser_events},
        {"label": "Email", "count": email_events},
        {"label": "Cloud", "count": cloud_events}
    ]
    events_by_channel = [
        KeyValueCount(
            label=c["label"],
            count=c["count"],
            percentage=round(c["count"] / total_events * 100, 1) if total_events > 0 else 0.0
        )
        for c in channel_counts
    ]

    # Risk level distribution
    risk_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for e in db.query(DLPEvent).all():
        if e.risk_level in risk_counts:
            risk_counts[e.risk_level] += 1

    risk_dist = [
        KeyValueCount(
            label=lvl,
            count=cnt,
            percentage=round(cnt / total_events * 100, 1) if total_events > 0 else 0.0
        )
        for lvl, cnt in risk_counts.items()
    ]

    # Top Destinations
    dest_records = (
        db.query(DLPEvent.destination, func.count(DLPEvent.id).label("cnt"))
        .filter(DLPEvent.destination.isnot(None))
        .group_by(DLPEvent.destination)
        .order_by(desc("cnt"))
        .limit(6)
        .all()
    )
    top_destinations = [
        KeyValueCount(
            label=dest or "Unknown",
            count=cnt,
            percentage=round(cnt / total_events * 100, 1) if total_events > 0 else 0.0
        )
        for dest, cnt in dest_records
    ]

    # Top sensitive files
    top_files = (
        db.query(DLPEvent.id, DLPEvent.file_name, DLPEvent.channel, DLPEvent.risk_score, DLPEvent.action)
        .filter(DLPEvent.sensitive_data_detected == True)
        .order_by(DLPEvent.risk_score.desc())
        .limit(6)
        .all()
    )
    top_sensitive_files = [
        {
            "id": f[0],
            "file_name": f[1],
            "channel": f[2],
            "risk_score": f[3],
            "action": f[4]
        }
        for f in top_files
    ]

    # Top risk users
    emp_records = db.query(Employee).order_by(Employee.risk_score.desc()).limit(5).all()
    top_risk_users = [
        {
            "employee_id": e.employee_id,
            "username": e.username,
            "risk_score": e.risk_score,
            "status": e.status
        }
        for e in emp_records
    ]

    return DLPStatisticsResponse(
        total_dlp_events=total_events,
        usb_events=usb_events,
        browser_events=browser_events,
        email_events=email_events,
        cloud_events=cloud_events,
        blocked_transfers=blocked_transfers,
        warned_transfers=warned_transfers,
        allowed_transfers=allowed_transfers,
        critical_incidents=critical_incidents,
        events_by_channel=events_by_channel,
        risk_distribution=risk_dist,
        top_destinations=top_destinations,
        top_sensitive_files=top_sensitive_files,
        top_risk_users=top_risk_users
    )

@router.delete("/sensitive-files/clear-all", status_code=status.HTTP_200_OK)
def clear_all_sensitive_files(
    db: Session = Depends(get_db),
    auth_caller: Optional[User] = Depends(get_current_user_or_agent)
):
    """Clear all sensitive data flags from DLP events and remove indexed FileRecords."""
    dlp_cnt = db.query(DLPEvent).filter(DLPEvent.sensitive_data_detected == True).delete(synchronize_session=False)
    file_cnt = db.query(FileRecord).delete(synchronize_session=False)
    db.commit()
    logger.info(f"Cleared {dlp_cnt} sensitive DLP events and {file_cnt} indexed files.")
    return {"message": "All flagged sensitive files cleared successfully", "dlp_events_deleted": dlp_cnt, "files_deleted": file_cnt}

@router.delete("/sensitive-files/{file_name}", status_code=status.HTTP_200_OK)
def delete_sensitive_file(
    file_name: str,
    db: Session = Depends(get_db),
    auth_caller: Optional[User] = Depends(get_current_user_or_agent)
):
    """Delete all sensitive DLP events and file records matching the file name."""
    dlp_cnt = db.query(DLPEvent).filter(DLPEvent.file_name == file_name).delete(synchronize_session=False)
    file_cnt = db.query(FileRecord).filter(FileRecord.filename == file_name).delete(synchronize_session=False)
    db.commit()
    logger.info(f"Deleted sensitive records for file '{file_name}' ({dlp_cnt} DLP events, {file_cnt} FileRecords)")
    return {"message": f"Flagged file '{file_name}' deleted successfully", "file_name": file_name}

@router.get("/alerts")
def get_dlp_alerts(
    db: Session = Depends(get_db),
    auth_caller: Optional[User] = Depends(get_current_user_or_agent)
):
    """Retrieve high and critical DLP alerts."""
    alerts = (
        db.query(Alert)
        .filter(Alert.severity.in_(["HIGH", "CRITICAL"]))
        .order_by(Alert.created_at.desc())
        .limit(20)
        .all()
    )
    return alerts

# ==================== Policy & Rule Management ====================

@router.get("/policies", response_model=List[DLPPolicyResponse])
def list_policies(
    db: Session = Depends(get_db),
    auth_caller: Optional[User] = Depends(get_current_user_or_agent)
):
    """List all configurable DLP policies."""
    # Ensure default policies exist
    policy_service.seed_default_policies(db)
    return db.query(DLPPolicy).order_by(DLPPolicy.min_risk_score.desc()).all()

@router.post("/policies", response_model=DLPPolicyResponse)
def create_policy(
    pol_in: DLPPolicyCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin)
):
    """Create a new DLP policy rule."""
    pol = DLPPolicy(**pol_in.model_dump())
    db.add(pol)
    db.commit()
    db.refresh(pol)
    return pol

@router.patch("/policies/{policy_id}", response_model=DLPPolicyResponse)
def update_policy(
    policy_id: int,
    pol_update: DLPPolicyUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin)
):
    """Update an existing DLP policy rule."""
    pol = db.query(DLPPolicy).filter(DLPPolicy.id == policy_id).first()
    if not pol:
        raise HTTPException(status_code=404, detail="Policy not found")

    update_data = pol_update.model_dump(exclude_unset=True)
    for k, v in update_data.items():
        setattr(pol, k, v)

    db.commit()
    db.refresh(pol)
    return pol

@router.delete("/policies/{policy_id}")
def delete_policy(
    policy_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin)
):
    """Delete a DLP policy rule."""
    pol = db.query(DLPPolicy).filter(DLPPolicy.id == policy_id).first()
    if not pol:
        raise HTTPException(status_code=404, detail="Policy not found")
    db.delete(pol)
    db.commit()
    return {"message": f"Policy #{policy_id} deleted successfully"}

@router.get("/rules", response_model=List[PolicyRuleResponse])
def list_sensitive_rules(
    db: Session = Depends(get_db),
    auth_caller: Optional[User] = Depends(get_current_user_or_agent)
):
    """List configurable sensitive data regex/keyword rules."""
    return db.query(PolicyRule).all()

@router.post("/rules", response_model=PolicyRuleResponse)
def create_sensitive_rule(
    rule_in: PolicyRuleCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin)
):
    """Add a new custom sensitive data detection rule."""
    rule = PolicyRule(**rule_in.model_dump())
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule

@router.delete("/rules/{rule_id}")
def delete_sensitive_rule(
    rule_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin)
):
    """Delete a sensitive data detection rule."""
    rule = db.query(PolicyRule).filter(PolicyRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    db.delete(rule)
    db.commit()
    return {"message": f"Rule #{rule_id} deleted successfully"}

# ==================== Multi-Channel Simulation ====================

@router.post("/simulate", response_model=DLPGenericScanResponse)
def simulate_channel_dlp(
    scan_req: DLPGenericScanRequest,
    db: Session = Depends(get_db),
    auth_caller: Optional[User] = Depends(get_current_user_or_agent)
):
    """
    Simulate a DLP transfer scenario across any channel (USB, Browser, Cloud, Email).
    Runs complete pipeline: Scanning -> Risk Scoring -> Policy Decision -> Event Generation.
    """
    return scan_dlp_file(scan_req=scan_req, db=db, auth_caller=auth_caller)
