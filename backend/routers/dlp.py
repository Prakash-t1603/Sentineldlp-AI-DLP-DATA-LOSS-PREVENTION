import os
import base64
import tempfile
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query, UploadFile, File, Form
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

from backend.database import get_db
from backend.models import DLPEvent, DLPPolicy, PolicyRule, Employee, FileRecord, Alert, Incident, User
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

@router.post("/scan", response_model=DLPGenericScanResponse)
def scan_dlp_file(
    scan_req: DLPGenericScanRequest,
    db: Session = Depends(get_db),
    auth_caller: Optional[User] = Depends(get_current_user_or_agent)
):
    """
    Centralized DLP Scanner endpoint shared by USB, Browser, Cloud, and Email modules.
    Runs Content NLP -> Regex -> Keywords -> PII -> OCR -> Risk Engine -> Policy Engine.
    """
    channel = scan_req.channel.upper()
    destination = scan_req.destination or scan_req.application
    file_name = scan_req.file_name
    file_size = scan_req.file_size
    file_hash = ""
    extracted_text = scan_req.extracted_text or ""

    # Decode base64 payload if provided
    if scan_req.file_content_base64:
        try:
            raw_bytes = base64.b64decode(scan_req.file_content_base64)
            file_size = len(raw_bytes)
            import hashlib
            file_hash = hashlib.sha256(raw_bytes).hexdigest()
            try:
                extracted_text = raw_bytes.decode("utf-8")
            except Exception:
                ext = Path(file_name).suffix.lower() if file_name else ".dat"
                with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp:
                    tmp.write(raw_bytes)
                    tmp_path = Path(tmp.name)
                try:
                    text, _ = file_analysis_service.extract_text_from_file(tmp_path)
                    extracted_text = text or extracted_text
                finally:
                    try:
                        tmp_path.unlink()
                    except Exception:
                        pass
        except Exception as e:
            logger.warning(f"Error reading base64 file content in DLP scan: {e}")

    # Read from local filepath if provided and text is empty
    elif scan_req.file_path and Path(scan_req.file_path).exists():
        p = Path(scan_req.file_path)
        file_size = p.stat().st_size
        file_hash = compute_file_hash(p)
        file_name = p.name
        if not extracted_text:
            text, _ = file_analysis_service.extract_text_from_file(p)
            extracted_text = text

    # 1. Centralized Classification & Entity Scanner
    clf_result = classifier_service.classify_file(
        filename=file_name,
        filepath=scan_req.file_path or file_name,
        file_size=file_size,
        extracted_text=extracted_text,
        file_hash=file_hash
    )

    classification = clf_result.get("classification", "PUBLIC")
    sensitivity_score = clf_result.get("sensitivity_score", 0.0)
    detected_entities = clf_result.get("detected_entities", [])
    indicators = clf_result.get("indicators", [])
    sensitive_data_detected = sensitivity_score >= 30.0 or len(detected_entities) > 0

    # 2. Centralized Risk Engine
    has_keywords = any("confidential" in ind.lower() or "proprietary" in ind.lower() for ind in indicators)
    risk_info = risk_service.calculate_dlp_risk(
        channel=channel,
        sensitivity_score=sensitivity_score,
        classification=classification,
        destination=destination,
        application=scan_req.application,
        file_size=file_size,
        sensitive_entities_count=len(detected_entities),
        has_sensitive_keywords=has_keywords
    )
    risk_score = risk_info["risk_score"]
    risk_level = risk_info["risk_level"]

    # 3. Centralized Policy Engine
    policy_decision = policy_service.evaluate_policy(
        db=db,
        channel=channel,
        risk_score=risk_score,
        sensitive_data_detected=sensitive_data_detected,
        destination=destination
    )
    action = policy_decision["action"]
    policy_name = policy_decision["policy_name"]

    # 4. Ensure employee exists
    emp_id = scan_req.employee_id or "UNKNOWN-EMP"
    emp = db.query(Employee).filter(Employee.employee_id == emp_id).first()
    if not emp:
        emp = Employee(
            employee_id=emp_id,
            username=emp_id,
            hostname=scan_req.device_id or "WORKSTATION",
            status="ONLINE",
            risk_score=0.0
        )
        db.add(emp)
        db.commit()

    # 5. Record DLPEvent in Database
    ext = Path(file_name).suffix.lower() if file_name else ""
    entity_summary = ", ".join([f"{e['entity_type']} (x{e['count']})" for e in detected_entities]) if detected_entities else "None"
    details_str = (
        f"Channel: {channel} | Application: {scan_req.application} | Destination: {destination} | "
        f"File: '{file_name}' ({file_size} bytes) | Classification: {classification} ({sensitivity_score}/100) | "
        f"Entities: [{entity_summary}] | Policy: '{policy_name}' -> {action}"
    )

    event = DLPEvent(
        employee_id=emp_id,
        device_id=scan_req.device_id or "WORKSTATION",
        channel=channel,
        application=scan_req.application,
        destination=destination,
        file_name=file_name,
        file_hash=file_hash,
        file_size=file_size,
        file_type=ext,
        sensitive_data_detected=sensitive_data_detected,
        detection_type="PII" if detected_entities else ("CLASSIFIER" if sensitivity_score > 0 else "BENIGN"),
        risk_score=risk_score,
        risk_level=risk_level,
        action=action,
        timestamp=datetime.now(timezone.utc),
        status="BLOCKED" if action == "BLOCK" else ("WARNED" if action == "WARN" else "ALLOWED"),
        details=details_str
    )
    db.add(event)
    db.commit()
    db.refresh(event)

    # 6. Real-Time Alerting for HIGH and CRITICAL events
    alert_created = False
    alert_id = None
    if action == "BLOCK" or risk_score >= 60.0 or policy_decision.get("create_alert", False):
        alert_desc = (
            f"🚨 DLP INCIDENT [{action}] on {channel}: Transfer of '{file_name}' ({classification}, "
            f"Sensitivity: {sensitivity_score}/100) via {scan_req.application} to '{destination}'. "
            f"Detected: [{entity_summary}]. Risk: {risk_score} ({risk_level})."
        )
        alert = alert_service.process_and_create_alert(
            db=db,
            employee_id=emp_id,
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
        message=f"DLP Scan Completed: Policy decided {action}."
    )

@router.post("/browser-event", response_model=DLPGenericScanResponse)
def handle_browser_event(
    req: BrowserDLPEventRequest,
    db: Session = Depends(get_db),
    auth_caller: Optional[User] = Depends(get_current_user_or_agent)
):
    """
    Handle file upload interception events from the Browser DLP extension / web client.
    Supports Google Drive, OneDrive, Dropbox, Webmail, WhatsApp Web, etc.
    """
    emp_id = req.employee_id or req.employee or "employee01"
    dev_id = req.device_id or req.device or "DESKTOP-001"
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
    """Ingest a pre-computed or endpoint-agent generated DLP event."""
    emp = db.query(Employee).filter(Employee.employee_id == event_in.employee_id).first()
    if not emp:
        emp = Employee(
            employee_id=event_in.employee_id,
            username=event_in.employee_id,
            hostname=event_in.device_id or "WORKSTATION",
            status="ONLINE",
            risk_score=event_in.risk_score
        )
        db.add(emp)
        db.commit()

    event = DLPEvent(**event_in.model_dump())
    db.add(event)
    db.commit()
    db.refresh(event)

    # If action is BLOCK or risk >= 60, create alert
    if event.action == "BLOCK" or event.risk_score >= 60.0:
        alert_desc = f"🚨 DLP Event [{event.action}] on {event.channel}: {event.file_name} -> {event.destination} (Risk: {event.risk_score})"
        alert_service.process_and_create_alert(
            db=db,
            employee_id=event.employee_id,
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
        db.query(DLPEvent.file_name, DLPEvent.channel, DLPEvent.risk_score, DLPEvent.action)
        .filter(DLPEvent.sensitive_data_detected == True)
        .order_by(DLPEvent.risk_score.desc())
        .limit(6)
        .all()
    )
    top_sensitive_files = [
        {
            "file_name": f[0],
            "channel": f[1],
            "risk_score": f[2],
            "action": f[3]
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
