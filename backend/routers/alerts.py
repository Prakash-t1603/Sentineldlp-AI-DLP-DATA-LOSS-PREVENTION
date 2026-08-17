from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from backend.database import get_db
from backend.models import Alert, Employee, FileRecord, User, Incident
from backend.schemas import AlertCreate, AlertUpdate, AlertResponse, AlertHistoryStats
from backend.services.alert_service import alert_service
from backend.dependencies import get_current_user_or_agent, require_analyst_or_admin
from backend.utils.helpers import get_logger

logger = get_logger("SentinelDLP.AlertsRouter")
router = APIRouter(prefix="/alerts", tags=["Alert Management"])

@router.get("/stats", response_model=AlertHistoryStats)
def get_alert_history_stats(
    db: Session = Depends(get_db),
    auth_caller: Optional[User] = Depends(get_current_user_or_agent)
):
    """Retrieve statistical breakdown of alert history by lifecycle state."""
    total = db.query(Alert).count()
    open_count = db.query(Alert).filter(Alert.status == "OPEN").count()
    investigating_count = db.query(Alert).filter(Alert.status.in_(["INVESTIGATING", "ACKNOWLEDGED"])).count()
    resolved_count = db.query(Alert).filter(Alert.status == "RESOLVED").count()
    false_pos_count = db.query(Alert).filter(Alert.status == "FALSE_POSITIVE").count()
    critical_count = db.query(Alert).filter(Alert.severity == "CRITICAL").count()

    return AlertHistoryStats(
        total_alerts=total,
        open_alerts=open_count,
        investigating_alerts=investigating_count,
        resolved_alerts=resolved_count,
        false_positive_alerts=false_pos_count,
        critical_alerts=critical_count
    )

@router.get("", response_model=List[AlertResponse])
def list_alerts(
    severity: Optional[str] = Query(None),
    status_filter: Optional[str] = Query(None, alias="status"),
    employee_id: Optional[str] = Query(None),
    skip: int = 0,
    limit: int = 200,
    db: Session = Depends(get_db),
    auth_caller: Optional[User] = Depends(get_current_user_or_agent)
):
    """Retrieve security alerts with multi-dimensional filtering."""
    query = db.query(Alert)
    if severity:
        query = query.filter(Alert.severity == severity.upper())
    if status_filter:
        s = status_filter.upper()
        if s == "INVESTIGATING":
            query = query.filter(Alert.status.in_(["INVESTIGATING", "ACKNOWLEDGED"]))
        else:
            query = query.filter(Alert.status == s)
    if employee_id:
        query = query.filter(Alert.employee_id == employee_id)

    alerts = query.order_by(Alert.created_at.desc()).offset(skip).limit(limit).all()

    # Populate helper fields for response
    results = []
    for a in alerts:
        res = AlertResponse.model_validate(a)
        if a.employee:
            res.employee_username = a.employee.username
        if a.file:
            res.filename = a.file.filename
        results.append(res)

    return results

@router.post("", response_model=AlertResponse, status_code=status.HTTP_201_CREATED)
def create_alert(
    alert_in: AlertCreate,
    db: Session = Depends(get_db),
    auth_caller: Optional[User] = Depends(get_current_user_or_agent)
):
    """Ingest a new DLP alert from an endpoint agent or analyst."""
    created = alert_service.process_and_create_alert(
        db=db,
        employee_id=alert_in.employee_id,
        alert_type=alert_in.alert_type,
        description=alert_in.description,
        source=alert_in.source,
        file_id=alert_in.file_id,
        risk_score=alert_in.risk_score,
        severity=alert_in.severity
    )
    return AlertResponse.model_validate(created)

@router.patch("/{alert_id}", response_model=AlertResponse)
def update_alert_status(
    alert_id: int,
    update_data: AlertUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin)
):
    """Triage and update alert lifecycle status (OPEN, ACKNOWLEDGED, RESOLVED)."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    if update_data.status:
        alert.status = update_data.status

    db.commit()
    db.refresh(alert)
    logger.info(f"User {current_user.username} updated Alert #{alert.id} status to {alert.status}")
    return AlertResponse.model_validate(alert)

@router.get("/{alert_id}", response_model=AlertResponse)
def get_alert_detail(
    alert_id: int,
    db: Session = Depends(get_db),
    auth_caller: Optional[User] = Depends(get_current_user_or_agent)
):
    """Get detailed information about a specific alert."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    
    res = AlertResponse.model_validate(alert)
    if alert.employee:
        res.employee_username = alert.employee.username
    if alert.file:
        res.filename = alert.file.filename
    return res

@router.delete("/clear-all", status_code=status.HTTP_200_OK)
def clear_all_alerts(
    db: Session = Depends(get_db),
    auth_caller: Optional[User] = Depends(get_current_user_or_agent)
):
    """Purge all alerts, incidents, and reset employee risk scores."""
    incidents_count = db.query(Incident).delete()
    alerts_count = db.query(Alert).delete()
    employees = db.query(Employee).all()
    for emp in employees:
        emp.risk_score = 0.0
        emp.status = "ONLINE"
    db.commit()
    logger.info(f"Purged {alerts_count} alerts and {incidents_count} incidents.")
    return {
        "message": "All alert data removed successfully",
        "alerts_removed": alerts_count,
        "incidents_removed": incidents_count
    }

