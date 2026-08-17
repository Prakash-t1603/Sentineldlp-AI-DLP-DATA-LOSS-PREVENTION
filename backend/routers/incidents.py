from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from backend.database import get_db
from backend.models import Incident, Employee, User
from backend.schemas import IncidentCreate, IncidentUpdate, IncidentResponse
from backend.dependencies import require_analyst_or_admin
from backend.utils.helpers import get_logger

logger = get_logger("SentinelDLP.IncidentsRouter")
router = APIRouter(prefix="/incidents", tags=["Incident Management"])

@router.get("", response_model=List[IncidentResponse])
def list_incidents(
    status_filter: Optional[str] = Query(None, alias="status"),
    severity: Optional[str] = Query(None),
    employee_id: Optional[str] = Query(None),
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin)
):
    """List security incidents with filtering by status, severity, and endpoint."""
    query = db.query(Incident)
    if status_filter:
        query = query.filter(Incident.status == status_filter.upper())
    if severity:
        query = query.filter(Incident.severity == severity.upper())
    if employee_id:
        query = query.filter(Incident.employee_id == employee_id)

    incidents = query.order_by(Incident.created_at.desc()).offset(skip).limit(limit).all()
    results = []
    for inc in incidents:
        res = IncidentResponse.model_validate(inc)
        if inc.employee:
            res.employee_username = inc.employee.username
        results.append(res)
    return results

@router.post("", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
def create_incident(
    incident_in: IncidentCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin)
):
    """Create a new manual security investigation incident."""
    new_inc = Incident(
        employee_id=incident_in.employee_id,
        alert_id=incident_in.alert_id,
        title=incident_in.title,
        description=incident_in.description,
        severity=incident_in.severity,
        status=incident_in.status,
        assigned_to=incident_in.assigned_to or current_user.username,
        investigation_notes=incident_in.investigation_notes,
        created_at=datetime.now(timezone.utc)
    )
    db.add(new_inc)
    db.commit()
    db.refresh(new_inc)
    logger.info(f"Incident #{new_inc.id} created by {current_user.username} for employee {incident_in.employee_id}")
    return IncidentResponse.model_validate(new_inc)

@router.patch("/{incident_id}", response_model=IncidentResponse)
def update_incident(
    incident_id: int,
    update_data: IncidentUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin)
):
    """Update incident investigation status, notes, containment, or resolution."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    if update_data.title:
        incident.title = update_data.title
    if update_data.description:
        incident.description = update_data.description
    if update_data.severity:
        incident.severity = update_data.severity
    if update_data.assigned_to:
        incident.assigned_to = update_data.assigned_to
    if update_data.investigation_notes:
        incident.investigation_notes = update_data.investigation_notes
    if update_data.status:
        incident.status = update_data.status
        if update_data.status == "RESOLVED" and not incident.resolved_at:
            incident.resolved_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(incident)
    logger.info(f"Analyst {current_user.username} updated Incident #{incident.id} (Status: {incident.status})")
    
    res = IncidentResponse.model_validate(incident)
    if incident.employee:
        res.employee_username = incident.employee.username
    return res

@router.get("/{incident_id}", response_model=IncidentResponse)
def get_incident_detail(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin)
):
    """Retrieve detailed investigation records for a specific incident."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    
    res = IncidentResponse.model_validate(incident)
    if incident.employee:
        res.employee_username = incident.employee.username
    return res
