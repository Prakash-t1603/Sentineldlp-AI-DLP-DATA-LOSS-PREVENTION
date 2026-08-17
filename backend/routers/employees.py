from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from backend.database import get_db
from backend.models import Employee, FileRecord, Alert, Incident, ActivityLog, User
from backend.schemas import (
    EmployeeCreate, EmployeeUpdate, EmployeeResponse, EmployeeDetailResponse,
    ActivityLogResponse, FileRecordResponse, AlertResponse, IncidentResponse
)
from backend.dependencies import require_analyst_or_admin, get_current_user_or_agent, require_admin
from backend.utils.helpers import get_logger

logger = get_logger("SentinelDLP.EmployeesRouter")
router = APIRouter(prefix="/employees", tags=["Employee Endpoints"])

@router.post("/register", response_model=EmployeeResponse, status_code=status.HTTP_201_CREATED)
def register_or_update_employee(
    emp_data: EmployeeCreate,
    db: Session = Depends(get_db),
    auth_caller: Optional[User] = Depends(get_current_user_or_agent)
):
    """Register a new employee endpoint or update existing endpoint metadata upon agent connect."""
    employee = db.query(Employee).filter(Employee.employee_id == emp_data.employee_id).first()
    if employee:
        employee.hostname = emp_data.hostname or employee.hostname
        employee.ip_address = emp_data.ip_address or employee.ip_address
        employee.operating_system = emp_data.operating_system or employee.operating_system
        employee.status = "ONLINE"
        employee.last_seen = datetime.now(timezone.utc)
    else:
        employee = Employee(
            employee_id=emp_data.employee_id,
            username=emp_data.username,
            hostname=emp_data.hostname or "UNKNOWN_HOST",
            ip_address=emp_data.ip_address or "127.0.0.1",
            operating_system=emp_data.operating_system or "Windows",
            status="ONLINE",
            last_seen=datetime.now(timezone.utc),
            risk_score=0.0
        )
        db.add(employee)
    
    db.commit()
    db.refresh(employee)
    logger.info(f"Endpoint registered/updated: {employee.employee_id} ({employee.hostname})")
    return employee

@router.post("/heartbeat/{employee_id}", response_model=EmployeeResponse)
def employee_heartbeat(
    employee_id: str,
    db: Session = Depends(get_db),
    auth_caller: Optional[User] = Depends(get_current_user_or_agent)
):
    """Update employee endpoint online status and last seen timestamp."""
    employee = db.query(Employee).filter(Employee.employee_id == employee_id).first()
    if not employee:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Employee endpoint not found")
    
    employee.status = "ONLINE"
    employee.last_seen = datetime.now(timezone.utc)
    db.commit()
    db.refresh(employee)
    return employee

@router.get("", response_model=List[EmployeeResponse])
def list_employees(
    status_filter: Optional[str] = Query(None, alias="status"),
    min_risk: Optional[float] = Query(None, ge=0.0, le=100.0),
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin)
):
    """List all monitored endpoints with filtering capabilities (Analysts and Admins)."""
    query = db.query(Employee)
    if status_filter:
        query = query.filter(Employee.status == status_filter.upper())
    if min_risk is not None:
        query = query.filter(Employee.risk_score >= min_risk)
        
    employees = query.order_by(Employee.risk_score.desc()).offset(skip).limit(limit).all()
    return employees

@router.get("/{employee_id}", response_model=EmployeeDetailResponse)
def get_employee_detail(
    employee_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin)
):
    """Retrieve full 360-degree security profile of an employee endpoint."""
    employee = db.query(Employee).filter(Employee.employee_id == employee_id).first()
    if not employee:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Employee not found")

    activities = db.query(ActivityLog).filter(
        ActivityLog.employee_id == employee_id
    ).order_by(ActivityLog.timestamp.desc()).limit(50).all()

    files = db.query(FileRecord).filter(
        FileRecord.employee_id == employee_id
    ).order_by(FileRecord.sensitivity.desc()).limit(50).all()

    alerts = db.query(Alert).filter(
        Alert.employee_id == employee_id
    ).order_by(Alert.created_at.desc()).limit(50).all()

    incidents = db.query(Incident).filter(
        Incident.employee_id == employee_id
    ).order_by(Incident.created_at.desc()).limit(20).all()

    # Generate synthetic/calculated risk timeline points from recent activities
    risk_history = [
        {
            "timestamp": act.timestamp.isoformat() if act.timestamp else "",
            "activity_type": act.activity_type,
            "risk_score": act.risk_score
        }
        for act in activities[:15]
    ]

    return EmployeeDetailResponse(
        employee=EmployeeResponse.model_validate(employee),
        activities=[ActivityLogResponse.model_validate(a) for a in activities],
        files=[FileRecordResponse.model_validate(f) for f in files],
        alerts=[AlertResponse.model_validate(a) for a in alerts],
        incidents=[IncidentResponse.model_validate(i) for i in incidents],
        risk_history=risk_history
    )

@router.delete("/{employee_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_employee(
    employee_id: str,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_admin)
):
    """Delete an employee endpoint record (Admin only)."""
    employee = db.query(Employee).filter(Employee.employee_id == employee_id).first()
    if not employee:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Employee not found")
    
    db.delete(employee)
    db.commit()
    logger.info(f"Admin {admin_user.username} deleted endpoint {employee_id}")
    return None
