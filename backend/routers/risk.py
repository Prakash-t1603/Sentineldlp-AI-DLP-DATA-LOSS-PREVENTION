from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List, Dict, Any, Optional
from backend.database import get_db
from backend.models import Employee, Alert, ActivityLog, User
from backend.services.risk_service import risk_service
from backend.dependencies import require_analyst_or_admin, get_current_user_or_agent

router = APIRouter(prefix="/risk", tags=["Risk & UEBA Analytics"])

@router.get("/fleet")
def get_fleet_risk_overview(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin)
):
    """Retrieve fleet risk metrics, UEBA anomaly breakdown, and top risk endpoints."""
    employees = db.query(Employee).all()
    total = len(employees)
    if total == 0:
        return {
            "average_fleet_risk": 0.0,
            "distribution": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
            "top_risk": []
        }

    scores = [e.risk_score for e in employees]
    avg_score = sum(scores) / total

    dist = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for s in scores:
        level = risk_service.get_risk_level(s)
        dist[level] += 1

    top_risk = db.query(Employee).order_by(Employee.risk_score.desc()).limit(10).all()
    top_data = [
        {
            "employee_id": e.employee_id,
            "username": e.username,
            "hostname": e.hostname,
            "risk_score": e.risk_score,
            "risk_level": risk_service.get_risk_level(e.risk_score),
            "status": e.status,
            "alert_count": len(e.alerts)
        }
        for e in top_risk
    ]

    return {
        "average_fleet_risk": round(avg_score, 1),
        "total_endpoints": total,
        "distribution": dist,
        "top_risk_endpoints": top_data
    }

@router.post("/reset-all", status_code=status.HTTP_200_OK)
def reset_all_risk(
    db: Session = Depends(get_db),
    auth_caller: Optional[User] = Depends(get_current_user_or_agent)
):
    """Reset UEBA risk scores to 0.0 for all employees across the fleet."""
    employees = db.query(Employee).all()
    for emp in employees:
        emp.risk_score = 0.0
        if emp.status == "SUSPICIOUS":
            emp.status = "ONLINE"
    db.commit()
    return {"message": f"Successfully reset risk scores for {len(employees)} endpoints", "count": len(employees)}

@router.post("/reset/{employee_id}", status_code=status.HTTP_200_OK)
def reset_single_employee_risk(
    employee_id: str,
    db: Session = Depends(get_db),
    auth_caller: Optional[User] = Depends(get_current_user_or_agent)
):
    """Reset UEBA risk score to 0.0 for a specific employee."""
    employee = db.query(Employee).filter(Employee.employee_id == employee_id).first()
    if not employee:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Employee not found")
    employee.risk_score = 0.0
    if employee.status == "SUSPICIOUS":
        employee.status = "ONLINE"
    db.commit()
    return {"message": f"Risk score for '{employee_id}' reset to 0.0", "employee_id": employee_id}

@router.get("/employee/{employee_id}")
def get_employee_ueba(
    employee_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin)
):
    """Run real-time UEBA calculation for an employee."""
    employee = db.query(Employee).filter(Employee.employee_id == employee_id).first()
    if not employee:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Employee not found")
    
    return risk_service.calculate_employee_ueba_risk(db, employee_id)

@router.post("/simulate")
def simulate_activity_risk(
    activity_type: str = Query("USB_COPY"),
    sensitivity_score: float = Query(75.0, ge=0.0, le=100.0),
    classification: str = Query("CONFIDENTIAL"),
    process_name: Optional[str] = Query(None),
    destination: Optional[str] = Query(None),
    current_user: User = Depends(require_analyst_or_admin)
):
    """Ad-hoc simulation tool for calculating risk outcomes for potential threat scenarios."""
    return risk_service.calculate_event_risk(
        activity_type=activity_type,
        sensitivity_score=sensitivity_score,
        classification=classification,
        process_name=process_name,
        destination=destination
    )
