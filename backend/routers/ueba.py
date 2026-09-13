"""
SentinelDLP - User and Entity Behavior Analytics (UEBA) API Router
Endpoints for behavioral profiling, baseline management, statistical anomaly review,
and department peer group metrics.
"""

from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models import UEBAProfile, UEBAAnomaly, Employee, User
from backend.schemas import UEBAProfileResponse, UEBAAnomalyResponse
from backend.dependencies import get_current_user
from backend.ai.ueba import ueba_engine

router = APIRouter(prefix="/ueba", tags=["User and Entity Behavior Analytics (UEBA)"])


@router.get("/profiles", response_model=List[UEBAProfileResponse])
def list_ueba_profiles(
    department: Optional[str] = None,
    anomaly_status: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List all employee behavioral baseline profiles."""
    query = db.query(UEBAProfile)
    if department:
        query = query.filter(UEBAProfile.department == department)
    if anomaly_status:
        query = query.filter(UEBAProfile.anomaly_status == anomaly_status)

    profiles = query.order_by(UEBAProfile.current_anomaly_score.desc()).all()
    
    # If empty, generate profiles for all registered employees
    if not profiles:
        employees = db.query(Employee).all()
        for emp in employees:
            ueba_engine.get_or_create_profile(db, emp.employee_id, emp.department or "Engineering")
        profiles = query.order_by(UEBAProfile.current_anomaly_score.desc()).all()

    return profiles


@router.get("/profile/{employee_id}", response_model=UEBAProfileResponse)
def get_employee_ueba_profile(
    employee_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get single employee behavioral profile with statistical baseline distributions."""
    profile = db.query(UEBAProfile).filter(UEBAProfile.employee_id == employee_id).first()
    if not profile:
        profile = ueba_engine.get_or_create_profile(db, employee_id)
    return profile


@router.post("/recalculate/{employee_id}", response_model=UEBAProfileResponse)
def recalculate_employee_baseline(
    employee_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Trigger baseline profile recalculation for an employee from historical DLP events."""
    profile = ueba_engine.update_baseline_from_events(db, employee_id)
    return profile


@router.get("/anomalies", response_model=List[UEBAAnomalyResponse])
def list_ueba_anomalies(
    employee_id: Optional[str] = None,
    severity: Optional[str] = None,
    anomaly_type: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List behavioral anomalies flagged across the fleet."""
    query = db.query(UEBAAnomaly)
    if employee_id:
        query = query.filter(UEBAAnomaly.employee_id == employee_id)
    if severity:
        query = query.filter(UEBAAnomaly.severity == severity)
    if anomaly_type:
        query = query.filter(UEBAAnomaly.anomaly_type == anomaly_type)

    return query.order_by(UEBAAnomaly.timestamp.desc()).limit(limit).all()


@router.get("/summary")
def get_ueba_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Fleet-wide UEBA behavioral health, risk distribution, and department statistics."""
    total_profiles = db.query(UEBAProfile).count()
    critical_count = db.query(UEBAProfile).filter(UEBAProfile.anomaly_status == "CRITICAL").count()
    suspicious_count = db.query(UEBAProfile).filter(UEBAProfile.anomaly_status == "SUSPICIOUS").count()
    normal_count = db.query(UEBAProfile).filter(UEBAProfile.anomaly_status == "NORMAL").count()
    
    total_anomalies = db.query(UEBAAnomaly).count()
    after_hours_anomalies = db.query(UEBAAnomaly).filter(UEBAAnomaly.anomaly_type == "AFTER_HOURS_ACTIVITY").count()
    volume_spike_anomalies = db.query(UEBAAnomaly).filter(UEBAAnomaly.anomaly_type == "VOLUME_SPIKE").count()
    usb_anomalies = db.query(UEBAAnomaly).filter(UEBAAnomaly.anomaly_type == "UNUSUAL_USB_TRANSFER").count()

    return {
        "total_employees_profiled": total_profiles,
        "normal_employees": normal_count,
        "suspicious_employees": suspicious_count,
        "critical_employees": critical_count,
        "total_anomalies_flagged": total_anomalies,
        "after_hours_anomalies": after_hours_anomalies,
        "volume_spikes": volume_spike_anomalies,
        "unusual_usb_transfers": usb_anomalies
    }
