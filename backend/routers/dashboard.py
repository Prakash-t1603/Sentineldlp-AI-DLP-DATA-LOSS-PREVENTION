from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List, Dict, Any
from backend.database import get_db
from backend.models import Employee, FileRecord, Alert, Incident, ActivityLog, User
from backend.schemas import (
    DashboardSummaryResponse, DashboardStats, KeyValueCount,
    EmployeeRiskRanking, AlertResponse, ActivityLogResponse
)
from backend.services.risk_service import risk_service
from backend.dependencies import require_analyst_or_admin

router = APIRouter(prefix="/dashboard", tags=["SOC Dashboard Analytics"])

@router.get("/summary", response_model=DashboardSummaryResponse)
def get_dashboard_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin)
):
    """
    Retrieve real-time consolidated SOC dashboard statistics,
    chart distributions, and threat intelligence streams.
    """
    total_employees = db.query(Employee).count()
    online_employees = db.query(Employee).filter(Employee.status == "ONLINE").count()
    sensitive_files = db.query(FileRecord).filter(
        FileRecord.classification.in_(["CONFIDENTIAL", "HIGHLY_CONFIDENTIAL"])
    ).count()
    open_alerts = db.query(Alert).filter(Alert.status == "OPEN").count()
    critical_alerts = db.query(Alert).filter(Alert.severity == "CRITICAL").count()
    active_incidents = db.query(Incident).filter(Incident.status.in_(["OPEN", "INVESTIGATING", "CONTAINED"])).count()
    avg_risk = db.query(func.avg(Employee.risk_score)).scalar() or 0.0

    stats = DashboardStats(
        total_employees=total_employees,
        online_employees=online_employees,
        sensitive_files=sensitive_files,
        open_alerts=open_alerts,
        critical_alerts=critical_alerts,
        active_incidents=active_incidents,
        average_risk_score=round(float(avg_risk), 1)
    )

    # 1. Risk distribution
    risk_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    employees = db.query(Employee).all()
    for emp in employees:
        lvl = risk_service.get_risk_level(emp.risk_score)
        risk_counts[lvl] += 1
    
    risk_dist = [
        KeyValueCount(
            label=lvl,
            count=cnt,
            percentage=round((cnt / total_employees * 100), 1) if total_employees > 0 else 0.0
        )
        for lvl, cnt in risk_counts.items()
    ]

    # 2. Alerts by severity
    total_alerts_count = db.query(Alert).count()
    sev_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    alerts = db.query(Alert).all()
    for a in alerts:
        if a.severity in sev_counts:
            sev_counts[a.severity] += 1

    alerts_dist = [
        KeyValueCount(
            label=sev,
            count=cnt,
            percentage=round((cnt / total_alerts_count * 100), 1) if total_alerts_count > 0 else 0.0
        )
        for sev, cnt in sev_counts.items()
    ]

    # 3. Files by classification
    total_files_count = db.query(FileRecord).count()
    cls_counts = {"PUBLIC": 0, "INTERNAL": 0, "CONFIDENTIAL": 0, "HIGHLY_CONFIDENTIAL": 0}
    files = db.query(FileRecord).all()
    for f in files:
        if f.classification in cls_counts:
            cls_counts[f.classification] += 1

    files_dist = [
        KeyValueCount(
            label=cls,
            count=cnt,
            percentage=round((cnt / total_files_count * 100), 1) if total_files_count > 0 else 0.0
        )
        for cls, cnt in cls_counts.items()
    ]

    # 4. Top risk employees ranking
    top_emp_records = db.query(Employee).order_by(Employee.risk_score.desc()).limit(5).all()
    top_risk_employees = [
        EmployeeRiskRanking(
            employee_id=e.employee_id,
            username=e.username,
            hostname=e.hostname,
            risk_score=e.risk_score,
            risk_level=risk_service.get_risk_level(e.risk_score),
            alert_count=len(e.alerts),
            last_seen=e.last_seen
        )
        for e in top_emp_records
    ]

    # 5. Recent Alerts
    recent_alerts_records = db.query(Alert).order_by(Alert.created_at.desc()).limit(10).all()
    recent_alerts = []
    for a in recent_alerts_records:
        res = AlertResponse.model_validate(a)
        if a.employee:
            res.employee_username = a.employee.username
        if a.file:
            res.filename = a.file.filename
        recent_alerts.append(res)

    # 6. Recent Activities
    recent_act_records = db.query(ActivityLog).order_by(ActivityLog.timestamp.desc()).limit(10).all()
    recent_activities = [ActivityLogResponse.model_validate(act) for act in recent_act_records]

    return DashboardSummaryResponse(
        stats=stats,
        risk_distribution=risk_dist,
        alerts_by_severity=alerts_dist,
        files_by_classification=files_dist,
        top_risk_employees=top_risk_employees,
        recent_alerts=recent_alerts,
        recent_activities=recent_activities
    )
