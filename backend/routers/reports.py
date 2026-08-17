from fastapi import APIRouter, Depends, Response, status
from sqlalchemy.orm import Session
from typing import Optional
from backend.database import get_db
from backend.services.report_service import report_service
from backend.dependencies import require_analyst_or_admin, get_optional_current_user
from backend.models import User

router = APIRouter(prefix="/reports", tags=["Reporting & Compliance"])

@router.get("/summary")
def get_executive_report_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin)
):
    """Retrieve executive DLP threat, incident, and endpoint summary."""
    return report_service.generate_executive_summary(db)

@router.get("/export/alerts.csv")
def download_alerts_csv(
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_optional_current_user)
):
    """Download full alerts data in standard CSV format."""
    csv_content = report_service.export_alerts_csv(db)
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=sentineldlp_alerts_export.csv"}
    )

@router.get("/export/activities.csv")
def download_activities_csv(
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_optional_current_user)
):
    """Download raw endpoint activity logs in standard CSV format."""
    csv_content = report_service.export_activity_logs_csv(db)
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=sentineldlp_activities_export.csv"}
    )
