import pytest
from pathlib import Path
from backend.services.file_analysis_service import file_analysis_service
from backend.services.classifier_service import classifier_service
from backend.services.risk_service import risk_service
from backend.database import SessionLocal
from backend.services.alert_service import alert_service
from backend.models import Alert, Incident, Employee, FileRecord

def test_full_detection_and_incident_flow():
    # 1. Prepare sensitive file in monitored directory
    test_file = Path("monitored_data/e2e_test_credentials.txt")
    test_file.write_text("DATABASE_URL=postgres://admin:MasterSecret2026!@db.internal:5432/prod\nAWS_KEY=AKIAIOSFODNN7EXAMPLE")

    # 2. Document extraction
    text, method = file_analysis_service.extract_text_from_file(test_file)
    assert method == "PLAIN_TEXT"
    assert "AKIAIOSFODNN7EXAMPLE" in text

    # 3. DLP Classification
    clf = classifier_service.classify_file(
        filename=test_file.name,
        filepath=str(test_file),
        file_size=test_file.stat().st_size,
        extracted_text=text
    )
    assert clf["classification"] == "HIGHLY_CONFIDENTIAL"
    assert clf["sensitivity_score"] >= 90.0

    # 4. Risk Engine
    risk_info = risk_service.calculate_event_risk(
        activity_type="CREATE",
        sensitivity_score=clf["sensitivity_score"],
        classification=clf["classification"]
    )
    assert risk_info["risk_level"] in ["HIGH", "CRITICAL"]

    # 5. Database Alert and Auto-Incident Creation
    db = SessionLocal()
    emp = db.query(Employee).filter(Employee.employee_id == "EMP-E2E-TEST").first()
    if not emp:
        emp = Employee(
            employee_id="EMP-E2E-TEST",
            username="e2e_tester",
            full_name="E2E Tester",
            status="ONLINE",
            risk_score=0.0
        )
        db.add(emp)
        db.commit()

    alert = alert_service.process_and_create_alert(
        db=db,
        employee_id="EMP-E2E-TEST",
        alert_type="DLP_CREDENTIAL_LEAK",
        description=f"Sensitive file {test_file.name} created on endpoint",
        risk_score=clf["sensitivity_score"],
        severity="CRITICAL"
    )

    assert alert.id is not None
    assert alert.severity == "CRITICAL"

    # Check auto-created incident
    incident = db.query(Incident).filter(Incident.alert_id == alert.id).first()
    assert incident is not None
    assert incident.status == "OPEN"
    assert incident.severity == "CRITICAL"

    db.close()

    # Cleanup test file
    if test_file.exists():
        test_file.unlink()
