import pytest
from backend.database import SessionLocal, Base, engine
from backend.models import Alert, Incident, DLPEvent, Employee

@pytest.fixture(autouse=True, scope="session")
def clean_test_environment():
    """Ensure tests run cleanly and do not leave behind test alerts or incidents in sentinel.db."""
    yield
    # Teardown after test session completes
    db = SessionLocal()
    try:
        # Delete alerts and incidents generated during test executions
        db.query(Incident).delete()
        db.query(Alert).delete()
        db.query(DLPEvent).delete()
        
        # Reset any test employee risk scores
        for emp in db.query(Employee).all():
            emp.risk_score = 0.0
            emp.status = "ONLINE"
            
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()
