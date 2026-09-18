import pytest
from backend.database import SessionLocal, Base, engine
from backend.models import Alert, Incident, DLPEvent, Employee

def _clean_db():
    db = SessionLocal()
    try:
        db.query(Incident).delete()
        db.query(Alert).delete()
        db.query(DLPEvent).delete()
        for emp in db.query(Employee).all():
            emp.risk_score = 0.0
            emp.status = "ONLINE"
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()

@pytest.fixture(autouse=True, scope="session")
def clean_test_environment():
    """Ensure tests run cleanly and do not leave behind test alerts or incidents in sentinel.db."""
    _clean_db()
    yield
    _clean_db()

def pytest_sessionfinish(session, exitstatus):
    """Final teardown ensuring sentinel.db is left completely clean."""
    _clean_db()
