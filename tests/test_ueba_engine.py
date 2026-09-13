"""
Unit & Integration Tests for SentinelDLP User and Entity Behavior Analytics (UEBA) Engine.
"""

from datetime import datetime, timezone, timedelta
import pytest
from fastapi.testclient import TestClient

from backend.main import app, init_database
from backend.database import SessionLocal
from backend.models import User, Employee, UEBAProfile, UEBAAnomaly, DLPEvent
from backend.ai.ueba import ueba_engine


@pytest.fixture(scope="module")
def client():
    init_database()
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def auth_headers(client):
    login_resp = client.post("/api/v1/auth/login", json={
        "username_or_email": "admin@sentineldlp.io",
        "password": "Admin@123456"
    })
    token = login_resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="function")
def db_session():
    init_database()
    db = SessionLocal()
    try:
        # Ensure test employees exist
        emp1 = db.query(Employee).filter(Employee.employee_id == "EMP-UEBA-01").first()
        if not emp1:
            emp1 = Employee(
                employee_id="EMP-UEBA-01",
                username="alice_vance",
                full_name="Alice Vance",
                email="alice@company.com",
                department="Engineering",
                designation="DevOps Lead"
            )
            db.add(emp1)

        emp2 = db.query(Employee).filter(Employee.employee_id == "EMP-UEBA-02").first()
        if not emp2:
            emp2 = Employee(
                employee_id="EMP-UEBA-02",
                username="bob_finance",
                full_name="Bob Finance",
                email="bob@company.com",
                department="Finance",
                designation="Financial Analyst"
            )
            db.add(emp2)
        db.commit()
        yield db
    finally:
        db.close()


# ==================== 1. Baseline Profiling & Insufficient Data ====================

def test_ueba_insufficient_baseline_behavior(db_session):
    """When employee has < 5 events, engine should not fire false positive alarms."""
    # Reset employee profile to 0 events
    profile = ueba_engine.get_or_create_profile(db_session, "EMP-UEBA-01")
    profile.total_events_observed = 0
    db_session.commit()

    res = ueba_engine.evaluate_event(
        db=db_session,
        employee_id="EMP-UEBA-01",
        channel="FILE",
        file_size_bytes=1024,
        sensitive_entity_count=0
    )
    assert res.anomaly_level == "INSUFFICIENT_BASELINE"
    assert res.anomaly_score == 0.0
    assert res.has_anomaly is False


def test_ueba_baseline_calculation_from_events(db_session):
    """Seed historical events and verify statistical mean/std calculation."""
    now = datetime.now(timezone.utc)
    
    # Seed 10 historical events across 3 days
    for i in range(10):
        ev = DLPEvent(
            event_id=f"DLP-UEBA-HIST-{i}",
            employee_id="EMP-UEBA-01",
            channel="FILE" if i < 8 else "USB",
            application="Explorer",
            file_name=f"test_file_{i}.txt",
            timestamp=now - timedelta(days=i % 3)
        )
        db_session.add(ev)
    db_session.commit()

    profile = ueba_engine.update_baseline_from_events(db_session, "EMP-UEBA-01")
    assert profile.total_events_observed >= 10
    assert profile.mean_daily_files > 0
    assert profile.std_daily_files > 0


# ==================== 2. Anomaly Detection Methods ====================

def test_ueba_volume_spike_anomaly(db_session):
    """Test Z-score volume spike detection when burst of events occurs."""
    profile = ueba_engine.get_or_create_profile(db_session, "EMP-UEBA-01")
    profile.total_events_observed = 25
    profile.mean_daily_files = 8.0
    profile.std_daily_files = 2.0
    db_session.commit()

    # Simulate sudden 20 events in short window
    res = ueba_engine.evaluate_event(
        db=db_session,
        employee_id="EMP-UEBA-01",
        channel="FILE",
        recent_window_events_count=20
    )
    assert res.has_anomaly is True
    assert res.anomaly_score >= 0.60
    assert any(a.anomaly_type == "VOLUME_SPIKE" for a in res.anomalies)


def test_ueba_unusual_usb_transfer(db_session):
    """Test unusual USB transfer when employee baseline has 0 USB transfers."""
    profile = ueba_engine.get_or_create_profile(db_session, "EMP-UEBA-02")
    profile.total_events_observed = 30
    profile.mean_daily_usb_copies = 0.05
    db_session.commit()

    res = ueba_engine.evaluate_event(
        db=db_session,
        employee_id="EMP-UEBA-02",
        channel="USB",
        sensitive_entity_count=2
    )
    assert res.has_anomaly is True
    assert any(a.anomaly_type == "UNUSUAL_USB_TRANSFER" for a in res.anomalies)


def test_ueba_after_hours_detection(db_session):
    """Test off-hours access detection for day-shift employee."""
    profile = ueba_engine.get_or_create_profile(db_session, "EMP-UEBA-01")
    profile.total_events_observed = 20
    profile.after_hours_ratio = 0.02

    midnight_sunday = datetime(2026, 9, 13, 2, 30, 0, tzinfo=timezone.utc)
    res = ueba_engine.evaluate_event(
        db=db_session,
        employee_id="EMP-UEBA-01",
        channel="FILE",
        sensitive_entity_count=1,
        event_time=midnight_sunday
    )
    assert res.has_anomaly is True
    assert any(a.anomaly_type == "AFTER_HOURS_ACTIVITY" for a in res.anomalies)


# ==================== 3. UEBA API Endpoints ====================

def test_api_list_profiles_and_summary(client, auth_headers):
    # 1. Profiles list
    res_prof = client.get("/api/v1/ueba/profiles", headers=auth_headers)
    assert res_prof.status_code == 200
    profiles = res_prof.json()
    assert len(profiles) >= 2

    # 2. Single profile
    res_single = client.get("/api/v1/ueba/profile/EMP-UEBA-01", headers=auth_headers)
    assert res_single.status_code == 200
    assert res_single.json()["employee_id"] == "EMP-UEBA-01"

    # 3. Fleet UEBA summary
    res_sum = client.get("/api/v1/ueba/summary", headers=auth_headers)
    assert res_sum.status_code == 200
    sum_data = res_sum.json()
    assert "total_employees_profiled" in sum_data
    assert "normal_employees" in sum_data
