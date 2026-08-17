import pytest
from backend.services.risk_service import risk_service

def test_risk_level_mapping():
    assert risk_service.get_risk_level(15.0) == "LOW"
    assert risk_service.get_risk_level(45.0) == "MEDIUM"
    assert risk_service.get_risk_level(68.0) == "HIGH"
    assert risk_service.get_risk_level(92.0) == "CRITICAL"

def test_event_risk_usb_transfer():
    # USB copy of a high-sensitivity file should result in high/critical risk
    result = risk_service.calculate_event_risk(
        activity_type="USB_COPY",
        sensitivity_score=90.0,
        classification="HIGHLY_CONFIDENTIAL",
        process_name="explorer.exe"
    )
    assert result["risk_score"] >= 60.0
    assert result["risk_level"] in ["HIGH", "CRITICAL"]

def test_event_risk_suspicious_process():
    result = risk_service.calculate_event_risk(
        activity_type="NETWORK_TRANSFER",
        sensitivity_score=60.0,
        classification="CONFIDENTIAL",
        process_name="tor.exe"
    )
    assert result["factors"]["process_contribution"] > 0
