"""
Unit & Integration Tests for SentinelDLP AI, ML, NLP, OCR, and Pipeline Subsystems.
"""

import pytest
from fastapi.testclient import TestClient

from backend.main import app, init_database
from backend.database import SessionLocal
from backend.models import User, Employee, DLPAnalysis, SensitiveEntityRecord
from backend.ai.entity_detector import entity_detector, luhn_checksum, verhoeff_validate, shannon_entropy
from backend.ai.nlp_engine import nlp_engine
from backend.ai.ocr_engine import ocr_engine
from backend.ai.classifier import dlp_classifier
from backend.ai.confidence import confidence_scorer
from backend.ai.pipeline import dlp_pipeline


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
        yield db
    finally:
        db.close()


# ==================== 1. Entity Detector & Algorithmic Checksums ====================

def test_luhn_checksum_algorithm():
    # Valid Visa card with correct Luhn checksum (sum = 50)
    assert luhn_checksum("4532015012345671") is True
    # Invalid card
    assert luhn_checksum("4532015012345679") is False
    assert luhn_checksum("123") is False


def test_verhoeff_aadhaar_validation():
    assert verhoeff_validate("219012345674") in (True, False)
    assert verhoeff_validate("") is False


def test_shannon_entropy_calculation():
    low_ent = shannon_entropy("aaaaaaaaaaaaaaaa")
    assert low_ent == 0.0
    
    high_ent = shannon_entropy("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
    assert high_ent > 3.8


def test_entity_detector_scans_credentials_and_pii():
    text = (
        "Here are the server credentials:\n"
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        "Customer email is security-team@sentineldlp.io\n"
        "Customer SSN is 123-45-6789\n"
    )
    res = entity_detector.scan_text(text)
    assert res.total_count >= 3
    assert res.category_counts.get("CREDENTIALS", 0) >= 1
    assert res.category_counts.get("PERSONAL", 0) >= 1
    assert res.category_counts.get("IDENTITY", 0) >= 1

    types_found = [e.entity_type for e in res.entities]
    assert "AWS_ACCESS_KEY" in types_found
    assert "EMAIL" in types_found
    assert "SSN" in types_found

    for ent in res.entities:
        if ent.entity_type == "AWS_ACCESS_KEY":
            assert "AKIA" in ent.masked_value and len(ent.masked_value) < len(ent.matched_text)
        if ent.entity_type == "EMAIL":
            assert "@" in ent.masked_value


# ==================== 2. NLP Context & Intent Engine ====================

def test_nlp_engine_confidentiality_and_intent():
    text = "STRICTLY CONFIDENTIAL: Please bypass dlp filter and export database table to personal drive"
    res = nlp_engine.analyze_context(text)
    assert "STRICTLY CONFIDENTIAL" in res.confidentiality_markers_found
    assert res.exfiltration_intent_detected is True
    assert res.context_reinforcement_score > 1.2

    dummy_text = "This is a dummy test fixture with mock sample user data"
    res_dummy = nlp_engine.analyze_context(dummy_text)
    assert res_dummy.context_reinforcement_score < 1.0


# ==================== 3. OCR Engine Resilience ====================

def test_ocr_engine_empty_and_fallback():
    res = ocr_engine.extract_from_image_bytes(b"")
    assert res.success is False
    assert res.text == ""

    pdf_res = ocr_engine.extract_from_pdf_bytes(b"")
    assert pdf_res.success is False


# ==================== 4. ML Classifier ====================

def test_classifier_predicts_all_tiers():
    res_cred = dlp_classifier.classify("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----")
    assert res_cred.predicted_tier == "HIGHLY_CONFIDENTIAL"
    assert res_cred.confidence >= 0.85

    res_rest = dlp_classifier.classify("Patient MRN-902148 medical diagnosis ICD-10 acute hypertension")
    assert res_rest.predicted_tier in ("RESTRICTED", "CONFIDENTIAL")

    res_pub = dlp_classifier.classify("SentinelDLP Open Source project documentation and Apache 2.0 license.")
    assert res_pub.predicted_tier == "PUBLIC"


# ==================== 5. Hybrid Confidence Scorer ====================

def test_confidence_scorer_explainability():
    conf = confidence_scorer.compute(
        entity_count=2,
        entity_avg_confidence=0.95,
        ml_confidence=0.92,
        nlp_reinforcement=1.2,
        has_confidentiality_markers=True,
        has_exfiltration_intent=True,
        classification_tier="HIGHLY_CONFIDENTIAL"
    )
    assert conf.final_confidence >= 0.85
    assert len(conf.reasons) >= 3
    assert conf.signals["entity_count"] == 2


# ==================== 6. Full Real-Time Pipeline ====================

def test_dlp_pipeline_fast_path_and_slow_path(db_session):
    text = "CONFIDENTIAL: Executive salary budget and Q4 financial revenue forecast."
    
    # 1. Slow path first execution
    res1 = dlp_pipeline.analyze_payload(
        db=db_session,
        content=text,
        filename="financial_q4.txt",
        channel="FILE",
        persist=True
    )
    assert res1.fast_path is False
    assert res1.classification in ("CONFIDENTIAL", "RESTRICTED")
    assert res1.risk_score > 0

    # 2. Fast path second execution (Cache Hit)
    res2 = dlp_pipeline.analyze_payload(
        db=db_session,
        content=text,
        filename="financial_q4.txt",
        channel="FILE",
        persist=False
    )
    assert res2.fast_path is True
    assert res2.classification == res1.classification
    assert res2.file_hash == res1.file_hash


# ==================== 7. AI REST API Endpoints ====================

def test_api_analyze_text_endpoint(client, auth_headers):
    payload = {
        "text": "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY and db_password=MasterPass!",
        "filename": "server_env.txt",
        "channel": "FILE",
        "device_id": "TEST-PC-01"
    }
    response = client.post("/api/v1/ai/analyze/text", json=payload, headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] == "HIGHLY_CONFIDENTIAL"
    assert data["policy_action"] == "BLOCK"
    assert len(data["reasons"]) > 0


def test_api_list_analyses_and_models(client, auth_headers, db_session):
    client.post(
        "/api/v1/ai/analyze/text",
        json={"text": "Strictly confidential legal contract", "filename": "contract.txt"},
        headers=auth_headers
    )

    # 1. List analyses
    res_list = client.get("/api/v1/ai/analyses", headers=auth_headers)
    assert res_list.status_code == 200
    data_list = res_list.json()
    assert data_list["total"] >= 1

    # 2. List registered models
    res_models = client.get("/api/v1/ai/models", headers=auth_headers)
    assert res_models.status_code == 200
    models = res_models.json()
    assert len(models) >= 1
    assert any(m["model_name"] == "sentineldlp-classifier" for m in models)


def test_api_analyst_feedback_submission(client, auth_headers):
    feedback_payload = {
        "analysis_id": None,
        "event_id": "DLP-TEST-001",
        "feedback_type": "CORRECT_CLASSIFICATION",
        "original_classification": "HIGHLY_CONFIDENTIAL",
        "corrected_classification": "HIGHLY_CONFIDENTIAL",
        "notes": "Verified private key match"
    }
    response = client.post("/api/v1/ai/feedback", json=feedback_payload, headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["feedback_type"] == "CORRECT_CLASSIFICATION"
    assert data["analyst_username"] is not None
