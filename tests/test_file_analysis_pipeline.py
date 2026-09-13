import io
import os
import json
import base64
import pytest
from pathlib import Path
from fastapi.testclient import TestClient

from backend.main import app, init_database
from backend.database import SessionLocal, get_db
from backend.models import DLPEvent, DLPAnalysis, Employee, User
from backend.services.file_analysis_service import file_analysis_service, MAX_ANALYSIS_FILE_SIZE
from backend.ai.pipeline import dlp_pipeline, DLPAnalysisResult
from backend.ai.entity_detector import entity_detector
from backend.ai.ocr_engine import ocr_engine

TEST_DATA_DIR = Path(__file__).parent / "test_data"


@pytest.fixture(scope="module")
def client():
    init_database()
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def auth_headers(client):
    init_database()
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


# ==========================================
# 1. Plain Text Clean File Analysis
# ==========================================
def test_1_clean_text_analysis(db_session, auth_headers):
    clean_path = TEST_DATA_DIR / "clean.txt"
    with open(clean_path, "rb") as f:
        clean_bytes = f.read()

    res = dlp_pipeline.analyze_payload(
        db=db_session,
        content_bytes=clean_bytes,
        filename="clean.txt",
        channel="FILE",
        destination="Local Storage",
        employee_id="EMP-TEST-01"
    )

    assert res.classification == "PUBLIC"
    assert res.risk_level == "LOW"
    assert res.policy_action == "ALLOW"
    assert len(res.entities) == 0


# ==========================================
# 2. Confidential Text File Analysis
# ==========================================
def test_2_confidential_text_analysis(db_session, auth_headers):
    conf_path = TEST_DATA_DIR / "confidential.txt"
    with open(conf_path, "rb") as f:
        conf_bytes = f.read()

    res = dlp_pipeline.analyze_payload(
        db=db_session,
        content_bytes=conf_bytes,
        filename="confidential.txt",
        channel="FILE",
        destination="External Drive",
        employee_id="EMP-TEST-01"
    )

    assert res.classification in ("CONFIDENTIAL", "RESTRICTED")
    assert res.risk_score >= 35.0
    assert res.policy_action in ("WARN", "BLOCK")


# ==========================================
# 3. Excel Spreadsheet (XLSX) Content Inspection
# ==========================================
def test_3_xlsx_spreadsheet_analysis(db_session, auth_headers):
    xlsx_path = TEST_DATA_DIR / "employee_data.xlsx"
    with open(xlsx_path, "rb") as f:
        xlsx_bytes = f.read()

    text, method, meta = file_analysis_service.extract_text_from_bytes(xlsx_bytes, filename="employee_data.xlsx")
    assert method == "OPENPYXL"
    assert "Salary" in text or "EMP-" in text or "alice.smith" in text

    res = dlp_pipeline.analyze_payload(
        db=db_session,
        content_bytes=xlsx_bytes,
        filename="employee_data.xlsx",
        channel="BROWSER",
        destination="drive.google.com",
        employee_id="EMP-TEST-01"
    )

    assert res.classification in ("CONFIDENTIAL", "RESTRICTED", "HIGHLY_CONFIDENTIAL")
    assert res.sensitivity_score >= 30.0
    assert len(res.entities) > 0
    assert res.policy_action in ("WARN", "BLOCK")


# ==========================================
# 4. CSV Document Analysis
# ==========================================
def test_4_csv_structured_data_analysis(db_session, auth_headers):
    csv_path = TEST_DATA_DIR / "sample.csv"
    with open(csv_path, "rb") as f:
        csv_bytes = f.read()

    res = dlp_pipeline.analyze_payload(
        db=db_session,
        content_bytes=csv_bytes,
        filename="sample.csv",
        channel="BROWSER",
        destination="mail.google.com",
        employee_id="EMP-TEST-01"
    )

    assert len(res.entities) > 0
    assert res.risk_score >= 50.0
    assert res.policy_action in ("WARN", "BLOCK")


# ==========================================
# 5. DOCX Word Document Analysis
# ==========================================
def test_5_docx_document_analysis(db_session, auth_headers):
    docx_path = TEST_DATA_DIR / "sample.docx"
    with open(docx_path, "rb") as f:
        docx_bytes = f.read()

    text, method, meta = file_analysis_service.extract_text_from_bytes(docx_bytes, filename="sample.docx")
    assert method == "DOCX"
    assert "Confidential" in text or "Salary" in text or "EMP-99881" in text

    res = dlp_pipeline.analyze_payload(
        db=db_session,
        content_bytes=docx_bytes,
        filename="sample.docx",
        channel="FILE",
        destination="Local",
        employee_id="EMP-TEST-01"
    )

    assert res.classification in ("CONFIDENTIAL", "RESTRICTED")
    assert res.sensitivity_score >= 30.0


# ==========================================
# 6. JSON Configuration & API Keys Analysis
# ==========================================
def test_6_json_configuration_secrets_analysis(db_session, auth_headers):
    json_path = TEST_DATA_DIR / "sample.json"
    with open(json_path, "rb") as f:
        json_bytes = f.read()

    res = dlp_pipeline.analyze_payload(
        db=db_session,
        content_bytes=json_bytes,
        filename="sample.json",
        channel="BROWSER",
        destination="pastebin.com",
        employee_id="EMP-TEST-01"
    )

    assert res.classification in ("HIGHLY_CONFIDENTIAL", "RESTRICTED")
    assert res.risk_level in ("HIGH", "CRITICAL")
    assert res.policy_action == "BLOCK"


# ==========================================
# 7. Image File OCR Analysis
# ==========================================
def test_7_image_ocr_analysis(db_session, auth_headers):
    img_path = TEST_DATA_DIR / "image_sensitive.png"
    with open(img_path, "rb") as f:
        img_bytes = f.read()

    res = dlp_pipeline.analyze_payload(
        db=db_session,
        content_bytes=img_bytes,
        filename="image_sensitive.png",
        channel="BROWSER",
        destination="mail.google.com",
        employee_id="EMP-TEST-01"
    )

    assert res.ocr_used is True
    assert res.classification in ("RESTRICTED", "HIGHLY_CONFIDENTIAL", "CONFIDENTIAL")
    assert res.risk_score >= 60.0
    assert res.policy_action in ("WARN", "BLOCK")


# ==========================================
# 8. Scanned PDF Document Analysis
# ==========================================
def test_8_scanned_pdf_ocr_analysis(db_session, auth_headers):
    pdf_path = TEST_DATA_DIR / "scanned_sample.pdf"
    with open(pdf_path, "rb") as f:
        pdf_bytes = f.read()

    text, method, meta = file_analysis_service.extract_text_from_bytes(pdf_bytes, filename="scanned_sample.pdf")
    assert meta.get("pages_processed", 0) >= 1

    res = dlp_pipeline.analyze_payload(
        db=db_session,
        content_bytes=pdf_bytes,
        filename="scanned_sample.pdf",
        channel="USB",
        destination="/media/usb_drive",
        employee_id="EMP-TEST-01"
    )

    assert res.risk_score >= 60.0
    assert res.policy_action == "BLOCK"


# ==========================================
# 9. Credentials & Secrets Leak Test
# ==========================================
def test_9_credential_leak_detection(db_session, auth_headers):
    cred_path = TEST_DATA_DIR / "credential_test.txt"
    with open(cred_path, "rb") as f:
        cred_bytes = f.read()

    res = dlp_pipeline.analyze_payload(
        db=db_session,
        content_bytes=cred_bytes,
        filename="credential_test.txt",
        channel="BROWSER",
        destination="mail.google.com",
        employee_id="EMP-TEST-01"
    )

    assert res.classification == "HIGHLY_CONFIDENTIAL"
    assert res.risk_level == "CRITICAL"
    assert res.policy_action == "BLOCK"
    assert any(e["category"] == "CREDENTIALS" for e in res.entities)


# ==========================================
# 10. Browser File Upload Interception Pipeline API
# ==========================================
def test_10_browser_upload_interception_api(client, db_session, auth_headers):
    img_path = TEST_DATA_DIR / "image_sensitive.png"
    with open(img_path, "rb") as f:
        b64_content = base64.b64encode(f.read()).decode("utf-8")

    payload = {
        "channel": "BROWSER",
        "application": "Gmail Webmail",
        "domain": "mail.google.com",
        "file_name": "synthetic_id_card.png",
        "file_size": 25000,
        "file_content_base64": b64_content,
        "employee_id": "EMP-BROWSER-TEST",
        "device_id": "DESKTOP-TEST"
    }

    res = client.post("/api/v1/dlp/browser-event", json=payload, headers=auth_headers)
    assert res.status_code == 200
    data = res.json()

    assert data["channel"] == "BROWSER"
    assert data["classification"] in ("RESTRICTED", "HIGHLY_CONFIDENTIAL", "CONFIDENTIAL")
    assert data["risk_score"] >= 75.0
    assert data["action"] == "BLOCK"
    assert data["ocr"]["used"] is True
    assert data["status"] == "BLOCKED"


# ==========================================
# 11. SHA-256 Hash Caching Performance & Invalidation
# ==========================================
def test_11_sha256_hash_cache(db_session, auth_headers):
    sample_bytes = b"Cache test content for SHA256 evaluation: EMP-99182, Salary: $120,000"
    
    # 1. First execution (Slow-path)
    res1 = dlp_pipeline.analyze_payload(
        db=db_session,
        content_bytes=sample_bytes,
        filename="sample_v1.txt",
        employee_id="EMP-TEST-01"
    )
    assert res1.fast_path is False

    # 2. Second execution with same content bytes but different filename (Fast-path hit)
    res2 = dlp_pipeline.analyze_payload(
        db=db_session,
        content_bytes=sample_bytes,
        filename="renamed_sample.txt",
        employee_id="EMP-TEST-01"
    )
    assert res2.fast_path is True
    assert res2.file_hash == res1.file_hash
    assert res2.classification == res1.classification

    # 3. Third execution with modified content bytes (Cache Miss -> Fresh Analysis)
    modified_bytes = sample_bytes + b" - modified with additional context"
    res3 = dlp_pipeline.analyze_payload(
        db=db_session,
        content_bytes=modified_bytes,
        filename="sample_v1.txt",
        employee_id="EMP-TEST-01"
    )
    assert res3.fast_path is False
    assert res3.file_hash != res1.file_hash


# ==========================================
# 12. Large File Safety Limit (50MB)
# ==========================================
def test_12_large_file_size_limit_handling():
    oversized_bytes = b"0" * (MAX_ANALYSIS_FILE_SIZE + 1024)
    text, method, meta = file_analysis_service.extract_text_from_bytes(oversized_bytes, filename="large_dump.dat")
    assert method == "CONTENT_ANALYSIS_LIMIT_EXCEEDED"
    assert text == ""


# ==========================================
# 13. Policy Decision Waits for Content Analysis
# ==========================================
def test_13_policy_decision_waits_for_content(client, db_session, auth_headers):
    # A generic filename 'document.txt' with sensitive content must not default to ALLOW/LOW
    sensitive_bytes = b"Confidential API keys: AKIAIOSFODNN7EXAMPLE and private password: SuperSecretPassword123!"
    
    payload = {
        "channel": "BROWSER",
        "application": "Google Drive",
        "destination": "drive.google.com",
        "file_name": "document.txt",
        "file_size": len(sensitive_bytes),
        "file_content_base64": base64.b64encode(sensitive_bytes).decode("utf-8"),
        "employee_id": "EMP-001"
    }

    res = client.post("/api/v1/dlp/scan", json=payload, headers=auth_headers)
    assert res.status_code == 200
    data = res.json()

    assert data["classification"] in ("HIGHLY_CONFIDENTIAL", "RESTRICTED")
    assert data["risk_score"] >= 80.0
    assert data["action"] == "BLOCK"
    assert data["sensitive_data_detected"] is True


# ==========================================
# 14. Rich Detection Details Formatting
# ==========================================
def test_14_detection_details_formatting(client, db_session, auth_headers):
    # Ingest event and verify DLPEvent.details contains structured markers
    sensitive_bytes = b"Employee Record: EMP-10294, Name: John Smith, DOB: 12/04/1985, Salary: $135,000"
    payload = {
        "channel": "USB",
        "application": "USB Storage",
        "destination": "/media/usb",
        "file_name": "employee_roster.txt",
        "file_size": len(sensitive_bytes),
        "file_content_base64": base64.b64encode(sensitive_bytes).decode("utf-8"),
        "employee_id": "EMP-001"
    }

    res = client.post("/api/v1/dlp/scan", json=payload, headers=auth_headers)
    assert res.status_code == 200
    data = res.json()

    # Query event from DB
    event = db_session.query(DLPEvent).filter(DLPEvent.event_id == data["event_id"]).first()
    assert event is not None
    assert "OCR:" in event.details
    assert "NLP:" in event.details
    assert "ML:" in event.details
    assert "Risk:" in event.details
    assert "Policy:" in event.details
