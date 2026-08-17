import shutil
import pytest
from pathlib import Path
from PIL import Image, ImageDraw
import tempfile
from backend.services.nlp_service import nlp_service
from backend.services.classifier_service import classifier_service
from backend.utils.helpers import compute_file_hash

def test_nlp_aws_key_detection():
    sample = "Exporting AWS credentials: AKIAIOSFODNN7EXAMPLE for deployment"
    entities, score, classification = nlp_service.scan_text(sample)
    assert any(e["entity_type"] == "AWS_ACCESS_KEY" for e in entities)
    assert classification == "HIGHLY_CONFIDENTIAL"
    assert score >= 90.0

def test_nlp_credit_card_luhn():
    valid_card = "Customer payment: 4111 1111 1111 1111 on transaction"
    invalid_card = "Some numbers: 4111 1111 1111 1112 in text"
    
    entities_val, _, _ = nlp_service.scan_text(valid_card)
    assert any(e["entity_type"] == "CREDIT_CARD_NUMBER" for e in entities_val)

    entities_inval, _, _ = nlp_service.scan_text(invalid_card)
    assert not any(e["entity_type"] == "CREDIT_CARD_NUMBER" for e in entities_inval)

def test_nlp_aadhaar_card_detection():
    sample1 = "UIDAI Govt of India Aadhaar Number: 5489 1234 8901"
    entities1, score1, class1 = nlp_service.scan_text(sample1)
    assert any(e["entity_type"] == "AADHAAR_NUMBER" for e in entities1)
    assert class1 == "HIGHLY_CONFIDENTIAL"
    assert score1 >= 90.0

def test_nlp_pan_card_detection():
    sample = "Income Tax Department PAN Card Number: ABCDE1234F"
    entities, score, classification = nlp_service.scan_text(sample)
    assert any(e["entity_type"] == "PAN_CARD_NUMBER" for e in entities)
    assert classification == "HIGHLY_CONFIDENTIAL"
    assert score >= 90.0

def test_nlp_employee_salary_details():
    sample = "Employee Name: John Doe | Employee ID: EMP-2026-9901 | Monthly Salary: ₹125,000 | CTC: 1500000"
    entities, score, classification = nlp_service.scan_text(sample)
    assert any(e["entity_type"] in ["EMPLOYEE_SALARY_RECORD", "EMPLOYEE_ID_RECORD"] for e in entities)
    assert classification in ["CONFIDENTIAL", "HIGHLY_CONFIDENTIAL"]
    assert score >= 75.0

def test_nlp_company_credentials():
    sample = "postgres://admin_user:SuperSecretPassword9981!@db.internal.corp:5432/production"
    entities, score, classification = nlp_service.scan_text(sample)
    assert any(e["entity_type"] == "DB_CONNECTION_STRING" for e in entities)
    assert classification == "HIGHLY_CONFIDENTIAL"
    assert score >= 95.0

def test_classifier_service_public_file():
    result = classifier_service.classify_file(
        filename="readme.txt",
        filepath="/home/user/readme.txt",
        file_size=500,
        extracted_text="This is a public open source project documentation."
    )
    assert result["classification"] == "PUBLIC"
    assert result["sensitivity_score"] < 30.0

def test_classifier_service_confidential_file():
    result = classifier_service.classify_file(
        filename="company_financial_strategy.docx",
        filepath="/home/user/company_financial_strategy.docx",
        file_size=24000,
        extracted_text="TOP SECRET: Strictly Confidential Q3 financial roadmap and payroll numbers."
    )
    assert result["classification"] in ["CONFIDENTIAL", "HIGHLY_CONFIDENTIAL"]
    assert result["sensitivity_score"] >= 70.0

def test_classifier_generic_whatsapp_image_document_recognition():
    img = Image.new('RGB', (750, 300), color=(255, 255, 255))
    d = ImageDraw.Draw(img)
    d.text((30, 30), 'GOVT OF INDIA UNIQUE IDENTIFICATION AUTHORITY', fill=(0, 0, 0))
    d.text((30, 70), 'Name: Rahul Sharma', fill=(0, 0, 0))
    d.text((30, 110), '5489 1234 8901', fill=(0, 0, 0))
    d.text((30, 150), 'Mera Aadhaar Meri Pehchan', fill=(0, 0, 0))

    tmp_path = Path(tempfile.gettempdir()) / "WhatsApp Image 2026-07-13 at 8.45.37 AM.jpeg"
    img.save(tmp_path)

    result = classifier_service.classify_file(
        filename="WhatsApp Image 2026-07-13 at 8.45.37 AM.jpeg",
        filepath=str(tmp_path),
        file_size=tmp_path.stat().st_size,
        extracted_text=""
    )
    assert result["classification"] == "HIGHLY_CONFIDENTIAL"
    assert result["sensitivity_score"] >= 90.0
    assert result["document_type"] == "Aadhaar Card (National ID)"

# ==================== STEP 3 REGRESSION TESTS ====================

def test_rename_does_not_bypass_detection(tmp_path):
    """
    1. Create a synthetic test image containing fake Aadhaar-formatted text, save as 'aadhar_sample.jpg'.
    2. Classify it, assert it's flagged sensitive.
    3. Copy the SAME file, rename it to 'vacation_photo.jpg'.
    4. Classify the renamed copy, assert it is STILL flagged sensitive with the same confidence.
    """
    img = Image.new('RGB', (800, 350), color=(255, 255, 255))
    d = ImageDraw.Draw(img)
    d.text((40, 30), 'GOVT OF INDIA UNIQUE IDENTIFICATION AUTHORITY', fill=(0, 0, 0))
    d.text((40, 75), 'Name: Anjali Verma', fill=(0, 0, 0))
    d.text((40, 120), '8899 4433 2211', fill=(0, 0, 0))
    d.text((40, 165), 'Mera Aadhaar Meri Pehchan', fill=(0, 0, 0))

    file1 = tmp_path / "aadhar_sample.jpg"
    img.save(file1)

    result1 = classifier_service.classify_file(
        filename="aadhar_sample.jpg",
        filepath=str(file1),
        file_size=file1.stat().st_size,
        extracted_text=""
    )
    assert result1["classification"] == "HIGHLY_CONFIDENTIAL"
    assert result1["sensitivity_score"] >= 90.0
    assert result1["document_type"] == "Aadhaar Card (National ID)"

    # Copy to vacation_photo.jpg (exact same byte content)
    file2 = tmp_path / "vacation_photo.jpg"
    shutil.copyfile(file1, file2)

    result2 = classifier_service.classify_file(
        filename="vacation_photo.jpg",
        filepath=str(file2),
        file_size=file2.stat().st_size,
        extracted_text=""
    )
    assert result2["classification"] == "HIGHLY_CONFIDENTIAL"
    assert result2["sensitivity_score"] == result1["sensitivity_score"]
    assert result2["confidence"] == result1["confidence"]
    assert result2["document_type"] == result1["document_type"]

def test_same_name_different_content_not_confused(tmp_path):
    """
    1. Create two DIFFERENT synthetic files (one with fake PII content, one with clean/non-sensitive content),
       both saved with the exact same filename 'sample.jpg' in different folders.
    2. Classify both, assert they get DIFFERENT classification results matching their actual content.
    """
    dir1 = tmp_path / "folder_sensitive"
    dir2 = tmp_path / "folder_clean"
    dir1.mkdir()
    dir2.mkdir()

    # Sensitive image: Fake Aadhaar card
    img_sensitive = Image.new('RGB', (800, 350), color=(255, 255, 255))
    d1 = ImageDraw.Draw(img_sensitive)
    d1.text((40, 30), 'GOVT OF INDIA UNIQUE IDENTIFICATION AUTHORITY', fill=(0, 0, 0))
    d1.text((40, 75), 'Name: Vikram Singh', fill=(0, 0, 0))
    d1.text((40, 120), '9900 1122 3344', fill=(0, 0, 0))
    d1.text((40, 165), 'Mera Aadhaar Meri Pehchan', fill=(0, 0, 0))
    file_sensitive = dir1 / "sample.jpg"
    img_sensitive.save(file_sensitive)

    # Clean image: Meeting notes placeholder
    img_clean = Image.new('RGB', (800, 350), color=(255, 255, 255))
    d2 = ImageDraw.Draw(img_clean)
    d2.text((40, 30), 'Weekly Team Sync Meeting Agenda and Discussion Notes', fill=(0, 0, 0))
    d2.text((40, 75), 'Project roadmap timeline review and milestone tracking', fill=(0, 0, 0))
    d2.text((40, 120), 'Open Source Documentation Guidelines and Best Practices', fill=(0, 0, 0))
    file_clean = dir2 / "sample.jpg"
    img_clean.save(file_clean)

    result_sensitive = classifier_service.classify_file(
        filename="sample.jpg",
        filepath=str(file_sensitive),
        file_size=file_sensitive.stat().st_size,
        extracted_text=""
    )

    result_clean = classifier_service.classify_file(
        filename="sample.jpg",
        filepath=str(file_clean),
        file_size=file_clean.stat().st_size,
        extracted_text=""
    )

    assert result_sensitive["classification"] == "HIGHLY_CONFIDENTIAL"
    assert result_sensitive["sensitivity_score"] >= 90.0

    assert result_clean["classification"] == "PUBLIC"
    assert result_clean["sensitivity_score"] < 30.0

    assert result_sensitive["classification"] != result_clean["classification"]

def test_ocr_failure_does_not_default_to_safe(tmp_path):
    """
    Feed a blank/unreadable image file through the pipeline.
    Assert the result is 'Unknown/Unclassified' with a logged warning, NOT silently classified as safe/public.
    """
    blank_img = Image.new('RGB', (50, 50), color=(0, 0, 0))
    blank_file = tmp_path / "blank_unreadable.jpg"
    blank_img.save(blank_file)

    result = classifier_service.classify_file(
        filename="blank_unreadable.jpg",
        filepath=str(blank_file),
        file_size=blank_file.stat().st_size,
        extracted_text=""
    )

    assert result["classification"] == "Unknown/Unclassified"
    assert result["classification"] != "PUBLIC"
    assert result["classification"] != "SAFE"
    assert "OCR" in result["indicators"][0] or "Unclassified" in result["indicators"][0]

def test_hash_cache_keyed_by_content_only(tmp_path):
    """
    Directly unit test the cache lookup function:
    - Same bytes, two different filenames -> same cache key.
    - Different bytes, same filename -> different cache keys.
    """
    dir_a = tmp_path / "dir_a"
    dir_b = tmp_path / "dir_b"
    dir_a.mkdir()
    dir_b.mkdir()

    content_x = b"TOP SECRET MASTER DATABASE CREDENTIALS postgres://admin:P@ss123@db:5432/db"
    content_y = b"Public Open Source Readme File with Community Guidelines"

    file_a = dir_a / "file_one.txt"
    file_b = dir_b / "file_two_renamed.txt"
    file_c = dir_b / "file_one.txt"

    file_a.write_bytes(content_x)
    file_b.write_bytes(content_x)  # Identical content to file_a, different filename
    file_c.write_bytes(content_y)  # Different content from file_a, same filename

    hash_a = compute_file_hash(file_a)
    hash_b = compute_file_hash(file_b)
    hash_c = compute_file_hash(file_c)

    # 1. Byte hash equality
    assert hash_a == hash_b
    assert hash_a != hash_c

    # 2. Classifier cache behavior
    classifier_service.clear_cache()
    
    # Classify file_a (populates cache for hash_a)
    res_a = classifier_service.classify_file(
        filename=file_a.name,
        filepath=str(file_a),
        file_size=len(content_x),
        extracted_text=content_x.decode()
    )
    assert classifier_service.get_cached_classification(hash_a) is not None

    # Classify file_b with different name but same bytes -> cache hit
    res_b = classifier_service.classify_file(
        filename=file_b.name,
        filepath=str(file_b),
        file_size=len(content_x),
        extracted_text=""
    )
    assert res_b["classification"] == res_a["classification"]
    assert res_b["sensitivity_score"] == res_a["sensitivity_score"]

    # Classify file_c with same name as file_a but different bytes -> different classification & cache entry
    res_c = classifier_service.classify_file(
        filename=file_c.name,
        filepath=str(file_c),
        file_size=len(content_y),
        extracted_text=content_y.decode()
    )
    assert res_c["classification"] != res_a["classification"]
    assert res_c["classification"] == "PUBLIC"
    assert classifier_service.get_cached_classification(hash_c) is not None
    assert classifier_service.get_cached_classification(hash_c) != classifier_service.get_cached_classification(hash_a)

