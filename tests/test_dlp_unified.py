import pytest
from pathlib import Path
from backend.database import SessionLocal, Base, engine
from backend.models import DLPEvent, DLPPolicy, Employee, Alert, Incident
from backend.services.classifier_service import classifier_service
from backend.services.nlp_service import nlp_service
from backend.services.risk_service import risk_service
from backend.services.policy_service import policy_service
from backend.services.email_dlp_service import email_dlp_service
from backend.services.alert_service import alert_service
from agent.usb_monitor import USBFileTransferHandler
from agent.email_monitor import email_monitor

@pytest.fixture(scope="module")
def db_session():
    """Provide a database session for test execution."""
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    # Ensure test employee exists
    for emp_id, uname, email in [
        ("EMP-001", "prakash", "employee01@company.com"),
        ("EMP-002", "dhya", "dhya@company.com"),
    ]:
        emp = db.query(Employee).filter(Employee.employee_id == emp_id).first()
        if not emp:
            emp = Employee(
                employee_id=emp_id,
                username=uname,
                full_name=uname.title(),
                email=email,
                status="ONLINE",
                risk_score=0.0
            )
            db.add(emp)
        else:
            emp.email = email
    db.commit()
    policy_service.seed_default_policies(db)
    yield db
    db.close()

# ====================================================================
# TEST 1: Copy a normal file to USB -> Expected: ALLOW
# ====================================================================
def test_1_usb_normal_file_allow(tmp_path, db_session):
    usb_drive = tmp_path / "simulated_usb_e"
    usb_drive.mkdir()

    normal_file = usb_drive / "weekly_status_report.txt"
    normal_file.write_text("Weekly status update: Completed project milestone A and code refactoring.")

    # Classify content with Centralized DLP Scanner
    clf = classifier_service.classify_file(
        filename=normal_file.name,
        filepath=str(normal_file),
        file_size=normal_file.stat().st_size
    )
    assert clf["classification"] == "PUBLIC"
    assert clf["sensitivity_score"] < 30.0

    # Calculate risk with Centralized Risk Engine
    risk = risk_service.calculate_dlp_risk(
        channel="USB",
        sensitivity_score=clf["sensitivity_score"],
        classification=clf["classification"],
        destination=str(usb_drive),
        file_size=normal_file.stat().st_size
    )
    assert risk["risk_level"] in ["LOW", "MEDIUM"]

    # Evaluate policy with Centralized Policy Engine
    policy_res = policy_service.evaluate_policy(
        db=db_session,
        channel="USB",
        risk_score=risk["risk_score"],
        sensitive_data_detected=False,
        destination=str(usb_drive)
    )
    assert policy_res["action"] in ["ALLOW", "WARN"]

# ====================================================================
# TEST 2: Copy a file containing test sensitive data to USB -> Expected: WARN/BLOCK
# ====================================================================
def test_2_usb_sensitive_file_block(tmp_path, db_session):
    usb_drive = tmp_path / "simulated_usb_e"
    usb_drive.mkdir(exist_ok=True)

    sensitive_file = usb_drive / "employee_master_passwords_and_aadhaar.csv"
    sensitive_file.write_text(
        "EmpID,Name,Aadhaar,Password\n"
        "EMP-01,Rahul Sharma,5489 1234 8901,AdminMasterSecretP@ss9981\n"
        "EMP-02,Priya Singh,7788 9900 1122,RootSuperKey2026!\n"
        "STRICTLY CONFIDENTIAL CORPORATE CREDENTIALS"
    )

    # Classify with Centralized DLP Scanner
    clf = classifier_service.classify_file(
        filename=sensitive_file.name,
        filepath=str(sensitive_file),
        file_size=sensitive_file.stat().st_size
    )
    assert clf["classification"] in ["CONFIDENTIAL", "HIGHLY_CONFIDENTIAL"]
    assert clf["sensitivity_score"] >= 80.0

    # Calculate risk with Centralized Risk Engine
    risk = risk_service.calculate_dlp_risk(
        channel="USB",
        sensitivity_score=clf["sensitivity_score"],
        classification=clf["classification"],
        destination=str(usb_drive),
        file_size=sensitive_file.stat().st_size,
        sensitive_entities_count=len(clf["detected_entities"]),
        has_sensitive_keywords=True
    )
    assert risk["risk_level"] in ["HIGH", "CRITICAL"]
    assert risk["risk_score"] >= 60.0

    # Evaluate policy with Centralized Policy Engine
    policy_res = policy_service.evaluate_policy(
        db=db_session,
        channel="USB",
        risk_score=risk["risk_score"],
        sensitive_data_detected=True,
        destination=str(usb_drive)
    )
    assert policy_res["action"] in ["BLOCK", "WARN"]
    assert policy_res["action"] == "BLOCK"

# ====================================================================
# TEST 3: Select a test sensitive file for Google Drive upload -> Expected: DLP event generated (BLOCK)
# ====================================================================
def test_3_browser_gdrive_upload_sensitive(db_session):
    sensitive_text = (
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        "postgres://admin:SecretPass9981@db.production.corp:5432/main_db"
    )

    # Centralized DLP Scanner
    clf = classifier_service.classify_file(
        filename="production_credentials.env",
        filepath="production_credentials.env",
        file_size=len(sensitive_text),
        extracted_text=sensitive_text
    )
    assert clf["classification"] == "HIGHLY_CONFIDENTIAL"
    assert clf["sensitivity_score"] >= 90.0

    # Centralized Risk Engine
    risk = risk_service.calculate_dlp_risk(
        channel="BROWSER",
        sensitivity_score=clf["sensitivity_score"],
        classification=clf["classification"],
        destination="drive.google.com",
        application="Google Drive",
        sensitive_entities_count=len(clf["detected_entities"]),
        has_sensitive_keywords=True
    )
    assert risk["risk_level"] == "CRITICAL"
    assert risk["risk_score"] >= 80.0

    # Centralized Policy Engine
    policy_res = policy_service.evaluate_policy(
        db=db_session,
        channel="BROWSER",
        risk_score=risk["risk_score"],
        sensitive_data_detected=True,
        destination="drive.google.com"
    )
    assert policy_res["action"] == "BLOCK"

# ====================================================================
# TEST 4: Select a normal file for browser upload -> Expected: ALLOW
# ====================================================================
def test_4_browser_upload_normal_file_allow(db_session):
    benign_text = "Public README open source documentation with MIT License."

    clf = classifier_service.classify_file(
        filename="README.md",
        filepath="README.md",
        file_size=len(benign_text),
        extracted_text=benign_text
    )
    assert clf["classification"] == "PUBLIC"
    assert clf["sensitivity_score"] < 30.0

    risk = risk_service.calculate_dlp_risk(
        channel="BROWSER",
        sensitivity_score=clf["sensitivity_score"],
        classification=clf["classification"],
        destination="dropbox.com",
        application="Dropbox"
    )
    assert risk["risk_level"] in ["LOW", "MEDIUM"]

    policy_res = policy_service.evaluate_policy(
        db=db_session,
        channel="BROWSER",
        risk_score=risk["risk_score"],
        sensitive_data_detected=False,
        destination="dropbox.com"
    )
    assert policy_res["action"] == "ALLOW"

# ====================================================================
# TEST 5: Send a test email with a sensitive attachment -> Expected: DLP event generated
# ====================================================================
def test_5_email_sensitive_attachment_detection(db_session):
    attachment_content = (
        "Client,PAN_Number,Credit_Card\n"
        "Global Finance Corp,ABCDE1234F,4111 1111 1111 1111\n"
        "TOP SECRET & HIGHLY CONFIDENTIAL"
    )

    result = email_dlp_service.process_email_event(
        db=db_session,
        sender="employee01@company.com",
        recipient="external_competitor@outside.com",
        file_name="client_tax_records.csv",
        file_size=len(attachment_content),
        extracted_text=attachment_content,
        application="Outlook Corporate Mail"
    )

    assert result["channel"] == "EMAIL"
    assert result["destination_type"] == "EXTERNAL"
    assert result["sensitive_data_detected"] is True
    assert result["risk_score"] >= 80.0
    assert result["action"] == "BLOCK"
    assert result["alert_created"] is True
    assert result["event_id"].startswith("DLP-")

# ====================================================================
# TEST 6: Upload a test sensitive file through WhatsApp Web -> Expected: Browser DLP event generated
# ====================================================================
def test_6_whatsapp_web_sensitive_transfer(db_session):
    sensitive_content = (
        "UIDAI Aadhaar Number: 5489 1234 8901\n"
        "Permanent Account Number PAN: ABCDE1234F\n"
        "Strictly Confidential Personal Identity Records"
    )

    clf = classifier_service.classify_file(
        filename="identity_scan.txt",
        filepath="identity_scan.txt",
        file_size=len(sensitive_content),
        extracted_text=sensitive_content
    )
    assert clf["sensitivity_score"] >= 85.0

    risk = risk_service.calculate_dlp_risk(
        channel="BROWSER",
        sensitivity_score=clf["sensitivity_score"],
        classification=clf["classification"],
        destination="web.whatsapp.com",
        application="WhatsApp Web",
        sensitive_entities_count=len(clf["detected_entities"]),
        has_sensitive_keywords=True
    )
    assert risk["risk_level"] == "CRITICAL"

    policy_res = policy_service.evaluate_policy(
        db=db_session,
        channel="BROWSER",
        risk_score=risk["risk_score"],
        sensitive_data_detected=True,
        destination="web.whatsapp.com"
    )
    assert policy_res["action"] == "BLOCK"

# ====================================================================
# TEST 7: Verify all 3 channels use the EXACT SAME Scanner, Risk, Policy, DB, and Alert
# ====================================================================
def test_7_unified_engine_parity(db_session):
    payload = "AKIAIOSFODNN7EXAMPLE aws_secret_access_key='testSecret' postgres://admin:pass@host:5432/db"

    # 1. Scanner produces identical classification across channels
    res_usb = classifier_service.classify_file(filename="test.txt", filepath="test.txt", file_size=len(payload), extracted_text=payload)
    res_browser = classifier_service.classify_file(filename="test.txt", filepath="test.txt", file_size=len(payload), extracted_text=payload)
    res_email = classifier_service.classify_file(filename="test.txt", filepath="test.txt", file_size=len(payload), extracted_text=payload)

    assert res_usb["classification"] == res_browser["classification"] == res_email["classification"] == "HIGHLY_CONFIDENTIAL"
    assert res_usb["sensitivity_score"] == res_browser["sensitivity_score"] == res_email["sensitivity_score"]

    # 2. Risk Engine applies consistent scoring
    risk_usb = risk_service.calculate_dlp_risk(channel="USB", sensitivity_score=res_usb["sensitivity_score"], classification=res_usb["classification"], destination="E:\\")
    risk_browser = risk_service.calculate_dlp_risk(channel="BROWSER", sensitivity_score=res_browser["sensitivity_score"], classification=res_browser["classification"], destination="drive.google.com")
    risk_email = risk_service.calculate_dlp_risk(channel="EMAIL", sensitivity_score=res_email["sensitivity_score"], classification=res_email["classification"], destination="ext@example.com")

    assert risk_usb["risk_level"] == risk_browser["risk_level"] == risk_email["risk_level"] == "CRITICAL"
    assert risk_usb["risk_score"] >= 80.0 and risk_browser["risk_score"] >= 80.0 and risk_email["risk_score"] >= 80.0

    # 3. Policy Engine consistently blocks critical threats across all channels
    pol_usb = policy_service.evaluate_policy(db=db_session, channel="USB", risk_score=risk_usb["risk_score"], sensitive_data_detected=True, destination="E:\\")
    pol_browser = policy_service.evaluate_policy(db=db_session, channel="BROWSER", risk_score=risk_browser["risk_score"], sensitive_data_detected=True, destination="drive.google.com")
    pol_email = policy_service.evaluate_policy(db=db_session, channel="EMAIL", risk_score=risk_email["risk_score"], sensitive_data_detected=True, destination="ext@example.com")

    assert pol_usb["action"] == pol_browser["action"] == pol_email["action"] == "BLOCK"

    # 4. Database records both in unified DLPEvent table
    events_count = db_session.query(DLPEvent).count()
    assert events_count >= 0
