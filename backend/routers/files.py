import os
import shutil
from pathlib import Path
from typing import List, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Form, Query
from sqlalchemy.orm import Session
from backend.database import get_db
from backend.models import FileRecord, Employee, User
from backend.schemas import (
    FileRecordResponse, FileScanRequest, FileScanResponse,
    FileBulkDeleteRequest, FileBulkDeleteResponse
)
from backend.services.file_analysis_service import file_analysis_service
from backend.services.classifier_service import classifier_service
from backend.services.risk_service import risk_service
from backend.services.alert_service import alert_service
from backend.utils.helpers import compute_file_hash, get_logger
from backend.config import settings
from backend.dependencies import get_current_user_or_agent, require_analyst_or_admin

logger = get_logger("SentinelDLP.FilesRouter")
router = APIRouter(prefix="/files", tags=["File Inspection & DLP"])

@router.get("", response_model=List[FileRecordResponse])
def list_files(
    employee_id: Optional[str] = Query(None),
    classification: Optional[str] = Query(None),
    min_sensitivity: Optional[float] = Query(None, ge=0.0, le=100.0),
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    auth_caller: Optional[User] = Depends(get_current_user_or_agent)
):
    """List indexed file records with optional filtering."""
    query = db.query(FileRecord)
    if employee_id:
        query = query.filter(FileRecord.employee_id == employee_id)
    if classification:
        query = query.filter(FileRecord.classification == classification.upper())
    if min_sensitivity is not None:
        query = query.filter(FileRecord.sensitivity >= min_sensitivity)

    files = query.order_by(FileRecord.sensitivity.desc()).offset(skip).limit(limit).all()
    return files

@router.post("/scan", response_model=FileScanResponse)
def scan_file_on_disk(
    scan_req: FileScanRequest,
    db: Session = Depends(get_db),
    auth_caller: Optional[User] = Depends(get_current_user_or_agent)
):
    """Deep inspect an existing file on the filesystem and index classification results."""
    filepath = Path(scan_req.filepath)
    if not filepath.exists() or not filepath.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"File not found on filesystem: {scan_req.filepath}"
        )

    file_size = filepath.stat().st_size
    file_hash = compute_file_hash(filepath)
    ext = filepath.suffix.lower()

    # 1. Text extraction
    extracted_text, method = file_analysis_service.extract_text_from_file(filepath)

    # 2. Classification & Entity detection
    clf_result = classifier_service.classify_file(
        filename=filepath.name,
        filepath=str(filepath),
        file_size=file_size,
        extracted_text=extracted_text,
        file_hash=file_hash
    )

    classification = clf_result["classification"]
    sensitivity_score = clf_result["sensitivity_score"]
    detected_entities = clf_result["detected_entities"]
    confidence = clf_result["confidence"]

    # 3. Calculate Risk
    risk_info = risk_service.calculate_event_risk(
        activity_type=scan_req.action_type,
        sensitivity_score=sensitivity_score,
        classification=classification
    )
    risk_score = risk_info["risk_score"]
    risk_level = risk_info["risk_level"]

    # 4. Ensure Employee exists before inserting FileRecord (Prevents SQLite Foreign Key error)
    emp = db.query(Employee).filter(Employee.employee_id == scan_req.employee_id).first()
    if not emp:
        emp = Employee(
            employee_id=scan_req.employee_id,
            username=scan_req.employee_id,
            hostname="WORKSTATION",
            status="ONLINE",
            risk_score=0.0
        )
        db.add(emp)
        db.commit()

    # 5. Upsert FileRecord in Database
    file_record = db.query(FileRecord).filter(
        (FileRecord.filepath == str(filepath)) & (FileRecord.employee_id == scan_req.employee_id)
    ).first()

    if file_record:
        file_record.file_size = file_size
        file_record.hash = file_hash
        file_record.classification = classification
        file_record.sensitivity = sensitivity_score
        file_record.modified_at = datetime.now(timezone.utc)
    else:
        file_record = FileRecord(
            employee_id=scan_req.employee_id,
            filename=filepath.name,
            filepath=str(filepath),
            extension=ext,
            file_size=file_size,
            hash=file_hash,
            classification=classification,
            sensitivity=sensitivity_score,
            created_at=datetime.now(timezone.utc)
        )
        db.add(file_record)

    db.commit()
    db.refresh(file_record)

    # 5. Generate Alert if sensitive or high risk
    alert_created = False
    alert_id = None
    if risk_score >= 30.0 or classification in ["CONFIDENTIAL", "HIGHLY_CONFIDENTIAL"]:
        doc_type = clf_result.get("document_type")
        doc_prefix = f"Image identified as '{doc_type}' ('{filepath.name}')" if doc_type else f"File '{filepath.name}'"
        desc = (
            f"{doc_prefix} scanned on endpoint '{scan_req.employee_id}'. "
            f"Classification: {classification} (Score: {sensitivity_score}/100, Confidence: {int(confidence*100)}%). "
            f"Detected {len(detected_entities)} sensitive entity types."
        )
        new_alert = alert_service.process_and_create_alert(
            db=db,
            employee_id=scan_req.employee_id,
            alert_type="SENSITIVE_FILE_DISCOVERED",
            description=desc,
            source="FILE_SCANNER",
            file_id=file_record.id,
            risk_score=risk_score,
            severity=risk_level
        )
        alert_created = True
        alert_id = new_alert.id

    return FileScanResponse(
        filename=filepath.name,
        filepath=str(filepath),
        extension=ext,
        file_size=file_size,
        hash=file_hash,
        classification=classification,
        confidence=confidence,
        detected_entities=detected_entities,
        sensitivity_score=sensitivity_score,
        risk_score=risk_score,
        risk_level=risk_level,
        alert_created=alert_created,
        alert_id=alert_id
    )

@router.post("/upload-scan", response_model=FileScanResponse)
async def upload_and_scan_file(
    file: UploadFile = File(...),
    employee_id: str = Form(...),
    db: Session = Depends(get_db),
    auth_caller: Optional[User] = Depends(get_current_user_or_agent)
):
    """Directly upload a file to the DLP server for instant text extraction, OCR, and classification."""
    upload_dir = Path(settings.UPLOAD_PATH) / employee_id
    upload_dir.mkdir(parents=True, exist_ok=True)
    destination_path = upload_dir / file.filename

    # Save uploaded file safely
    with open(destination_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    scan_req = FileScanRequest(
        filepath=str(destination_path),
        employee_id=employee_id,
        action_type="UPLOAD_SCAN"
    )
    return scan_file_on_disk(scan_req=scan_req, db=db, auth_caller=auth_caller)

@router.post("/bulk-delete", response_model=FileBulkDeleteResponse)
def bulk_delete_files(
    req: FileBulkDeleteRequest,
    db: Session = Depends(get_db),
    auth_caller: Optional[User] = Depends(get_current_user_or_agent)
):
    """Bulk delete indexed file records."""
    if not req.file_ids:
        return FileBulkDeleteResponse(message="No file IDs specified", deleted_count=0, deleted_ids=[])

    deleted_ids = []
    for fid in req.file_ids:
        rec = db.query(FileRecord).filter(FileRecord.id == fid).first()
        if rec:
            db.delete(rec)
            deleted_ids.append(fid)

    db.commit()
    return FileBulkDeleteResponse(
        message=f"Successfully deleted {len(deleted_ids)} file record(s)",
        deleted_count=len(deleted_ids),
        deleted_ids=deleted_ids
    )

@router.delete("/clear-all", status_code=status.HTTP_200_OK)
def clear_all_files(
    db: Session = Depends(get_db),
    auth_caller: Optional[User] = Depends(get_current_user_or_agent)
):
    """Purge all indexed file records from database."""
    deleted_count = db.query(FileRecord).delete()
    db.commit()
    return {"message": "All file records removed", "files_removed": deleted_count}

@router.delete("/{file_id}", status_code=status.HTTP_200_OK)
def delete_file_record(
    file_id: int,
    db: Session = Depends(get_db),
    auth_caller: Optional[User] = Depends(get_current_user_or_agent)
):
    """Delete a specific file record."""
    rec = db.query(FileRecord).filter(FileRecord.id == file_id).first()
    if not rec:
        raise HTTPException(status_code=404, detail="File record not found")
    db.delete(rec)
    db.commit()
    return {"message": f"File record #{file_id} deleted successfully"}

