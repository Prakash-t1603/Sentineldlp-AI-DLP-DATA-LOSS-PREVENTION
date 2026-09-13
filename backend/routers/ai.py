"""
SentinelDLP - AI & Machine Learning Intelligence API Router
Endpoints for real-time text & document DLP inspection, SOC analyst feedback,
model metadata registry, and AI engine telemetry.
"""

import json
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Form, Query
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models import DLPAnalysis, SensitiveEntityRecord, AIClassificationRecord, ModelMetadata, AnalystFeedback, User
from backend.schemas import (
    DLPAnalysisRequest, DLPAnalysisResponse, DLPAnalysisListResponse,
    AnalystFeedbackCreate, AnalystFeedbackResponse, ModelMetadataResponse
)
from backend.dependencies import get_current_user, require_analyst_or_admin
from backend.ai.pipeline import dlp_pipeline, DLPAnalysisResult
from backend.ai.model_manager import model_manager
from backend.services.file_analysis_service import file_analysis_service

router = APIRouter(prefix="/ai", tags=["AI & Machine Learning Intelligence"])


def _format_analysis_response(rec: DLPAnalysis) -> DLPAnalysisResponse:
    """Format ORM DLPAnalysis model into validated Pydantic response."""
    entities_data = []
    if rec.detected_entities_json:
        try:
            entities_data = json.loads(rec.detected_entities_json)
        except Exception:
            pass

    reasons_data = []
    if rec.reasons_json:
        try:
            reasons_data = json.loads(rec.reasons_json)
        except Exception:
            pass

    signals_data = {}
    if rec.signals_json:
        try:
            signals_data = json.loads(rec.signals_json)
        except Exception:
            pass

    return DLPAnalysisResponse(
        id=rec.id,
        event_id=rec.event_id,
        employee_id=rec.employee_id,
        device_id=rec.device_id,
        filename=rec.filename,
        file_hash=rec.file_hash,
        file_size=rec.file_size,
        file_type=rec.file_type,
        channel=rec.channel,
        destination=rec.destination,
        classification=rec.classification,
        confidence=rec.confidence,
        sensitivity_score=rec.sensitivity_score,
        ocr_used=rec.ocr_used,
        nlp_used=rec.nlp_used,
        ml_used=rec.ml_used,
        ueba_used=rec.ueba_used,
        fast_path=rec.fast_path,
        anomaly_score=rec.anomaly_score,
        anomaly_level=rec.anomaly_level,
        risk_score=rec.risk_score,
        risk_level=rec.risk_level,
        policy_action=rec.policy_action,
        detected_entities=entities_data,
        reasons=reasons_data,
        signals=signals_data,
        timestamp=rec.timestamp
    )


@router.post("/analyze/text", response_model=DLPAnalysisResponse)
def analyze_text_endpoint(
    req: DLPAnalysisRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Real-time multi-stage AI DLP analysis for textual content.
    Runs Entity Detector, NLP Context Analyzer, ML Classifier, and Confidence Aggregator.
    """
    result: DLPAnalysisResult = dlp_pipeline.analyze_payload(
        db=db,
        content=req.text or "",
        filename=req.filename or "payload.txt",
        channel=req.channel or "FILE",
        destination=req.destination or "",
        employee_id=req.employee_id,
        device_id=req.device_id or "WORKSTATION",
        persist=True
    )

    if result.analysis_id:
        rec = db.query(DLPAnalysis).filter(DLPAnalysis.id == result.analysis_id).first()
        if rec:
            return _format_analysis_response(rec)

    return DLPAnalysisResponse(
        id=result.analysis_id,
        event_id=result.event_id,
        employee_id=result.employee_id,
        device_id=result.device_id,
        filename=result.filename,
        file_hash=result.file_hash,
        file_size=result.file_size,
        file_type=result.filename.split(".")[-1].lower() if "." in result.filename else "",
        channel=result.channel,
        destination=result.destination if hasattr(result, "destination") else "",
        classification=result.classification,
        confidence=result.confidence,
        sensitivity_score=result.sensitivity_score,
        ocr_used=result.ocr_used,
        nlp_used=result.nlp_used,
        ml_used=result.ml_used,
        ueba_used=result.ueba_used,
        fast_path=result.fast_path,
        anomaly_score=result.ueba_breakdown.get("anomaly_score", 0.0),
        anomaly_level=result.ueba_breakdown.get("anomaly_level", "NORMAL"),
        risk_score=result.risk_score,
        risk_level=result.risk_level,
        policy_action=result.policy_action,
        detected_entities=result.entities,
        reasons=result.reasons,
        signals=result.signals
    )


@router.post("/analyze/file", response_model=DLPAnalysisResponse)
async def analyze_file_upload_endpoint(
    file: UploadFile = File(...),
    channel: str = Form("FILE"),
    destination: str = Form(""),
    employee_id: Optional[str] = Form(None),
    device_id: str = Form("WORKSTATION"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Upload and analyze documents or images (TXT, CSV, JSON, PDF, DOCX, XLSX, PPTX, PNG, JPG).
    Applies OCR for images and scanned PDFs.
    """
    content_bytes = await file.read()
    filename = file.filename or "upload.bin"

    # Extract text from document or image
    from backend.ai.ocr_engine import ocr_engine
    extracted_text = ""
    if ocr_engine.is_image(filename):
        ocr_res = ocr_engine.extract_from_image_bytes(content_bytes, filename=filename)
        extracted_text = ocr_res.text
    elif filename.lower().endswith(".pdf"):
        ocr_res = ocr_engine.extract_from_pdf_bytes(content_bytes)
        extracted_text = ocr_res.text
    else:
        try:
            extracted_text = content_bytes.decode("utf-8", errors="ignore")
        except Exception:
            extracted_text = ""

    result: DLPAnalysisResult = dlp_pipeline.analyze_payload(
        db=db,
        content=extracted_text,
        content_bytes=content_bytes,
        filename=filename,
        channel=channel,
        destination=destination,
        employee_id=employee_id,
        device_id=device_id,
        persist=True
    )

    if result.analysis_id:
        rec = db.query(DLPAnalysis).filter(DLPAnalysis.id == result.analysis_id).first()
        if rec:
            return _format_analysis_response(rec)

    return DLPAnalysisResponse(
        id=result.analysis_id,
        filename=filename,
        file_hash=result.file_hash,
        file_size=len(content_bytes),
        channel=channel,
        classification=result.classification,
        confidence=result.confidence,
        sensitivity_score=result.sensitivity_score,
        risk_score=result.risk_score,
        risk_level=result.risk_level,
        policy_action=result.policy_action,
        ocr_used=result.ocr_used,
        detected_entities=result.entities,
        reasons=result.reasons,
        signals=result.signals
    )


@router.get("/analyses", response_model=DLPAnalysisListResponse)
def list_analyses_endpoint(
    classification: Optional[str] = None,
    risk_level: Optional[str] = None,
    channel: Optional[str] = None,
    employee_id: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List recent deep DLP analyses with filtering."""
    query = db.query(DLPAnalysis)

    if classification:
        query = query.filter(DLPAnalysis.classification == classification)
    if risk_level:
        query = query.filter(DLPAnalysis.risk_level == risk_level)
    if channel:
        query = query.filter(DLPAnalysis.channel == channel)
    if employee_id:
        query = query.filter(DLPAnalysis.employee_id == employee_id)

    total = query.count()
    items = query.order_by(DLPAnalysis.timestamp.desc()).offset(offset).limit(limit).all()

    return DLPAnalysisListResponse(
        total=total,
        items=[_format_analysis_response(rec) for rec in items]
    )


@router.get("/analyses/{analysis_id}", response_model=DLPAnalysisResponse)
def get_analysis_detail_endpoint(
    analysis_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get single DLP analysis detail with entity breakdown and explainable reasons."""
    rec = db.query(DLPAnalysis).filter(DLPAnalysis.id == analysis_id).first()
    if not rec:
        raise HTTPException(status_code=404, detail="DLP Analysis not found")
    return _format_analysis_response(rec)


@router.post("/feedback", response_model=AnalystFeedbackResponse)
def submit_analyst_feedback_endpoint(
    feedback: AnalystFeedbackCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin)
):
    """Submit SOC analyst feedback on classification accuracy to feed continuous learning."""
    rec = AnalystFeedback(
        analysis_id=feedback.analysis_id,
        event_id=feedback.event_id,
        analyst_username=current_user.username,
        feedback_type=feedback.feedback_type,
        original_classification=feedback.original_classification,
        corrected_classification=feedback.corrected_classification,
        notes=feedback.notes
    )
    db.add(rec)
    db.commit()
    db.refresh(rec)
    return rec


@router.get("/models", response_model=List[ModelMetadataResponse])
def list_models_endpoint(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List registered AI/ML models, versions, and accuracy evaluation metrics."""
    return model_manager.list_models(db)


@router.get("/stats")
def get_ai_stats_endpoint(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Aggregate statistics for AI DLP classifications and entity detections."""
    total_analyses = db.query(DLPAnalysis).count()
    ocr_count = db.query(DLPAnalysis).filter(DLPAnalysis.ocr_used == True).count()
    blocked_count = db.query(DLPAnalysis).filter(DLPAnalysis.policy_action == "BLOCK").count()
    warned_count = db.query(DLPAnalysis).filter(DLPAnalysis.policy_action == "WARN").count()
    
    # Classification breakdown
    tiers = ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED", "HIGHLY_CONFIDENTIAL"]
    tier_counts = {t: db.query(DLPAnalysis).filter(DLPAnalysis.classification == t).count() for t in tiers}

    # Entity counts
    entity_types = db.query(SensitiveEntityRecord.entity_type, SensitiveEntityRecord.category).all()
    entity_type_counts: Dict[str, int] = {}
    category_counts: Dict[str, int] = {}
    for etype, cat in entity_types:
        entity_type_counts[etype] = entity_type_counts.get(etype, 0) + 1
        category_counts[cat] = category_counts.get(cat, 0) + 1

    return {
        "total_analyses": total_analyses,
        "ocr_processed_files": ocr_count,
        "blocked_transfers": blocked_count,
        "warned_transfers": warned_count,
        "classification_breakdown": tier_counts,
        "category_counts": category_counts,
        "entity_type_counts": entity_type_counts
    }
