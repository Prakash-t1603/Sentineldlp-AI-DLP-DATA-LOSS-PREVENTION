"""
SentinelDLP - Real-Time Multi-Stage AI DLP Pipeline
Orchestrates Fast-Path and Slow-Path deep inspection across Entity Detection,
NLP Context, ML Classification, OCR, Confidence Scoring, and UEBA Analytics.
"""

import json
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field, asdict
from sqlalchemy.orm import Session

from backend.ai.entity_detector import entity_detector, DetectionResult, DetectedEntity
from backend.ai.nlp_engine import nlp_engine, NLPContextResult
from backend.ai.ocr_engine import ocr_engine, OCRResult
from backend.ai.classifier import dlp_classifier, ClassificationResult
from backend.ai.confidence import confidence_scorer, ConfidenceBreakdown
from backend.ai.ueba import ueba_engine, UEBAResult
from backend.models import DLPAnalysis, SensitiveEntityRecord, AIClassificationRecord, UEBAAnomaly


@dataclass
class DLPAnalysisResult:
    analysis_id: Optional[int] = None
    event_id: Optional[str] = None
    employee_id: Optional[str] = None
    device_id: str = "WORKSTATION"
    filename: str = "unknown"
    file_hash: str = ""
    file_size: int = 0
    channel: str = "FILE"
    
    # Classification & Sensitivity
    classification: str = "PUBLIC"  # PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED, HIGHLY_CONFIDENTIAL
    category: str = "UNCLASSIFIED"
    confidence: float = 0.0  # 0.0 to 1.0
    sensitivity_score: float = 0.0  # 0.0 to 100.0
    
    # Risk & Policy Enforcement
    risk_score: float = 0.0  # 0.0 to 100.0
    risk_level: str = "LOW"  # LOW, MEDIUM, HIGH, CRITICAL
    policy_action: str = "ALLOW"  # ALLOW, WARN, BLOCK
    
    # Execution Signals
    fast_path: bool = False
    ocr_used: bool = False
    nlp_used: bool = True
    ml_used: bool = True
    ueba_used: bool = True
    
    # Detailed Subsystem Breakdowns
    entities: List[Dict[str, Any]] = field(default_factory=list)
    entity_summary: str = ""
    nlp_summary: Dict[str, Any] = field(default_factory=dict)
    classification_breakdown: Dict[str, Any] = field(default_factory=dict)
    confidence_breakdown: Dict[str, Any] = field(default_factory=dict)
    ueba_breakdown: Dict[str, Any] = field(default_factory=dict)
    
    # Human-readable Explainability
    reasons: List[str] = field(default_factory=list)
    signals: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class DLPPipeline:
    """
    Unified High-Performance DLP Engine coordinating all AI/ML submodules.
    """

    # In-memory fast-path hash cache (file_hash -> DLPAnalysisResult)
    _CACHE_MAX_SIZE = 1000
    _fast_cache: Dict[str, Dict[str, Any]] = {}

    def __init__(self):
        pass

    def _compute_hash(self, content: bytes) -> str:
        return hashlib.sha256(content).hexdigest()

    def analyze_payload(
        self,
        db: Session,
        content: str = "",
        content_bytes: Optional[bytes] = None,
        filename: str = "payload.txt",
        channel: str = "FILE",
        destination: str = "",
        employee_id: Optional[str] = None,
        device_id: str = "WORKSTATION",
        event_id: Optional[str] = None,
        event_time: Optional[datetime] = None,
        persist: bool = True
    ) -> DLPAnalysisResult:
        """
        Execute full multi-tier DLP & UEBA inspection on textual or binary payload.
        """
        event_time = event_time or datetime.now(timezone.utc)
        file_size = len(content_bytes) if content_bytes is not None else len(content.encode("utf-8", errors="ignore"))
        
        # Calculate SHA256 Hash
        if content_bytes is not None:
            file_hash = self._compute_hash(content_bytes)
        else:
            file_hash = self._compute_hash(content.encode("utf-8", errors="ignore"))

        # ==================== 1. FAST-PATH CACHE CHECK ====================
        if file_hash in self._fast_cache:
            cached = self._fast_cache[file_hash]
            # Fast path hit
            res = DLPAnalysisResult(
                analysis_id=cached.get("analysis_id"),
                event_id=event_id or cached.get("event_id"),
                employee_id=employee_id or cached.get("employee_id"),
                device_id=device_id,
                filename=filename,
                file_hash=file_hash,
                file_size=file_size,
                channel=channel,
                classification=cached.get("classification", "PUBLIC"),
                category=cached.get("category", "UNCLASSIFIED"),
                confidence=cached.get("confidence", 0.9),
                sensitivity_score=cached.get("sensitivity_score", 0.0),
                risk_score=cached.get("risk_score", 0.0),
                risk_level=cached.get("risk_level", "LOW"),
                policy_action=cached.get("policy_action", "ALLOW"),
                fast_path=True,
                ocr_used=cached.get("ocr_used", False),
                entities=cached.get("entities", []),
                entity_summary=cached.get("entity_summary", ""),
                nlp_summary=cached.get("nlp_summary", {}),
                confidence_breakdown=cached.get("confidence_breakdown", {}),
                reasons=["Fast-Path Content Hash Cache Hit (Instant Sub-millisecond Analysis)"] + cached.get("reasons", [])
            )
            return res

        # ==================== 2. SLOW-PATH: OCR / TEXT EXTRACTION ====================
        ocr_used = False
        ocr_confidence = 1.0
        extracted_text = content
        extraction_method = "DIRECT_TEXT"
        extraction_meta: Dict[str, Any] = {}

        if content_bytes is not None:
            from backend.services.file_analysis_service import file_analysis_service
            extracted_text, extraction_method, extraction_meta = file_analysis_service.extract_text_from_bytes(content_bytes, filename=filename)
            if extraction_meta.get("ocr_used") or extraction_method in ("OCR", "PDF_OCR", "PDF_EMBEDDED_IMAGE_OCR"):
                ocr_used = True
                ocr_confidence = extraction_meta.get("ocr_confidence", 0.88)
        elif not extracted_text and ocr_engine.is_image(filename):
            ocr_used = True
            ocr_confidence = 0.85

        # ==================== 3. SENSITIVE ENTITY DETECTION ====================
        detection: DetectionResult = entity_detector.scan_text(extracted_text)

        # ==================== 4. NLP CONTEXT & INTENT ANALYSIS ====================
        nlp_res: NLPContextResult = nlp_engine.analyze_context(extracted_text)

        # ==================== 5. MACHINE LEARNING CLASSIFICATION ====================
        classification: ClassificationResult = dlp_classifier.classify(
            text=extracted_text,
            entity_counts=detection.category_counts
        )

        # Override/Promote tier if authoritative markers or high severity entities found
        tier = classification.predicted_tier
        if "STRICTLY CONFIDENTIAL" in nlp_res.confidentiality_markers_found or "TOP SECRET" in nlp_res.confidentiality_markers_found:
            if tier in ("PUBLIC", "INTERNAL", "CONFIDENTIAL"):
                tier = "RESTRICTED"
        if detection.category_counts.get("CREDENTIALS", 0) > 0:
            tier = "HIGHLY_CONFIDENTIAL"
        elif (detection.category_counts.get("FINANCIAL", 0) > 0 or detection.category_counts.get("IDENTITY", 0) > 0) and tier in ("PUBLIC", "INTERNAL"):
            tier = "RESTRICTED"
        elif detection.category_counts.get("CORPORATE", 0) > 0 and tier == "PUBLIC":
            tier = "CONFIDENTIAL"

        # ==================== 6. HYBRID CONFIDENCE SCORING ====================
        conf_breakdown: ConfidenceBreakdown = confidence_scorer.compute(
            entity_count=detection.total_count,
            entity_avg_confidence=(sum(e.confidence for e in detection.entities) / len(detection.entities)) if detection.entities else 0.0,
            ml_confidence=classification.confidence,
            nlp_reinforcement=nlp_res.context_reinforcement_score,
            has_confidentiality_markers=bool(nlp_res.confidentiality_markers_found),
            has_exfiltration_intent=nlp_res.exfiltration_intent_detected,
            ocr_used=ocr_used,
            ocr_confidence=ocr_confidence,
            classification_tier=tier
        )

        # ==================== 7. UEBA BEHAVIORAL EVALUATION ====================
        ueba_res = UEBAResult(employee_id=employee_id or "ANONYMOUS", anomaly_score=0.0)
        if employee_id:
            try:
                ueba_res = ueba_engine.evaluate_event(
                    db=db,
                    employee_id=employee_id,
                    channel=channel,
                    file_size_bytes=file_size,
                    sensitive_entity_count=detection.total_count,
                    event_time=event_time
                )
            except Exception:
                pass

        # ==================== 8. COMPOSITE SENSITIVITY & RISK CALCULATION ====================
        # Base Sensitivity Score (0.0 - 100.0)
        tier_base_scores = {
            "PUBLIC": 0.0,
            "INTERNAL": 30.0,
            "CONFIDENTIAL": 65.0,
            "RESTRICTED": 85.0,
            "HIGHLY_CONFIDENTIAL": 98.0
        }
        base_sens = tier_base_scores.get(tier, 10.0)
        entity_boost = min(30.0, detection.total_count * 5.0)
        sensitivity_score = min(100.0, max(0.0, base_sens + entity_boost))

        # Composite Risk Score Calculation
        # Risk factors: Sensitivity (40%), Confidence (25%), Channel Severity (15%), UEBA Anomaly (20%)
        channel_risk_multiplier = {
            "USB": 1.3,
            "EXTERNAL_DRIVE": 1.3,
            "BROWSER": 1.2,
            "EMAIL": 1.15,
            "CLIPBOARD": 1.1,
            "FILE": 1.0
        }.get(channel.upper(), 1.0)

        # Destination Risk Add-on (external / cloud / webmail)
        dest_lower = (destination or "").lower()
        dest_risk_addon = 0.0
        if any(ext_dest in dest_lower for ext_dest in ["gmail", "mail.google", "drive.google", "dropbox", "onedrive", "wetransfer", "mega.nz", "box.com", "whatsapp"]):
            dest_risk_addon = 10.0

        # Temporal Risk (after-hours: outside 8am-7pm or weekend)
        temporal_risk_addon = 0.0
        if event_time.weekday() >= 5 or event_time.hour < 8 or event_time.hour >= 19:
            temporal_risk_addon = 5.0

        raw_risk = (
            (sensitivity_score * 0.40) +
            (conf_breakdown.final_confidence * 100.0 * 0.25) +
            (ueba_res.anomaly_score * 100.0 * 0.20)
        ) * channel_risk_multiplier + dest_risk_addon + temporal_risk_addon

        # Additional risk boost if exfiltration intent detected
        if nlp_res.exfiltration_intent_detected:
            raw_risk += 25.0

        # If sensitive entities exist, ensure risk is at least HIGH (>= 75)
        if detection.total_count > 0 or tier in ("RESTRICTED", "HIGHLY_CONFIDENTIAL"):
            raw_risk = max(raw_risk, 80.0)
        elif tier == "CONFIDENTIAL":
            raw_risk = max(raw_risk, 60.0)
        elif tier == "INTERNAL":
            raw_risk = max(raw_risk, 35.0)

        risk_score = round(min(100.0, max(0.0, raw_risk)), 1)

        # Risk Level determination
        if risk_score >= 80.0 or tier == "HIGHLY_CONFIDENTIAL":
            risk_level = "CRITICAL"
            policy_action = "BLOCK"
        elif risk_score >= 60.0 or tier == "RESTRICTED":
            risk_level = "HIGH"
            policy_action = "BLOCK" if channel in ("USB", "EXTERNAL_DRIVE", "BROWSER") else "WARN"
        elif risk_score >= 35.0 or tier == "CONFIDENTIAL":
            risk_level = "MEDIUM"
            policy_action = "WARN"
        else:
            risk_level = "LOW"
            policy_action = "ALLOW"

        # Combine explainable reasons
        all_reasons = []
        if tier != "PUBLIC":
            all_reasons.append(f"AI Content Classification: {tier} ({classification.predicted_category})")
        all_reasons.extend(conf_breakdown.reasons)
        if ueba_res.has_anomaly:
            all_reasons.append(f"UEBA Anomaly Flag: {ueba_res.explanation}")
        if not all_reasons:
            all_reasons.append("Payload content verified clean; no sensitive signals detected.")

        entities_dicts = [e.to_dict() for e in detection.entities]

        # ==================== 9. DATABASE PERSISTENCE ====================
        analysis_record_id = None
        if persist:
            try:
                analysis_rec = DLPAnalysis(
                    event_id=event_id,
                    employee_id=employee_id,
                    device_id=device_id,
                    filename=filename,
                    file_hash=file_hash,
                    file_size=file_size,
                    file_type=filename.split(".")[-1].lower() if "." in filename else "",
                    channel=channel,
                    destination=destination,
                    classification=tier,
                    confidence=conf_breakdown.final_confidence,
                    sensitivity_score=sensitivity_score,
                    ocr_used=ocr_used,
                    nlp_used=True,
                    ml_used=True,
                    ueba_used=bool(employee_id),
                    fast_path=False,
                    anomaly_score=ueba_res.anomaly_score,
                    anomaly_level=ueba_res.anomaly_level,
                    risk_score=risk_score,
                    risk_level=risk_level,
                    policy_action=policy_action,
                    detected_entities_json=json.dumps(entities_dicts),
                    reasons_json=json.dumps(all_reasons),
                    signals_json=json.dumps(conf_breakdown.signals),
                    timestamp=event_time
                )
                db.add(analysis_rec)
                db.flush()
                analysis_record_id = analysis_rec.id

                # Persist sensitive entity records
                for ent in detection.entities:
                    ent_rec = SensitiveEntityRecord(
                        analysis_id=analysis_rec.id,
                        entity_type=ent.entity_type,
                        category=ent.category,
                        count=1,
                        confidence=ent.confidence,
                        masked_sample=ent.masked_value
                    )
                    db.add(ent_rec)

                # Persist classification record
                cls_rec = AIClassificationRecord(
                    file_hash=file_hash,
                    model_name="sentineldlp-classifier",
                    model_version=classification.model_version,
                    predicted_class=tier,
                    confidence=classification.confidence,
                    categories_json=json.dumps(classification.category_probabilities),
                    probabilities_json=json.dumps(classification.tier_probabilities),
                    features_used_json=json.dumps(classification.top_features),
                    created_at=event_time
                )
                db.add(cls_rec)

                # Persist UEBA Anomaly if present
                if ueba_res.has_anomaly and employee_id:
                    for a in ueba_res.anomalies:
                        anom_rec = UEBAAnomaly(
                            employee_id=employee_id,
                            device_id=device_id,
                            anomaly_score=ueba_res.anomaly_score,
                            anomaly_type=a.anomaly_type,
                            severity=a.severity,
                            description=a.description,
                            metric_name=a.anomaly_type,
                            observed_value=a.observed_value,
                            expected_value=a.expected_value,
                            z_score=a.z_score,
                            peer_group_avg=a.peer_group_avg,
                            timestamp=event_time
                        )
                        db.add(anom_rec)

                db.commit()
            except Exception as e:
                db.rollback()

        # Update fast cache
        result_dict = {
            "analysis_id": analysis_record_id,
            "event_id": event_id,
            "employee_id": employee_id,
            "classification": tier,
            "category": classification.predicted_category,
            "confidence": conf_breakdown.final_confidence,
            "sensitivity_score": sensitivity_score,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "policy_action": policy_action,
            "ocr_used": ocr_used,
            "entities": entities_dicts,
            "entity_summary": detection.raw_findings_summary,
            "nlp_summary": nlp_res.to_dict(),
            "confidence_breakdown": conf_breakdown.to_dict(),
            "reasons": all_reasons
        }

        if len(self._fast_cache) >= self._CACHE_MAX_SIZE:
            # Evict oldest entry
            self._fast_cache.pop(next(iter(self._fast_cache)))
        self._fast_cache[file_hash] = result_dict

        return DLPAnalysisResult(
            analysis_id=analysis_record_id,
            event_id=event_id,
            employee_id=employee_id,
            device_id=device_id,
            filename=filename,
            file_hash=file_hash,
            file_size=file_size,
            channel=channel,
            classification=tier,
            category=classification.predicted_category,
            confidence=conf_breakdown.final_confidence,
            sensitivity_score=sensitivity_score,
            risk_score=risk_score,
            risk_level=risk_level,
            policy_action=policy_action,
            fast_path=False,
            ocr_used=ocr_used,
            nlp_used=True,
            ml_used=True,
            ueba_used=bool(employee_id),
            entities=entities_dicts,
            entity_summary=detection.raw_findings_summary,
            nlp_summary=nlp_res.to_dict(),
            classification_breakdown=classification.to_dict(),
            confidence_breakdown=conf_breakdown.to_dict(),
            ueba_breakdown=ueba_res.to_dict(),
            reasons=all_reasons,
            signals=conf_breakdown.signals,
            timestamp=event_time.isoformat()
        )


# Singleton instance for direct import
dlp_pipeline = DLPPipeline()
