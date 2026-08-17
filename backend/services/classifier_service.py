import hashlib
import re
from pathlib import Path
from typing import Dict, Any, List, Optional
from backend.services.nlp_service import nlp_service
from backend.services.ocr_service import ocr_service, SUPPORTED_OCR_EXTENSIONS
from backend.utils.helpers import get_logger, compute_file_hash

logger = get_logger("SentinelDLP.ClassifierService")

class ClassifierService:
    def __init__(self):
        self._ml_model_loaded = False
        self._embedding_model = None
        # Cache keyed strictly on SHA-256 byte content hash
        self._content_hash_cache: Dict[str, Dict[str, Any]] = {}

    def get_cached_classification(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Retrieve classification result by byte content hash."""
        if not file_hash:
            return None
        return self._content_hash_cache.get(file_hash)

    def cache_classification(self, file_hash: str, result: Dict[str, Any]) -> None:
        """Store classification result keyed strictly by byte content hash."""
        if file_hash and result:
            self._content_hash_cache[file_hash] = result

    def clear_cache(self) -> None:
        """Clear the content hash cache."""
        self._content_hash_cache.clear()

    def classify_file(
        self,
        filename: str,
        filepath: str,
        file_size: int,
        extracted_text: str = "",
        file_hash: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Classify a file record strictly based on actual byte content / extracted text / visual OCR analysis.
        Filename, path, and extension are NEVER used as evidence of sensitivity and never cause early exit.
        Classification results are cached exclusively by SHA-256 byte content hash.
        """
        path_obj = Path(filepath) if filepath else Path(filename)
        ext = path_obj.suffix.lower()

        # 1. Compute/verify SHA-256 byte content hash for caching
        if not file_hash:
            if filepath and Path(filepath).is_file():
                file_hash = compute_file_hash(filepath)
            elif extracted_text:
                file_hash = hashlib.sha256(extracted_text.encode("utf-8", errors="ignore")).hexdigest()

        # Check byte-content cache (skip if previous result was Unknown/Unclassified)
        if file_hash:
            cached_result = self.get_cached_classification(file_hash)
            if cached_result is not None and cached_result.get("classification") != "Unknown/Unclassified":
                logger.debug(f"Content hash cache HIT for hash '{file_hash[:12]}...' (file: '{path_obj.name}')")
                return cached_result.copy()

        # 2. Extract text if not provided and file exists
        if not extracted_text and filepath and Path(filepath).is_file():
            from backend.services.file_analysis_service import file_analysis_service
            extracted_text, _ = file_analysis_service.extract_text_from_file(path_obj)

        indicators = []
        image_doc_class = "PUBLIC"
        image_doc_score = 0.0
        document_identified_type = None

        # 3. Visual Document & Image OCR Analysis (for supported image extensions)
        if ext in SUPPORTED_OCR_EXTENSIONS or ocr_service.is_image_file(path_obj):
            img_result = ocr_service.classify_image_document(path_obj, ocr_text=extracted_text)
            
            # Handle OCR failure / empty OCR text -> classify as Unknown/Unclassified (do NOT cache so retries can succeed)
            if img_result.get("classification") == "Unknown/Unclassified":
                unknown_result = {
                    "classification": "Unknown/Unclassified",
                    "confidence": 0.50,
                    "sensitivity_score": img_result.get("sensitivity_score", 25.0),
                    "detected_entities": [],
                    "indicators": ["OCR extraction failed or yielded empty text on image file"],
                    "document_type": img_result.get("document_type", "Unclassified Image (OCR Empty/Failed)"),
                    "text_length": 0
                }
                return unknown_result

            if img_result.get("is_sensitive"):
                document_identified_type = img_result.get("document_type")
                image_doc_class = img_result.get("classification", "HIGHLY_CONFIDENTIAL")
                image_doc_score = img_result.get("sensitivity_score", 95.0)
                details = img_result.get("details", "")
                indicators.append(f"Visual Document Recognition: Identified as '{document_identified_type}' ({details})")

                # If extracted text was updated by OCR
                if not extracted_text and img_result.get("extracted_text"):
                    extracted_text = img_result.get("extracted_text")

        # 4. Content NLP & Regex entity scanning
        detected_entities, content_score, content_class = nlp_service.scan_text(extracted_text)
        for entity in detected_entities:
            indicators.append(f"Detected {entity['count']}x {entity['entity_type']} ({entity['classification']})")

        # If visual document classifier identified a sensitive ID card, add it to detected entities
        if document_identified_type:
            entity_tag = document_identified_type.upper().replace(" ", "_").replace("(", "").replace(")", "").replace("/", "_")
            if not any(e.get("entity_type") == entity_tag for e in detected_entities):
                detected_entities.insert(0, {
                    "entity_type": entity_tag,
                    "count": 1,
                    "classification": image_doc_class,
                    "score": image_doc_score,
                    "samples": [img_result.get("details", document_identified_type)]
                })

        # 5. Decision Matrix & Hierarchical Resolution
        class_hierarchy = {
            "PUBLIC": 0,
            "INTERNAL": 1,
            "CONFIDENTIAL": 2,
            "HIGHLY_CONFIDENTIAL": 3
        }

        # Combine content and image OCR signals only (never filename)
        final_score = max(content_score, image_doc_score)
        
        # Boost confidence when strong visual or content signals agree
        if image_doc_score >= 80.0 or content_score >= 85.0:
            final_score = min(100.0, max(final_score, 92.0))

        # Highest classification resolution
        classes = [content_class, image_doc_class]
        final_classification = max(classes, key=lambda c: class_hierarchy.get(c, 0))

        # Direct threshold floors for critical findings
        if final_score >= 85:
            final_classification = "HIGHLY_CONFIDENTIAL"
        elif final_score >= 60 and class_hierarchy.get(final_classification, 0) < 2:
            final_classification = "CONFIDENTIAL"
        elif final_score >= 30 and class_hierarchy.get(final_classification, 0) < 1:
            final_classification = "INTERNAL"
        elif final_score < 30 and not indicators:
            final_classification = "PUBLIC"

        confidence = 0.96 if len(indicators) >= 2 else (0.88 if len(indicators) > 0 else 0.70)

        result = {
            "classification": final_classification,
            "confidence": round(confidence, 2),
            "sensitivity_score": round(final_score, 1),
            "detected_entities": detected_entities,
            "indicators": indicators,
            "document_type": document_identified_type,
            "text_length": len(extracted_text)
        }

        # Store in content hash cache
        if file_hash:
            self.cache_classification(file_hash, result)

        return result

classifier_service = ClassifierService()
