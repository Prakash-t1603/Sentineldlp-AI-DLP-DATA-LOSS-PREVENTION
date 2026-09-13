"""
SentinelDLP - Explainable Hybrid Confidence Engine
Combines Entity Detection, NLP Context, ML Classification, and OCR signals into a calibrated,
auditable confidence score with human-readable explanations.
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field, asdict


@dataclass
class ConfidenceBreakdown:
    final_confidence: float = 0.0  # 0.0 to 1.0
    entity_confidence: float = 0.0
    nlp_confidence: float = 0.0
    ml_confidence: float = 0.0
    ocr_confidence: float = 1.0
    context_multiplier: float = 1.0
    reasons: List[str] = field(default_factory=list)
    signals: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ConfidenceScorer:
    """
    Computes explainable, calibrated confidence for DLP events.
    Weights components:
    - Entity Detection: 45%
    - ML Classification: 35%
    - NLP Context & Intent: 20%
    Adjusted by OCR penalty (if OCR was utilized) and context multipliers.
    """

    WEIGHT_ENTITY = 0.45
    WEIGHT_ML = 0.35
    WEIGHT_NLP = 0.20

    def compute(
        self,
        entity_count: int,
        entity_avg_confidence: float,
        ml_confidence: float,
        nlp_reinforcement: float,
        has_confidentiality_markers: bool,
        has_exfiltration_intent: bool,
        ocr_used: bool = False,
        ocr_confidence: float = 1.0,
        classification_tier: str = "PUBLIC"
    ) -> ConfidenceBreakdown:
        reasons: List[str] = []
        signals: Dict[str, Any] = {}

        # 1. Base Entity Score
        if entity_count > 0:
            e_score = entity_avg_confidence
            reasons.append(f"Detected {entity_count} sensitive entity matches with avg confidence {e_score:.2f}")
        else:
            e_score = 0.0
            reasons.append("No explicit sensitive entities detected in payload")

        # 2. ML Score
        m_score = ml_confidence
        reasons.append(f"ML Classifier returned {classification_tier} with confidence {m_score:.2f}")

        # 3. NLP Context Score
        n_score = 0.7  # neutral
        if has_confidentiality_markers:
            n_score += 0.25
            reasons.append("NLP detected authoritative corporate confidentiality markers")
        if has_exfiltration_intent:
            n_score += 0.20
            reasons.append("NLP detected data-exfiltration or policy evasion intent phrases")
        if nlp_reinforcement < 0.8:
            reasons.append("NLP detected dummy/test/mock data patterns (confidence attenuated)")
        n_score = min(1.0, max(0.2, n_score))

        # 4. Weighted combination
        if entity_count > 0:
            raw_score = (
                self.WEIGHT_ENTITY * e_score +
                self.WEIGHT_ML * m_score +
                self.WEIGHT_NLP * n_score
            )
        else:
            # When no entities, ML + NLP determine confidence
            raw_score = 0.65 * m_score + 0.35 * n_score

        # 5. Apply context multiplier
        adjusted_score = raw_score * nlp_reinforcement

        # 6. Apply OCR factor if applicable
        if ocr_used:
            ocr_factor = max(0.6, ocr_confidence)
            adjusted_score = adjusted_score * ocr_factor
            reasons.append(f"OCR transcription factor ({ocr_factor:.2f}) applied")

        # Final calibration bounds (0.0 to 1.0)
        final_conf = max(0.05, min(0.99, round(adjusted_score, 3)))

        signals = {
            "entity_count": entity_count,
            "entity_avg_conf": round(e_score, 3),
            "ml_conf": round(m_score, 3),
            "nlp_conf": round(n_score, 3),
            "context_multiplier": round(nlp_reinforcement, 2),
            "ocr_used": ocr_used,
            "ocr_conf": round(ocr_confidence, 2)
        }

        return ConfidenceBreakdown(
            final_confidence=final_conf,
            entity_confidence=round(e_score, 3),
            nlp_confidence=round(n_score, 3),
            ml_confidence=round(m_score, 3),
            ocr_confidence=round(ocr_confidence, 3),
            context_multiplier=round(nlp_reinforcement, 2),
            reasons=reasons,
            signals=signals
        )


# Singleton instance for direct import
confidence_scorer = ConfidenceScorer()
