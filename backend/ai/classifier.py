"""
SentinelDLP - Machine Learning Content Classifier
Multi-class & multi-tier sensitivity classification combining TF-IDF feature extraction,
calibrated machine learning models, and domain rule boost.
"""

import os
import re
import joblib
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field, asdict

# Sensitivity levels hierarchy
SENSITIVITY_TIERS = [
    "PUBLIC",
    "INTERNAL",
    "CONFIDENTIAL",
    "RESTRICTED",
    "HIGHLY_CONFIDENTIAL"
]

CATEGORIES = [
    "UNCLASSIFIED",
    "PII",
    "FINANCIAL",
    "CREDENTIAL",
    "INTELLECTUAL_PROPERTY",
    "HEALTHCARE",
    "GENERAL_CORP"
]


@dataclass
class ClassificationResult:
    predicted_tier: str = "PUBLIC"  # PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED, HIGHLY_CONFIDENTIAL
    confidence: float = 0.0  # 0.0 to 1.0
    predicted_category: str = "UNCLASSIFIED"
    tier_probabilities: Dict[str, float] = field(default_factory=dict)
    category_probabilities: Dict[str, float] = field(default_factory=dict)
    top_features: List[str] = field(default_factory=list)
    model_version: str = "v2.3.0-hybrid"
    explanation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class DLPClassifier:
    """
    Production Content Classifier for Data Loss Prevention.
    Combines Scikit-Learn ML models with heuristic and semantic confidence boosters.
    """

    MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")
    MODEL_PATH = os.path.join(MODEL_DIR, "dlp_classifier.joblib")
    VECTORIZER_PATH = os.path.join(MODEL_DIR, "dlp_vectorizer.joblib")

    # Domain keywords and sensitivity mapping for heuristic fallback
    KEYWORD_TIER_WEIGHTS = {
        # HIGHLY_CONFIDENTIAL / CREDENTIALS
        "private key": ("HIGHLY_CONFIDENTIAL", "CREDENTIAL", 0.98),
        "begin rsa private key": ("HIGHLY_CONFIDENTIAL", "CREDENTIAL", 1.0),
        "aws_secret_access_key": ("HIGHLY_CONFIDENTIAL", "CREDENTIAL", 0.98),
        "database password": ("HIGHLY_CONFIDENTIAL", "CREDENTIAL", 0.95),
        "client_secret": ("HIGHLY_CONFIDENTIAL", "CREDENTIAL", 0.92),
        "db_password": ("HIGHLY_CONFIDENTIAL", "CREDENTIAL", 0.90),
        "master key": ("HIGHLY_CONFIDENTIAL", "CREDENTIAL", 0.90),
        "ssn": ("RESTRICTED", "PII", 0.92),
        "social security number": ("RESTRICTED", "PII", 0.95),
        "aadhaar": ("RESTRICTED", "PII", 0.90),
        "medical record": ("RESTRICTED", "HEALTHCARE", 0.90),
        "patient diagnosis": ("RESTRICTED", "HEALTHCARE", 0.92),
        "credit card": ("RESTRICTED", "FINANCIAL", 0.90),
        "cardholder": ("RESTRICTED", "FINANCIAL", 0.88),
        "salary breakdown": ("CONFIDENTIAL", "FINANCIAL", 0.85),
        "payroll data": ("CONFIDENTIAL", "FINANCIAL", 0.85),
        "strictly confidential": ("CONFIDENTIAL", "GENERAL_CORP", 0.90),
        "proprietary and confidential": ("CONFIDENTIAL", "INTELLECTUAL_PROPERTY", 0.90),
        "trade secret": ("RESTRICTED", "INTELLECTUAL_PROPERTY", 0.95),
        "internal use only": ("INTERNAL", "GENERAL_CORP", 0.80),
        "employee handbook": ("INTERNAL", "GENERAL_CORP", 0.75),
        "quarterly financial forecast": ("CONFIDENTIAL", "FINANCIAL", 0.85),
        "merger and acquisition": ("RESTRICTED", "GENERAL_CORP", 0.92),
        "source code": ("CONFIDENTIAL", "INTELLECTUAL_PROPERTY", 0.75),
        "public release": ("PUBLIC", "GENERAL_CORP", 0.85),
        "open source": ("PUBLIC", "INTELLECTUAL_PROPERTY", 0.80),
        "press release": ("PUBLIC", "GENERAL_CORP", 0.90),
    }

    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.is_trained = False
        self._load_model()

    def _load_model(self):
        """Attempt to load trained scikit-learn artifacts if present on disk."""
        if os.path.exists(self.MODEL_PATH) and os.path.exists(self.VECTORIZER_PATH):
            try:
                self.model = joblib.load(self.MODEL_PATH)
                self.vectorizer = joblib.load(self.VECTORIZER_PATH)
                self.is_trained = True
            except Exception:
                self.is_trained = False

    def predict_heuristic(self, text: str, entity_counts: Optional[Dict[str, int]] = None) -> ClassificationResult:
        """
        Deterministic, highly calibrated heuristic classification when ML model is initializing
        or to augment ML predictions with ground-truth signatures.
        """
        if not text:
            return ClassificationResult(
                predicted_tier="PUBLIC",
                confidence=0.5,
                predicted_category="UNCLASSIFIED",
                tier_probabilities={"PUBLIC": 0.9, "INTERNAL": 0.05, "CONFIDENTIAL": 0.03, "RESTRICTED": 0.01, "HIGHLY_CONFIDENTIAL": 0.01},
                explanation="Empty text payload, defaulted to PUBLIC"
            )

        text_lower = text.lower()
        tier_scores = {tier: 0.05 for tier in SENSITIVITY_TIERS}
        cat_scores = {cat: 0.05 for cat in CATEGORIES}

        matched_cues = []

        # Check entity detector inputs if passed
        if entity_counts:
            cred_count = entity_counts.get("CREDENTIALS", 0)
            fin_count = entity_counts.get("FINANCIAL", 0)
            ident_count = entity_counts.get("IDENTITY", 0)
            health_count = entity_counts.get("HEALTH", 0)
            corp_count = entity_counts.get("CORPORATE", 0)
            pii_count = entity_counts.get("PERSONAL", 0)

            if cred_count > 0:
                tier_scores["HIGHLY_CONFIDENTIAL"] += cred_count * 2.5
                cat_scores["CREDENTIAL"] += cred_count * 2.0
                matched_cues.append(f"Credentials detected (x{cred_count})")
            if fin_count > 0:
                tier_scores["RESTRICTED"] += fin_count * 1.8
                tier_scores["CONFIDENTIAL"] += fin_count * 1.0
                cat_scores["FINANCIAL"] += fin_count * 2.0
                matched_cues.append(f"Financial records detected (x{fin_count})")
            if ident_count > 0:
                tier_scores["RESTRICTED"] += ident_count * 1.5
                cat_scores["PII"] += ident_count * 1.5
                matched_cues.append(f"Identity numbers detected (x{ident_count})")
            if health_count > 0:
                tier_scores["RESTRICTED"] += health_count * 1.8
                cat_scores["HEALTHCARE"] += health_count * 2.0
                matched_cues.append(f"Health records detected (x{health_count})")
            if corp_count > 0:
                tier_scores["CONFIDENTIAL"] += corp_count * 1.2
                cat_scores["INTELLECTUAL_PROPERTY"] += corp_count * 1.0
            if pii_count > 0:
                tier_scores["INTERNAL"] += pii_count * 0.5
                cat_scores["PII"] += pii_count * 1.0

        # Scan domain keyword patterns
        for phrase, (tier, cat, weight) in self.KEYWORD_TIER_WEIGHTS.items():
            if phrase in text_lower:
                tier_scores[tier] += weight * 1.5
                cat_scores[cat] += weight * 1.5
                matched_cues.append(f"Keyword match: '{phrase}'")

        # Normalize tier probabilities via Softmax
        import math
        exp_tier = {t: math.exp(min(s, 20.0)) for t, s in tier_scores.items()}
        sum_exp_tier = sum(exp_tier.values())
        tier_probs = {t: round(v / sum_exp_tier, 4) for t, v in exp_tier.items()}

        exp_cat = {c: math.exp(min(s, 20.0)) for c, s in cat_scores.items()}
        sum_exp_cat = sum(exp_cat.values())
        cat_probs = {c: round(v / sum_exp_cat, 4) for c, v in exp_cat.items()}

        top_tier = max(tier_probs.items(), key=lambda x: x[1])[0]
        top_cat = max(cat_probs.items(), key=lambda x: x[1])[0]
        confidence = tier_probs[top_tier]

        # Adjust confidence floor for definitive matches
        if top_tier in ("HIGHLY_CONFIDENTIAL", "RESTRICTED") and matched_cues:
            confidence = max(0.85, confidence)
        elif top_tier == "CONFIDENTIAL" and matched_cues:
            confidence = max(0.75, confidence)
        elif not matched_cues:
            top_tier = "PUBLIC"
            top_cat = "GENERAL_CORP"
            confidence = 0.90

        explanation = f"Classified as {top_tier} ({top_cat}) based on: " + (", ".join(matched_cues[:4]) if matched_cues else "Neutral text patterns")

        return ClassificationResult(
            predicted_tier=top_tier,
            confidence=round(confidence, 3),
            predicted_category=top_cat,
            tier_probabilities=tier_probs,
            category_probabilities=cat_probs,
            top_features=matched_cues[:6],
            model_version="v2.3.0-heuristic",
            explanation=explanation
        )

    def classify(self, text: str, entity_counts: Optional[Dict[str, int]] = None) -> ClassificationResult:
        """
        Classify text using ML model if available, otherwise heuristic engine.
        If ML is available, combines ML probabilities with entity signatures.
        """
        if self.is_trained and self.model and self.vectorizer:
            try:
                X = self.vectorizer.transform([text])
                probs = self.model.predict_proba(X)[0]
                classes = self.model.classes_
                
                tier_probs = {}
                for cls, prob in zip(classes, probs):
                    tier_probs[cls] = round(float(prob), 4)
                
                # Fill missing classes with small baseline
                for tier in SENSITIVITY_TIERS:
                    if tier not in tier_probs:
                        tier_probs[tier] = 0.001

                top_tier = max(tier_probs.items(), key=lambda x: x[1])[0]
                conf = tier_probs[top_tier]

                # If strong entity signals exist (e.g. RSA private keys), ensure ML didn't underpredict
                if entity_counts and entity_counts.get("CREDENTIALS", 0) > 0:
                    top_tier = "HIGHLY_CONFIDENTIAL"
                    conf = max(conf, 0.96)
                elif entity_counts and (entity_counts.get("FINANCIAL", 0) > 0 or entity_counts.get("IDENTITY", 0) > 0):
                    if top_tier in ("PUBLIC", "INTERNAL"):
                        top_tier = "RESTRICTED"
                        conf = max(conf, 0.90)

                # Heuristic category mapping
                heur = self.predict_heuristic(text, entity_counts)

                return ClassificationResult(
                    predicted_tier=top_tier,
                    confidence=round(conf, 3),
                    predicted_category=heur.predicted_category,
                    tier_probabilities=tier_probs,
                    category_probabilities=heur.category_probabilities,
                    top_features=heur.top_features,
                    model_version="v2.3.0-ml",
                    explanation=f"ML Predicted {top_tier} with confidence {conf:.2f}."
                )
            except Exception:
                pass

        return self.predict_heuristic(text, entity_counts)


# Singleton instance for direct import
dlp_classifier = DLPClassifier()
