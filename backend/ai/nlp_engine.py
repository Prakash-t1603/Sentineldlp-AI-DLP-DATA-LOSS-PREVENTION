"""
SentinelDLP - Natural Language Processing (NLP) Engine
Context window analysis, confidentiality marker detection, data-exfiltration intent scoring,
and text feature extraction.
"""

import re
from typing import List, Dict, Any, Set, Tuple
from dataclasses import dataclass, field, asdict


@dataclass
class NLPContextResult:
    confidentiality_markers_found: List[str] = field(default_factory=list)
    exfiltration_intent_detected: bool = False
    intent_signals: List[str] = field(default_factory=list)
    context_reinforcement_score: float = 1.0  # > 1.0 reinforces sensitivity, < 1.0 attenuates (e.g. test data)
    top_keywords: List[str] = field(default_factory=list)
    is_code_or_structured_data: bool = False
    language_summary: str = "EN"
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class NLPEngine:
    """
    Lightweight, fast NLP Engine for deep context and intent understanding in DLP.
    """

    # Markers indicating organizational classification
    CONFIDENTIALITY_MARKERS = [
        "strictly confidential",
        "top secret",
        "proprietary and confidential",
        "internal use only",
        "trade secret",
        "do not distribute",
        "attorney-client privilege",
        "restricted distribution",
        "non-disclosure agreement",
        "confidential offering memorandum",
        "privileged communication",
        "company confidential"
    ]

    # Cues that confirm high likelihood of real sensitive data
    REINFORCING_CUES = [
        "password", "secret", "credentials", "api key", "access token", "auth token",
        "private key", "database password", "connection string", "credit card", "cvv",
        "social security", "tax identification", "salary", "payroll", "medical history",
        "customer records", "financial statements", "revenue forecast", "source code",
        "master key", "ssh key", "production database", "prod credentials"
    ]

    # Cues that suggest mock, testing, or dummy data (attenuation)
    ATTENUATING_CUES = [
        "sample", "example", "dummy", "fake", "test", "mock", "placeholder",
        "lorem ipsum", "foo", "bar", "baz", "test_user", "sample_card", "fixture",
        "unit test", "spec test", "mock data", "stub", "example.com"
    ]

    # Data exfiltration / bypass phrases
    EXFILTRATION_INTENT_PATTERNS = [
        r"(?:bypass|disable|evade)\s+(?:dlp|monitoring|agent|security|edr)",
        r"(?:dump|export|download)\s+(?:customer|user|db|database|credit card|client)\s+(?:data|table|records|leak)",
        r"(?:send|upload|transfer)\s+(?:all\s+files|database|source code)\s+to\s+(?:personal|external|usb|drive|dropbox|mega)",
        r"(?:hide|encrypt|zip\s+with\s+password|obfuscate)\s+(?:files|data|confidential|leak)",
        r"(?:resignation|quitting|leaving\s+company)\s+.*(?:take|copy|backup)\s+(?:files|code|clients)"
    ]

    STOPWORDS = {
        "a", "about", "above", "after", "again", "against", "all", "am", "an", "and", "any", "are",
        "as", "at", "be", "because", "been", "before", "being", "below", "between", "both", "but",
        "by", "can", "did", "do", "does", "doing", "don", "down", "during", "each", "few", "for",
        "from", "further", "had", "has", "have", "having", "he", "her", "here", "hers", "herself",
        "him", "himself", "his", "how", "i", "if", "in", "into", "is", "it", "its", "itself", "just",
        "me", "more", "most", "my", "myself", "no", "nor", "not", "now", "of", "off", "on", "once",
        "only", "or", "other", "our", "ours", "ourselves", "out", "over", "own", "s", "same", "she",
        "should", "so", "some", "such", "t", "than", "that", "the", "their", "theirs", "them",
        "themselves", "then", "there", "these", "they", "this", "those", "through", "to", "too",
        "under", "until", "up", "very", "was", "we", "were", "what", "when", "where", "which",
        "while", "who", "whom", "why", "with", "you", "your", "yours", "yourself", "yourselves"
    }

    def __init__(self):
        self._compiled_intent_patterns = [
            re.compile(pat, re.IGNORECASE) for pat in self.EXFILTRATION_INTENT_PATTERNS
        ]

    def tokenize(self, text: str) -> List[str]:
        """Simple, fast regex tokenization into lowercase alphanumeric words."""
        if not text:
            return []
        return [w.lower() for w in re.findall(r"\b[A-Za-z0-9_-]{2,}\b", text)]

    def extract_keywords(self, text: str, top_n: int = 10) -> List[str]:
        """Extract top informative keywords excluding stopwords."""
        tokens = self.tokenize(text)
        freq: Dict[str, int] = {}
        for token in tokens:
            if token not in self.STOPWORDS and not token.isdigit():
                freq[token] = freq.get(token, 0) + 1
        
        sorted_keywords = sorted(freq.items(), key=lambda x: x[1], reverse=True)
        return [word for word, _ in sorted_keywords[:top_n]]

    def analyze_context(self, text: str) -> NLPContextResult:
        """
        Perform comprehensive NLP context, marker, and intent evaluation on content.
        """
        if not text or not isinstance(text, str):
            return NLPContextResult()

        text_lower = text.lower()
        
        # 1. Detect Confidentiality Markers
        found_markers = []
        for marker in self.CONFIDENTIALITY_MARKERS:
            if marker in text_lower:
                found_markers.append(marker.upper())

        # 2. Detect Exfiltration / Malicious Intent
        intent_detected = False
        intent_signals = []
        for pat in self._compiled_intent_patterns:
            matches = pat.findall(text_lower)
            if matches:
                intent_detected = True
                intent_signals.extend(matches if isinstance(matches[0], str) else [m[0] for m in matches])

        # 3. Compute Context Reinforcement Multiplier
        reinforcing_count = 0
        for cue in self.REINFORCING_CUES:
            if cue in text_lower:
                reinforcing_count += 1

        attenuating_count = 0
        for cue in self.ATTENUATING_CUES:
            if cue in text_lower:
                attenuating_count += 1

        # Base multiplier is 1.0 (neutral). Range: 0.4 (mock test data) to 1.6 (high-risk corporate leak)
        multiplier = 1.0
        if found_markers:
            multiplier += 0.25 * min(len(found_markers), 2)
        if reinforcing_count > 0:
            multiplier += min(0.3, reinforcing_count * 0.08)
        if attenuating_count > 0 and reinforcing_count == 0 and not found_markers:
            multiplier -= min(0.5, attenuating_count * 0.15)
        if intent_detected:
            multiplier += 0.35

        multiplier = max(0.3, min(2.0, round(multiplier, 2)))

        # 4. Check if text is structured data or code
        is_code = bool(re.search(r"(?:def\s+[a-zA-Z_]|import\s+[a-zA-Z_]|function\s*\(|class\s+[A-Za-z]|SELECT\s+.*FROM|INSERT\s+INTO|\{[\s\S]*\}|\[[\s\S]*\])", text))

        # 5. Extract top keywords
        top_keywords = self.extract_keywords(text, top_n=8)

        return NLPContextResult(
            confidentiality_markers_found=found_markers,
            exfiltration_intent_detected=intent_detected,
            intent_signals=list(set(intent_signals)),
            context_reinforcement_score=multiplier,
            top_keywords=top_keywords,
            is_code_or_structured_data=is_code,
            details={
                "reinforcing_cue_count": reinforcing_count,
                "attenuating_cue_count": attenuating_count,
                "marker_count": len(found_markers)
            }
        )


# Singleton instance for direct import
nlp_engine = NLPEngine()
