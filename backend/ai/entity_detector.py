"""
SentinelDLP - Modular Sensitive Entity Detector
High-performance regex, algorithmic checksums, Shannon entropy, and contextual verification
covering Personal, Financial, Identity, Credentials, Corporate, and Health data.
"""

import re
import math
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict


def shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy of a string (bits per symbol)."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    frequencies = {}
    for char in data:
        frequencies[char] = frequencies.get(char, 0) + 1
    for count in frequencies.values():
        p_x = count / length
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)
    return entropy


def luhn_checksum(card_number: str) -> bool:
    """Validate a credit card number string using the standard Luhn (mod 10) algorithm."""
    digits = [int(c) for c in card_number if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    
    checksum = 0
    reverse_digits = digits[::-1]
    for idx, digit in enumerate(reverse_digits):
        if idx % 2 == 1:
            doubled = digit * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += digit
    return checksum % 10 == 0


def verhoeff_validate(number: str) -> bool:
    """Validate a number string using the Verhoeff checksum algorithm (used for Aadhaar)."""
    d_table = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
        [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
        [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
        [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
        [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
        [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
        [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
        [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
        [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
    ]
    p_table = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
        [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
        [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
        [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
        [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
        [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
        [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]
    ]
    inv_table = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]

    digits = [int(c) for c in number if c.isdigit()]
    if not digits:
        return False
    
    c = 0
    for i, item in enumerate(reversed(digits)):
        c = d_table[c][p_table[i % 8][item]]
    return c == 0


def mask_sensitive_value(value: Optional[str], entity_type: str) -> str:
    """Mask a sensitive value preserving safety while maintaining SOC analyst context."""
    if not value or not isinstance(value, str):
        return "****"
    val = value.strip()
    if not val:
        return "****"
    
    if entity_type == "CREDIT_CARD":
        clean = re.sub(r"[ -]", "", val)
        if len(clean) >= 8:
            return f"{clean[:4]}-****-****-{clean[-4:]}"
        return "****"
    elif entity_type in ("AWS_ACCESS_KEY", "AWS_SECRET_KEY"):
        if len(val) > 8:
            return f"{val[:4]}...{val[-4:]}"
        return "********"
    elif entity_type == "EMAIL":
        if "@" in val:
            user, domain = val.split("@", 1)
            masked_user = (user[0] + "***" + user[-1]) if len(user) > 2 else "***"
            return f"{masked_user}@{domain}"
        return "***@***.***"
    elif entity_type == "SSN":
        clean = re.sub(r"[ -]", "", val)
        if len(clean) == 9:
            return f"***-**-{clean[-4:]}"
        return "***-**-****"
    elif entity_type == "AADHAAR":
        clean = re.sub(r"[ -]", "", val)
        if len(clean) == 12:
            return f"XXXX-XXXX-{clean[-4:]}"
        return "XXXX-XXXX-XXXX"
    elif entity_type == "PAN_CARD":
        if len(val) == 10:
            return f"{val[:3]}****{val[-2:]}"
        return "**********"
    elif entity_type in ("RSA_PRIVATE_KEY", "SSH_PRIVATE_KEY", "PRIVATE_KEY_HEADER"):
        return "-----BEGIN PRIVATE KEY ... [REDACTED]-----"
    elif entity_type == "JWT_TOKEN":
        parts = val.split(".")
        if len(parts) == 3:
            return f"{parts[0][:10]}...[JWT_PAYLOAD_MASKED]...{parts[2][-6:]}"
        return "eyJ...[REDACTED_JWT]"
    elif entity_type in ("PASSWORD", "PASSWORD_IN_TEXT", "DATABASE_URI"):
        return "********[REDACTED_SECRET]********"
    elif entity_type == "PHONE_NUMBER":
        digits = re.sub(r"\D", "", val)
        if len(digits) >= 10:
            return f"+**-***-***{digits[-4:]}"
        return "+**-***-****"
    
    # Generic masking
    if len(val) > 6:
        return f"{val[:2]}...{val[-2:]}"
    return "****"


@dataclass
class DetectedEntity:
    entity_type: str
    category: str
    matched_text: str
    masked_value: str
    start: int
    end: int
    confidence: float
    context_snippet: str
    validation_passed: bool
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DetectionResult:
    entities: List[DetectedEntity] = field(default_factory=list)
    category_counts: Dict[str, int] = field(default_factory=dict)
    entity_type_counts: Dict[str, int] = field(default_factory=dict)
    total_count: int = 0
    highest_severity_category: str = "PERSONAL"
    raw_findings_summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entities": [e.to_dict() for e in self.entities],
            "category_counts": self.category_counts,
            "entity_type_counts": self.entity_type_counts,
            "total_count": self.total_count,
            "highest_severity_category": self.highest_severity_category,
            "raw_findings_summary": self.raw_findings_summary
        }


class EntityDetector:
    """
    Comprehensive Modular Entity Detector for Enterprise DLP.
    Scans plain text and extracted document contents across multiple categories.
    """

    CATEGORIES = ["CREDENTIALS", "FINANCIAL", "IDENTITY", "PERSONAL", "CORPORATE", "HEALTH"]
    
    # Severity weight per category for risk calculations
    CATEGORY_SEVERITY_WEIGHTS = {
        "CREDENTIALS": 1.0,
        "FINANCIAL": 0.9,
        "IDENTITY": 0.85,
        "HEALTH": 0.8,
        "CORPORATE": 0.75,
        "PERSONAL": 0.6
    }

    def __init__(self):
        self._compile_patterns()

    def _compile_patterns(self):
        """Compile optimized regex patterns with context-aware boundaries."""
        self.patterns = {
            # ==================== CREDENTIALS & SECRETS ====================
            "AWS_ACCESS_KEY": {
                "category": "CREDENTIALS",
                "pattern": re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
                "base_confidence": 0.98,
                "validator": lambda m: len(m) == 20
            },
            "AWS_SECRET_KEY": {
                "category": "CREDENTIALS",
                "pattern": re.compile(r"(?:aws_secret_access_key|aws_sec_key|secret_key)[\s:=\"']+([A-Za-z0-9/+=]{40})[\s\"']?", re.IGNORECASE),
                "base_confidence": 0.95,
                "validator": lambda m: len(m) == 40 and shannon_entropy(m) > 3.8
            },
            "RSA_PRIVATE_KEY": {
                "category": "CREDENTIALS",
                "pattern": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[^-]+-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", re.DOTALL),
                "base_confidence": 1.0,
                "validator": lambda m: "PRIVATE KEY" in m
            },
            "PRIVATE_KEY_HEADER": {
                "category": "CREDENTIALS",
                "pattern": re.compile(r"-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----", re.IGNORECASE),
                "base_confidence": 1.0,
                "validator": lambda m: True
            },
            "JWT_TOKEN": {
                "category": "CREDENTIALS",
                "pattern": re.compile(r"\b(eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})\b"),
                "base_confidence": 0.96,
                "validator": lambda m: m.count(".") == 2 and shannon_entropy(m) > 4.0
            },
            "GENERIC_API_KEY": {
                "category": "CREDENTIALS",
                "pattern": re.compile(r"(?:api_key|apikey|secret_token|access_token|bearer_token)[\s:=\"']+([A-Za-z0-9_\-]{24,64})[\s\"']?", re.IGNORECASE),
                "base_confidence": 0.88,
                "validator": lambda m: len(m) >= 24 and shannon_entropy(m) > 3.5
            },
            "PASSWORD_IN_CONFIG": {
                "category": "CREDENTIALS",
                "pattern": re.compile(r"(?:password|passwd|db_password|pwd|admin_pass|client_secret)[\s:=]+[\"']?([^\s\"';,#]{6,64})[\"']?", re.IGNORECASE),
                "base_confidence": 0.85,
                "validator": lambda m: not m.lower() in ("null", "none", "true", "false", "default", "changeme", "example")
            },
            "DATABASE_URI": {
                "category": "CREDENTIALS",
                "pattern": re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|mssql):\/\/[a-zA-Z0-9_\-\.]+:[^@\s\/]+@[a-zA-Z0-9_\-\.]+(?::\d+)?\/[a-zA-Z0-9_\-\.]*\b", re.IGNORECASE),
                "base_confidence": 0.98,
                "validator": lambda m: "@" in m and ":" in m
            },

            # ==================== FINANCIAL DATA ====================
            "CREDIT_CARD": {
                "category": "FINANCIAL",
                # Visa, MasterCard, Amex, Discover, Diners, JCB, RuPay
                "pattern": re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11}|(?:508[5-9]|652[1-2]|608[0-5])[0-9]{12})\b|\b(?:\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{4})\b"),
                "base_confidence": 0.95,
                "validator": lambda m: luhn_checksum(m)
            },
            "IBAN": {
                "category": "FINANCIAL",
                "pattern": re.compile(r"\b([A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16})\b"),
                "base_confidence": 0.90,
                "validator": lambda m: 15 <= len(re.sub(r"\s", "", m)) <= 34
            },
            "SWIFT_BIC": {
                "category": "FINANCIAL",
                "pattern": re.compile(r"\b(?:SWIFT|BIC|SWIFT-BIC|ROUTING CODE)[\s:#]+([A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b", re.IGNORECASE),
                "base_confidence": 0.92,
                "validator": lambda m: len(m) in (8, 11)
            },
            "CRYPTO_WALLET": {
                "category": "FINANCIAL",
                # Bitcoin (Legacy/Segwit) & Ethereum addresses
                "pattern": re.compile(r"\b(1[a-km-zA-HJ-NP-Z1-9]{25,34}|3[a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,39}|0x[a-fA-F0-9]{40})\b"),
                "base_confidence": 0.92,
                "validator": lambda m: (m.startswith("0x") and len(m) == 42) or (m.startswith(("1", "3", "bc1")) and len(m) >= 26)
            },
            "PAN_CARD": {
                "category": "FINANCIAL",
                # Indian Income Tax PAN (5 letters, 4 digits, 1 letter)
                "pattern": re.compile(r"\b([A-Z]{5}[0-9]{4}[A-Z]{1})\b"),
                "base_confidence": 0.92,
                "validator": lambda m: m[3] in "CPHFATBLJG" # Valid fourth character for PAN holder status
            },

            # ==================== IDENTITY DATA ====================
            "SSN": {
                "category": "IDENTITY",
                "pattern": re.compile(r"\b(?!000|666|9\d{2})([0-8]\d{2})[- ](?!00)(\d{2})[- ](?!0000)(\d{4})\b"),
                "base_confidence": 0.93,
                "validator": lambda m: True
            },
            "AADHAAR": {
                "category": "IDENTITY",
                "pattern": re.compile(r"(?:(?:Aadhaar|Aadhar|UIDAI|Aadhaar Number|Aadhar No)[\s:#]*)?\b([2-9]{1}[0-9]{3}\s?[0-9]{4}\s?[0-9]{4})\b", re.IGNORECASE),
                "base_confidence": 0.92,
                "validator": lambda m: verhoeff_validate(m) or len(re.sub(r"\s", "", m)) == 12
            },
            "IDENTITY_CARD": {
                "category": "IDENTITY",
                "pattern": re.compile(r"\b(?:Identity Card|ID Card|Govt ID|National ID|Citizen ID|Voter ID|Identity Number)[\s:#]+([A-Z0-9\-\s]{5,20})\b", re.IGNORECASE),
                "base_confidence": 0.90,
                "validator": lambda m: len(m.strip()) >= 5
            },
            "PASSPORT_US": {
                "category": "IDENTITY",
                "pattern": re.compile(r"\b(?:passport|passport\s+no|passport\s+#)[\s:]*([A-Z0-9]{9})\b", re.IGNORECASE),
                "base_confidence": 0.88,
                "validator": lambda m: len(m) == 9
            },
            "DRIVING_LICENSE": {
                "category": "IDENTITY",
                "pattern": re.compile(r"\b(?:driver['\s]?s?\s*license|DLN?|DL[\s#]+)[\s:]*([A-Z0-9]{7,14})\b", re.IGNORECASE),
                "base_confidence": 0.85,
                "validator": lambda m: len(m) >= 7
            },

            # ==================== PERSONAL DATA (PII) ====================
            "EMAIL": {
                "category": "PERSONAL",
                "pattern": re.compile(r"\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b"),
                "base_confidence": 0.95,
                "validator": lambda m: not m.endswith((".png", ".jpg", ".gif", ".svg", ".css", ".js"))
            },
            "PHONE_NUMBER": {
                "category": "PERSONAL",
                "pattern": re.compile(r"\b(?:\+?[1-9]\d{0,2}[ -]?)?\(?\d{3}\)?[ -]?\d{3}[ -]?\d{4}\b"),
                "base_confidence": 0.85,
                "validator": lambda m: 10 <= len(re.sub(r"\D", "", m)) <= 15
            },
            "DATE_OF_BIRTH": {
                "category": "PERSONAL",
                "pattern": re.compile(r"\b(?:DOB|Birth Date|Date of Birth)[\s:]+(\d{1,2}[/-]\d{1,2}[/-]\d{2,4})\b", re.IGNORECASE),
                "base_confidence": 0.88,
                "validator": lambda m: True
            },
            "PERSON_NAME": {
                "category": "PERSONAL",
                "pattern": re.compile(r"\b(?:Name|Full Name|Employee Name|Candidate Name)[\s:#]+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)\b"),
                "base_confidence": 0.82,
                "validator": lambda m: len(m.split()) >= 2
            },

            # ==================== CORPORATE & EMPLOYEE DATA ====================
            "EMPLOYEE_ID": {
                "category": "CORPORATE",
                "pattern": re.compile(r"\b(?:EMP[-_]?[0-9]{3,8}|(?:Employee ID|Staff ID|Badge ID)[\s:#]+([A-Z0-9-_]{3,12}))\b", re.IGNORECASE),
                "base_confidence": 0.92,
                "validator": lambda m: len(m.strip()) >= 3
            },
            "SALARY_COMPENSATION": {
                "category": "CORPORATE",
                "pattern": re.compile(r"\b(?:Salary|Gross Pay|Net Pay|Base Pay|CTC|Compensation)[\s:#|=]+([$₹€£]?[0-9,]{4,}(?:\.\d{2})?(?:\s*(?:USD|INR|EUR|GBP|LPA|per month|p\.a\.))?)\b", re.IGNORECASE),
                "base_confidence": 0.90,
                "validator": lambda m: len(m.strip()) >= 4
            },
            "CONFIDENTIALITY_NOTICE": {
                "category": "CORPORATE",
                "pattern": re.compile(r"\b(STRICTLY CONFIDENTIAL|HIGHLY CONFIDENTIAL|PROPRIETARY AND CONFIDENTIAL|TRADE SECRET|INTERNAL USE ONLY|DO NOT DISTRIBUTE|PRIVILEGED & CONFIDENTIAL|RESTRICTED ACCESS)\b", re.IGNORECASE),
                "base_confidence": 0.95,
                "validator": lambda m: True
            },
            "MERGER_ACQUISITION": {
                "category": "CORPORATE",
                "pattern": re.compile(r"\b(merger and acquisition|m&a target|non-disclosure agreement|confidential offering memorandum|term sheet confidential|due diligence report)\b", re.IGNORECASE),
                "base_confidence": 0.90,
                "validator": lambda m: True
            },
            "SOURCE_CODE_SECRETS": {
                "category": "CORPORATE",
                "pattern": re.compile(r"(?:SECRET_KEY|ENCRYPTION_KEY|SALT_KEY|PRIVATE_TOKEN)\s*=\s*[\"']([^\"']{16,})[\"']"),
                "base_confidence": 0.94,
                "validator": lambda m: shannon_entropy(m) > 3.2
            },

            # ==================== HEALTHCARE (HIPAA) ====================
            "MEDICAL_RECORD_NUMBER": {
                "category": "HEALTH",
                "pattern": re.compile(r"\b(?:MRN|Medical Record Number|Patient ID)[\s:#]+([A-Z0-9]{6,12})\b", re.IGNORECASE),
                "base_confidence": 0.88,
                "validator": lambda m: True
            },
            "HEALTH_INSURANCE_ID": {
                "category": "HEALTH",
                "pattern": re.compile(r"\b(?:Policy Number|Member ID|RxBIN)[\s:#]+([A-Z0-9]{8,14})\b", re.IGNORECASE),
                "base_confidence": 0.85,
                "validator": lambda m: True
            }
        }

    def _extract_context(self, text: str, start: int, end: int, window: int = 50) -> str:
        """Extract surrounding text context for SOC analyst review and confidence adjustment."""
        c_start = max(0, start - window)
        c_end = min(len(text), end + window)
        prefix = "..." if c_start > 0 else ""
        suffix = "..." if c_end < len(text) else ""
        return f"{prefix}{text[c_start:c_end].strip()}{suffix}"

    def scan_text(self, text: str, max_entities: int = 200) -> DetectionResult:
        """
        Scan plain text for all sensitive entity categories and return structured findings.
        """
        if not text or not isinstance(text, str):
            return DetectionResult()

        detected: List[DetectedEntity] = []
        category_counts = {cat: 0 for cat in self.CATEGORIES}
        entity_type_counts: Dict[str, int] = {}
        
        seen_spans = set()  # Prevent overlapping duplicate matches

        for entity_type, config in self.patterns.items():
            category = config["category"]
            regex = config["pattern"]
            base_conf = config["base_confidence"]
            validator = config.get("validator")

            for match in regex.finditer(text):
                if len(detected) >= max_entities:
                    break

                # Support both group extraction and full match
                matched_val = next((g for g in match.groups() if g is not None), match.group(0)) if match.lastindex else match.group(0)
                if not matched_val:
                    matched_val = match.group(0)
                span = (match.start(), match.end())
                
                # Check for overlap
                if any(s <= span[0] < e or s < span[1] <= e for s, e in seen_spans):
                    continue

                # Run algorithmic validation if defined
                val_passed = True
                confidence = base_conf
                if validator:
                    try:
                        val_passed = validator(matched_val)
                    except Exception:
                        val_passed = False

                if not val_passed:
                    # Penalize confidence if algorithm validation fails (e.g. Luhn failed)
                    confidence = max(0.1, confidence - 0.45)
                    # For strict types like credit cards or aadhaar, skip if checksum completely fails
                    if entity_type in ("CREDIT_CARD", "AADHAAR") and not val_passed:
                        continue

                seen_spans.add(span)
                masked_val = mask_sensitive_value(matched_val, entity_type)
                context_snippet = self._extract_context(text, span[0], span[1])

                entity = DetectedEntity(
                    entity_type=entity_type,
                    category=category,
                    matched_text=matched_val,
                    masked_value=masked_val,
                    start=span[0],
                    end=span[1],
                    confidence=round(confidence, 3),
                    context_snippet=context_snippet,
                    validation_passed=val_passed,
                    details={"entropy": round(shannon_entropy(matched_val), 2)}
                )

                detected.append(entity)
                category_counts[category] = category_counts.get(category, 0) + 1
                entity_type_counts[entity_type] = entity_type_counts.get(entity_type, 0) + 1

        # Determine highest severity category
        highest_sev = "PERSONAL"
        max_weight = 0.0
        for cat, count in category_counts.items():
            if count > 0:
                weight = self.CATEGORY_SEVERITY_WEIGHTS.get(cat, 0.5)
                if weight > max_weight:
                    max_weight = weight
                    highest_sev = cat

        # Generate human-readable summary
        summary_parts = []
        for cat in self.CATEGORIES:
            c = category_counts.get(cat, 0)
            if c > 0:
                summary_parts.append(f"{cat}: {c}")
        findings_summary = ", ".join(summary_parts) if summary_parts else "No sensitive entities detected"

        return DetectionResult(
            entities=detected,
            category_counts=category_counts,
            entity_type_counts=entity_type_counts,
            total_count=len(detected),
            highest_severity_category=highest_sev,
            raw_findings_summary=findings_summary
        )


# Singleton instance for direct import
entity_detector = EntityDetector()
