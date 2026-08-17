import re
from typing import List, Dict, Any, Tuple
from backend.utils.helpers import get_logger

logger = get_logger("SentinelDLP.NLPService")

class NLPService:
    def __init__(self):
        self._init_patterns()

    def _init_patterns(self):
        """Compile regex patterns for high-speed sensitive data discovery."""
        self.patterns = {
            # 1. Indian National Identity Documents (Aadhaar & PAN Card)
            "AADHAAR_NUMBER": (
                re.compile(r"\b([2-9]\d{3}[-\s]?\d{4}[-\s]?\d{4})\b"),
                92, "HIGHLY_CONFIDENTIAL"
            ),
            "AADHAAR_KEYWORD": (
                re.compile(r"(?i)\b(aadhaar|aadhar|uidai|mera\s*aadhaar|unique\s*identification\s*authority)\b"),
                85, "CONFIDENTIAL"
            ),
            "PAN_CARD_NUMBER": (
                re.compile(r"\b([A-Z]{5}[0-9]{4}[A-Z]{1})\b", re.IGNORECASE),
                92, "HIGHLY_CONFIDENTIAL"
            ),
            "PAN_CARD_KEYWORD": (
                re.compile(r"(?i)\b(pan\s*card|pan\s*no|pan\s*number|permanent\s*account\s*number|income\s*tax\s*department)\b"),
                85, "CONFIDENTIAL"
            ),
            "PASSPORT_NUMBER": (
                re.compile(r"(?i)\b(passport\s*(?:no|num|number)?\s*[:=]?\s*[A-PR-WYa-pr-wy0-9]{8,12})\b|\b([A-PR-WYa-pr-wy][1-9]\d\s?\d{4}[1-9])\b"),
                90, "HIGHLY_CONFIDENTIAL"
            ),
            "VOTER_OR_DL_ID": (
                re.compile(r"(?i)\b(voter\s*id|epic\s*no|driving\s*licen[sc]e|dl\s*no)\s*[:=]?\s*([A-Za-z0-9\-\/]{6,20})\b|\b([A-Z]{2}[0-9]{2}[0-9]{4}[0-9]{7})\b"),
                85, "CONFIDENTIAL"
            ),

            # 2. Employee Details & HR / Payroll Records
            "EMPLOYEE_SALARY_RECORD": (
                re.compile(r"(?i)\b(salary|ctc|compensation|payroll|gross\s*pay|net\s*pay|bonus\s*rollout|appraisal|annual\s*package|monthly\s*stipend|increment|basic\s*pay|hra|allowance)\s*[:=]?\s*(\$|₹|rs\.?|inr|usd|eur)?\s*([0-9,]+(?:\.[0-9]{2})?)\b"),
                88, "HIGHLY_CONFIDENTIAL"
            ),
            "EMPLOYEE_ID_RECORD": (
                re.compile(r"(?i)\b(employee\s*id|emp\s*id|emp_id|employee_id|staff\s*id|employee\s*code)\s*[:=]?\s*([A-Za-z0-9_\-\/]{3,24})\b"),
                75, "CONFIDENTIAL"
            ),
            "EMPLOYEE_PII_DIRECTORY": (
                re.compile(r"(?i)\b(date\s*of\s*birth|dob|joining\s*date|blood\s*group|emergency\s*contact|designation|department|reporting\s*manager)\s*[:=]\s*([^,\n\r]+)"),
                70, "CONFIDENTIAL"
            ),

            # 3. Company Credentials, Passwords & Secrets
            "AWS_ACCESS_KEY": (
                re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
                95, "HIGHLY_CONFIDENTIAL"
            ),
            "AWS_SECRET_KEY": (
                re.compile(r"(?i)\baws_secret_access_key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
                98, "HIGHLY_CONFIDENTIAL"
            ),
            "GITHUB_TOKEN": (
                re.compile(r"\b(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})\b"),
                98, "HIGHLY_CONFIDENTIAL"
            ),
            "OPENAI_API_KEY": (
                re.compile(r"\b(sk-[a-zA-Z0-9]{48,64}|sk-proj-[a-zA-Z0-9_\-]{48,128})\b"),
                95, "HIGHLY_CONFIDENTIAL"
            ),
            "SLACK_TOKEN": (
                re.compile(r"\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b"),
                92, "HIGHLY_CONFIDENTIAL"
            ),
            "GENERIC_API_KEY": (
                re.compile(r"(?i)\b(api_key|apikey|secret_key|client_secret|auth_token|access_token)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{16,64})['\"]"),
                90, "HIGHLY_CONFIDENTIAL"
            ),
            "JWT_TOKEN": (
                re.compile(r"\beyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\b"),
                80, "CONFIDENTIAL"
            ),
            "PRIVATE_KEY_HEADER": (
                re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----|\bssh-rsa\s+[A-Za-z0-9+/=]{100,}"),
                100, "HIGHLY_CONFIDENTIAL"
            ),
            "HARDCODED_PASSWORD": (
                re.compile(r"(?i)\b(password|passwd|pwd|db_pass|admin_pass|root_password|master_key)\s*[:=]\s*['\"]([^'\"\s]{6,64})['\"]"),
                90, "HIGHLY_CONFIDENTIAL"
            ),
            "DB_CONNECTION_STRING": (
                re.compile(r"(?i)(postgres|postgresql|mysql|mongodb|redis|mssql|oracle|sqlite):\/\/[a-zA-Z0-9_\-]+:[^@\s]+@[a-zA-Z0-9.\-]+"),
                98, "HIGHLY_CONFIDENTIAL"
            ),

            # 4. Financial & Payment Info
            "CREDIT_CARD_NUMBER": (
                re.compile(r"\b(?:4[0-9]{3}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}|5[1-5][0-9]{2}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}|3[47][0-9]{2}[-\s]?[0-9]{6}[-\s]?[0-9]{5}|4[0-9]{12}(?:[0-9]{3})?)\b"),
                92, "HIGHLY_CONFIDENTIAL"
            ),
            "IBAN_ACCOUNT": (
                re.compile(r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{12,30}\b"),
                80, "CONFIDENTIAL"
            ),

            # 5. Global National Identity & Contact Details
            "US_SSN": (
                re.compile(r"\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b"),
                92, "HIGHLY_CONFIDENTIAL"
            ),
            "EMAIL_ADDRESS": (
                re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"),
                30, "INTERNAL"
            ),
            "PHONE_NUMBER": (
                re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
                30, "INTERNAL"
            ),

            # 6. Corporate Confidentiality & Legal Markers
            "CONFIDENTIAL_MARKER": (
                re.compile(r"(?i)\b(strictly\s*confidential|highly\s*confidential|proprietary|trade\s*secret|do\s*not\s*distribute|internal\s*use\s*only|top\s*secret|nda\s*protected|company\s*confidential)\b"),
                80, "CONFIDENTIAL"
            ),
        }

    @staticmethod
    def _luhn_validate(card_num: str) -> bool:
        """Validate credit card number using Luhn algorithm."""
        digits = [int(c) for c in re.sub(r"\D", "", card_num)]
        if len(digits) < 13 or len(digits) > 19:
            return False
        checksum = 0
        reversed_digits = digits[::-1]
        for i, d in enumerate(reversed_digits):
            if i % 2 == 1:
                doubled = d * 2
                checksum += doubled - 9 if doubled > 9 else doubled
            else:
                checksum += d
        return checksum % 10 == 0

    def scan_text(self, text: str) -> Tuple[List[Dict[str, Any]], float, str]:
        """
        Scan extracted document text for sensitive entity patterns.
        """
        if not text:
            return [], 0.0, "PUBLIC"

        detected_entities = []
        max_score = 0.0
        highest_class = "PUBLIC"

        class_hierarchy = {
            "PUBLIC": 0,
            "INTERNAL": 1,
            "CONFIDENTIAL": 2,
            "HIGHLY_CONFIDENTIAL": 3
        }

        for entity_name, (pattern, base_score, classification) in self.patterns.items():
            matches = list(pattern.finditer(text))
            if not matches:
                continue

            valid_matches_count = 0
            sample_snippets = []

            for match in matches[:5]:
                matched_text = match.group(0)
                
                # Verify Credit Card matches with Luhn check
                if entity_name == "CREDIT_CARD_NUMBER":
                    if not self._luhn_validate(matched_text):
                        continue

                valid_matches_count += 1
                # Mask matched text for safe reporting
                if len(matched_text) > 4:
                    masked = matched_text[:2] + "*" * (len(matched_text) - 4) + matched_text[-2:]
                else:
                    masked = "***"
                sample_snippets.append(masked)

            if valid_matches_count > 0:
                density_bonus = min(15.0, (valid_matches_count - 1) * 3.0)
                effective_score = min(100.0, base_score + density_bonus)

                detected_entities.append({
                    "entity_type": entity_name,
                    "count": valid_matches_count,
                    "classification": classification,
                    "score": effective_score,
                    "samples": sample_snippets
                })

                if effective_score > max_score:
                    max_score = effective_score

                if class_hierarchy[classification] > class_hierarchy[highest_class]:
                    highest_class = classification

        return detected_entities, max_score, highest_class

nlp_service = NLPService()
