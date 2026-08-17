import os
import re
import platform
from pathlib import Path
from typing import Optional, Dict, Any
from backend.utils.helpers import get_logger

logger = get_logger("SentinelDLP.OCRService")

SUPPORTED_OCR_EXTENSIONS = {".jpg", ".jpeg", ".png", ".bmp", ".tiff", ".webp"}

class OCRService:
    def __init__(self):
        self._easyocr_reader = None
        self._initialized = False

    def is_image_file(self, filepath: Path) -> bool:
        """Check if file extension is a supported image format for OCR."""
        if not filepath:
            return False
        return filepath.suffix.lower() in SUPPORTED_OCR_EXTENSIONS

    def _preprocess_image(self, img):
        """Enhance image for OCR accuracy (convert to RGB, resize small images)."""
        try:
            from PIL import Image
            if img.mode != "RGB":
                img = img.convert("RGB")
            w, h = img.size
            if w < 1000 or h < 1000:
                scale = max(1000 / w, 1000 / h, 1.5)
                new_w, new_h = int(w * scale), int(h * scale)
                img = img.resize((new_w, new_h), Image.Resampling.LANCZOS)
        except Exception:
            pass
        return img

    def extract_text_from_image(self, filepath: Path) -> str:
        """
        Extract text from an image file using multi-tier OCR engines:
        1. Native Windows 10/11 WinOCR (Instant & highly accurate)
        2. EasyOCR (PyTorch-based)
        3. PyTesseract (Tesseract OCR fallback)
        """
        if not filepath or not filepath.exists() or not filepath.is_file():
            return ""

        if not self.is_image_file(filepath):
            return ""

        # 1. Try native Windows 10/11 WinOCR
        try:
            import winocr
            from PIL import Image
            with Image.open(filepath) as raw_img:
                img = self._preprocess_image(raw_img)
                res = winocr.recognize_pil_sync(img, 'en')
                text = res.get('text', '').strip()
                if text:
                    logger.info(f"WinOCR successfully extracted {len(text)} chars from {filepath.name}")
                    return text
        except Exception as e:
            logger.debug(f"WinOCR attempt for {filepath.name}: {e}")

        # 2. Try EasyOCR
        try:
            import easyocr
            if self._easyocr_reader is None:
                self._easyocr_reader = easyocr.Reader(['en'], gpu=False, verbose=False)
            results = self._easyocr_reader.readtext(str(filepath), detail=0)
            text = " ".join(results).strip()
            if text:
                logger.info(f"EasyOCR extracted {len(text)} chars from {filepath.name}")
                return text
        except Exception as e:
            logger.debug(f"EasyOCR attempt for {filepath.name}: {e}")

        # 3. Try PyTesseract
        try:
            from PIL import Image
            import pytesseract
            with Image.open(filepath) as raw_img:
                img = self._preprocess_image(raw_img)
                text = pytesseract.image_to_string(img).strip()
                if text:
                    logger.info(f"PyTesseract extracted {len(text)} chars from {filepath.name}")
                    return text
        except Exception:
            pass

        return ""

    def classify_image_document(self, filepath: Path, ocr_text: str = "") -> Dict[str, Any]:
        """
        Deep visual and semantic classification of an image document.
        Identifies the exact type of document (Aadhaar Card, PAN Card, Passport, ID Card, Payment Card, Credentials)
        strictly based on extracted OCR content.
        """
        if not ocr_text and filepath and filepath.exists():
            ocr_text = self.extract_text_from_image(filepath)

        # Log first ~100 characters of extracted text for verification
        logger.info(f"OCR Extracted text from '{filepath.name if filepath else 'image'}': '{ocr_text[:100]}'")

        if not ocr_text or not ocr_text.strip():
            logger.warning(f"OCR extraction failed or returned empty text for image: {filepath.name if filepath else 'unknown'}")
            return {
                "document_type": "Unclassified Image (OCR Empty/Failed)",
                "is_sensitive": False,
                "classification": "Unknown/Unclassified",
                "sensitivity_score": 25.0,
                "details": "OCR extraction yielded no readable text. Flagged as Unknown/Unclassified for manual investigation.",
                "extracted_number": None,
                "extracted_text": ""
            }

        text_lower = ocr_text.lower()

        # 1. Aadhaar Card (National ID)
        aadhaar_num_match = re.search(r"\b([2-9]\d{3}[-\s]?\d{4}[-\s]?\d{4})\b", ocr_text)
        aadhaar_kw = [w for w in ["aadhaar", "aadhar", "uidai", "unique identification", "mera aadhaar", "govt of india", "government of india", "enrollment no", "bharat sarkar"] if w in text_lower]
        if (aadhaar_num_match and len(aadhaar_kw) >= 1) or ("aadhaar" in text_lower or "aadhar" in text_lower or "uidai" in text_lower):
            num_str = aadhaar_num_match.group(0) if aadhaar_num_match else "Detected via UIDAI Header"
            masked = num_str[:4] + " **** " + num_str[-4:] if len(num_str) >= 8 else num_str
            return {
                "document_type": "Aadhaar Card (National ID)",
                "is_sensitive": True,
                "classification": "HIGHLY_CONFIDENTIAL",
                "sensitivity_score": 95.0,
                "details": f"Aadhaar No: {masked} | UIDAI Govt of India Identity Document",
                "extracted_number": masked,
                "extracted_text": ocr_text
            }

        # 2. PAN Card (Income Tax Department)
        pan_num_match = re.search(r"\b([A-Z]{5}[0-9]{4}[A-Z]{1})\b", ocr_text, re.IGNORECASE)
        pan_kw = [w for w in ["income tax", "permanent account", "pan card", "pan no", "incometax", "income tax department", "govt. of india"] if w in text_lower]
        if (pan_num_match and len(pan_kw) >= 1) or ("permanent account" in text_lower or "income tax department" in text_lower):
            pan_str = pan_num_match.group(0).upper() if pan_num_match else "Detected via Income Tax Header"
            return {
                "document_type": "PAN Card (Income Tax Identity)",
                "is_sensitive": True,
                "classification": "HIGHLY_CONFIDENTIAL",
                "sensitivity_score": 95.0,
                "details": f"PAN No: {pan_str} | Income Tax Department Govt of India",
                "extracted_number": pan_str,
                "extracted_text": ocr_text
            }

        # 3. Passport Document
        passport_match = re.search(r"\b([A-PR-WYa-pr-wy][1-9]\d\s?\d{4}[1-9])\b", ocr_text)
        passport_kw = [w for w in ["passport", "republic of india", "p<ind", "nationality", "place of birth", "type p", "date of expiry"] if w in text_lower]
        if (passport_match and len(passport_kw) >= 1) or ("passport" in text_lower and len(passport_kw) >= 2):
            pass_str = passport_match.group(0) if passport_match else "Detected"
            return {
                "document_type": "Passport Document",
                "is_sensitive": True,
                "classification": "HIGHLY_CONFIDENTIAL",
                "sensitivity_score": 95.0,
                "details": f"Passport Identity Document | No: {pass_str}",
                "extracted_number": pass_str,
                "extracted_text": ocr_text
            }

        # 4. Driving License / Voter ID
        dl_voter_kw = [w for w in ["driving licence", "driving license", "transport department", "election commission", "voter id", "epic no", "elector photo identity"] if w in text_lower]
        if len(dl_voter_kw) >= 1:
            return {
                "document_type": "Government Driving License / Voter ID",
                "is_sensitive": True,
                "classification": "CONFIDENTIAL",
                "sensitivity_score": 88.0,
                "details": f"Government Issued ID ({', '.join(dl_voter_kw) if dl_voter_kw else 'ID Scan'})",
                "extracted_number": None,
                "extracted_text": ocr_text
            }

        # 5. Credit / Debit Payment Card
        cc_match = re.search(r"\b(?:4[0-9]{3}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}|5[1-5][0-9]{2}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4})\b", ocr_text)
        cc_kw = [w for w in ["visa", "mastercard", "rupay", "debit card", "credit card", "valid thru", "cvv", "expires"] if w in text_lower]
        if cc_match or len(cc_kw) >= 2:
            cc_str = cc_match.group(0) if cc_match else "Detected"
            masked_cc = cc_str[:4] + " **** **** " + cc_str[-4:] if len(cc_str) >= 12 else cc_str
            return {
                "document_type": "Credit / Debit Payment Card",
                "is_sensitive": True,
                "classification": "HIGHLY_CONFIDENTIAL",
                "sensitivity_score": 96.0,
                "details": f"Payment Card: {masked_cc}",
                "extracted_number": masked_cc,
                "extracted_text": ocr_text
            }

        # 6. Company Credentials / Secret Screenshot
        secret_kw = [w for w in ["api_key", "secret_key", "client_secret", "password", "root_password", "database_url", "postgres://", "mysql://", "aws_secret", "bearer ", "ssh-rsa"] if w in text_lower]
        if len(secret_kw) >= 1:
            return {
                "document_type": "Confidential Credentials Screenshot",
                "is_sensitive": True,
                "classification": "HIGHLY_CONFIDENTIAL",
                "sensitivity_score": 98.0,
                "details": f"Secrets / Credentials: {', '.join(secret_kw)}",
                "extracted_number": None,
                "extracted_text": ocr_text
            }

        # 7. Employee ID Badge / Salary Record
        emp_kw = [w for w in ["employee id", "emp id", "salary slip", "payslip", "gross pay", "net salary", "identity card", "staff id", "employee code"] if w in text_lower]
        if len(emp_kw) >= 1:
            return {
                "document_type": "Employee ID Badge / Salary Document",
                "is_sensitive": True,
                "classification": "CONFIDENTIAL",
                "sensitivity_score": 85.0,
                "details": f"Employee Record: {', '.join(emp_kw) if emp_kw else 'Employee Document'}",
                "extracted_number": None,
                "extracted_text": ocr_text
            }

        return {
            "document_type": "General Image Document",
            "is_sensitive": False,
            "classification": "PUBLIC",
            "sensitivity_score": 0.0,
            "details": "No sensitive identity or credential patterns detected in image",
            "extracted_number": None,
            "extracted_text": ocr_text
        }

ocr_service = OCRService()
