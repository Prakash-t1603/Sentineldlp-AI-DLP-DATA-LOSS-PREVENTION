import sys
from pathlib import Path

# Ensure project root is in python sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

# Register smart OCR mock extractor for test environments where EasyOCR/Tesseract weights are not present
from backend.services.ocr_service import ocr_service

_test_text_registry = {
    "sample_id": "GOVT OF INDIA UNIQUE IDENTIFICATION AUTHORITY Name: Meera Patel 7766 5544 3322 Mera Aadhaar Meri Pehchan",
    "WhatsApp Image": "GOVT OF INDIA UNIQUE IDENTIFICATION AUTHORITY Name: Rahul Sharma 5489 1234 8901 Mera Aadhaar Meri Pehchan",
    "aadhar_sample": "GOVT OF INDIA UNIQUE IDENTIFICATION AUTHORITY Name: Anjali Verma 8899 4433 2211 Mera Aadhaar Meri Pehchan",
    "vacation_photo": "GOVT OF INDIA UNIQUE IDENTIFICATION AUTHORITY Name: Anjali Verma 8899 4433 2211 Mera Aadhaar Meri Pehchan",
    "folder_sensitive": "GOVT OF INDIA UNIQUE IDENTIFICATION AUTHORITY Name: Vikram Singh 9900 1122 3344 Mera Aadhaar Meri Pehchan",
    "folder_clean": "Weekly Team Sync Meeting Agenda and Discussion Notes Project roadmap timeline review Open Source Documentation Guidelines"
}

def _test_ocr_extractor(filepath: Path) -> str:
    path_str = str(filepath)
    for key, txt in _test_text_registry.items():
        if key in path_str:
            return txt
    return ""

ocr_service._mock_extractor = _test_ocr_extractor
