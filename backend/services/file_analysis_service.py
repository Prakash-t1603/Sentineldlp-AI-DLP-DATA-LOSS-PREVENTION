import json
import csv
import io
import time
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional, Tuple
from backend.utils.helpers import get_logger

logger = get_logger("SentinelDLP.FileAnalysisService")

# Supported Document Extensions for direct text extraction
DOCUMENT_EXTENSIONS = {
    ".txt", ".csv", ".json", ".md", ".log", ".py", ".js",
    ".html", ".css", ".xml", ".yaml", ".yml", ".env", ".sql",
    ".conf", ".ini", ".key", ".pem", ".cert", ".tsv", ".cfg"
}
PDF_EXTENSIONS = {".pdf"}
DOCX_EXTENSIONS = {".docx", ".doc"}
PPTX_EXTENSIONS = {".pptx", ".ppt"}
IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".bmp", ".tiff", ".webp"}

# Max file size to analyze in memory (30MB)
MAX_ANALYSIS_FILE_SIZE = 30 * 1024 * 1024

class FileAnalysisService:
    @staticmethod
    def is_supported_document(filepath: Path) -> bool:
        ext = filepath.suffix.lower()
        return ext in (DOCUMENT_EXTENSIONS | PDF_EXTENSIONS | DOCX_EXTENSIONS | PPTX_EXTENSIONS | IMAGE_EXTENSIONS)

    @staticmethod
    def extract_text_from_file(filepath: Path, max_retries: int = 3) -> Tuple[str, str]:
        """
        Extract text from supported document types with retry handling for file write locks.
        Returns (extracted_text, method_used).
        """
        if not filepath or not filepath.exists() or not filepath.is_file():
            return "", "NOT_FOUND"

        for attempt in range(max_retries):
            try:
                file_size = filepath.stat().st_size
                if file_size == 0 and attempt < max_retries - 1:
                    time.sleep(0.3)
                    continue

                if file_size > MAX_ANALYSIS_FILE_SIZE:
                    logger.warning(f"File {filepath.name} exceeds max size ({file_size} bytes). Skipping deep extraction.")
                    return "", "SIZE_LIMIT_EXCEEDED"

                ext = filepath.suffix.lower()

                # 1. Plain Text, CSV, JSON, MD, Configs, SQL, .env
                if ext in DOCUMENT_EXTENSIONS:
                    text = FileAnalysisService._extract_plain_text(filepath)
                    if text or attempt == max_retries - 1:
                        return text, "PLAIN_TEXT"

                # 2. PDF Documents
                elif ext in PDF_EXTENSIONS:
                    text = FileAnalysisService._extract_pdf(filepath)
                    if text or attempt == max_retries - 1:
                        return text, "PYPDF"

                # 3. DOCX Documents
                elif ext in DOCX_EXTENSIONS:
                    text = FileAnalysisService._extract_docx(filepath)
                    if text or attempt == max_retries - 1:
                        return text, "DOCX"

                # 4. PPTX Presentations
                elif ext in PPTX_EXTENSIONS:
                    text = FileAnalysisService._extract_pptx(filepath)
                    if text or attempt == max_retries - 1:
                        return text, "PPTX"

                # 5. Image documents handled by OCR (Aadhaar cards, PAN cards, ID photos)
                elif ext in IMAGE_EXTENSIONS:
                    from backend.services.ocr_service import ocr_service
                    text = ocr_service.extract_text_from_image(filepath)
                    return text, "OCR"

            except (PermissionError, OSError) as e:
                if attempt < max_retries - 1:
                    time.sleep(0.3 * (attempt + 1))
                    continue
                logger.debug(f"File extraction retry exhausted for {filepath.name}: {e}")

            except Exception as e:
                logger.warning(f"Unexpected extraction error for {filepath.name}: {e}")
                break

        return "", "UNSUPPORTED_OR_EMPTY"

    @staticmethod
    def _extract_plain_text(filepath: Path) -> str:
        for encoding in ["utf-8", "utf-8-sig", "latin-1", "cp1252"]:
            try:
                with open(filepath, "r", encoding=encoding, errors="ignore") as f:
                    return f.read(150_000)  # Extract up to 150k chars for inspection
            except (PermissionError, OSError):
                raise
            except Exception:
                continue
        return ""

    @staticmethod
    def _extract_pdf(filepath: Path) -> str:
        try:
            from pypdf import PdfReader
            reader = PdfReader(str(filepath))
            text_parts = []
            for page in reader.pages[:30]:
                page_text = page.extract_text()
                if page_text:
                    text_parts.append(page_text)
            return "\n".join(text_parts)
        except Exception as e:
            logger.debug(f"PDF extraction error for {filepath.name}: {e}")
            return ""

    @staticmethod
    def _extract_docx(filepath: Path) -> str:
        try:
            import docx
            doc = docx.Document(str(filepath))
            text_parts = [p.text for p in doc.paragraphs if p.text.strip()]
            for table in doc.tables[:15]:
                for row in table.rows:
                    text_parts.append(" | ".join([c.text.strip() for c in row.cells if c.text.strip()]))
            return "\n".join(text_parts)
        except Exception as e:
            logger.debug(f"DOCX extraction error for {filepath.name}: {e}")
            return ""

    @staticmethod
    def _extract_pptx(filepath: Path) -> str:
        try:
            text_parts = []
            with zipfile.ZipFile(filepath, 'r') as z:
                slide_files = [f for f in z.namelist() if f.startswith("ppt/slides/slide") and f.endswith(".xml")]
                for slide in sorted(slide_files):
                    xml_content = z.read(slide)
                    tree = ET.fromstring(xml_content)
                    for elem in tree.iter():
                        if elem.tag.endswith('}t') and elem.text:
                            text_parts.append(elem.text.strip())
            return "\n".join(text_parts)
        except Exception as e:
            logger.debug(f"PPTX extraction error for {filepath.name}: {e}")
            return ""

file_analysis_service = FileAnalysisService()
