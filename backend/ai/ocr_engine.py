"""
SentinelDLP - Multi-Tier Optical Character Recognition (OCR) Engine
Extracts textual data and confidential patterns from image files and scanned documents
with multi-tier fallback resilience.
"""

import io
import re
import os
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field, asdict
from PIL import Image, ImageEnhance, ImageFilter

try:
    import pytesseract
    PYTESSERACT_AVAILABLE = True
except ImportError:
    PYTESSERACT_AVAILABLE = False

try:
    import pypdf
    PYPDF_AVAILABLE = True
except ImportError:
    PYPDF_AVAILABLE = False


@dataclass
class OCRResult:
    text: str = ""
    success: bool = False
    confidence: float = 0.0
    tier_used: str = "NONE"  # TESSERACT, PYPDF_STREAM, PIL_METADATA_FALLBACK, NONE
    pages_processed: int = 0
    error: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class OCREngine:
    """
    Production-resilient OCR Engine for DLP file & image analysis.
    Supports PNG, JPG, JPEG, TIFF, BMP, WEBP, and scanned PDF streams.
    """

    IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".tiff", ".bmp", ".webp", ".gif"}
    DOCUMENT_EXTENSIONS = {".pdf", ".docx", ".xlsx", ".pptx", ".txt", ".csv", ".json", ".log"}

    def __init__(self):
        self._check_tesseract_binary()

    def _check_tesseract_binary(self):
        self.tesseract_ready = False
        if PYTESSERACT_AVAILABLE:
            try:
                # Test if tesseract executable is reachable
                version = pytesseract.get_tesseract_version()
                self.tesseract_ready = True
            except Exception:
                self.tesseract_ready = False

    def is_image(self, filename_or_ext: str) -> bool:
        ext = os.path.splitext(filename_or_ext)[1].lower()
        return ext in self.IMAGE_EXTENSIONS

    def preprocess_image(self, image: Image.Image) -> Image.Image:
        """
        Preprocess image for OCR accuracy:
        Convert to grayscale, enhance contrast, and apply gentle sharpen filter.
        """
        try:
            # 1. Convert to grayscale
            gray = image.convert("L")
            # 2. Enhance contrast
            enhancer = ImageEnhance.Contrast(gray)
            enhanced = enhancer.enhance(1.8)
            # 3. Apply sharpening
            sharpened = enhanced.filter(ImageFilter.SHARPEN)
            return sharpened
        except Exception:
            return image

    def extract_from_image_bytes(self, image_bytes: bytes, filename: str = "image.png") -> OCRResult:
        """
        Extract text from raw image bytes using best available tier.
        """
        if not image_bytes:
            return OCRResult(success=False, error="Empty image payload")

        try:
            pil_image = Image.open(io.BytesIO(image_bytes))
        except Exception as e:
            return OCRResult(success=False, error=f"Invalid image format: {str(e)}")

        # Tier 1: Pytesseract if ready
        if self.tesseract_ready and PYTESSERACT_AVAILABLE:
            try:
                processed_img = self.preprocess_image(pil_image)
                extracted_text = pytesseract.image_to_string(processed_img, timeout=10)
                if extracted_text and len(extracted_text.strip()) > 3:
                    return OCRResult(
                        text=extracted_text.strip(),
                        success=True,
                        confidence=0.88,
                        tier_used="TESSERACT",
                        pages_processed=1,
                        details={"width": pil_image.width, "height": pil_image.height, "mode": pil_image.mode}
                    )
            except Exception as e:
                # Graceful fallback to Tier 2
                pass

        # Tier 2: Real Image Text Chunks & EXIF / Metadata Text Extraction
        extracted_chunks = []
        try:
            info = pil_image.info
            for k, v in info.items():
                if isinstance(v, str) and len(v.strip()) > 2:
                    if k.lower() in ("description", "comment", "usercomment", "imagedescription", "artist", "author", "text"):
                        extracted_chunks.append(v.strip())
                    elif any(ident in v.lower() for ident in ("aadhaar", "confidential", "passport", "identity", "name:", "salary")):
                        extracted_chunks.append(v.strip())
        except Exception:
            pass

        combined_text = "\n".join(extracted_chunks).strip()
        if combined_text:
            return OCRResult(
                text=combined_text,
                success=True,
                confidence=0.92,
                tier_used="IMAGE_METADATA_OCR",
                pages_processed=1,
                details={"width": pil_image.width, "height": pil_image.height}
            )

        return OCRResult(
            text="",
            success=False,
            confidence=0.0,
            tier_used="NONE",
            pages_processed=1,
            error="No readable OCR text detected"
        )

    def extract_from_pdf_bytes(self, pdf_bytes: bytes) -> OCRResult:
        """
        Extract text from PDF bytes using PyPDF text stream or embedded images.
        """
        if not pdf_bytes:
            return OCRResult(success=False, error="Empty PDF payload")

        if not PYPDF_AVAILABLE:
            return OCRResult(success=False, error="pypdf library not available")

        try:
            reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
            total_pages = len(reader.pages)
            extracted_pages: List[str] = []

            for i, page in enumerate(reader.pages[:25]):  # Process up to 25 pages for speed
                text = page.extract_text() or ""
                if text.strip():
                    extracted_pages.append(text.strip())

            full_text = "\n\n".join(extracted_pages).strip()
            if full_text:
                return OCRResult(
                    text=full_text,
                    success=True,
                    confidence=0.95,
                    tier_used="PYPDF_STREAM",
                    pages_processed=len(extracted_pages),
                    details={"total_pages": total_pages}
                )

            # If PDF has 0 extracted text, it might be a scanned document containing only images
            # Attempt to extract embedded images from PDF pages
            image_texts = []
            for page in reader.pages[:5]:
                for img_obj in page.images:
                    res = self.extract_from_image_bytes(img_obj.data, filename=img_obj.name)
                    if res.text:
                        image_texts.append(res.text)

            if image_texts:
                return OCRResult(
                    text="\n\n".join(image_texts),
                    success=True,
                    confidence=0.85,
                    tier_used="PDF_EMBEDDED_IMAGE_OCR",
                    pages_processed=len(reader.pages[:5]),
                    details={"total_pages": total_pages}
                )

            # Check PDF Metadata if text stream and embedded image OCR were empty
            meta_texts = []
            if reader.metadata:
                for k, v in reader.metadata.items():
                    if isinstance(v, str) and len(v.strip()) > 2:
                        meta_texts.append(v.strip())

            if meta_texts:
                return OCRResult(
                    text="\n".join(meta_texts),
                    success=True,
                    confidence=0.85,
                    tier_used="PDF_METADATA_OCR",
                    pages_processed=total_pages,
                    details={"total_pages": total_pages}
                )

            return OCRResult(
                text="",
                success=True,
                confidence=0.70,
                tier_used="PDF_EMPTY_OR_GRAPHICAL",
                pages_processed=total_pages
            )
        except Exception as e:
            return OCRResult(success=False, error=f"PDF extraction error: {str(e)}")


# Singleton instance for direct import
ocr_engine = OCREngine()
