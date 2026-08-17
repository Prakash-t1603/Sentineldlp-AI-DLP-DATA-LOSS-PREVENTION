# Implementation Plan — SentinelDLP AI Content-Based Classification Engine Fix

## Problem Overview
SentinelDLP's Classification Engine currently makes sensitivity decisions based on filename strings (via `SENSITIVE_FILENAME_KEYWORDS` in `classifier_service.py` and filename pattern checks in `ocr_service.py`) rather than exclusively analyzing file byte content. As a result, renaming a sensitive image (e.g. `aadhar.jpeg` → `sample.jpeg`) causes detection to be bypassed if OCR fails or if filename heuristics were the sole trigger. Furthermore, caching and deduplication in monitor handlers are keyed by filepath string rather than SHA-256 content hashes, and failed/empty OCR extractions silently default to `"PUBLIC"`.

## User Review Required
> [!IMPORTANT]
> - Filename-based classification heuristics (`SENSITIVE_FILENAME_KEYWORDS`) will be completely eliminated from classification decisions. Filename and extension will strictly be used to select extraction handlers (OCR for images, PyPDF for PDFs, etc.).
> - Failed or empty OCR extractions on images will now classify as `"Unknown/Unclassified"` with a warning log rather than silently defaulting to `"PUBLIC"`.
> - Deduplication and classification caching will be strictly keyed by SHA-256 byte content hash.

## Proposed Changes

### 1. Classification & OCR Services

#### [MODIFY] [classifier_service.py](file:///c:/Users/praka/Music/employee-monitoring-system/backend/services/classifier_service.py)
- Remove `SENSITIVE_FILENAME_KEYWORDS` heuristic scoring logic from `classify_file()`.
- Add content-hash-based caching: `_content_hash_cache` dictionary keyed strictly by SHA-256 of file bytes.
- Add `get_cached_classification(file_hash: str)` and `cache_classification(file_hash: str, result: Dict[str, Any])` helper methods.
- Compute SHA-256 byte hash if `filepath` is provided, check cache before running extraction/classification, and store result in cache.
- Propagate `"Unknown/Unclassified"` status when OCR extraction fails on images.

#### [MODIFY] [ocr_service.py](file:///c:/Users/praka/Music/employee-monitoring-system/backend/services/ocr_service.py)
- Remove all `filename_lower` keyword checks across Aadhaar, PAN, Passport, DL/Voter ID, and Employee ID classification rules.
- Add debug logging of the first ~100 characters of extracted text for every image processed.
- Handle empty/failed OCR extraction: return `"document_type": "Unclassified Image (OCR Empty/Failed)"`, `"classification": "Unknown/Unclassified"`, `"sensitivity_score": 25.0`, and log a warning instead of returning `"PUBLIC"` with `0.0` score.

### 2. Schema & Models

#### [MODIFY] [schemas.py](file:///c:/Users/praka/Music/employee-monitoring-system/backend/schemas.py)
- Update regex patterns for `classification` and `sensitivity_level` to accept `"Unknown/Unclassified"`, `"UNKNOWN"`, `"UNCLASSIFIED"`, as well as standard tiers (`PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `HIGHLY_CONFIDENTIAL`).

### 3. Agent Monitors & File Router

#### [MODIFY] [file_monitor.py](file:///c:/Users/praka/Music/employee-monitoring-system/agent/file_monitor.py)
- Update `_recently_alerted` deduplication cache to key by file byte SHA-256 hash (`compute_file_hash(filepath)`) instead of `path_key` (filepath string).

#### [MODIFY] [usb_monitor.py](file:///c:/Users/praka/Music/employee-monitoring-system/agent/usb_monitor.py)
- Update `_recently_alerted` deduplication cache to key by file byte SHA-256 hash (`compute_file_hash(filepath)`) instead of `path_key` (filepath string).

### 4. Tests

#### [MODIFY] [test_classifier.py](file:///c:/Users/praka/Music/employee-monitoring-system/tests/test_classifier.py)
- Replace outdated `test_classifier_filename_heuristics` with content-based verification.
- Implement the 4 mandatory regression tests:
  1. `test_rename_does_not_bypass_detection`: Verify `aadhar_sample.jpg` and `vacation_photo.jpg` (identical Aadhaar image bytes) both classify as `HIGHLY_CONFIDENTIAL` with identical scores.
  2. `test_same_name_different_content_not_confused`: Verify two files with identical filename `sample.jpg` in different directories with different byte contents receive distinct classification results.
  3. `test_ocr_failure_does_not_default_to_safe`: Verify blank/corrupted image results in `"Unknown/Unclassified"` with a logged warning.
  4. `test_hash_cache_keyed_by_content_only`: Unit test cache lookup verifying identical bytes produce identical cache keys, different bytes produce different cache keys.

## Verification Plan

### Automated Tests
- Run `pytest` across all test suites to confirm 100% pass rate.
- Run dedicated test verification for:
  `pytest tests/test_classifier.py -v`
  `pytest tests/test_e2e_flow.py -v`
  `pytest tests/test_api.py -v`
  `pytest tests/test_agent.py -v`

### Manual / Scenario Verification (Step 4)
- Create synthetic Aadhaar card image named `sample.jpeg`.
- Process through full DLP pipeline (`extract_text_from_file` -> `classify_file` -> risk & alert evaluation).
- Verify and print alert output demonstrating that classification was driven strictly by OCR-extracted text content.
