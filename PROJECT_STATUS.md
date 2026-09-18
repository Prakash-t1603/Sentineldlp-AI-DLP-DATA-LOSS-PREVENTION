# SentinelDLP AI - Project Implementation Status Report

## 1. Executive Project Summary
**SentinelDLP AI** is a production-grade, enterprise Data Loss Prevention (DLP) and User & Entity Behavior Analytics (UEBA) platform. Designed for distributed corporate environments, financial institutions, and regulated sectors, SentinelDLP AI protects corporate assets against data exfiltration across all primary endpoint vectors (Removable USB media, Browser & Cloud Storage uploads, Corporate Email attachments, Workstation Clipboard, Local Filesystem directories, and background exfiltration processes).

The system features an authoritative Master Employee Lifecycle and Hardware Device Binding architecture, dual-path AI/OCR inspection pipeline, multi-factor composite risk engine, dynamic statistical UEBA baselining, and a comprehensive real-time SOC Administrator Dashboard alongside a dedicated Employee Endpoint Portal.

---

## 2. Completed Architecture & Subsystems

### A. Backend Architecture & High-Concurrency Database (`backend/`)
- [x] **Authentication & Role-Based Access Control (`config.py`, `utils/security.py`, `routers/auth.py`)**:
  - Secure bcrypt password hashing with safe 72-byte truncation.
  - Cryptographic JWT token generation and verification with 24-hour expiration.
  - Multi-tier RBAC (`admin`, `security_analyst`, `employee`) and agent secret token header (`X-Agent-Secret`) validation.
- [x] **Database Engine & ORM (`database.py`, `models.py`)**:
  - SQLite with WAL (Write-Ahead Logging) mode and Foreign Key enforcement for ultra-low latency concurrent read/write transactions.
  - Schema parity and ready-to-deploy compatibility with enterprise PostgreSQL (`postgresql+psycopg://...`).
- [x] **Relational Data Models & Master Identity Attribution**:
  - `User`: RBAC credentials, email, active status, last login.
  - `Employee`: Master employee record (`employee_id`, full name, email, department, designation, status: `ONLINE`/`WARNING`/`OFFLINE`, composite risk score, last seen).
  - `Device`: Hardware endpoint binding (`device_id`, employee binding, hostname, OS, IP address, provisioned cryptographic `device_token`, monitoring state, dynamic status).
  - `DLPEvent`: Detailed audit ledger capturing event ID, channel (`USB`, `BROWSER`, `EMAIL`, `CLIPBOARD`, `FILE`), application, file name, hash, size, classification, sensitivity, entity breakdown, composite risk score, and policy action (`ALLOW`, `WARN`, `BLOCK`).
  - `DLPAnalysis`: Deep inspection audit records linked to events, preserving fast-path cache hit flags and explanation logs.
  - `Alert`: Real-time SOC threat notifications with severity mapping (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), employee/device correlation, and triage workflows (`OPEN`, `ACKNOWLEDGED`, `RESOLVED`).
  - `Incident`: Automated case generation for High and Critical severity threats with analyst assignment, containment status, and investigation notes.
  - `ActivityLog`: Real-time workstation event timeline (`CREATE`, `MODIFY`, `DELETE`, `MOVE`, `RENAME`, `USB_COPY`, `PROCESS_SPAWN`, `CLOUD_SYNC`).
  - `PolicyRule`: Dynamic enterprise DLP governance rules per channel and sensitivity tier.
  - `UEBAProfile` & `UEBAAnomaly`: 30-day rolling baseline metrics, event velocity, after-hours activity ratios, and statistical Z-score anomaly tracking.
- [x] **Pydantic v2 Schemas (`schemas.py`)**: Complete validation and serialization models using `ConfigDict(from_attributes=True)`.

### B. AI/ML, NLP & Multi-Tier OCR Pipeline Subsystem (`backend/ai/` & `backend/services/`)
- [x] **Multi-Format Document Extraction (`file_analysis_service.py`)**:
  - Native cell-by-cell extraction for spreadsheets (`.xlsx`, `.xls`) with header-column semantic mapping.
  - Paragraph, table, header, and footer extraction for `.docx` documents.
  - Delimiter-aware structured parsing for `.csv` and `.tsv`.
  - Recursive tree flattening for `.json` data files.
  - Multi-encoding plain text and code parsers (`.txt`, `.env`, `.py`, `.sql`, `.key`, `.log`, `.md`).
  - Scanned and vector PDF extraction via `pypdf` with automatic OCR fallback.
  - Strict 50MB file size safety ceiling to guard against memory exhaustion.
- [x] **Multi-Tier Optical Character Recognition (`ocr_engine.py`, `ocr_service.py`)**:
  - Image text extraction for `.png`, `.jpg`, `.jpeg`, `.tiff`, `.bmp`, and `.webp`.
  - Fault-tolerant fallback handling for non-image or unparseable payloads.
- [x] **6-Category Entity Recognition & Pattern Scanner (`entity_detector.py`, `nlp_service.py`)**:
  - Credentials & Secrets: AWS access keys (`AKIA...`), GitHub personal access tokens (`ghp_...`), Slack tokens, generic high-entropy API keys, private keys (`BEGIN PRIVATE KEY`), database connection strings.
  - Financial Data: Credit card numbers with algorithmic Luhn checksum verification.
  - National & Personal Identifiers: Indian Aadhaar numbers (Verhoeff checksum validation), Indian PAN cards, US Social Security Numbers (SSNs), corporate email addresses.
  - Contextual NLP Exfiltration Keywords: Confidential markings (`STRICTLY CONFIDENTIAL`, `INTERNAL ONLY`, `PROPRIETARY`, `BOARD ONLY`, `SALARY RECORD`).
  - Shannon Entropy Engine: Detects high-randomness cryptographic secrets.
- [x] **Machine Learning Sensitivity Classifier (`classifier.py`, `classifier_service.py`)**:
  - Scikit-Learn TF-IDF vectorizer + Calibrated Logistic Regression model.
  - 5-Tier Classification: `PUBLIC` (0.00-0.20), `INTERNAL` (0.21-0.50), `CONFIDENTIAL` (0.51-0.75), `RESTRICTED` (0.76-0.90), and `HIGHLY_CONFIDENTIAL` (0.91-1.00).
- [x] **Fast-Path SHA-256 Content Hash Caching**:
  - Instant microsecond response for duplicate files while maintaining independent event identity attribution and per-device logging.
- [x] **Explainable Confidence Engine (`confidence.py`)**:
  - Multi-factor transparency logs detailing base model probability, entity density bonuses, and regex confirmation weights.

### C. Multi-Factor Composite Risk & UEBA Analytics Engine (`backend/services/risk_service.py`, `backend/ai/ueba.py`)
- [x] **0 - 100 Composite Risk Calculation**:
  - Additive formula incorporating content sensitivity (0-50 pts), channel risk weight (0-20 pts: USB 1.0, Browser 0.9, Email 0.8, Clipboard 0.7, File 0.5), destination threat multiplier (0-15 pts: external storage, anonymous pastebins, cloud storage), UEBA anomaly score (0-15 pts), and after-hours timing multiplier (1.2x).
- [x] **UEBA Baseline Profiling & Anomaly Detection**:
  - Rolling mean and standard deviation of file transfer volumes per employee.
  - Z-score spike detection (flags actions with Z > 2.5).
  - Off-hours and weekend exfiltration detection.
  - Protection against false alarms on new endpoints (< 5 baseline events).

### D. Endpoint Monitoring Agent Daemon (`agent/`)
- [x] **Lightweight Standalone Client (`agent.py`, `config.py`, `api_client.py`)**:
  - Fully decoupled: Zero central database or server module dependencies on employee workstations.
  - Master Employee & Device Identity Persistence: Saves provisioned `device_id` and `device_token` locally in `agent/.device_config.json`.
  - Authoritative Header Authentication: Transmits `X-Agent-Secret`, `X-Device-Id`, and `X-Device-Token` with every request.
- [x] **Monitoring Channels**:
  - **Filesystem Watcher (`file_monitor.py`)**: Real-time Watchdog observer with recursive monitoring, extension filtering, ignore lists (`.git`, `node_modules`, `.venv`), and debounced event dispatch.
  - **Removable USB Watchdog (`usb_monitor.py`)**: Real-time detection of USB drive insertion and file copy interception across Linux (`/media/*`, `/mnt/*`) and Windows (logical drive query).
  - **Process & Exfiltration Tool Monitor (`process_monitor.py`)**: Periodically audits active processes for unauthorized egress utilities (`curl`, `wget`, `mega-cmd`, `tor`, `winscp`, `putty`, `filezilla`, `nc`).
  - **Workstation Clipboard Monitor (`clipboard_monitor.py`)**: Scans clipboard buffer for sensitive regex patterns and passwords.
  - **Browser Extension Receiver (`browser_monitor.py`)**: Local HTTP daemon listening on `127.0.0.1:8765` (with automatic failover to 8766-8768) to receive DOM pre-flight events from browser extensions.
  - **Offline Fault Tolerance (`event_queue.py`)**: Buffers events in local SQLite (`logs/offline_events.db`) during network disconnects, automatically replaying and flushing queued events upon server reconnection.
  - **Dynamic Heartbeat (`api_client.py`)**: Transmits telemetry, queue state, and active monitors every 15 seconds.

### E. Enterprise Browser Extension (`browser_extension/`)
- [x] **Manifest V3 Architecture (`manifest.json`, `content.js`, `background.js`, `popup.html`, `popup.js`)**:
  - Intercepts 3 primary browser egress vectors: DOM file input pickers, drag-and-drop file drops, and clipboard file/image paste operations.
  - Pure Base64 DataURL Ingestion: Encodes binary documents and images without character corruption.
  - Pre-Flight Local Dispatch: Queries local agent receiver on port 8765/8766/8767 before upload occurs.
  - Active DOM Blocking: Empties `input.value = ""` and displays a real-time red security warning toast if policy returns `action: "BLOCK"`.

### F. Frontend SOC Management Portals & Web Consoles (`frontend/`)
- [x] **SOC Administrator Dashboard (`dashboard.html`, `dashboard.js`)**:
  - 7 live KPI stat cards (Total Events, Blocked Attempts, Critical Alerts, Active Endpoints, Flagged Files, Fleet Risk Index, Monitored Channels).
  - 3 dynamic Chart.js visualizations (Fleet Risk Distribution, Alerts by Severity, Files Classification Breakdown).
  - Top At-Risk Employees Leaderboard with 1-click drilldown into 360° Profile Modal.
  - Real-time Alert Ticker and Live Activity Log Feed with auto-refresh.
- [x] **Alert Management Console (`alerts.html`, `alerts.js`)**:
  - Real-time threat alert stream with severity badges, channel filters, search bar, triage modal (Acknowledge / Resolve), single-item delete, and batch bulk delete.
- [x] **Incident Response Center (`incidents.html`, `incidents.js`)**:
  - Auto-generated cases for High/Critical alerts, analyst assignment, containment status updates (`OPEN`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`), and investigation notes log.
- [x] **Endpoint Fleet & UEBA Directory (`employees.html`, `employees.js`)**:
  - Fleet table with dynamic status (`ONLINE`, `WARNING`, `OFFLINE`), hardware device binding, and 360-degree drilldown modal displaying employee activity history, bound devices, correlated alerts, and DLP events.
- [x] **File Data Lake & DLP Inspector (`files.html`, `files.js`)**:
  - Document catalog, manual path scanner, and physical file upload scanner with instant OCR & NLP classification.
- [x] **AI DLP Live Inspection Sandbox (`ai_analysis.html`, `ai_analysis.js`)**:
  - Interactive test sandbox for raw text and document payloads with live entity breakdown, confidence traces, and analyst feedback submission.
- [x] **UEBA Behavioral Analytics Console (`ueba.html`, `ueba.js`)**:
  - Fleet-wide behavioral health metrics, baseline distribution charts, employee anomaly tables, and on-demand baseline recalculation.
- [x] **Alert History & Audit Ledger (`alert_history.html`, `alert_history.js`)**:
  - Historical chronological audit logs of all past DLP alerts and compliance events.
- [x] **DLP Multi-Vector Simulator (`dlp_simulation.html`, `dlp_simulation.js`)**:
  - Interactive simulator to test USB, Browser, Email, and Clipboard egress scenarios.
- [x] **Policy Governance Settings (`settings.html`)**:
  - Active DLP rules per channel, risk thresholds, and agent token inspection.
- [x] **Dedicated Employee Endpoint Portal (`employee_portal.html`, `employee_portal.js`)**:
  - Strictly separated non-admin portal for employees to view workstation security status, corporate data handling policies, and self-service pre-flight DLP file checks.

---

## 3. Automated Test Battery & Verification Matrix

The test suite consists of **150 automated test cases** across 18 specialized modules, all passing with a **100% success rate**:

| Test Module | Description | Tests | Status |
| :--- | :--- | :---: | :---: |
| `tests/test_agent.py` | Standalone agent monitoring (USB, File, Clipboard) | 7 | ✅ PASSED |
| `tests/test_agent_heartbeat_fix.py` | Heartbeat intervals, queue state & status evaluation | 7 | ✅ PASSED |
| `tests/test_agent_identity_model.py` | Local device config, token persistence & validation | 7 | ✅ PASSED |
| `tests/test_ai_dlp.py` | NLP entity extraction, OCR engine, confidence scoring | 12 | ✅ PASSED |
| `tests/test_api.py` | Core REST API routes, JWT authentication, CSV exports | 11 | ✅ PASSED |
| `tests/test_audit_concurrency.py` | Concurrency audit under simulated multi-endpoint load | 1 | ✅ PASSED |
| `tests/test_auth.py` | Bcrypt password hashing, JWT flow, RBAC policies | 3 | ✅ PASSED |
| `tests/test_centralized_fleet.py` | Fleet registration, heartbeat decay, standalone resilience | 24 | ✅ PASSED |
| `tests/test_classifier.py` | ML classifier, sensitive entity heuristics, hash cache | 13 | ✅ PASSED |
| `tests/test_dlp_unified.py` | Multi-channel DLP parity (USB, Browser, Email, Paste) | 7 | ✅ PASSED |
| `tests/test_e2e_flow.py` | End-to-end detection, alerting, and auto-incident creation | 1 | ✅ PASSED |
| `tests/test_employee_device_isolation.py` | Strict device-employee isolation, spoofing rejection | 12 | ✅ PASSED |
| `tests/test_employee_relationship.py` | Master employee lifecycle, 1:N device binding, 360 profile | 11 | ✅ PASSED |
| `tests/test_enterprise_architecture.py` | Multi-endpoint registration, offline queue, telemetry | 6 | ✅ PASSED |
| `tests/test_file_analysis_pipeline.py` | Multi-format extraction (XLSX, DOCX, CSV, PDF, OCR) | 14 | ✅ PASSED |
| `tests/test_multi_user_attribution.py` | Multi-user attribution across simultaneous workstations | 5 | ✅ PASSED |
| `tests/test_risk.py` | Composite risk scoring mathematical formulas | 3 | ✅ PASSED |
| `tests/test_ueba_engine.py` | UEBA baseline profiling, Z-score spikes, off-hours | 6 | ✅ PASSED |
| **TOTAL** | **Comprehensive Full Test Battery** | **150** | **✅ 100% PASSING** |

---

## 4. Master CLI Commands Reference

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Start FastAPI Central Backend Server
```bash
python run.py backend --host 0.0.0.0 --port 8000
```
Web Access Points:
- **SOC Administrator Dashboard**: [http://127.0.0.1:8000/dashboard](http://127.0.0.1:8000/dashboard) (or [http://172.24.143.236:8000/dashboard](http://172.24.143.236:8000/dashboard))
- **Dedicated Employee Portal**: [http://127.0.0.1:8000/employee-portal](http://127.0.0.1:8000/employee-portal)
- **AI Inspection Sandbox**: [http://127.0.0.1:8000/ai-analysis](http://127.0.0.1:8000/ai-analysis)
- **UEBA Behavioral Analytics**: [http://127.0.0.1:8000/ueba](http://127.0.0.1:8000/ueba)
- **Interactive Swagger API Docs**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **Health Check**: [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)

### Start Endpoint Monitoring Agent
```bash
# Guided Interactive Setup (Prompts for Server URL, Employee ID, Name, Dept, Designation)
python agent/agent.py --interactive

# Command-line Execution (Linux / macOS / Windows)
python agent/agent.py --server "http://127.0.0.1:8000" --employee-id "EMP-001" --name "Prakash T" --dept "Cybersecurity" --desig "Security Architect"

# Automated Linux Workstation Installer
chmod +x ./agent/install_linux.sh
./agent/install_linux.sh "http://172.24.143.236:8000" "EMP-001" "Prakash T" "prakash@gmail.com" "Cyber Security" "Security Architect"

# Automated Windows Workstation Installer (PowerShell Administrator)
powershell -ExecutionPolicy Bypass -File .\agent\install_windows.ps1 -ServerUrl "http://172.24.143.236:8000" -EmployeeId "EMP-001" -FullName "Prakash T" -Email "prakash@gmail.com" -Department "Cyber Security" -Designation "Security Architect"
```

### Multi-Endpoint Fleet Simulation & AI Training
```bash
# Launch multi-workstation simulated fleet (Engineering, Finance, HR)
python run.py simulate

# Train TF-IDF + Logistic Regression classification model
python training/train_classifier.py

# Evaluate model metrics (Precision, Recall, F1-score)
python training/evaluate.py

# Clean simulated fleet test records
python scripts/cleanup_simulated_data.py
```

### Database & Alert Maintenance
```bash
# Reset all employee risk scores and clear active alerts
python run.py clear-alerts

# Clean database reset
python run.py reset-db
```

### Run Full Test Battery
```bash
pytest tests/ -v
```

---

## 5. Security Hardening & Enterprise Compliance
1. **Zero Wire Decryption**: Inspects payloads directly at the source DOM layer and local file/process hooks before encryption, eliminating the need for invasive TLS MITM root certificates.
2. **Cryptographic Token Binding**: Hardware devices authenticate via provisioned `X-Device-Token` credentials, preventing workstation impersonation or rogue event injection.
3. **Offline Queue Persistence**: Events occurring during network dropouts are preserved in local SQLite storage and reliably synchronized upon reconnection.
4. **Regulatory Standards Alignment**:
   - **GDPR Article 32**: Technical and organizational safeguards for personal data.
   - **HIPAA Security Rule §164.312**: Transmission security and ePHI egress controls.
   - **PCI-DSS Requirement 3 & 4**: Cardholder data protection with Luhn verification.
   - **ISO/IEC 27001 Annex A.8.12**: Data leakage prevention controls.
