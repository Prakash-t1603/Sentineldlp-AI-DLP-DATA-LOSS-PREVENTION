# SentinelDLP AI - Project Implementation Status Report

## 1. Project Summary
**SentinelDLP AI** has been reconstructed from scratch as a full-featured, endpoint-based cybersecurity and Data Loss Prevention (DLP) system. The system monitors employee file activity, detects sensitive data exposure (credentials, secrets, PII, financial info, confidential marks), analyzes USB transfers, evaluates threat processes, computes multi-factor risk scores and UEBA anomalies, generates real-time alerts, and presents live SOC telemetry in an administrator dashboard while maintaining a strictly separate Employee Endpoint Portal.

---

## 2. Completed Components

### A. Backend Architecture & Database (`backend/`)
- [x] **Configuration & Security (`config.py`, `utils/security.py`)**: Environment variables, direct bcrypt password hashing with 72-byte safe truncation, JWT token generation & validation with 24-hour expiration.
- [x] **Database Engine & ORM (`database.py`, `models.py`)**: SQLite with Foreign Key & WAL mode enabled; schema compatible with PostgreSQL (`postgresql+psycopg://...`).
- [x] **Entities & Relationships**:
  - `User`: RBAC (`admin`, `security_analyst`, `employee`), password hash, active status.
  - `Employee`: `employee_id`, hostname, IP, OS, status (`ONLINE`, `OFFLINE`, `SUSPICIOUS`), last seen, risk score.
  - `FileRecord`: file hash (SHA-256), classification (`PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `HIGHLY_CONFIDENTIAL`), sensitivity score.
  - `Alert`: `alert_type`, severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), risk score, source, status (`OPEN`, `ACKNOWLEDGED`, `RESOLVED`).
  - `Incident`: Auto-created on High/Critical alerts, assigned analyst, status (`OPEN`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`), investigation notes.
  - `ActivityLog`: File operations (`CREATE`, `MODIFY`, `DELETE`, `MOVE`, `RENAME`, `USB_COPY`, `PROCESS_SPAWN`, `CLOUD_SYNC`).
  - `PolicyRule`: Dynamic DLP rule definitions.
- [x] **Pydantic v2 Schemas (`schemas.py`)**: Full serialization and validation models using `ConfigDict(from_attributes=True)`.
- [x] **Dependencies (`dependencies.py`)**: JWT Bearer extraction, RBAC decorators, and agent secret token header (`X-Agent-Secret`) validation.

### B. Local Analysis & AI / ML Engine (`backend/services/`)
- [x] **Document Extraction (`file_analysis_service.py`)**: Multi-layer parsing for `.pdf` (`pypdf`), `.docx` (`python-docx`), `.txt`, `.csv`, `.json`, `.md` with size guards.
- [x] **OCR Engine (`ocr_service.py`)**: Safe image text extraction with format verification (`.jpg`, `.jpeg`, `.png`, `.bmp`, `.tiff`); guaranteed zero-crash fallback on unsupported files like `.env`.
- [x] **Regex & NLP Entity Scanner (`nlp_service.py`)**: Detects AWS keys, GitHub tokens, Slack tokens, generic API keys, private keys, passwords, database URLs, credit card numbers (Luhn validated), Aadhaar IDs, SSNs, emails, and confidential markings.
- [x] **Modular Classifier (`classifier_service.py`)**: Evaluates filename heuristics + content entities + keyword density into a 4-tier classification (`PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `HIGHLY_CONFIDENTIAL`) with confidence score. Safe rule-based fallback when SentenceTransformers are not loaded.
- [x] **Risk & UEBA Scoring (`risk_service.py`)**: 0-100 composite risk calculation with action weights (USB transfer, process vector, time anomaly) and Isolation Forest anomaly detection when historical activity >= 20.
- [x] **Alert Orchestration (`alert_service.py`)**: Real-time alert ingestion, automatic employee risk updating, and auto-incident generation for High/Critical threats.
- [x] **Reporting Service (`report_service.py`)**: Generates executive metrics summaries and formatted CSV exports for alerts and activities.

### C. Backend API Endpoints (`backend/routers/`)
- [x] `POST /api/v1/auth/register`, `POST /api/v1/auth/login`, `GET /api/v1/auth/me`
- [x] `GET /api/v1/users`, `PATCH /api/v1/users/{id}`
- [x] `POST /api/v1/employees/register`, `POST /api/v1/employees/heartbeat/{id}`, `GET /api/v1/employees`, `GET /api/v1/employees/{id}`
- [x] `GET /api/v1/files`, `POST /api/v1/files/scan`, `POST /api/v1/files/upload-scan`
- [x] `GET /api/v1/alerts`, `POST /api/v1/alerts`, `PATCH /api/v1/alerts/{id}`, `GET /api/v1/alerts/{id}`
- [x] `GET /api/v1/incidents`, `POST /api/v1/incidents`, `PATCH /api/v1/incidents/{id}`, `GET /api/v1/incidents/{id}`
- [x] `GET /api/v1/reports/summary`, `GET /api/v1/reports/export/alerts.csv`, `GET /api/v1/reports/export/activities.csv`
- [x] `GET /api/v1/risk/fleet`, `GET /api/v1/risk/employee/{id}`, `POST /api/v1/risk/simulate`
- [x] `GET /api/v1/dashboard/summary` (Live metrics and chart datasets)

### D. Endpoint Monitoring Agent (`agent/`)
- [x] **File Monitor (`file_monitor.py`)**: Watchdog observer using `Path` resolution, extension filters, directory ignore lists (`.git`, `node_modules`, `.venv`, etc.), event debounce, and real-time backend telemetry dispatch.
- [x] **USB Monitor (`usb_monitor.py`)**: Removable storage insertion/removal detector using PyWin32 / logical drives on Windows and mount path monitoring on Linux.
- [x] **Process Monitor (`process_monitor.py`)**: Detects unauthorized exfiltration utilities (curl, wget, mega, dropbox, winscp, filezilla, tor, nc) with `psutil`.
- [x] **Agent Coordinator (`agent.py`)**: Automatic registration, 15-second heartbeat worker, unified monitor thread management, and graceful shutdown signal handlers.

### E. Frontend User Interfaces (`frontend/`)
- [x] **SOC Administrator Dashboard (`dashboard.html`, `dashboard.js`)**: 7 live KPI stat cards, 3 dynamic Chart.js visualizations (Risk distribution, Alerts by severity, Files classification), top at-risk employee ranking, live alert ticker, and real-time activity feed.
- [x] **Alert Management Console (`alerts.html`, `alerts.js`)**: Severity and status filtering, search bar, triage modal with Acknowledge/Resolve workflows.
- [x] **Incident Response Center (`incidents.html`, `incidents.js`)**: Case creation, analyst assignment, containment status updates, and investigation notes editor.
- [x] **Endpoint Fleet & UEBA Directory (`employees.html`, `employees.js`)**: Fleet directory with 360-degree drilldown modal displaying activities, files, and alert history.
- [x] **File Data Lake & DLP Inspector (`files.html`, `files.js`)**: Document registry, manual file path scanner, and direct file upload scanner.
- [x] **Compliance Reports (`reports.html`, `reports.js`)**: Executive summary cards and one-click CSV report downloads.
- [x] **Policy Settings (`settings.html`)**: Active DLP rules, risk tiers, and agent token inspection.
- [x] **Separate Dedicated Employee Portal (`employee_portal.html`, `employee_portal.js`)**: Workstation security status, corporate data handling policies, and self-service DLP pre-flight file check tool.

---

## 3. Incomplete / Deferred Components
- **None**: All core requirements, backend routes, local analysis engines, endpoint agent monitors, database models, and frontends are fully implemented and verified.

---

## 4. Commands to Run

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Start FastAPI Backend Server
```bash
python run.py backend --host 0.0.0.0 --port 8000
```
Access points:
- **SOC Administrator Dashboard**: [http://172.24.143.236:8000/dashboard](http://172.24.143.236:8000/dashboard) (or [http://127.0.0.1:8000/dashboard](http://127.0.0.1:8000/dashboard))
- **Employee Endpoint Portal**: [http://172.24.143.236:8000/employee-portal](http://172.24.143.236:8000/employee-portal)
- **Interactive Swagger API Docs**: [http://172.24.143.236:8000/docs](http://172.24.143.236:8000/docs)
- **Health Check**: [http://172.24.143.236:8000/health](http://172.24.143.236:8000/health)

### Start Endpoint Monitoring Agent
```bash
# Local development mode
python run.py agent

# Remote workstation mode
python -m agent.agent --server-url http://172.24.143.236:8000 --employee-id EMP-001

# Linux automated installer
./agent/install_linux.sh "http://172.24.143.236:8000" "EMP-001"

# Windows automated installer
powershell -ExecutionPolicy Bypass -File .\agent\install_windows.ps1 -ServerUrl "http://172.24.143.236:8000" -EmployeeId "EMP-001"
```

### Run Multi-Endpoint Fleet Simulator
```bash
python run.py sim-agents
```

### Database & Alert Maintenance
```bash
# Purge all alerts and reset employee risk scores to clean baseline
python run.py clear-alerts

# Reset database to clean state
python run.py reset-db
```

### Run Automated Tests
```bash
python run.py test
# or:
pytest tests/ -v
```

---

## 5. Known Limitations & Enterprise Guidelines
1. **HTTPS Traffic Inspection**: In accordance with defensive security design and endpoint boundaries, arbitrary HTTPS browser traffic is not decrypted on the wire. Monitored cloud sync directories, browser upload integration points, and process activity are monitored instead.
2. **EasyOCR Initial Download**: EasyOCR will download its English language weights (~30MB) on the very first image OCR scan if an active internet connection is available; otherwise, the safe image and text fallback rules operate seamlessly.
3. **Admin Privileges for USB Monitoring**: On Windows, querying logical drives works in user space; low-level hardware device blocking requires elevated Administrator execution if enforcement is added.
