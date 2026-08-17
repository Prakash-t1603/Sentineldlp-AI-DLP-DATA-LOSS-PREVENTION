# SentinelDLP AI - Employee Activity & Data Loss Prevention System

**SentinelDLP AI** is an enterprise-grade endpoint cybersecurity and Data Loss Prevention (DLP) platform designed to detect sensitive data exposure, monitor employee file operations, detect unauthorized USB and process transfers, and provide real-time threat intelligence through an advanced Security Operations Center (SOC) dashboard.

---

## Architecture Overview

```
Employee Endpoint Machine
        │
        ▼
Endpoint Monitoring Agent (agent/agent.py)
        │
        ├────── Watchdog File Monitor (Creation, Modification, Rename, Deletion)
        ├────── Removable USB Monitor (Windows PyWin32 / Linux udev)
        ├────── Exfiltration Process Monitor (psutil threat detection)
        └────── System Event Auditor
        │
        ▼  (Telemetry over REST API)
Local Analysis & NLP / OCR Engine
        │
        ├────── Document Text Extraction (.pdf, .docx, .txt, .csv, .json, .md)
        ├────── Safe OCR Image Processing (EasyOCR / Fallback)
        ├────── Regex & NLP Sensitive Entity Scanner (API Keys, PII, SSN, Credit Cards)
        ├────── Modular Multi-Tier Classifier (PUBLIC, INTERNAL, CONFIDENTIAL, HIGHLY_CONFIDENTIAL)
        ├────── Multi-Factor Risk Scoring Engine (0 - 100)
        └────── UEBA Behavioral Anomaly Detection (Isolation Forest)
        │
        ▼
FastAPI Backend (backend/main.py)
        │
        ├────── JWT & Role-Based Access Control (Admin, Security Analyst, Employee)
        ├────── SQLAlchemy ORM (SQLite for Dev / PostgreSQL-Ready Architecture)
        └────── REST Endpoints (/auth, /dashboard, /alerts, /incidents, /employees, /files, /reports)
        │
        ▼
Frontends (Separated Architecture)
        ├────── 1. SOC Administrator & Analyst Dashboard (dashboard.html, alerts.html, incidents.html...)
        └────── 2. Dedicated Employee Workstation Portal (employee_portal.html)
```

---

## Technology Stack

- **Backend**: Python 3.11+, FastAPI, Uvicorn, SQLAlchemy, Pydantic v2
- **Security**: JWT Authentication, bcrypt password hashing, RBAC
- **Analysis & ML**: Scikit-learn (Isolation Forest), Pandas, NumPy, pypdf, python-docx, Pillow, EasyOCR
- **Endpoint Agent**: Watchdog, psutil, PyWin32
- **Frontend**: HTML5, CSS3, Vanilla JS, Bootstrap 5, Chart.js, Font Awesome 6

---

## Directory Structure

```
employee-monitoring-sustem/
├── backend/
│   ├── config.py              # Configuration & environment loader
│   ├── database.py            # SQLAlchemy engine, session & WAL setup
│   ├── models.py              # SQLAlchemy database models
│   ├── schemas.py             # Pydantic schemas for request/response validation
│   ├── dependencies.py        # JWT security & RBAC dependencies
│   ├── main.py                # FastAPI app assembly & frontend mounting
│   │
│   ├── routers/
│   │   ├── auth.py            # Login, register, me endpoints
│   │   ├── users.py           # Admin user management
│   │   ├── employees.py       # Endpoint fleet registration & 360 profiles
│   │   ├── files.py           # File data lake & manual/upload DLP scanner
│   │   ├── alerts.py          # Alert triage & lifecycle
│   │   ├── incidents.py       # Incident investigation & containment
│   │   ├── reports.py         # Executive summary & CSV data downloads
│   │   ├── risk.py            # Fleet risk overview & UEBA simulation
│   │   └── dashboard.py       # Aggregated SOC metrics & chart statistics
│   │
│   ├── services/
│   │   ├── file_analysis_service.py # Text extraction for docs & pdfs
│   │   ├── ocr_service.py           # Safe image OCR with format guards
│   │   ├── nlp_service.py           # Regex & NLP sensitive pattern scanner
│   │   ├── classifier_service.py    # Multi-tier classification engine
│   │   ├── risk_service.py          # Composite risk scoring & Isolation Forest UEBA
│   │   ├── alert_service.py         # Alert generation & auto-incident triggers
│   │   └── report_service.py        # Executive reporting & CSV export formatters
│   │
│   └── utils/
│       ├── security.py        # Password hashing & JWT functions
│       └── helpers.py         # File hashing & sanitized logging
│
├── agent/
│   ├── config.py              # Endpoint agent configuration
│   ├── file_monitor.py        # Watchdog filesystem observer
│   ├── usb_monitor.py         # Removable media & USB detector
│   ├── process_monitor.py     # Suspicious process & exfiltration watcher
│   ├── event_monitor.py       # System event auditor
│   └── agent.py               # Main agent service coordinator
│
├── frontend/
│   ├── index.html             # Landing & Portal Selector
│   ├── login.html             # SOC Login & Analyst Registration
│   ├── dashboard.html         # SOC Executive Dashboard
│   ├── alerts.html            # Alert Management Console
│   ├── incidents.html         # Incident Response Board
│   ├── employees.html         # Endpoint Fleet & UEBA Directory
│   ├── files.html             # Monitored File Data Lake & Inspector
│   ├── reports.html           # Compliance & Threat Reports
│   ├── settings.html          # DLP Policies & Config
│   ├── employee_portal.html   # Dedicated Employee Workstation View
│   ├── css/style.css          # Modern dark SOC cybersecurity styling
│   └── js/                    # Client-side controllers & API client
│
├── monitored_data/            # Default monitored test directory
├── uploads/                   # Upload storage
├── logs/                      # Structured system audit logs
├── tests/                     # Automated pytest suite
├── .env.example               # Environment template
├── .env                       # Active configuration
├── requirements.txt           # Project dependencies
├── run.py                     # Unified CLI launcher
├── README.md                  # Complete documentation
└── PROJECT_STATUS.md          # Implementation verification status
```

---

## Installation & Setup

### 1. Create and Activate Virtual Environment

**Windows:**
```powershell
python -m venv .venv
.venv\Scripts\activate
```

**Linux / macOS:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

---

## Running the Application

### 1. Seed Demo Simulation Data (Optional but Recommended)
```bash
python run.py seed
```

### 2. Start the FastAPI Backend Server
```bash
python run.py backend
```
Or directly with Uvicorn:
```bash
uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

Once running, access the web portals:
- **SOC Administrator Dashboard**: [http://127.0.0.1:8000/dashboard](http://127.0.0.1:8000/dashboard)
- **Employee Endpoint Portal**: [http://127.0.0.1:8000/employee-portal](http://127.0.0.1:8000/employee-portal)
- **Interactive Swagger API Docs**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

**Default Credentials:**
- Administrator: `admin@sentineldlp.io` / `Admin@123456`
- Security Analyst: `analyst@sentineldlp.io` / `Analyst@123456`

### 3. Start the Endpoint Monitoring Agent
In a separate terminal on the monitored machine:
```bash
python run.py agent
```
Any file created, modified, or moved in `monitored_data/` will be analyzed in real time.

---

## Running Automated Tests

Run the full pytest suite:
```bash
python run.py test
```
Or:
```bash
pytest tests/ -v
```

---

## Safety & Defensive Architecture
- Monitored directories are strictly configurable.
- The agent never alters or destroys user files.
- Structured logging automatically redacts passwords, tokens, and sensitive document bodies.
- Safe OCR and NLP fallbacks ensure unsupported file extensions or missing ML weights never crash the system.
