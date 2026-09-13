# 🛡️ SentinelDLP AI - Enterprise Data Loss Prevention & Threat Intelligence Platform

[![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![License](https://img.shields.io/badge/License-Proprietary-red.svg)]()
[![Test Suite](https://img.shields.io/badge/Tests-117%2F117%20Passing%20(100%25)-brightgreen.svg)]()
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg)]()

**SentinelDLP AI** is an enterprise-grade endpoint cybersecurity, Data Loss Prevention (DLP), and User & Entity Behavior Analytics (UEBA) platform. It safeguards proprietary source code, credentials, PII, financial records, and confidential assets across workstation filesystems, removable USB media, web browser uploads (Google Drive, Dropbox, WhatsApp Web), email attachments, clipboard transfers, and background processes in real time.

---

## 📑 Table of Contents

- [Architectural Overview & Working Process](#-architectural-overview--working-process)
- [Core Features & Protection Channels](#-core-features--protection-channels)
- [AI, OCR & Deep Content Inspection Pipeline](#-ai-ocr--deep-content-inspection-pipeline)
- [UEBA Behavioral Analytics Engine](#-ueba-behavioral-analytics-engine)
- [Technology Stack](#-technology-stack)
- [Directory Structure](#-directory-structure)
- [Prerequisites & System Requirements](#-prerequisites--system-requirements)
- [Step-by-Step Installation Guide](#-step-by-step-installation-guide)
  - [1. Central Server Setup](#1-central-server-setup)
  - [2. Endpoint Agent Installation (Linux)](#2-endpoint-agent-installation-linux)
  - [3. Endpoint Agent Installation (Windows)](#3-endpoint-agent-installation-windows)
  - [4. Browser Extension Installation](#4-browser-extension-installation)
- [Complete Running Commands Reference](#-complete-running-commands-reference)
  - [Launch Central Server](#launch-central-server)
  - [Launch Endpoint Agent](#launch-endpoint-agent)
  - [AI Model Training & Evaluation](#ai-model-training--evaluation)
  - [Multi-Endpoint Fleet Simulation](#multi-endpoint-fleet-simulation)
  - [Run Full Automated Test Battery](#run-full-automated-test-battery)
- [SOC Management Portals & Web Navigation](#-soc-management-portals--web-navigation)
- [Default Credentials & Authentication](#-default-credentials--authentication)
- [Verification & Testing](#-verification--testing)
- [License & Author](#-license--author)

---

## 🏗️ Architectural Overview & Working Process

SentinelDLP AI enforces a strict, decoupled client-server architecture with centralized policy management and distributed endpoint interception.

```
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   EMPLOYEE WORKSTATION                                      │
│                                                                                             │
│   ┌────────────────────────┐      ┌─────────────────────────┐     ┌─────────────────────┐  │
│   │  Filesystem Watchdog   │      │  Removable USB Sensor   │     │  Clipboard Monitor  │  │
│   └───────────┬────────────┘      └────────────┬────────────┘     └──────────┬──────────┘  │
│               │                                │                             │             │
│               │                   ┌────────────┴────────────┐                │             │
│               │                   │  Process & Tool Watcher │                │             │
│               │                   └────────────┬────────────┘                │             │
│               │                                │                             │             │
│               └───────────────────────┬────────┴─────────────────────────────┘             │
│                                       ▼                                                     │
│                  ┌──────────────────────────────────────────────┐                           │
│                  │  Endpoint Protection Agent (agent/agent.py)  │                           │
│                  │  - Telemetry & Event Buffering (Offline DB)  │                           │
│                  │  - Device Token Authentication               │                           │
│                  └────────────────────┬─────────────────────────┘                           │
│                                       ▲                                                     │
│                                       │ (HTTP Port :8765 Ingestion)                         │
│                  ┌────────────────────┴─────────────────────────┐                           │
│                  │   Browser Extension (Manifest V3)            │                           │
│                  │   - Uploads / Drag-Drop / Paste Interceptor  │                           │
│                  │   - Base64 Ingestion (GDrive/WhatsApp/Gmail) │                           │
│                  └──────────────────────────────────────────────┘                           │
└───────────────────────────────────────┬─────────────────────────────────────────────────────┘
                                        │
                                        │ REST API (X-Agent-Secret / X-Device-Token)
                                        │ (Heartbeat every 15s, Ingest Events /api/v1/dlp/events)
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                           CENTRAL DLP SERVER & SOC ENGINE (FastAPI)                         │
│                                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────────────────────┐  │
│  │ AI & Content Inspection Pipeline                                                      │  │
│  │  ├── Multi-Format Parser (XLSX, CSV, DOCX, PDF, TXT, JSON, MD, LOG)                   │  │
│  │  ├── Tesseract OCR & Scanned PDF OCR Fallback Engine                                 │  │
│  │  ├── Regex & NLP Pattern Entity Recognizers (Aadhaar, PAN, CC, Keys, Passwords)       │  │
│  │  ├── SHA-256 Hash Verification Cache & 50MB Safety Limit                              │  │
│  │  └── TF-IDF + Logistic Regression Classifier (PUBLIC, INTERNAL, CONFIDENTIAL, CRITICAL│  │
│  └───────────────────────────────────┬───────────────────────────────────────────────────┘  │
│                                      │                                                      │
│  ┌───────────────────────────────────┴───────────────────────────────────────────────────┐  │
│  │ Multi-Factor Risk & Policy Decision Engine                                            │  │
│  │  ├── Composite Risk Score Formula (0 - 100)                                           │  │
│  │  ├── Policy Rule Engine (ALLOW, WARN, ENCRYPT, QUARANTINE, BLOCK)                     │  │
│  │  └── Isolation Forest UEBA Engine (Velocity spikes, After-hours, Anomaly detection)   │  │
│  └───────────────────────────────────┬───────────────────────────────────────────────────┘  │
│                                      │                                                      │
│  ┌───────────────────────────────────┴───────────────────────────────────────────────────┐  │
│  │ Master Employee Directory & Security Intelligence                                     │  │
│  │  ├── Master Employee Lifecycle (OFFLINE -> ONLINE on Agent Registration)              │  │
│  │  ├── Hardware Device Telemetry Binding (1:N Devices per Employee)                     │  │
│  │  ├── Correlated Security Threat Alerts & Incident Lifecycle Management                │  │
│  │  └── SQLite Database (WAL Mode Enabled for High Concurrency)                          │  │
│  └───────────────────────────────────┬───────────────────────────────────────────────────┘  │
└───────────────────────────────────────┬─────────────────────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                             SOC DASHBOARDS & EMPLOYEE PORTALS                               │
│                                                                                             │
│  ├── 🛡️ SOC Executive Dashboard (dashboard.html) - Real-time Threat & Fleet Analytics      │
│  ├── 👥 Employee Fleet Management (employees.html) - 360° Profile Dossier Modal            │
│  ├── 🚨 Threat Alerts Center (alerts.html & alert_history.html) - Triage & Bulk Actions     │
│  ├── 📁 File Vault & DLP Inspector (files.html) - Content inspection & hash logs            │
│  ├── 🔍 AI DLP Live Sandbox (/ai-analysis) - Test file classification & confidence scores   │
│  ├── 📈 UEBA Analytics Center (/ueba) - Employee behavioral anomaly tracking                │
│  └── 💼 Employee Workstation Portal (/employee-portal) - Self-service transparency          │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🛡️ Core Features & Protection Channels

1. **Removable USB Storage Protection**:
   - Hardware detection using OS mount points and block device signals (`/media`, `/run/media`, `/mnt`, drive letters `D:`-`Z:`).
   - Automatic attachment of file system watchers on newly inserted drives.
   - Real-time blocking and quarantining of confidential transfers.

2. **Web Browser & Cloud Storage Interception**:
   - Google Chrome, Microsoft Edge, and Brave browser extension running Manifest V3.
   - Intercepts file uploads, drag-and-drop actions, and clipboard pastes to cloud services (Google Drive, Microsoft OneDrive, Dropbox, Box, Mega, WhatsApp Web, Gmail, Outlook Web).
   - Ingests actual file payload directly to local endpoint agent via `http://127.0.0.1:8765`.

3. **Corporate Email & MIME Attachment Scanner**:
   - Parses RFC 822 MIME email streams and raw EML files.
   - Recursively inspects nested email attachments for confidential intellectual property and credentials.

4. **Workstation Clipboard & File Watcher**:
   - Real-time clipboard poller (every 400ms) detecting sensitive copied text (passwords, private keys, credit cards).
   - Watchdog filesystem observer recursively monitoring designated workspace folders.

5. **Exfiltration Tool & Process Monitor**:
   - Continuous scanning of running system processes against blacklists (`curl`, `wget`, `winscp`, `filezilla`, `tor`, `megasync`, `netcat`, `nmap`).
   - Generates activity logs and policy blocks upon unauthorized process launches.

---

## 🧠 AI, OCR & Deep Content Inspection Pipeline

The inspection engine combines deterministic algorithmic checks with NLP and machine learning:

1. **Multi-Format Document Parsers**:
   - **Spreadsheets (`.xlsx`, `.csv`)**: OpenPyXL / Pandas row-by-row cell extraction.
   - **Word Documents (`.docx`)**: python-docx paragraph, table, and header parsing.
   - **PDF Documents (`.pdf`)**: PyPDF text stream extraction with automatic fallback to OCR for scanned documents.
   - **Text & Configs (`.txt`, `.json`, `.yaml`, `.xml`, `.env`, `.pem`, `.key`)**: Direct text decoding and key-value analysis.

2. **Tesseract Optical Character Recognition (OCR)**:
   - Deep text extraction for image attachments (`.jpg`, `.jpeg`, `.png`, `.bmp`, `.tiff`).
   - Image preprocessing (grayscale conversion, thresholding, contrast enhancement).
   - OCR fallback engine for scanned PDFs containing flattened images without embedded text layers.

3. **Multi-Tier Pattern & Entity Recognizers**:
   - **Financial**: Credit card numbers validated with the **Luhn Algorithm**.
   - **National IDs**: Indian **Aadhaar** validated with the **Verhoeff Algorithm**; Indian **PAN** regex.
   - **Cloud Secrets & API Keys**: AWS Access Keys (`AKIA...`), Private Key Headers (`-----BEGIN RSA PRIVATE KEY-----`), GitHub/Slack Tokens.
   - **Entropy Checks**: Shannon entropy scanner to flag high-randomness secret keys and encrypted payloads.

4. **Supervised ML Classification**:
   - Scikit-learn pipeline using TF-IDF vectorization with Logistic Regression trained on corporate DLP corpora.
   - Predicts 4 distinct sensitivity tiers: `PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `HIGHLY_CONFIDENTIAL`.

5. **Performance & Safety Bounds**:
   - **Fast-Path SHA-256 Cache**: Avoids redundant deep scanning of identical files.
   - **50MB Safety Cap**: Prevents memory spikes and zip-bomb exhaustion attacks.

---

## 📈 UEBA Behavioral Analytics Engine

SentinelDLP's User & Entity Behavior Analytics (UEBA) subsystem tracks normal user behavior to detect insider threats:

- **Baseline Construction**: Computes rolling 14-day statistical baselines per employee (mean transfer volumes, typical daily event counts, standard deviation).
- **Z-Score Anomaly Detector**: Flags velocity spikes when an employee's data transfer volume deviates by $\ge 2.5\sigma$ from their peer group baseline.
- **After-Hours Activity Monitor**: Flags high-volume file transfers occurring outside standard corporate working hours (8:00 PM – 6:00 AM) and on weekends.
- **Isolation Forest Unsupervised Model**: Detects multi-dimensional multidirectional behavioral anomalies across event type distributions, transfer sizes, and sensitive entity counts.
- **Insufficient Baseline Protection**: Requires a minimum of 5 historical events before applying aggressive anomaly penalties, avoiding false positives on newly onboarded employees.

---

## 💻 Technology Stack

| Component | Technologies |
|---|---|
| **Backend Framework** | Python 3.10+, FastAPI, Uvicorn, Pydantic v2, Starlette |
| **Database & ORM** | SQLite 3 (WAL mode enabled for high concurrency), SQLAlchemy 2.0+ (PostgreSQL-ready) |
| **Machine Learning & NLP** | Scikit-learn, Pandas, NumPy, Joblib, Regex, Math |
| **OCR & Document Parsing** | Tesseract-OCR, Pillow (PIL), PyPDF, python-docx, OpenPyXL |
| **Endpoint Agent** | Watchdog (Filesystem), psutil (Processes), Socket, Requests, Systemd / Task Scheduler |
| **Browser Extension** | JavaScript (ES6+), Manifest V3, WebExtensions API, Fetch |
| **Frontend Dashboard** | HTML5, Modern CSS3 (Glassmorphic Dark Mode), Vanilla JavaScript, Bootstrap 5, Chart.js 4, FontAwesome 6 |
| **Testing & Quality** | Pytest, Requests-mock, Unittest, Flake8 |

---

## 📁 Directory Structure

```
DLP - Employee-Monitoring-System/
├── backend/
│   ├── ai/                        # AI inspection & OCR engines
│   │   ├── ocr_engine.py          # Tesseract OCR & image preprocessing
│   │   └── ueba_engine.py         # Isolation Forest & Z-Score anomaly engine
│   ├── routers/                   # FastAPI REST API endpoints
│   │   ├── agents.py              # Agent registration, heartbeats & fleet overview
│   │   ├── ai.py                  # AI live inspection sandbox endpoints
│   │   ├── alerts.py              # Threat alerts & triage lifecycle
│   │   ├── auth.py                # JWT authentication & session verification
│   │   ├── dashboard.py           # Real-time aggregated SOC statistics
│   │   ├── dlp.py                 # Core DLP event ingestion & inspection API
│   │   ├── employees.py           # Master Employee Directory & 360° Profile API
│   │   ├── files.py               # File vault & manual file upload scanner
│   │   ├── incidents.py           # Security incident management
│   │   ├── reports.py             # Executive summary & CSV report exports
│   │   ├── risk.py                # Risk scoring & sensitivity distribution
│   │   ├── ueba.py                # UEBA profile listing & anomaly summary
│   │   └── users.py               # System user & role management
│   ├── services/                  # Business logic & threat engines
│   │   ├── agent_service.py       # Device registration, tokens & status evaluation
│   │   ├── alert_service.py       # Alert creation & auto-incident triggers
│   │   ├── classifier_service.py  # Supervised ML text classifier
│   │   ├── file_analysis_service.py # Deep multi-format document parser
│   │   ├── nlp_service.py         # PII, financial & credential entity scanner
│   │   ├── policy_service.py      # DLP policy rules & action governance
│   │   ├── report_service.py      # Executive report generator
│   │   └── risk_service.py        # Composite risk calculation engine
│   ├── config.py                  # Central configuration & absolute paths
│   ├── database.py                # SQLAlchemy engine, session maker & auto-migrations
│   ├── models.py                  # Database relational models (Employee, Device, Alert...)
│   └── schemas.py                 # Pydantic schemas for data validation
│
├── agent/
│   ├── agent.py                   # Main SentinelDLP endpoint protection daemon
│   ├── api_client.py              # Secure HTTP API client with offline event buffering
│   ├── browser_monitor.py         # Local HTTP receiver on port 8765 for browser extension
│   ├── clipboard_monitor.py       # Real-time clipboard text watcher
│   ├── config.py                  # Endpoint agent configuration & credentials store
│   ├── email_monitor.py           # Corporate email & EML attachment scanner
│   ├── event_monitor.py           # Operating system event & audit monitor
│   ├── file_monitor.py            # Watchdog filesystem observer
│   ├── process_monitor.py         # Exfiltration tool & process scanner
│   ├── usb_monitor.py             # Removable media & USB storage watcher
│   ├── install_linux.sh           # Interactive/scripted Linux installer & systemd setup
│   └── install_windows.ps1        # Interactive/scripted Windows installer & Task setup
│
├── browser_extension/
│   ├── manifest.json              # Chrome Manifest V3 extension configuration
│   ├── background.js              # Background service worker & network monitor
│   ├── content.js                 # DOM upload & paste interceptor
│   ├── popup.html                 # Extension popup status interface
│   └── popup.js                   # Extension popup logic & agent connectivity check
│
├── frontend/                      # Web dashboard & management portals
│   ├── dashboard.html             # SOC Executive Dashboard
│   ├── employees.html             # Master Employee Directory & 360° Profile Modal
│   ├── alerts.html                # Live Security Alerts Center
│   ├── alert_history.html         # Historical Alert Audit Log
│   ├── incidents.html             # Incident Investigation & Containment Center
│   ├── files.html                 # File Vault & On-Demand DLP Scanner
│   ├── ai_analysis.html           # Live AI Inspection Sandbox
│   ├── ueba.html                  # UEBA Behavioral Risk Center
│   ├── reports.html               # Executive Summary & Export Center
│   ├── settings.html              # System Settings & Policy Rules
│   ├── employee_portal.html       # Employee Self-Service Transparency Portal
│   └── js/                        # Frontend UI controllers & Chart.js scripts
│
├── training/                      # ML training scripts & datasets
│   ├── train.py                   # Train TF-IDF + Logistic Regression model
│   ├── evaluate.py                # Model evaluation (Accuracy, Precision, Recall, F1)
│   └── sample_data.py             # Synthetic corporate training dataset
│
├── tests/                         # Full automated test battery (117 test cases)
│   ├── test_ai_dlp.py             # Tests for OCR, entity recognition, and classifiers
│   ├── test_centralized_fleet.py  # Tests for agent fleet lifecycle & heartbeat thresholds
│   ├── test_dlp_unified.py        # Tests for multi-channel DLP parity
│   ├── test_employee_relationship.py # Tests for Master Employee directory & 360° profile
│   ├── test_file_analysis_pipeline.py # Tests for document parsers & safety bounds
│   ├── test_ueba_engine.py        # Tests for UEBA anomaly detection & baseline models
│   └── conftest.py                # Test fixtures & clean database teardown
│
├── run.py                         # Master CLI entrypoint for all platform operations
├── requirements.txt               # Production Python dependencies
├── rules.txt                      # Comprehensive DLP detection rules specification
└── PROJECT_REPORT.txt             # Exhaustive technical report & operational manual
```

---

## ⚙️ Prerequisites & System Requirements

- **Operating System**: Linux (Ubuntu 20.04+, Debian 11+, RHEL 8+, Kali Linux), Windows 10/11, macOS 12+
- **Python**: Python `3.10` or higher (`python3 --version`)
- **Tesseract OCR**: Required for image text extraction:
  - **Linux (Ubuntu/Debian)**: `sudo apt-get update && sudo apt-get install -y tesseract-ocr`
  - **Linux (Fedora/RHEL)**: `sudo dnf install -y tesseract`
  - **Windows**: Install via [UB-Mannheim Tesseract Installer](https://github.com/UB-Mannheim/tesseract/wiki) and ensure `C:\Program Files\Tesseract-OCR` is added to your `PATH`.
  - **macOS**: `brew install tesseract`
- **Web Browser**: Google Chrome, Microsoft Edge, or Brave (for extension testing).

---

## 🚀 Step-by-Step Installation Guide

### 1. Central Server Setup

```bash
# 1. Clone the repository
git clone https://github.com/Prakash-t1603/Sentineldlp-AI-DLP-DATA-LOSS-PREVENTION.git
cd Sentineldlp-AI-DLP-DATA-LOSS-PREVENTION

# 2. Create and activate a Python virtual environment
python3 -m venv venv
source venv/bin/activate    # On Windows: .\venv\Scripts\activate

# 3. Install required Python packages
pip install --upgrade pip
pip install -r requirements.txt

# 4. Initialize Database Schema & Seed Master Records
python -c "from backend.main import init_database; init_database()"
```

---

### 2. Endpoint Agent Installation (Linux)

#### Method A: Automated Installer (Recommended)
```bash
# Run interactive installer (will prompt for Employee ID, Name, Dept, etc.)
sudo bash agent/install_linux.sh

# Or run non-interactively with parameters:
sudo bash agent/install_linux.sh http://127.0.0.1:8000 EMP-001 "Prakash T" "prakash@company.com" "Cybersecurity" "Senior SOC Analyst"
```

#### Method B: Direct Script Execution
```bash
python agent/agent.py --server "http://127.0.0.1:8000" --employee-id "EMP-001" --name "Prakash T" --email "prakash@company.com" --dept "Cybersecurity" --desig "Senior SOC Analyst"
```

---

### 3. Endpoint Agent Installation (Windows)

Open PowerShell as Administrator:

```powershell
# Run PowerShell installer
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\agent\install_windows.ps1 -ServerUrl "http://172.24.143.236:8000" -EmployeeId "EMP-001" -FullName "Prakash T" -Department "Cybersecurity"
```

---

### 4. Browser Extension Installation

1. Open your Chromium-based browser (Google Chrome, Microsoft Edge, Brave).
2. Navigate to `chrome://extensions/` (or `edge://extensions/`).
3. Enable **Developer mode** toggle in the top-right corner.
4. Click **Load unpacked** button.
5. Select the `browser_extension/` directory from this repository.
6. The SentinelDLP icon will appear in your browser toolbar. The extension will automatically connect to the local agent running on `http://127.0.0.1:8765`.

---

## 💻 Complete Running Commands Reference

All primary platform operations can be executed via the master CLI script [`run.py`](file:///home/prakash/Documents/DLP%20-%20Employee-Monitoring-System/run.py) or direct module execution.

### Launch Central Server

```bash
# Option 1: Master CLI Launcher (Listens on 0.0.0.0:8000 across LAN and Localhost)
python run.py backend

# Option 2: Custom Host and Port
python run.py backend --host 0.0.0.0 --port 8000

# Option 3: Direct Uvicorn Launcher
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

---

### Launch Endpoint Agent

```bash
# Run foreground endpoint protection agent
python agent/agent.py --server "http://127.0.0.1:8000" --employee-id "EMP-001" --name "Prakash T" --dept "Cybersecurity"

# Run agent via run.py wrapper
python run.py agent
```

---

### AI Model Training & Evaluation

```bash
# Train the Supervised Text Classification Model (TF-IDF + Logistic Regression)
python training/train.py

# Evaluate Classification Model & Generate Classification Report (Precision, Recall, F1)
python training/evaluate.py
```

---

### Multi-Endpoint Fleet Simulation

```bash
# Launch simulated fleet of 3 enterprise workstations (Engineering, Finance, HR)
python run.py simulate

# Clean up synthetic simulated data from database
python scripts/cleanup_simulated_data.py
```

---

### Run Full Automated Test Battery

The platform includes 117 automated unit and integration tests covering the entire security pipeline:

```bash
# Run full test suite with verbose output
pytest tests/ -v

# Run tests via run.py wrapper
python run.py test

# Run specific test modules
pytest tests/test_employee_relationship.py -v
pytest tests/test_file_analysis_pipeline.py -v
pytest tests/test_ai_dlp.py -v
pytest tests/test_ueba_engine.py -v
```

---

## 🖥️ SOC Management Portals & Web Navigation

Once the central server is running (`http://127.0.0.1:8000` or `http://<YOUR_IP>:8000`), access the following web portals:

| Web Portal | URL Route | Description |
|---|---|---|
| **SOC Executive Dashboard** | [`/dashboard.html`](http://127.0.0.1:8000/dashboard.html) | High-level risk radar, live DLP stream, fleet health, and threat charts. |
| **Master Employee Directory** | [`/employees.html`](http://127.0.0.1:8000/employees.html) | Corporate employee roster, live status badging, and **360° Profile Modal**. |
| **Live Security Alerts** | [`/alerts.html`](http://127.0.0.1:8000/alerts.html) | Real-time threat alerts with triage filters, risk scores, and quick resolve. |
| **Historical Alerts Log** | [`/alert_history.html`](http://127.0.0.1:8000/alert_history.html) | Historical audit log with CSV export and date range filters. |
| **Security Incidents Center** | [`/incidents.html`](http://127.0.0.1:8000/incidents.html) | Aggregated high-severity incidents for forensic investigation and containment. |
| **File Vault & DLP Scanner** | [`/files.html`](http://127.0.0.1:8000/files.html) | Monitored file repository with on-demand manual file upload scanner. |
| **AI DLP Live Sandbox** | [`/ai_analysis.html`](http://127.0.0.1:8000/ai_analysis.html) | Interactive sandbox to upload and test file classification and OCR confidence. |
| **UEBA Analytics Center** | [`/ueba.html`](http://127.0.0.1:8000/ueba.html) | User behavioral anomalies, volume velocity spikes, and after-hours tracking. |
| **Executive Reports Center** | [`/reports.html`](http://127.0.0.1:8000/reports.html) | Download executive summary PDFs, compliance CSVs, and audit reports. |
| **DLP Policy & System Settings** | [`/settings.html`](http://127.0.0.1:8000/settings.html) | Configure regex rules, channel thresholds, and admin user credentials. |
| **Employee Self-Service Portal** | [`/employee_portal.html`](http://127.0.0.1:8000/employee_portal.html) | Dedicated portal for employees to review their own workstation security status. |
| **Interactive API Documentation** | [`/docs`](http://127.0.0.1:8000/docs) | Swagger UI for complete REST API inspection and live testing. |

---

## 🔑 Default Credentials & Authentication

### System Administrative & Analyst Accounts

| Role | Username / Email | Password | Permissions |
|---|---|---|---|
| **SOC Administrator** | `admin` (`admin@sentineldlp.io`) | `Admin@123456` | Full platform access, employee creation/deletion, policy editing, user management. |
| **Security Analyst** | `analyst` (`analyst@sentineldlp.io`) | `Analyst@123456` | Alert triage, incident response, file investigation, read-only policy access. |

### Default Master Employees (Pre-Seeded)

| Employee ID | Full Name | Department | Designation | Pre-Assigned Device |
|---|---|---|---|---|
| `EMP-001` | **Prakash T** | Cybersecurity | Senior SOC Analyst | `EMP-PC-003` (Workstation `Devil`) |
| `EMP-DEV-01` | **Alex Rivera** | Engineering | Senior Software Engineer | `EMP-PC-001` (`WORKSTATION-ALEX`) |
| `EMP-FIN-02` | **Sarah Jenkins** | Finance | Lead Financial Analyst | `EMP-PC-002` (`FIN-LAPTOP-02`) |
| `EMP-HR-03` | **Marcus Vance** | Human Resources | HR Operations Manager | `EMP-PC-003` (`HR-STATION-03`) |

---

## 🧪 Verification & Testing

To verify that your installation is functioning with 100% test coverage:

```bash
# Execute the full test battery
pytest tests/ -v
```

Expected output:
```text
============================= 117 passed in 9.30s ==============================
```

All 117 automated tests validate:
- Master Employee Directory lifecycle (clean `OFFLINE` initialization, zero ghost records).
- Hardware Device Telemetry binding and token-authenticated heartbeats.
- Real-time OCR and scanned PDF fallback extraction.
- Deterministic Luhn, Verhoeff, and Shannon entropy pattern recognition.
- Browser extension payload ingestion and policy action execution.
- UEBA rolling baseline calculations and velocity anomaly thresholds.
- Correlated security threat alert and incident generation.

---

## 📄 License & Author

- **Author**: Prakash T ([@Prakash-t1603](https://github.com/Prakash-t1603))
- **Repository**: [https://github.com/Prakash-t1603/Sentineldlp-AI-DLP-DATA-LOSS-PREVENTION](https://github.com/Prakash-t1603/Sentineldlp-AI-DLP-DATA-LOSS-PREVENTION)
- **Project**: SentinelDLP AI Enterprise Data Loss Prevention & Threat Intelligence Platform
- **Release Version**: 2.5.0
