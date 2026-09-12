# SentinelDLP Endpoint Protection Agent

Lightweight, distributed endpoint protection agent for **SentinelDLP AI**.

---

## 🔒 What This Agent Monitors
- **USB Drives**: Removable storage insertion/removal & real-time file write watchdog.
- **Filesystem**: Monitored folders for sensitive file creation and cloud sync.
- **Clipboard**: Detects copied secrets and PII (API keys, passwords, Aadhaar, PAN, Credit Cards).
- **Browser Receiver**: Local loopback on `http://127.0.0.1:8765` for Chrome/Edge/Brave extension uploads.
- **Process Telemetry**: Monitors high-risk exfiltration processes (`curl`, `mega`, `tor`, `winscp`).

---

## 🚀 Quick Installation (Linux)

```bash
# 1. Clone or copy only this agent/ folder to the employee PC

# 2. Run automated installer:
./install_linux.sh "http://<CENTRAL_SERVER_IP>:8000" "EMP-001"

# Or manually:
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python -m agent --server-url "http://<CENTRAL_SERVER_IP>:8000" --employee-id "EMP-001"
```

---

## 🪟 Quick Installation (Windows)

```powershell
# In PowerShell (Run as Administrator):
.\install_windows.ps1 -ServerUrl "http://<CENTRAL_SERVER_IP>:8000" -EmployeeId "EMP-001"

# Or manually:
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
python -m agent --server-url "http://<CENTRAL_SERVER_IP>:8000" --employee-id "EMP-001"
```

---

## 🛡️ Offline Resiliency
If the employee machine loses network connection to the Central DLP Server, all alerts and events are buffered locally in `logs/offline_events.db` (SQLite) and flushed in FIFO order upon reconnection.
