# SentinelDLP Enterprise Browser Agent Extension (Manifest V3)

This is the official authorized enterprise browser extension for **SentinelDLP AI**. It provides real-time file upload inspection for:
- **Google Drive** (`drive.google.com`)
- **Microsoft OneDrive & SharePoint** (`onedrive.live.com`, `*.sharepoint.com`)
- **Dropbox** (`dropbox.com`)
- **WhatsApp Web** (`web.whatsapp.com`)
- **Webmail** (`mail.google.com`, `outlook.office.com`, `outlook.live.com`)
- **Other configured enterprise web applications**

---

## 🔒 Defensive Security Architecture
- **Zero HTTPS Traffic Decryption**: Does not attempt to decrypt HTTPS traffic on the wire or bypass encryption.
- **Direct & Endpoint Agent Communication**: Metadata and file pre-flight checks are evaluated against the Central DLP Server (`http://172.24.143.236:8000/api/dlp/browser-event`) and local Endpoint Agent receiver (`http://172.24.143.236:8765/browser-event`).
- **Policy Enforcement**: Automatically applies `ALLOW`, `WARN`, or `BLOCK` actions based on centralized DLP policy rules.

---

## 🚀 How to Load in Google Chrome / Microsoft Edge / Brave

1. Open your browser and navigate to:
   - **Chrome**: `chrome://extensions/`
   - **Edge**: `edge://extensions/`
   - **Brave**: `brave://extensions/`
2. Enable **Developer mode** (toggle switch in the top-right corner).
3. Click **"Load unpacked"** (or click the reload icon if already loaded).
4. Select this directory:
   `/home/prakash/Documents/DLP - Employee-Monitoring-System/browser_extension`
5. The **SentinelDLP AI - Enterprise Browser Agent** will connect directly to `http://172.24.143.236:8000`!

---

## 🧪 Testing File Upload Interception
1. Ensure the SentinelDLP backend server is running on `172.24.143.236`:
   ```bash
   python run.py backend --host 0.0.0.0 --port 8000
   ```
2. Open any web application (e.g. Google Drive, WhatsApp Web, Webmail, or custom portal).
3. Select a sensitive file (e.g. containing API keys, credentials, or PII) for upload.
4. The extension intercepts the upload in real time, transmits telemetry to `http://172.24.143.236:8000/api/dlp/browser-event`, displays the real-time DLP notification, and blocks or permits the upload according to policy.
