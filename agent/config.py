import os
import platform
import socket
import uuid
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Endpoint Host Discovery
HOSTNAME = socket.gethostname()
OS_NAME = f"{platform.system()} {platform.release()}"

# Try to get local IP address
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

LOCAL_IP = get_local_ip()

# Persistent employee & device identification files
AGENT_DIR = Path(__file__).resolve().parent
EMPLOYEE_ID_FILE = AGENT_DIR / ".employee_id"
DEVICE_CONFIG_FILE = AGENT_DIR / ".device_config.json"

def get_or_create_employee_id():
    if EMPLOYEE_ID_FILE.exists():
        try:
            return EMPLOYEE_ID_FILE.read_text().strip()
        except Exception:
            pass
    new_id = f"EMP-{HOSTNAME.upper()[:8]}-{uuid.uuid4().hex[:6].upper()}"
    try:
        EMPLOYEE_ID_FILE.write_text(new_id)
    except Exception:
        pass
    return new_id

EMPLOYEE_ID = get_or_create_employee_id()
USERNAME = os.getlogin() if hasattr(os, "getlogin") else os.environ.get("USERNAME", "employee_user")
EMPLOYEE_NAME = os.environ.get("EMPLOYEE_NAME") or os.environ.get("FULL_NAME") or USERNAME
EMPLOYEE_EMAIL = os.environ.get("EMPLOYEE_EMAIL") or os.environ.get("EMAIL") or f"{USERNAME}@company.local"
EMPLOYEE_DEPT = os.environ.get("EMPLOYEE_DEPT") or os.environ.get("DEPARTMENT") or "Engineering"
EMPLOYEE_DESIG = os.environ.get("EMPLOYEE_DESIG") or os.environ.get("DESIGNATION") or "Endpoint User"
EMPLOYEE_PHONE = os.environ.get("EMPLOYEE_PHONE") or ""

# Priority: DLP_SERVER_URL -> SERVER_URL -> BACKEND_URL -> default http://{LOCAL_IP}:8000
RAW_SERVER_URL = (
    os.environ.get("DLP_SERVER_URL") or
    os.environ.get("SERVER_URL") or
    os.environ.get("BACKEND_URL") or
    f"http://{LOCAL_IP}:8000"
).rstrip("/")

# Normalize server base URL
if RAW_SERVER_URL.endswith("/api/v1") or RAW_SERVER_URL.endswith("/api"):
    SERVER_URL = RAW_SERVER_URL.rsplit("/api", 1)[0]
else:
    SERVER_URL = RAW_SERVER_URL

API_BASE_URL = f"{SERVER_URL}/api/v1"
BACKEND_URL = SERVER_URL
AGENT_SECRET = os.environ.get("AGENT_SECRET", "sentinel_agent_telemetry_secure_token_key_9981")

# Local Device State Management
def load_device_credentials():
    import json
    if DEVICE_CONFIG_FILE.exists():
        try:
            return json.loads(DEVICE_CONFIG_FILE.read_text())
        except Exception:
            pass
    return {}

def save_device_credentials(device_id: str, device_token: str):
    import json
    try:
        data = {
            "device_id": device_id,
            "device_token": device_token,
            "server_url": SERVER_URL
        }
        DEVICE_CONFIG_FILE.write_text(json.dumps(data, indent=2))
    except Exception:
        pass

# Monitored Directories
DEFAULT_MONITOR_DIR = BASE_DIR / "monitored_data"
DEFAULT_MONITOR_DIR.mkdir(parents=True, exist_ok=True)
MONITORED_PATHS = [str(DEFAULT_MONITOR_DIR)]

# Timing Configuration
HEARTBEAT_INTERVAL_SECONDS = 15
PROCESS_SCAN_INTERVAL_SECONDS = 5
USB_POLL_INTERVAL_SECONDS = 2
CLIPBOARD_POLL_INTERVAL_SECONDS = 0.4
EVENT_DEBOUNCE_SECONDS = 1.0

# Supported Document Extensions for DLP inspection
SUPPORTED_EXTENSIONS = {
    ".pdf", ".docx", ".txt", ".csv", ".json", ".md",
    ".jpg", ".jpeg", ".png", ".bmp", ".tiff", ".webp",
    ".log", ".py", ".js", ".html", ".css", ".xml", ".yaml", ".yml",
    ".env", ".key", ".pem", ".cert", ".sql", ".conf", ".ini"
}

# Ignore Patterns (directories and temporary lock files)
IGNORE_DIRS = {
    ".git", ".venv", "venv", ".file", "node_modules", "__pycache__",
    ".idea", ".vscode", "AppData", "$Recycle.Bin", "System Volume Information"
}

IGNORE_FILE_PREFIXES = ("~", ".", "tmp_", "temp_")
IGNORE_FILE_SUFFIXES = (".tmp", ".crdownload", ".part", ".swp", ".lock")
