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

# Persistent employee ID on endpoint machine
EMPLOYEE_ID_FILE = BASE_DIR / "agent" / ".employee_id"
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

# Backend API Configuration
BACKEND_URL = os.environ.get("BACKEND_URL", "http://127.0.0.1:8000/api/v1")
AGENT_SECRET = os.environ.get("AGENT_SECRET", "sentinel_agent_telemetry_secure_token_key_9981")

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
