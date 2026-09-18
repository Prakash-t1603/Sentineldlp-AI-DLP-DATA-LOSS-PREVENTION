import os
import platform
import socket
import uuid
from pathlib import Path

from typing import Optional

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

import re

def normalize_employee_id(value: Optional[str]) -> Optional[str]:
    """
    Safely normalize employee ID by stripping UTF-8 BOM, decoded BOM artifacts ('ï»¿'),
    leading/trailing whitespace, and embedded control characters.
    """
    if value is None:
        return None

    value = str(value)

    # Remove UTF-8 BOM regardless of how it was decoded
    value = value.lstrip("\ufeff")

    # Also handle the common incorrectly decoded UTF-8 BOM
    if value.startswith("ï»¿"):
        value = value[3:]

    # Strip whitespace
    value = value.strip()
    return value

def validate_employee_id(value: Optional[str]) -> bool:
    """
    Validate normalized employee ID.
    Rejects malformed values containing BOMs, control characters, or unexpected Unicode artifacts.
    """
    if not value:
        return False
    if "\ufeff" in value or "ï»¿" in value or any(ord(c) < 32 for c in value):
        return False
    return bool(re.match(r"^[A-Za-z0-9_-]+$", value))

def normalize_server_url(url: Optional[str]) -> str:
    """
    Normalize server URL to ensure scheme (http:// or https://) is present,
    trailing slashes are removed, and /api or /api/v1 paths are stripped from base.
    Prevents double-adding http:// or broken requests without adapter schemes.
    """
    if not url:
        return f"http://{LOCAL_IP}:8000"

    u = str(url).strip().rstrip("/")
    if not (u.startswith("http://") or u.startswith("https://")):
        u = f"http://{u}"

    u = u.rstrip("/")
    if u.endswith("/api/v1"):
        u = u[:-7].rstrip("/")
    elif u.endswith("/api"):
        u = u[:-4].rstrip("/")

    return u

def _is_generated_employee_id(val: str) -> bool:
    """Return True if val looks like an auto-generated hostname/UUID/placeholder string."""
    if not val:
        return True
    v = normalize_employee_id(val).upper()
    if v in ("EMP-LOCAL", "EMP-UNKNOWN", "EMP-DEFAULT", "EMP-TEST", "NOT_ASSIGNED", "UNKNOWN"):
        return True
    if v.startswith("EMP-DESKTOP") or (v.startswith("EMP-WIN-") and len(v) > 15):
        return True
    if HOSTNAME and (v == f"EMP-{HOSTNAME.upper()}" or v.startswith(f"EMP-{HOSTNAME.upper()}-") or v.startswith(f"EMP-{HOSTNAME.upper()[:8]}-")):
        return True
    # Check for pattern like EMP-<HOST>-<HEX> or EMP-<UUID>
    if re.match(r"^EMP-[A-Z0-9_-]+-[A-F0-9]{4,16}$", v):
        return True
    return False

def get_configured_employee_id() -> str:
    """
    Retrieve configured Employee ID from environment, .env, or administrator-provisioned .employee_id file.
    Opens files with encoding='utf-8-sig' to automatically handle UTF-8 BOMs.
    NEVER automatically generates or fabricates an employee ID.
    """
    # 1. Environment variables (explicitly assigned by Admin/Installer)
    env_id = normalize_employee_id(os.environ.get("SENTINEL_EMPLOYEE_ID") or os.environ.get("EMPLOYEE_ID") or os.environ.get("DLP_EMPLOYEE_ID") or "")
    if env_id and validate_employee_id(env_id) and not _is_generated_employee_id(env_id):
        return env_id

    # 2. Administrator-provisioned .employee_id file
    if EMPLOYEE_ID_FILE.exists():
        try:
            with open(EMPLOYEE_ID_FILE, "r", encoding="utf-8-sig") as f:
                val = normalize_employee_id(f.read())
            if val and validate_employee_id(val) and not _is_generated_employee_id(val):
                return val
        except Exception:
            pass

    # 3. Provisioned device config file
    if DEVICE_CONFIG_FILE.exists():
        try:
            import json
            with open(DEVICE_CONFIG_FILE, "r", encoding="utf-8-sig") as f:
                cfg = json.loads(f.read())
            val = normalize_employee_id(cfg.get("employee_id") or "")
            if val and validate_employee_id(val) and not _is_generated_employee_id(val):
                return val
        except Exception:
            pass

    return ""

def save_configured_employee_id(emp_id: str):
    """Persist administrator-assigned employee ID to local .employee_id file without BOM."""
    norm_id = normalize_employee_id(emp_id)
    if norm_id and validate_employee_id(norm_id) and not _is_generated_employee_id(norm_id):
        try:
            with open(EMPLOYEE_ID_FILE, "w", encoding="utf-8") as f:
                f.write(norm_id)
        except Exception:
            pass

EMPLOYEE_ID = get_configured_employee_id()
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
)

SERVER_URL = normalize_server_url(RAW_SERVER_URL)
API_BASE_URL = f"{SERVER_URL}/api/v1"
BACKEND_URL = SERVER_URL
AGENT_SECRET = os.environ.get("AGENT_SECRET", "sentinel_agent_telemetry_secure_token_key_9981")

# Local Device State Management
def load_device_credentials() -> dict:
    import json
    if DEVICE_CONFIG_FILE.exists():
        try:
            with open(DEVICE_CONFIG_FILE, "r", encoding="utf-8-sig") as f:
                return json.loads(f.read())
        except Exception:
            pass
    return {}

def get_or_generate_stable_device_id(preferred_device_id: Optional[str] = None) -> str:
    """
    Retrieve locally persisted device ID or generate a stable unique device ID.
    Separate from employee ID to prevent device collision or hijacking.
    """
    if preferred_device_id and preferred_device_id.strip():
        dev_id = preferred_device_id.strip()
        save_device_credentials(dev_id, load_device_credentials().get("device_token", ""))
        return dev_id

    creds = load_device_credentials()
    saved_dev_id = creds.get("device_id")
    if saved_dev_id and saved_dev_id.strip():
        return saved_dev_id.strip()

    # Generate a unique stable device ID based on machine unique identifier
    unique_suffix = uuid.uuid4().hex[:8].upper()
    dev_id = f"EMP-PC-{unique_suffix}"
    save_device_credentials(dev_id, "")
    return dev_id

def save_device_credentials(device_id: str, device_token: str, employee_id: Optional[str] = None):
    import json
    try:
        data = load_device_credentials()
        data["device_id"] = device_id
        if device_token:
            data["device_token"] = device_token
        data["server_url"] = SERVER_URL
        if employee_id:
            norm_emp = normalize_employee_id(employee_id)
            if norm_emp:
                data["employee_id"] = norm_emp
                save_configured_employee_id(norm_emp)
        with open(DEVICE_CONFIG_FILE, "w", encoding="utf-8") as f:
            f.write(json.dumps(data, indent=2))
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
