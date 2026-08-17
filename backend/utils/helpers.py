import hashlib
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any, Union
from backend.config import settings

# Ensure stdout supports UTF-8 on Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Setup structured logger
LOG_FORMAT = "%(asctime)s | %(levelname)-8s | [%(name)s] %(message)s"
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format=LOG_FORMAT,
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(Path(settings.LOGS_DIR) / "sentineldlp.log", encoding="utf-8")
    ]
)

def get_logger(name: str) -> logging.Logger:
    """Get a named logger instance."""
    return logging.getLogger(name)

logger = get_logger("SentinelDLP.Core")

def compute_file_hash(filepath: Union[str, Path]) -> str:
    """Compute SHA-256 hash of a file safely in chunks."""
    sha256 = hashlib.sha256()
    path = Path(filepath)
    if not path.is_file():
        return ""
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        logger.warning(f"Could not hash file {path.name}: {str(e)}")
        return ""

def format_file_size(size_bytes: int) -> str:
    """Format byte size into human readable string."""
    if size_bytes == 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    size = float(size_bytes)
    while size >= 1024 and i < len(units) - 1:
        size /= 1024.0
        i += 1
    return f"{size:.2f} {units[i]}"

def sanitize_for_log(data: Any) -> Any:
    """Recursively redact sensitive keys from logging data."""
    sensitive_keys = {"password", "secret", "token", "key", "password_hash", "access_token", "secret_key"}
    if isinstance(data, dict):
        sanitized = {}
        for k, v in data.items():
            if any(s in k.lower() for s in sensitive_keys):
                sanitized[k] = "[REDACTED]"
            else:
                sanitized[k] = sanitize_for_log(v)
        return sanitized
    elif isinstance(data, list):
        return [sanitize_for_log(item) for item in data]
    return data

def log_security_event(
    component: str,
    event: str,
    severity: str = "INFO",
    employee_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    error: Optional[str] = None
):
    """Log structured security event ensuring zero leak of credentials or sensitive document bodies."""
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "component": component,
        "event": event,
        "severity": severity,
        "employee_id": employee_id or "SYSTEM",
        "details": sanitize_for_log(details or {}),
        "error": error
    }
    log_msg = json.dumps(payload)
    if severity.upper() in ["CRITICAL", "ERROR"]:
        logger.error(f"SECURITY_EVENT: {log_msg}")
    elif severity.upper() == "WARNING":
        logger.warning(f"SECURITY_EVENT: {log_msg}")
    else:
        logger.info(f"SECURITY_EVENT: {log_msg}")
