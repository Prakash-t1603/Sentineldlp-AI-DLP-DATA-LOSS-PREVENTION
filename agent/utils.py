import hashlib
import os
import sys
from pathlib import Path
from typing import Union, Optional
from agent.logger import get_agent_logger

logger = get_agent_logger("SentinelDLP.Agent.Utils")

def get_logger(name: str = "SentinelDLP.Agent"):
    """Compatibility alias for get_agent_logger."""
    return get_agent_logger(name)

def compute_file_hash(filepath: Union[str, Path]) -> str:
    """Compute SHA-256 hash of a file safely in 64KB chunks."""
    sha256 = hashlib.sha256()
    path = Path(filepath)
    if not path.is_file():
        return ""
    try:
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        logger.debug(f"Could not compute hash for {path}: {e}")
        return ""

def read_text_preview(filepath: Union[str, Path], max_chars: int = 4000) -> str:
    """Read a small text snippet from a text-based file for pre-flight scanning."""
    path = Path(filepath)
    if not path.is_file():
        return ""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read(max_chars)
    except Exception:
        return ""
