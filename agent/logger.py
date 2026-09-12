import os
import sys
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

AGENT_DIR = Path(__file__).resolve().parent
LOG_DIR = AGENT_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "sentinel_agent.log"

def get_agent_logger(name: str = "SentinelDLP.Agent") -> logging.Logger:
    """Configures a thread-safe, rotating file and console logger for the endpoint agent."""
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Console Handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # Rotating File Handler (Max 5MB per file, keeping 3 backups)
    try:
        file_handler = RotatingFileHandler(
            LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except Exception:
        pass

    logger.propagate = False
    return logger

logger = get_agent_logger("SentinelDLP.Agent")
