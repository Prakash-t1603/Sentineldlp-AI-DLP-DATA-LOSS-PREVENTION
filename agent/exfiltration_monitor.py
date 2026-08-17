import os
import re
import platform
import psutil
from typing import Dict, Any, Optional
from backend.utils.helpers import get_logger

logger = get_logger("SentinelDLP.Agent.ExfiltrationMonitor")

# Window title and process signatures for known exfiltration channels
EXFILTRATION_SIGNATURES = {
    "MESSAGING_APP": {
        "channel_name": "WhatsApp / Messaging",
        "icon": "fa-brands fa-whatsapp",
        "severity": "CRITICAL",
        "base_risk": 90.0,
        "processes": {
            "whatsapp.exe", "whatsapp", "telegram.exe", "telegram",
            "slack.exe", "slack", "teams.exe", "ms-teams.exe",
            "discord.exe", "discord", "signal.exe", "skype.exe", "wechat.exe"
        },
        "title_keywords": [
            "whatsapp", "telegram", "slack", "microsoft teams", "teams |",
            "discord", "signal", "skype", "wechat", "chat.google.com"
        ]
    },
    "WEB_STORAGE": {
        "channel_name": "Web Cloud Storage",
        "icon": "fa-cloud-arrow-up",
        "severity": "CRITICAL",
        "base_risk": 92.0,
        "processes": {
            "googledrivesync.exe", "dropbox.exe", "onedrive.exe",
            "mega.exe", "box.exe", "pcloud.exe"
        },
        "title_keywords": [
            "google drive", "google cloud", "dropbox", "onedrive",
            "wetransfer", "mega.nz", "mega —", "box |", "box.com",
            "mediafire", "icloud", "sendgb", "nextcloud", "file transfer",
            "upload", "filebin", "wormhole.app", "catbox"
        ]
    },
    "EMAIL": {
        "channel_name": "Email Client / Webmail",
        "icon": "fa-envelope",
        "severity": "HIGH",
        "base_risk": 85.0,
        "processes": {
            "outlook.exe", "thunderbird.exe", "mailspring.exe", "hiri.exe"
        },
        "title_keywords": [
            "gmail", "outlook", "thunderbird", "yahoo mail", "proton mail",
            "protonmail", "zoho mail", "webmail", "compose:", "new message",
            "mail.google.com", "outlook.office.com", "outlook.live.com"
        ]
    },
    "REMOTE_EXFILTRATION_TOOL": {
        "channel_name": "Remote Transfer / Anonymizer",
        "icon": "fa-terminal",
        "severity": "CRITICAL",
        "base_risk": 95.0,
        "processes": {
            "filezilla.exe", "winscp.exe", "tor.exe", "nc.exe",
            "ncat.exe", "curl.exe", "wget.exe", "anydesk.exe", "teamviewer.exe"
        },
        "title_keywords": [
            "filezilla", "winscp", "tor browser", "anydesk", "teamviewer"
        ]
    },
    "USB_MEDIA": {
        "channel_name": "Removable USB Storage",
        "icon": "fa-usb",
        "severity": "CRITICAL",
        "base_risk": 95.0,
        "processes": set(),
        "title_keywords": [
            "usb drive", "removable disk", "flash drive", "usb storage"
        ]
    }
}

class ExfiltrationMonitor:
    """
    Monitors active foreground window titles and processes to identify
    when an employee is interacting with exfiltration channels (WhatsApp, Web Storage, Email, etc.).
    """
    def __init__(self, agent_instance=None):
        self.agent = agent_instance
        self._system = platform.system()
        self._user32 = None
        self._kernel32 = None

        if self._system == "Windows":
            try:
                import ctypes
                self._user32 = ctypes.windll.user32
                self._kernel32 = ctypes.windll.kernel32
            except Exception as e:
                logger.warning(f"Failed to initialize Windows User32 ctypes: {e}")

    def get_foreground_window_info(self) -> Dict[str, Any]:
        """
        Query current foreground window title, process executable, and PID.
        """
        title = ""
        process_name = ""
        pid = 0

        if self._system == "Windows" and self._user32:
            try:
                import ctypes
                hwnd = self._user32.GetForegroundWindow()
                if hwnd:
                    length = self._user32.GetWindowTextLengthW(hwnd)
                    if length > 0:
                        buf = ctypes.create_unicode_buffer(length + 1)
                        self._user32.GetWindowTextW(hwnd, buf, length + 1)
                        title = buf.value

                    c_pid = ctypes.c_ulong()
                    self._user32.GetWindowThreadProcessId(hwnd, ctypes.byref(c_pid))
                    pid = c_pid.value
                    if pid:
                        try:
                            proc = psutil.Process(pid)
                            process_name = proc.name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
            except Exception as e:
                logger.debug(f"Error getting Windows foreground window: {e}")

        return {
            "title": title or "Unknown",
            "process_name": process_name or "Unknown",
            "pid": pid
        }

    def classify_target_channel(self, window_title: str, process_name: str) -> Optional[Dict[str, Any]]:
        """
        Determine if the active window or process matches an exfiltration channel.
        Returns category metadata or None if benign.
        """
        title_lower = (window_title or "").lower()
        proc_lower = (process_name or "").lower()

        for category_key, cfg in EXFILTRATION_SIGNATURES.items():
            # 1. Process matching
            if proc_lower in cfg["processes"]:
                return {
                    "category": category_key,
                    "channel_name": cfg["channel_name"],
                    "icon": cfg["icon"],
                    "severity": cfg["severity"],
                    "base_risk": cfg["base_risk"],
                    "match_type": "PROCESS",
                    "matched": proc_lower
                }

            # 2. Window title keyword matching
            for kw in cfg["title_keywords"]:
                if kw in title_lower:
                    return {
                        "category": category_key,
                        "channel_name": cfg["channel_name"],
                        "icon": cfg["icon"],
                        "severity": cfg["severity"],
                        "base_risk": cfg["base_risk"],
                        "match_type": "WINDOW_TITLE",
                        "matched": kw
                    }

        return None
