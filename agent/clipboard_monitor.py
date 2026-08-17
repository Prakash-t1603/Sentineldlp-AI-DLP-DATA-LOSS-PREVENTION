import time
import hashlib
import threading
import platform
from typing import Optional, Dict, Any, Tuple
from backend.services.nlp_service import nlp_service
from backend.utils.helpers import get_logger

logger = get_logger("SentinelDLP.Agent.ClipboardMonitor")

class ClipboardMonitor:
    """
    Real-time endpoint clipboard inspector.
    Monitors copied text and data streams, evaluates sensitive entity patterns
    (API Keys, Passwords, SSN, Credit Cards, Confidential tokens), correlates with
    the active foreground application (WhatsApp, Google Drive, Outlook, Webmail),
    and dispatches immediate DLP exfiltration alerts.
    """
    def __init__(self, agent_instance, exfiltration_monitor):
        self.agent = agent_instance
        self.exfiltration_monitor = exfiltration_monitor
        self.is_running = False
        self._thread = None
        self._last_content_hash = ""
        self._last_alert_time = 0.0
        self._system = platform.system()

        # Windows ctypes clipboard setup
        self._user32 = None
        self._kernel32 = None
        if self._system == "Windows":
            try:
                import ctypes
                from ctypes import wintypes
                self._user32 = ctypes.windll.user32
                self._kernel32 = ctypes.windll.kernel32
                self._CF_UNICODETEXT = 13
                self._user32.OpenClipboard.argtypes = [wintypes.HWND]
                self._user32.CloseClipboard.argtypes = []
                self._user32.GetClipboardData.argtypes = [wintypes.UINT]
                self._user32.GetClipboardData.restype = wintypes.HANDLE
                self._kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
                self._kernel32.GlobalLock.restype = ctypes.c_wchar_p
                self._kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
            except Exception as e:
                logger.warning(f"Windows clipboard ctypes initialization error: {e}")

    def _get_clipboard_text(self) -> Optional[str]:
        """Safely fetch text from the system clipboard."""
        if self._system == "Windows" and self._user32 and self._kernel32:
            try:
                if not self._user32.OpenClipboard(None):
                    return None
                try:
                    handle = self._user32.GetClipboardData(self._CF_UNICODETEXT)
                    if not handle:
                        return None
                    ptr = self._kernel32.GlobalLock(handle)
                    if not ptr:
                        return None
                    text = str(ptr)
                    self._kernel32.GlobalUnlock(handle)
                    return text
                finally:
                    self._user32.CloseClipboard()
            except Exception:
                return None
        else:
            # Fallback for Linux / macOS or if ctypes unavailable
            try:
                import tkinter as tk
                root = tk.Tk()
                root.withdraw()
                text = root.clipboard_get()
                root.destroy()
                return text
            except Exception:
                return None

    def _inspect_clipboard(self):
        """Read clipboard, evaluate sensitivity, correlate with active window, and alert."""
        text = self._get_clipboard_text()
        if not text or len(text.strip()) < 4:
            return

        # Hash check to avoid re-evaluating identical clipboard state
        content_hash = hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()
        if content_hash == self._last_content_hash:
            return
        self._last_content_hash = content_hash

        # Run high-speed NLP entity scan
        entities, max_score, classification = nlp_service.scan_text(text)
        if not entities or classification == "PUBLIC":
            return

        # Get active window & process information
        fg_info = self.exfiltration_monitor.get_foreground_window_info()
        win_title = fg_info.get("title", "Unknown Window")
        proc_name = fg_info.get("process_name", "Unknown Process")

        # Classify if foreground app is an exfiltration target (WhatsApp, Web Storage, Email, etc.)
        channel_info = self.exfiltration_monitor.classify_target_channel(win_title, proc_name)

        entity_summary = ", ".join([f"{e['entity_type']} (x{e['count']})" for e in entities])
        samples = []
        for e in entities:
            for s in e.get("samples", []):
                samples.append(s)
        sample_str = f" [Samples: {', '.join(samples[:3])}]" if samples else ""

        # Determine alert type & severity based on exfiltration vector
        if channel_info:
            category = channel_info["category"]
            channel_name = channel_info["channel_name"]

            if category == "MESSAGING_APP":
                alert_type = "EXFILTRATION_MESSAGING_APP"
                severity = "CRITICAL"
                risk_score = max(95.0, max_score)
                desc = (
                    f"🚨 REAL-TIME EXFILTRATION DETECTED: Sensitive data [{entity_summary}] copied "
                    f"to clipboard while {channel_name} was active ('{win_title}' / {proc_name}). "
                    f"Threat Vector: Instant Messaging / WhatsApp Exfiltration.{sample_str}"
                )
            elif category == "WEB_STORAGE":
                alert_type = "EXFILTRATION_WEB_STORAGE"
                severity = "CRITICAL"
                risk_score = max(96.0, max_score)
                desc = (
                    f"🚨 REAL-TIME EXFILTRATION DETECTED: Sensitive data [{entity_summary}] copied "
                    f"to clipboard while Web Cloud Storage was active ('{win_title}' / {proc_name}). "
                    f"Threat Vector: Cloud Storage Exfiltration.{sample_str}"
                )
            elif category == "EMAIL":
                alert_type = "EXFILTRATION_EMAIL"
                severity = "CRITICAL"
                risk_score = max(92.0, max_score)
                desc = (
                    f"🚨 REAL-TIME EXFILTRATION DETECTED: Sensitive data [{entity_summary}] copied "
                    f"to clipboard while Email application/tab was active ('{win_title}' / {proc_name}). "
                    f"Threat Vector: Email Exfiltration.{sample_str}"
                )
            else:
                alert_type = f"EXFILTRATION_{category}"
                severity = channel_info.get("severity", "CRITICAL")
                risk_score = max(channel_info.get("base_risk", 90.0), max_score)
                desc = (
                    f"🚨 REAL-TIME EXFILTRATION DETECTED: Sensitive data [{entity_summary}] copied "
                    f"while {channel_name} was active ('{win_title}' / {proc_name}).{sample_str}"
                )
        else:
            # General clipboard leak without active exfiltration app
            alert_type = "EXFILTRATION_CLIPBOARD_LEAK"
            severity = "CRITICAL" if classification == "HIGHLY_CONFIDENTIAL" else "HIGH"
            risk_score = max(75.0, max_score)
            desc = (
                f"⚠️ SENSITIVE CLIPBOARD ACTIVITY: Sensitive data [{entity_summary}] ({classification}) "
                f"copied to system clipboard from active window '{win_title}' ({proc_name}).{sample_str}"
            )

        logger.warning(f"DLP CLIPBOARD DETECTION: {alert_type} | Risk: {risk_score} | App: {win_title}")

        # Send Real-Time Alert to Backend
        self.agent.send_alert(
            alert_type=alert_type,
            description=desc,
            severity=severity,
            risk_score=risk_score,
            source="CLIPBOARD_MONITOR"
        )

        # Log Activity
        self.agent.send_activity_log(
            activity_type=alert_type,
            process_name=proc_name,
            destination=win_title,
            risk_score=risk_score
        )

    def _loop(self):
        logger.info("Real-time Clipboard DLP Monitor started (polling every 0.4s).")
        while self.is_running:
            try:
                self._inspect_clipboard()
            except Exception as e:
                logger.debug(f"Clipboard monitor loop tick error: {e}")
            time.sleep(0.4)

    def start(self):
        if not self.is_running:
            self.is_running = True
            self._thread = threading.Thread(target=self._loop, daemon=True)
            self._thread.start()

    def stop(self):
        self.is_running = False
        if self._thread:
            self._thread.join(timeout=2.0)
            logger.info("ClipboardMonitor stopped.")
