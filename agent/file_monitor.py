import time
import threading
from pathlib import Path
from typing import Dict, Optional, List
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

from agent.config import (
    SUPPORTED_EXTENSIONS, IGNORE_DIRS, IGNORE_FILE_PREFIXES,
    IGNORE_FILE_SUFFIXES, EVENT_DEBOUNCE_SECONDS
)
from agent.utils import compute_file_hash, read_text_preview
from agent.logger import get_agent_logger as get_logger

logger = get_logger("SentinelDLP.Agent.FileMonitor")

class DLPFileEventHandler(FileSystemEventHandler):
    def __init__(self, agent_instance):
        super().__init__()
        self.agent = agent_instance
        self._recently_alerted: Dict[str, float] = {}

    def _should_ignore_path(self, path_obj: Path) -> bool:
        """Check if path falls under ignore rules."""
        for part in path_obj.parts:
            if part in IGNORE_DIRS:
                return True
        name = path_obj.name
        if any(name.startswith(p) for p in IGNORE_FILE_PREFIXES):
            return True
        if any(name.endswith(s) for s in IGNORE_FILE_SUFFIXES):
            return True
        return False

    def _is_supported_extension(self, path_obj: Path) -> bool:
        return path_obj.suffix.lower() in SUPPORTED_EXTENSIONS

    def _is_recently_alerted(self, content_hash: str) -> bool:
        if not content_hash:
            return False
        now = time.time()
        last = self._recently_alerted.get(content_hash, 0)
        if (now - last) < 5.0:
            return True
        return False

    def on_created(self, event: FileSystemEvent):
        if event.is_directory:
            return
        path_obj = Path(event.src_path)
        if self._should_ignore_path(path_obj) or not self._is_supported_extension(path_obj):
            return
        self._schedule_file_event(path_obj, "CREATE")

    def on_modified(self, event: FileSystemEvent):
        if event.is_directory:
            return
        path_obj = Path(event.src_path)
        if self._should_ignore_path(path_obj) or not self._is_supported_extension(path_obj):
            return
        self._schedule_file_event(path_obj, "MODIFY")

    def on_moved(self, event: FileSystemEvent):
        if event.is_directory:
            return
        dest_obj = Path(event.dest_path)
        if self._should_ignore_path(dest_obj) or not self._is_supported_extension(dest_obj):
            return
        self._schedule_file_event(dest_obj, "RENAME", destination=str(dest_obj))

    def on_deleted(self, event: FileSystemEvent):
        if event.is_directory:
            return
        path_obj = Path(event.src_path)
        if self._should_ignore_path(path_obj):
            return
        logger.info(f"File DELETION detected: {path_obj.name}")
        self.agent.send_activity_log(
            activity_type="DELETE",
            filepath=str(path_obj),
            risk_score=10.0
        )

    def _schedule_file_event(self, filepath_obj: Path, activity_type: str, destination: Optional[str] = None):
        """Asynchronously process file write with retry backoff."""
        threading.Thread(
            target=self._handle_file_event_worker,
            args=(filepath_obj, activity_type, destination),
            daemon=True
        ).start()

    def _handle_file_event_worker(self, filepath_obj: Path, activity_type: str, destination: Optional[str] = None):
        try:
            # Retry loop: wait up to 5 attempts for Windows write completion
            extracted_text = ""
            file_size = 0
            for attempt in range(6):
                time.sleep(0.3 if attempt == 0 else 0.5)
                if not filepath_obj.exists():
                    continue

                try:
                    file_size = filepath_obj.stat().st_size
                    if file_size > 0 or attempt >= 2:
                        extracted_text, _ = file_analysis_service.extract_text_from_file(filepath_obj, max_retries=2)
                        if extracted_text or file_size > 0:
                            break
                except (PermissionError, OSError):
                    continue

            if not filepath_obj.exists():
                return

            file_size = filepath_obj.stat().st_size if filepath_obj.exists() else 0
            file_hash = compute_file_hash(filepath_obj)
            if file_hash and self._is_recently_alerted(file_hash):
                return

            # Check if active window is an exfiltration target (WhatsApp, Google Drive, Email)
            fg_info = self.agent.exfiltration_monitor.get_foreground_window_info() if hasattr(self.agent, "exfiltration_monitor") else {}
            win_title = fg_info.get("title", "")
            proc_name = fg_info.get("process_name", "")

            # Check if cloud sync folder destination (OneDrive, Dropbox, Google Drive)
            path_str_lower = str(filepath_obj).lower()
            is_cloud_folder = any(c in path_str_lower for c in ["onedrive", "google drive", "dropbox", "box sync", "icloud"])
            channel_info = self.agent.exfiltration_monitor.classify_target_channel(win_title, proc_name) if hasattr(self.agent, "exfiltration_monitor") else None

            # Dispatch file to Central Server for OCR, NLP & Policy Evaluation
            scan_res = self.agent.scan_file(filepath=filepath_obj, activity_type=activity_type, destination=destination)

            # Check if exfiltration channel correlation applies
            if is_cloud_folder:
                self.agent.send_alert(
                    alert_type="EXFILTRATION_CLOUD_SYNC",
                    description=f"File activity '{filepath_obj.name}' in Cloud Sync Folder '{filepath_obj.parent}'.",
                    severity="HIGH",
                    risk_score=70.0,
                    source="FILE_MONITOR"
                )
            elif channel_info:
                category = channel_info["category"]
                channel_name = channel_info["channel_name"]
                self.agent.send_alert(
                    alert_type=f"EXFILTRATION_{category}",
                    description=f"File '{filepath_obj.name}' accessed while {channel_name} was active ('{win_title}' / {proc_name}).",
                    severity="HIGH",
                    risk_score=75.0,
                    source="FILE_MONITOR"
                )

            # Record telemetry
            self.agent.send_activity_log(
                activity_type=activity_type,
                filepath=str(filepath_obj),
                destination=destination or (str(filepath_obj.parent) if is_cloud_folder else None),
                risk_score=15.0
            )

        except Exception as e:
            logger.error(f"Error handling file event for {filepath_obj}: {e}")


class FileMonitor:
    def __init__(self, agent_instance, monitored_paths: list):
        self.agent = agent_instance
        self.monitored_paths = monitored_paths
        self.observer = Observer()
        self.handler = DLPFileEventHandler(agent_instance)
        self.is_running = False

    def start(self):
        """Schedule observer on all valid monitored directory paths."""
        scheduled_count = 0
        for path_str in self.monitored_paths:
            try:
                path_obj = Path(path_str).resolve()
                path_obj.mkdir(parents=True, exist_ok=True)
                self.observer.schedule(self.handler, str(path_obj), recursive=True)
                logger.info(f"Watchdog monitoring scheduled on: {str(path_obj)}")
                scheduled_count += 1
            except Exception as e:
                logger.warning(f"Could not schedule path {path_str}: {e}")

        if scheduled_count > 0:
            self.observer.start()
            self.is_running = True
            logger.info(f"FileMonitor observer active across {scheduled_count} directories.")

    def stop(self):
        if self.is_running:
            self.observer.stop()
            self.observer.join(timeout=3.0)
            self.is_running = False
            logger.info("FileMonitor observer stopped.")
