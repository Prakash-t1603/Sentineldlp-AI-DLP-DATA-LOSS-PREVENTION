import os
import sys
import time
import platform
import threading
import psutil
import string
from pathlib import Path
from typing import Set, Dict, List, Optional
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

from agent.config import USB_POLL_INTERVAL_SECONDS, SUPPORTED_EXTENSIONS
from agent.utils import compute_file_hash, read_text_preview
from agent.logger import get_agent_logger as get_logger

logger = get_logger("SentinelDLP.Agent.USBMonitor")

class USBFileTransferHandler(FileSystemEventHandler):
    """
    Real-time watchdog event handler dedicated to removable USB media and external storage.
    Captures file creations, modifications, drag-and-drop, and copy-paste operations on USB drives.
    """
    def __init__(self, agent_instance, drive_path: str):
        super().__init__()
        self.agent = agent_instance
        self.drive_path = drive_path
        self._recently_alerted: Dict[str, float] = {}
        self._in_flight: Set[str] = set()
        self._lock = threading.Lock()

    def _is_recently_alerted(self, content_hash: str) -> bool:
        if not content_hash:
            return False
        now = time.time()
        last = self._recently_alerted.get(content_hash, 0)
        if (now - last) < 5.0:  # 5-second deduplication per content hash
            return True
        return False

    def on_created(self, event: FileSystemEvent):
        if event.is_directory:
            return
        self._schedule_inspection(Path(event.src_path), "CREATE")

    def on_modified(self, event: FileSystemEvent):
        if event.is_directory:
            return
        self._schedule_inspection(Path(event.src_path), "MODIFY")

    def on_moved(self, event: FileSystemEvent):
        if event.is_directory:
            return
        self._schedule_inspection(Path(event.dest_path), "MOVE")

    def _schedule_inspection(self, filepath: Path, action: str):
        """Asynchronously inspect the file with retry backoff to allow Windows/Linux file writes to complete."""
        norm_key = str(filepath).lower()
        with self._lock:
            if norm_key in self._in_flight:
                return
            self._in_flight.add(norm_key)

        threading.Thread(
            target=self._inspect_file_worker,
            args=(filepath, action),
            daemon=True
        ).start()

    def _inspect_file_worker(self, filepath: Path, action: str):
        norm_key = str(filepath).lower()
        try:
            name_lower = filepath.name.lower()
            suffix = filepath.suffix.lower()

            # Ignore system temporary artifacts and volume metadata
            system_ignore = (
                "thumbs.db", "desktop.ini", ".ds_store",
                "system volume information", "$recycle.bin", ".trashes", ".spotlight-v100"
            )
            if any(name_lower == s or name_lower.startswith(s) for s in system_ignore):
                return

            if any(name_lower.endswith(s) for s in (".crdownload", ".part", ".swp", ".lock")):
                return

            # Allow sensitive credentials without standard suffix or with leading dot
            is_credential_file = name_lower in [".env", ".key", ".pem", ".cert", "id_rsa", "credentials", "config.env"]
            if not is_credential_file and suffix and suffix not in SUPPORTED_EXTENSIONS:
                return

            # Retry loop: wait up to 6 attempts for OS file write completion
            extracted_text = ""
            file_size = 0
            last_size = -1
            is_img = suffix in [".jpg", ".jpeg", ".png", ".bmp", ".tiff", ".webp"]

            for attempt in range(6):
                time.sleep(0.3 if attempt == 0 else 0.5)
                if not filepath.exists():
                    continue

                try:
                    current_size = filepath.stat().st_size
                    if current_size > 0:
                        file_size = current_size
                        if not is_img:
                            extracted_text = read_text_preview(filepath)
                        if (current_size == last_size and attempt >= 1) or extracted_text:
                            break
                    last_size = current_size
                except (PermissionError, OSError):
                    continue

            if not filepath.exists():
                return

            file_size = filepath.stat().st_size if filepath.exists() else 0
            file_hash = compute_file_hash(filepath)

            if file_hash and self._is_recently_alerted(file_hash):
                return

            logger.info(f"⚡ USB File Activity intercepted: '{filepath.name}' ({file_size} bytes) on '{self.drive_path}'")

            # 1. Dispatch file scan to Central Server
            scan_res = None
            if hasattr(self.agent, "scan_file"):
                scan_res = self.agent.scan_file(filepath=filepath, activity_type="USB_COPY", destination=self.drive_path)

            classification = "PUBLIC"
            sensitivity_score = 0.0
            entities = []
            indicators = []
            doc_type = None

            if isinstance(scan_res, dict):
                classification = scan_res.get("classification", "PUBLIC")
                sensitivity_score = float(scan_res.get("sensitivity_score", 0.0))
                entities = scan_res.get("detected_entities", [])
                indicators = scan_res.get("indicators", [])
                doc_type = scan_res.get("document_type")
            else:
                # Lightweight endpoint-local text check for quick triage if server scan is pending
                preview = read_text_preview(filepath)
                if preview:
                    from agent.clipboard_monitor import scan_clipboard_text
                    ent, score, cls_name = scan_clipboard_text(preview)
                    if ent:
                        entities = ent
                        sensitivity_score = score
                        classification = cls_name

            # Format entity summary for alert
            if entities:
                entity_summary = ", ".join([f"{e['entity_type']} (x{e.get('count', 1)})" for e in entities])
            elif indicators:
                entity_summary = ", ".join(indicators[:3])
            else:
                entity_summary = "Removable Media Transfer"

            # Centralized Policy & Risk Evaluation
            sensitive_detected = sensitivity_score >= 30.0 or len(entities) > 0 or classification in ["CONFIDENTIAL", "HIGHLY_CONFIDENTIAL"]
            risk_score = min(100.0, max(85.0, sensitivity_score + 10.0)) if sensitive_detected else max(5.0, sensitivity_score)
            risk_level = "CRITICAL" if risk_score >= 80 else ("HIGH" if risk_score >= 60 else ("MEDIUM" if risk_score >= 30 else "LOW"))
            action = "BLOCK" if risk_score >= 80 else ("WARN" if risk_score >= 30 else "ALLOW")

            # If sensitive or confidential, trigger CRITICAL real-time DLP alert
            if sensitive_detected:
                if file_hash:
                    self._recently_alerted[file_hash] = time.time()
                target_desc = f"Image identified as '{doc_type}' ('{filepath.name}')" if doc_type else f"Sensitive file '{filepath.name}'"

                alert_desc = (
                    f"🚨 REAL-TIME USB EXFILTRATION DETECTED: {target_desc} "
                    f"({classification}, Sensitivity: {sensitivity_score}/100) transferred to "
                    f"Removable Storage '{self.drive_path}'. "
                    f"Detected: [{entity_summary}]."
                )
                logger.warning(f"CRITICAL USB EXFILTRATION: {target_desc} -> {self.drive_path}")

                if hasattr(self.agent, "send_alert"):
                    self.agent.send_alert(
                        alert_type="EXFILTRATION_USB_TRANSFER",
                        description=alert_desc,
                        severity="CRITICAL",
                        risk_score=risk_score,
                        source="USB_MONITOR"
                    )

            # Record unified DLP event
            if hasattr(self.agent, "send_dlp_event"):
                self.agent.send_dlp_event(
                    channel="USB",
                    application="USB Storage",
                    file_name=filepath.name,
                    destination=self.drive_path,
                    file_hash=file_hash,
                    file_size=file_size,
                    file_type=suffix,
                    sensitive_data_detected=sensitive_detected,
                    detection_type="PII" if entities else ("CLASSIFIER" if sensitivity_score > 0 else "BENIGN"),
                    risk_score=risk_score,
                    risk_level=risk_level,
                    action=action,
                    status="BLOCKED" if action == "BLOCK" else ("WARNED" if action == "WARN" else "ALLOWED"),
                    details=f"USB Copy: '{filepath.name}' to '{self.drive_path}'. [{entity_summary}]"
                )

            # Always log telemetry activity
            if hasattr(self.agent, "send_activity_log"):
                self.agent.send_activity_log(
                    activity_type="USB_COPY",
                    filepath=str(filepath),
                    destination=self.drive_path,
                    risk_score=sensitivity_score
                )

        except Exception as e:
            logger.error(f"Error inspecting USB file {filepath}: {e}")
        finally:
            with self._lock:
                self._in_flight.discard(norm_key)


class USBMonitor:
    def __init__(self, agent_instance):
        self.agent = agent_instance
        self.is_running = False
        self._thread = None
        self._known_drives: Set[str] = set()
        self._drive_observers: Dict[str, Observer] = {}
        self._system_type = platform.system()

    def _get_active_drives(self) -> Dict[str, str]:
        """
        Discover all currently connected removable / external storage drives on Windows and Linux.
        Uses psutil, Win32 API, /proc/mounts, and standard OS mount points.
        """
        drives = {}

        # ----------------------------------------------------
        # 1. WINDOWS USB & REMOVABLE DRIVE DISCOVERY
        # ----------------------------------------------------
        if self._system_type == "Windows":
            sys_drive = os.environ.get("SystemDrive", "C:").upper().rstrip("\\/")
            
            # Method A: Win32 API GetDriveType
            try:
                import win32file
                import win32api
                drive_strings = win32api.GetLogicalDriveStrings()
                for drive in drive_strings.split("\x00"):
                    if not drive:
                        continue
                    drive_letter = drive.upper().rstrip("\\/")
                    if drive_letter == sys_drive:
                        continue
                    try:
                        dtype = win32file.GetDriveType(drive)
                        # DRIVE_REMOVABLE = 2, DRIVE_REMOTE = 4, DRIVE_CDROM = 5, DRIVE_FIXED = 3
                        if dtype == win32file.DRIVE_REMOVABLE:
                            drives[drive] = "USB_REMOVABLE"
                        elif dtype == win32file.DRIVE_REMOTE:
                            drives[drive] = "NETWORK_SHARE"
                        elif dtype == 3:
                            # Non-system fixed drive (external USB HDD/SSD or secondary drive)
                            try:
                                vol = win32api.GetVolumeInformation(drive)
                                fstype = vol[-1] if vol else "NTFS"
                                drives[drive] = f"EXTERNAL_DRIVE ({fstype})"
                            except Exception:
                                drives[drive] = "EXTERNAL_DRIVE"
                    except Exception:
                        continue
            except Exception:
                pass

            # Method B: psutil partitions check
            try:
                partitions = psutil.disk_partitions(all=True)
                for part in partitions:
                    mount = part.mountpoint
                    drive_letter = mount.upper().rstrip("\\/")
                    if drive_letter == sys_drive:
                        continue
                    opts = part.opts.lower()
                    fstype = part.fstype.lower()

                    is_removable = (
                        "removable" in opts or
                        fstype in ["fat32", "fat", "exfat", "vfat"] or
                        drive_letter not in ["C:"]
                    )
                    if is_removable and mount not in drives:
                        drives[mount] = f"USB_STORAGE ({part.fstype})"
            except Exception as e:
                logger.debug(f"psutil disk partition error on Windows: {e}")

            # Method C: Drive letters fallback (D: through Z:)
            for letter in string.ascii_uppercase:
                if letter in ["C", "A"]:
                    continue
                d_str = f"{letter}:\\"
                if d_str not in drives:
                    p = Path(d_str)
                    try:
                        if p.exists() and p.is_dir():
                            drives[d_str] = "REMOVABLE_STORAGE"
                    except Exception:
                        pass

        # ----------------------------------------------------
        # 2. LINUX USB & REMOVABLE DRIVE DISCOVERY
        # ----------------------------------------------------
        else:
            # Method A: psutil partition scan
            try:
                partitions = psutil.disk_partitions(all=True)
                for part in partitions:
                    mount = part.mountpoint
                    opts = part.opts.lower()
                    fstype = part.fstype.lower()

                    is_external = (
                        mount.startswith(("/media", "/run/media", "/mnt", "/Volumes")) or
                        "removable" in opts or
                        fstype in ["fat32", "fat", "exfat", "vfat", "ntfs", "ext4", "iso9660"] and mount not in ["/", "/boot", "/home", "/etc"]
                    )
                    if is_external and mount not in ["/", "/boot", "/sys", "/proc", "/dev", "/run"]:
                        drives[mount] = f"USB_STORAGE ({part.fstype})"
            except Exception as e:
                logger.debug(f"psutil disk partition error on Linux: {e}")

            # Method B: Scan standard Linux USB mount directories (/media, /run/media, /mnt)
            mount_roots = ["/media", "/run/media", "/mnt"]
            for m_root in mount_roots:
                root_path = Path(m_root)
                if root_path.exists() and root_path.is_dir():
                    try:
                        for entry in root_path.iterdir():
                            if entry.is_dir():
                                # Check user subdirectories like /media/username/USB_NAME
                                for sub in entry.iterdir():
                                    if sub.is_dir() and str(sub) not in drives:
                                        drives[str(sub)] = "LINUX_USB_MOUNT"
                                if str(entry) not in drives and str(entry) not in ["/mnt/wsl", "/mnt/c", "/mnt/d"]:
                                    drives[str(entry)] = "LINUX_MOUNT"
                    except Exception:
                        pass

            # Method C: Parse /proc/mounts if available
            proc_mounts = Path("/proc/mounts")
            if proc_mounts.exists():
                try:
                    with open(proc_mounts, "r") as f:
                        for line in f:
                            parts = line.split()
                            if len(parts) >= 2:
                                dev, mnt = parts[0], parts[1]
                                if dev.startswith(("/dev/sd", "/dev/mmcblk", "/dev/nvme")) and mnt.startswith(("/media", "/run/media", "/mnt")):
                                    if mnt not in drives:
                                        drives[mnt] = f"LINUX_USB ({dev})"
                except Exception:
                    pass

        return drives

    def _attach_usb_watcher(self, drive_path: str):
        """Dynamically attach real-time Watchdog filesystem observer on the USB drive."""
        try:
            resolved_path = str(Path(drive_path).resolve())
        except Exception:
            resolved_path = drive_path

        if resolved_path in self._drive_observers or drive_path in self._drive_observers:
            return

        try:
            target_path = resolved_path if Path(resolved_path).exists() else drive_path
            obs = Observer()
            handler = USBFileTransferHandler(self.agent, drive_path)
            obs.schedule(handler, target_path, recursive=True)
            obs.start()
            self._drive_observers[resolved_path] = obs
            logger.info(f"🛡️  Live Watchdog DLP Interceptor attached to USB drive: {target_path}")
        except Exception as e:
            logger.warning(f"Could not attach Watchdog observer to USB drive {drive_path}: {e}")

    def _detach_usb_watcher(self, drive_path: str):
        """Detach filesystem watcher when USB drive is unmounted."""
        try:
            resolved_path = str(Path(drive_path).resolve())
        except Exception:
            resolved_path = drive_path

        obs = self._drive_observers.pop(resolved_path, None) or self._drive_observers.pop(drive_path, None)
        if obs:
            try:
                obs.stop()
                obs.join(timeout=1.0)
                logger.info(f"Detached Watchdog observer from USB drive: {drive_path}")
            except Exception as e:
                logger.debug(f"Error detaching USB watcher for {drive_path}: {e}")

    def _monitor_loop(self):
        """Poll for newly connected and removed drives on Windows and Linux."""
        logger.info(f"USB / Removable Media Monitor started (Polling every {USB_POLL_INTERVAL_SECONDS}s).")
        initial = self._get_active_drives()
        self._known_drives = set(initial.keys())

        # Attach watchers to all currently connected USB / removable drives
        for drive in self._known_drives:
            self._attach_usb_watcher(drive)

        while self.is_running:
            try:
                current_drives = self._get_active_drives()
                current_set = set(current_drives.keys())

                # Detect newly inserted drives
                inserted = current_set - self._known_drives
                for drive in inserted:
                    dtype = current_drives.get(drive, "REMOVABLE")
                    logger.warning(f"🔌 REMOVABLE STORAGE DETECTED: {drive} ({dtype})")
                    self.agent.send_alert(
                        alert_type="USB_DEVICE_ATTACHED",
                        description=f"Removable media device attached: '{drive}' ({dtype}). Live real-time DLP file interception engaged.",
                        severity="MEDIUM",
                        risk_score=35.0,
                        source="USB_MONITOR"
                    )
                    # Attach live watcher
                    self._attach_usb_watcher(drive)

                # Detect removed drives
                removed = self._known_drives - current_set
                for drive in removed:
                    logger.info(f"⏏️  Removable storage removed: {drive}")
                    self._detach_usb_watcher(drive)

                self._known_drives = current_set
            except Exception as e:
                logger.error(f"USB Monitor loop error: {e}")

            time.sleep(USB_POLL_INTERVAL_SECONDS)

    def start(self):
        if not self.is_running:
            self.is_running = True
            self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self._thread.start()

    def stop(self):
        self.is_running = False
        for drive in list(self._drive_observers.keys()):
            self._detach_usb_watcher(drive)
        if self._thread:
            self._thread.join(timeout=2.0)
            logger.info("USB Monitor stopped.")
