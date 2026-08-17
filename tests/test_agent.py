import pytest
from pathlib import Path
from agent.file_monitor import DLPFileEventHandler
from backend.services.ocr_service import ocr_service

class MockAgent:
    def __init__(self):
        self.scanned = []
    def scan_file(self, filepath, activity_type="CREATE", destination=None):
        self.scanned.append((filepath, activity_type))
    def send_activity_log(self, **kwargs):
        pass

def test_file_monitor_extension_filtering():
    agent = MockAgent()
    handler = DLPFileEventHandler(agent)

    # Valid supported extensions
    assert handler._is_supported_extension(Path("report.pdf")) is True
    assert handler._is_supported_extension(Path("contract.docx")) is True
    assert handler._is_supported_extension(Path("keys.json")) is True

    # Ignored directory checks
    assert handler._should_ignore_path(Path("C:/project/.git/HEAD")) is True
    assert handler._should_ignore_path(Path("C:/project/node_modules/package.json")) is True
    assert handler._should_ignore_path(Path("C:/project/__pycache__/mod.pyc")) is True

def test_ocr_safe_fallback_on_invalid_files():
    # Calling OCR on non-image or non-existent file should safely return empty string without crashing
    assert ocr_service.extract_text_from_image(Path("missing_file.xyz")) == ""
    assert ocr_service.extract_text_from_image(Path(".env")) == ""

def test_exfiltration_channel_classification():
    from agent.exfiltration_monitor import ExfiltrationMonitor
    monitor = ExfiltrationMonitor()

    # 1. WhatsApp / Messaging match
    match_wa = monitor.classify_target_channel("WhatsApp Web - Google Chrome", "chrome.exe")
    assert match_wa is not None
    assert match_wa["category"] == "MESSAGING_APP"
    assert "WhatsApp" in match_wa["channel_name"]

    match_tg = monitor.classify_target_channel("Telegram Desktop", "Telegram.exe")
    assert match_tg is not None
    assert match_tg["category"] == "MESSAGING_APP"

    # 2. Web Cloud Storage match
    match_gdrive = monitor.classify_target_channel("My Drive - Google Drive - Google Chrome", "chrome.exe")
    assert match_gdrive is not None
    assert match_gdrive["category"] == "WEB_STORAGE"

    match_wetransfer = monitor.classify_target_channel("WeTransfer | Send Large Files", "msedge.exe")
    assert match_wetransfer is not None
    assert match_wetransfer["category"] == "WEB_STORAGE"

    # 3. Email client / Webmail match
    match_gmail = monitor.classify_target_channel("Inbox (14) - user@company.com - Gmail - Google Chrome", "chrome.exe")
    assert match_gmail is not None
    assert match_gmail["category"] == "EMAIL"

    match_outlook = monitor.classify_target_channel("Outlook - Inbox", "OUTLOOK.EXE")
    assert match_outlook is not None
    assert match_outlook["category"] == "EMAIL"

    # 4. Benign local editor
    match_vscode = monitor.classify_target_channel("main.py - Visual Studio Code", "Code.exe")
    assert match_vscode is None

def test_clipboard_dlp_exfiltration_detection():
    from agent.clipboard_monitor import ClipboardMonitor
    from agent.exfiltration_monitor import ExfiltrationMonitor

    class MockAgentWithAlerts:
        def __init__(self):
            self.alerts = []
            self.logs = []
        def send_alert(self, **kwargs):
            self.alerts.append(kwargs)
        def send_activity_log(self, **kwargs):
            self.logs.append(kwargs)

    agent = MockAgentWithAlerts()
    exfil_mon = ExfiltrationMonitor()
    clip_mon = ClipboardMonitor(agent, exfil_mon)

    # Force simulated clipboard text containing AWS Secret Key
    sensitive_text = "AKIAIOSFODNN7EXAMPLE aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'"
    clip_mon._get_clipboard_text = lambda: sensitive_text

    # Mock foreground window as WhatsApp Web
    exfil_mon.get_foreground_window_info = lambda: {
        "title": "WhatsApp Web - Google Chrome",
        "process_name": "chrome.exe",
        "pid": 1234
    }

    clip_mon._inspect_clipboard()

    assert len(agent.alerts) == 1
    alert = agent.alerts[0]
    assert alert["alert_type"] == "EXFILTRATION_MESSAGING_APP"
    assert alert["severity"] == "CRITICAL"
    assert "WhatsApp" in alert["description"]

def test_usb_active_drives_discovery():
    from agent.usb_monitor import USBMonitor
    agent = MockAgent()
    usb_mon = USBMonitor(agent)
    drives = usb_mon._get_active_drives()
    assert isinstance(drives, dict)

def test_usb_file_transfer_sensitive_detection(tmp_path):
    from agent.usb_monitor import USBFileTransferHandler
    from PIL import Image, ImageDraw

    class MockAgentWithAlerts:
        def __init__(self):
            self.alerts = []
            self.logs = []
            self.scanned = []
        def send_alert(self, **kwargs):
            self.alerts.append(kwargs)
        def send_activity_log(self, **kwargs):
            self.logs.append(kwargs)
        def scan_file(self, filepath, activity_type="USB_COPY"):
            self.scanned.append((filepath, activity_type))

    agent = MockAgentWithAlerts()
    usb_drive_dir = tmp_path / "simulated_usb"
    usb_drive_dir.mkdir()
    handler = USBFileTransferHandler(agent, str(usb_drive_dir))

    # 1. Simulate copying a sensitive Aadhaar image file to USB
    img = Image.new('RGB', (800, 350), color=(255, 255, 255))
    d = ImageDraw.Draw(img)
    d.text((40, 30), 'GOVT OF INDIA UNIQUE IDENTIFICATION AUTHORITY', fill=(0, 0, 0))
    d.text((40, 75), 'Name: Meera Patel', fill=(0, 0, 0))
    d.text((40, 120), '7766 5544 3322', fill=(0, 0, 0))
    d.text((40, 165), 'Mera Aadhaar Meri Pehchan', fill=(0, 0, 0))

    transferred_file = usb_drive_dir / "sample_id.jpeg"
    img.save(transferred_file)

    handler._inspect_file_worker(transferred_file, "CREATE")

    assert len(agent.alerts) == 1
    alert = agent.alerts[0]
    assert alert["alert_type"] == "EXFILTRATION_USB_TRANSFER"
    assert alert["severity"] == "CRITICAL"
    assert alert["risk_score"] >= 85.0
    assert "Aadhaar" in alert["description"] or "HIGHLY_CONFIDENTIAL" in alert["description"]
    assert len(agent.scanned) == 1

def test_usb_file_transfer_benign_no_alert(tmp_path):
    from agent.usb_monitor import USBFileTransferHandler

    class MockAgentWithAlerts:
        def __init__(self):
            self.alerts = []
            self.logs = []
            self.scanned = []
        def send_alert(self, **kwargs):
            self.alerts.append(kwargs)
        def send_activity_log(self, **kwargs):
            self.logs.append(kwargs)
        def scan_file(self, filepath, activity_type="USB_COPY"):
            self.scanned.append((filepath, activity_type))

    agent = MockAgentWithAlerts()
    usb_drive_dir = tmp_path / "simulated_usb"
    usb_drive_dir.mkdir(exist_ok=True)
    handler = USBFileTransferHandler(agent, str(usb_drive_dir))

    clean_file = usb_drive_dir / "notes.txt"
    clean_file.write_text("Public shopping list: milk, eggs, bread.")

    handler._inspect_file_worker(clean_file, "CREATE")

    # Benign file should not generate any security alerts
    assert len(agent.alerts) == 0
    # But telemetry log should still be recorded
    assert len(agent.logs) == 1
    assert agent.logs[0]["activity_type"] == "USB_COPY"

