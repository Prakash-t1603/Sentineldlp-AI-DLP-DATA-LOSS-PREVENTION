import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column, Integer, String, Float, Boolean, DateTime, ForeignKey, Text
)
from sqlalchemy.orm import relationship
from backend.database import Base

def utcnow():
    return datetime.now(timezone.utc)

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, index=True, nullable=False)
    email = Column(String(128), unique=True, index=True, nullable=False)
    password_hash = Column(String(256), nullable=False)
    role = Column(String(32), default="employee", nullable=False)  # admin, security_analyst, employee
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    def __repr__(self):
        return f"<User {self.username} role={self.role}>"


class Employee(Base):
    __tablename__ = "employees"

    id = Column(Integer, primary_key=True, index=True)
    employee_id = Column(String(64), unique=True, index=True, nullable=False)
    full_name = Column(String(128), nullable=True)
    email = Column(String(128), nullable=True)
    phone_number = Column(String(32), nullable=True)
    department = Column(String(64), nullable=True)
    designation = Column(String(64), nullable=True)
    username = Column(String(64), index=True, nullable=False)
    status = Column(String(32), default="ONLINE", nullable=False)  # ONLINE, WARNING, OFFLINE, SUSPICIOUS
    manager = Column(String(128), nullable=True)
    location = Column(String(128), nullable=True)
    joining_date = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)
    active = Column(Boolean, default=True, nullable=False)
    
    # Host and network telemetry preserved for backward compatibility
    hostname = Column(String(128), default="UNKNOWN_HOST")
    ip_address = Column(String(64), default="127.0.0.1")
    operating_system = Column(String(64), default="Windows")
    last_seen = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)
    risk_score = Column(Float, default=0.0, nullable=False)  # 0.0 to 100.0

    # Multi-Device & Data Relationships
    files = relationship("FileRecord", back_populates="employee", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="employee", cascade="all, delete-orphan")
    incidents = relationship("Incident", back_populates="employee", cascade="all, delete-orphan")
    activities = relationship("ActivityLog", back_populates="employee", cascade="all, delete-orphan")
    dlp_events = relationship("DLPEvent", back_populates="employee", cascade="all, delete-orphan")
    devices = relationship("Device", back_populates="employee", cascade="all, delete-orphan")

    @property
    def is_active(self) -> bool:
        return self.active

    @is_active.setter
    def is_active(self, val: bool):
        self.active = val

    def __repr__(self):
        return f"<Employee {self.employee_id} ({self.full_name or self.username}) risk={self.risk_score}>"


class Device(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String(64), unique=True, index=True, nullable=False)  # e.g., EMP-PC-001, DEV-9B18
    hostname = Column(String(128), index=True, nullable=False)
    employee_id = Column(String(64), ForeignKey("employees.employee_id", ondelete="SET NULL"), nullable=True, index=True)
    username = Column(String(64), default="employee_user")
    operating_system = Column(String(64), default="Windows")
    ip_address = Column(String(64), default="127.0.0.1")
    mac_address = Column(String(64), nullable=True)
    agent_version = Column(String(32), default="2.1.0")
    status = Column(String(32), default="ONLINE", nullable=False)  # ONLINE, WARNING, OFFLINE
    monitoring_enabled = Column(Boolean, default=True, nullable=False)
    monitoring_status = Column(String(32), default="ACTIVE", nullable=False)  # ACTIVE, STOPPED, ERROR
    active_modules = Column(Text, default='{"usb":"ACTIVE","file":"ACTIVE","clipboard":"ACTIVE","process":"ACTIVE","browser":"ACTIVE","email":"ACTIVE","event":"ACTIVE"}', nullable=True)
    device_token = Column(String(256), nullable=False)
    last_seen = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)
    registered_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)

    # Relationships
    employee = relationship("Employee", back_populates="devices")

    def __repr__(self):
        return f"<Device {self.device_id} ({self.hostname}) [{self.status}]>"


class FileRecord(Base):
    __tablename__ = "file_records"

    id = Column(Integer, primary_key=True, index=True)
    employee_id = Column(String(64), ForeignKey("employees.employee_id", ondelete="CASCADE"), index=True, nullable=False)
    filename = Column(String(256), index=True, nullable=False)
    filepath = Column(String(1024), nullable=False)
    extension = Column(String(32), index=True, nullable=False)
    file_size = Column(Integer, default=0)
    hash = Column(String(64), index=True, default="")
    classification = Column(String(32), default="PUBLIC", nullable=False)  # PUBLIC, INTERNAL, CONFIDENTIAL, HIGHLY_CONFIDENTIAL
    sensitivity = Column(Float, default=0.0, nullable=False)  # 0.0 to 100.0
    created_at = Column(DateTime, default=utcnow, nullable=False)
    modified_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    # Relationships
    employee = relationship("Employee", back_populates="files")
    alerts = relationship("Alert", back_populates="file")

    def __repr__(self):
        return f"<FileRecord {self.filename} ({self.classification})>"


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    employee_id = Column(String(64), ForeignKey("employees.employee_id", ondelete="CASCADE"), index=True, nullable=False)
    file_id = Column(Integer, ForeignKey("file_records.id", ondelete="SET NULL"), nullable=True)
    alert_type = Column(String(64), nullable=False)  # SENSITIVE_FILE_DETECTED, USB_COPY, SUSPICIOUS_PROCESS, MASS_TRANSFER
    severity = Column(String(32), default="LOW", nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    risk_score = Column(Float, default=0.0, nullable=False)
    description = Column(Text, nullable=False)
    source = Column(String(64), default="FILE_MONITOR", nullable=False)  # FILE_MONITOR, USB_MONITOR, PROCESS_MONITOR, SCAN
    status = Column(String(32), default="OPEN", nullable=False)  # OPEN, ACKNOWLEDGED, RESOLVED
    created_at = Column(DateTime, default=utcnow, nullable=False)

    # Relationships
    employee = relationship("Employee", back_populates="alerts")
    file = relationship("FileRecord", back_populates="alerts")
    incidents = relationship("Incident", back_populates="alert")

    def __repr__(self):
        return f"<Alert {self.id} [{self.severity}] {self.alert_type}>"


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(Integer, ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True)
    employee_id = Column(String(64), ForeignKey("employees.employee_id", ondelete="CASCADE"), index=True, nullable=False)
    title = Column(String(256), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(32), default="MEDIUM", nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    status = Column(String(32), default="OPEN", nullable=False)  # OPEN, INVESTIGATING, CONTAINED, RESOLVED
    assigned_to = Column(String(64), nullable=True)
    investigation_notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    resolved_at = Column(DateTime, nullable=True)

    # Relationships
    employee = relationship("Employee", back_populates="incidents")
    alert = relationship("Alert", back_populates="incidents")

    def __repr__(self):
        return f"<Incident {self.id} {self.title} [{self.status}]>"


class ActivityLog(Base):
    __tablename__ = "activity_logs"

    id = Column(Integer, primary_key=True, index=True)
    employee_id = Column(String(64), ForeignKey("employees.employee_id", ondelete="CASCADE"), index=True, nullable=False)
    activity_type = Column(String(64), nullable=False)  # CREATE, MODIFY, DELETE, MOVE, RENAME, USB_COPY, PROCESS_SPAWN, CLOUD_SYNC
    filepath = Column(String(1024), nullable=True)
    process_name = Column(String(128), nullable=True)
    destination = Column(String(512), nullable=True)
    timestamp = Column(DateTime, default=utcnow, nullable=False)
    risk_score = Column(Float, default=0.0, nullable=False)

    # Relationships
    employee = relationship("Employee", back_populates="activities")

    def __repr__(self):
        return f"<ActivityLog {self.employee_id} {self.activity_type} at {self.timestamp}>"


class PolicyRule(Base):
    __tablename__ = "policy_rules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(128), nullable=False)
    rule_type = Column(String(32), nullable=False)  # REGEX, EXTENSION, KEYWORD, PATH
    pattern = Column(String(512), nullable=False)
    sensitivity_level = Column(String(32), default="CONFIDENTIAL", nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    def __repr__(self):
        return f"<PolicyRule {self.name} ({self.rule_type})>"


class DLPEvent(Base):
    __tablename__ = "dlp_events"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String(64), unique=True, index=True, default=lambda: f"DLP-{uuid.uuid4().hex[:12].upper()}", nullable=False)
    employee_id = Column(String(64), ForeignKey("employees.employee_id", ondelete="CASCADE"), index=True, nullable=False)
    device_id = Column(String(128), default="WORKSTATION", nullable=False)
    channel = Column(String(32), index=True, nullable=False)  # USB, BROWSER, CLOUD, EMAIL
    application = Column(String(128), nullable=False)  # Google Drive, WhatsApp Web, Outlook, Removable Storage, Dropbox, OneDrive, etc.
    destination = Column(String(512), nullable=True)  # drive.google.com, external@example.com, web.whatsapp.com, E:\, etc.
    file_name = Column(String(256), nullable=False)
    file_hash = Column(String(64), default="", index=True)
    file_size = Column(Integer, default=0)
    file_type = Column(String(32), default="")
    sensitive_data_detected = Column(Boolean, default=False, nullable=False)
    detection_type = Column(String(64), default="REGEX", nullable=False)  # REGEX, KEYWORD, PII, OCR, CLASSIFIER, EXTENSION, COMPOSITE
    risk_score = Column(Float, default=0.0, nullable=False)  # 0.0 to 100.0
    risk_level = Column(String(32), default="LOW", nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    action = Column(String(32), default="ALLOW", nullable=False)  # ALLOW, WARN, BLOCK
    timestamp = Column(DateTime, default=utcnow, nullable=False)
    status = Column(String(32), default="SCANNED", nullable=False)  # PENDING_SCAN, SCANNED, ALLOWED, WARNED, BLOCKED, ALERTED
    details = Column(Text, nullable=True)

    # Relationships
    employee = relationship("Employee", back_populates="dlp_events")

    def __repr__(self):
        return f"<DLPEvent {self.event_id} [{self.channel}] {self.file_name} -> {self.action} ({self.risk_level})>"


class DLPPolicy(Base):
    __tablename__ = "dlp_policies"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(128), nullable=False)
    channel = Column(String(32), default="ALL", nullable=False)  # ALL, USB, BROWSER, CLOUD, EMAIL
    min_risk_score = Column(Float, default=60.0, nullable=False)
    destination_type = Column(String(32), default="ALL", nullable=False)  # ALL, EXTERNAL, INTERNAL, REMOVABLE
    require_sensitive_data = Column(Boolean, default=True, nullable=False)
    action = Column(String(32), default="BLOCK", nullable=False)  # ALLOW, WARN, BLOCK
    create_alert = Column(Boolean, default=True, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    def __repr__(self):
        return f"<DLPPolicy {self.name} [{self.channel}] -> {self.action}>"

