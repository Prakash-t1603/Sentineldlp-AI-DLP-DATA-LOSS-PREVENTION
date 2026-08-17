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
    username = Column(String(64), index=True, nullable=False)
    hostname = Column(String(128), default="UNKNOWN_HOST")
    ip_address = Column(String(64), default="127.0.0.1")
    operating_system = Column(String(64), default="Windows")
    status = Column(String(32), default="ONLINE", nullable=False)  # ONLINE, OFFLINE, SUSPICIOUS
    last_seen = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)
    risk_score = Column(Float, default=0.0, nullable=False)  # 0.0 to 100.0

    # Relationships
    files = relationship("FileRecord", back_populates="employee", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="employee", cascade="all, delete-orphan")
    incidents = relationship("Incident", back_populates="employee", cascade="all, delete-orphan")
    activities = relationship("ActivityLog", back_populates="employee", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Employee {self.employee_id} ({self.username}) risk={self.risk_score}>"


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
