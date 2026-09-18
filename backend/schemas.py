from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, EmailStr, Field, ConfigDict, field_validator

# ==================== User & Auth Schemas ====================

class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    email: EmailStr
    role: str = Field("employee", pattern="^(admin|security_analyst|employee)$")

class UserCreate(UserBase):
    password: str = Field(..., min_length=6)

class UserLogin(BaseModel):
    username_or_email: str
    password: str

class UserResponse(UserBase):
    id: int
    is_active: bool
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse

class UserRoleUpdate(BaseModel):
    role: str = Field(..., pattern="^(admin|security_analyst|employee)$")
    is_active: Optional[bool] = None

# ==================== Employee Schemas ====================

class EmployeeBase(BaseModel):
    employee_id: str
    username: str
    full_name: Optional[str] = None
    email: Optional[str] = None
    phone_number: Optional[str] = None
    department: Optional[str] = None
    designation: Optional[str] = None
    manager: Optional[str] = None
    location: Optional[str] = None
    joining_date: Optional[datetime] = None
    active: Optional[bool] = True
    hostname: Optional[str] = "UNKNOWN_HOST"
    ip_address: Optional[str] = "127.0.0.1"
    operating_system: Optional[str] = "Windows"

class EmployeeCreate(EmployeeBase):
    pass

class EmployeeUpdate(BaseModel):
    full_name: Optional[str] = None
    email: Optional[str] = None
    phone_number: Optional[str] = None
    department: Optional[str] = None
    designation: Optional[str] = None
    manager: Optional[str] = None
    location: Optional[str] = None
    active: Optional[bool] = None
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    operating_system: Optional[str] = None
    status: Optional[str] = Field(None, pattern="^(ONLINE|WARNING|OFFLINE|SUSPICIOUS)$")
    risk_score: Optional[float] = Field(None, ge=0.0, le=100.0)

class EmployeeResponse(EmployeeBase):
    id: int
    status: str  # ONLINE, WARNING, OFFLINE, SUSPICIOUS, NOT_REGISTERED
    last_seen: Optional[datetime] = None
    last_seen_seconds_ago: Optional[int] = 0
    risk_score: float
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    device_count: Optional[int] = 0
    primary_device_id: Optional[str] = None
    monitoring_status: Optional[str] = "ACTIVE"
    active_modules: Optional[Dict[str, Any]] = None
    model_config = ConfigDict(from_attributes=True)

class EmployeeBulkDeleteRequest(BaseModel):
    employee_ids: List[str]
    hard_delete: bool = False

class EmployeeBulkDeleteResponse(BaseModel):
    message: str
    deleted_count: int
    deleted_ids: List[str]

# ==================== Device & Agent Schemas ====================

class DeviceRegisterRequest(BaseModel):
    hostname: str
    operating_system: Optional[str] = "Windows"
    ip_address: Optional[str] = "127.0.0.1"
    mac_address: Optional[str] = None
    username: Optional[str] = "employee_user"
    agent_version: Optional[str] = "2.1.0"
    employee_id: Optional[str] = None
    preferred_device_id: Optional[str] = None
    full_name: Optional[str] = None
    email: Optional[str] = None
    department: Optional[str] = None
    designation: Optional[str] = None
    phone_number: Optional[str] = None

class DeviceRegisterResponse(BaseModel):
    device_id: str
    device_token: str
    status: str
    employee_id: Optional[str] = None
    server_time: datetime
    heartbeat_interval_seconds: int = 15
    message: str = "Device registered successfully"

class DeviceHeartbeatRequest(BaseModel):
    device_id: str
    employee_id: Optional[str] = None
    hostname: Optional[str] = None
    username: Optional[str] = None
    full_name: Optional[str] = None
    email: Optional[str] = None
    department: Optional[str] = None
    designation: Optional[str] = None
    phone_number: Optional[str] = None
    ip_address: Optional[str] = None
    operating_system: Optional[str] = None
    agent_version: Optional[str] = "2.1.0"
    timestamp: Optional[datetime] = None
    status: Optional[str] = "ONLINE"
    monitoring_status: Optional[str] = "ACTIVE"
    active_monitoring_modules: Optional[Any] = None
    metrics: Optional[Dict[str, Any]] = None

class DeviceHeartbeatResponse(BaseModel):
    device_id: str
    status: str
    acknowledged: bool = True
    server_time: datetime

class AgentStatusEventRequest(BaseModel):
    device_id: str
    employee_id: Optional[str] = None
    event: str  # AGENT_STARTED, MONITORING_STARTED, AGENT_STOPPED
    timestamp: Optional[datetime] = None
    details: Optional[str] = None

class DeviceResponse(BaseModel):
    id: int
    device_id: str
    hostname: str
    employee_id: Optional[str] = None
    employee_name: Optional[str] = None
    employee_username: Optional[str] = None
    employee_department: Optional[str] = None
    username: Optional[str] = "employee_user"
    operating_system: str
    ip_address: str
    mac_address: Optional[str] = None
    agent_version: str
    status: str  # ONLINE, WARNING, OFFLINE
    monitoring_enabled: bool = True
    monitoring_status: str = "ACTIVE"  # ACTIVE, STOPPED, ERROR
    active_modules: Optional[Dict[str, Any]] = None
    last_seen: datetime
    last_seen_seconds_ago: Optional[int] = 0
    registered_at: datetime
    updated_at: Optional[datetime] = None
    is_active: bool
    model_config = ConfigDict(from_attributes=True)

class DeviceFleetSummaryResponse(BaseModel):
    total_devices: int
    online_devices: int
    offline_devices: int
    warning_devices: int
    devices: List[DeviceResponse]

class FleetStatusSummaryResponse(BaseModel):
    total_employees: int
    live_employees: int
    warning_employees: int
    offline_employees: int
    monitoring_active_employees: int
    total_devices: int
    online_devices: int
    warning_devices: int
    offline_devices: int
    devices: Optional[List[DeviceResponse]] = []
    employees: Optional[List[EmployeeResponse]] = []

# ==================== File Schemas ====================

class FileRecordBase(BaseModel):
    employee_id: str
    filename: str
    filepath: str
    extension: str
    file_size: int = 0
    hash: Optional[str] = ""
    classification: str = Field("PUBLIC", pattern="^(PUBLIC|INTERNAL|CONFIDENTIAL|HIGHLY_CONFIDENTIAL|Unknown/Unclassified|UNKNOWN|UNCLASSIFIED)$")
    sensitivity: float = Field(0.0, ge=0.0, le=100.0)

class FileRecordCreate(FileRecordBase):
    pass

class FileRecordResponse(FileRecordBase):
    id: int
    created_at: datetime
    modified_at: datetime
    model_config = ConfigDict(from_attributes=True)

class FileBulkDeleteRequest(BaseModel):
    file_ids: List[int]

class FileBulkDeleteResponse(BaseModel):
    message: str
    deleted_count: int
    deleted_ids: List[int]

class FileScanRequest(BaseModel):
    filepath: str
    employee_id: str
    action_type: str = "MANUAL_SCAN"

class FileScanResponse(BaseModel):
    filename: str
    filepath: str
    extension: str
    file_size: int
    hash: str
    classification: str
    confidence: float
    detected_entities: List[Dict[str, Any]]
    sensitivity_score: float
    risk_score: float
    risk_level: str
    alert_created: bool
    alert_id: Optional[int] = None

# ==================== Alert Schemas ====================

class AlertBase(BaseModel):
    employee_id: str
    device_id: Optional[str] = None
    event_id: Optional[str] = None
    file_id: Optional[int] = None
    alert_type: str
    severity: str = Field("LOW", pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$")
    risk_score: float = Field(0.0, ge=0.0, le=100.0)
    description: str
    source: str = "FILE_MONITOR"
    status: str = Field("OPEN", pattern="^(OPEN|ACKNOWLEDGED|INVESTIGATING|RESOLVED|FALSE_POSITIVE)$")

class AlertCreate(AlertBase):
    pass

class AlertUpdate(BaseModel):
    status: Optional[str] = Field(None, pattern="^(OPEN|ACKNOWLEDGED|INVESTIGATING|RESOLVED|FALSE_POSITIVE)$")

class AlertResponse(AlertBase):
    id: int
    created_at: datetime
    employee_username: Optional[str] = None
    employee_name: Optional[str] = None
    filename: Optional[str] = None
    model_config = ConfigDict(from_attributes=True)

class AlertHistoryStats(BaseModel):
    total_alerts: int
    open_alerts: int
    investigating_alerts: int
    resolved_alerts: int
    false_positive_alerts: int
    critical_alerts: int

class AlertBulkDeleteRequest(BaseModel):
    alert_ids: List[int]

class AlertBulkDeleteResponse(BaseModel):
    message: str
    deleted_count: int
    deleted_ids: List[int]

# ==================== Incident Schemas ====================

class IncidentBase(BaseModel):
    employee_id: str
    alert_id: Optional[int] = None
    title: str
    description: str
    severity: str = Field("MEDIUM", pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$")
    status: str = Field("OPEN", pattern="^(OPEN|INVESTIGATING|CONTAINED|RESOLVED)$")
    assigned_to: Optional[str] = None
    investigation_notes: Optional[str] = None

class IncidentCreate(IncidentBase):
    pass

class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = Field(None, pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$")
    status: Optional[str] = Field(None, pattern="^(OPEN|INVESTIGATING|CONTAINED|RESOLVED)$")
    assigned_to: Optional[str] = None
    investigation_notes: Optional[str] = None
    resolved_at: Optional[datetime] = None

class IncidentResponse(IncidentBase):
    id: int
    created_at: datetime
    resolved_at: Optional[datetime] = None
    employee_username: Optional[str] = None
    model_config = ConfigDict(from_attributes=True)

# ==================== Activity Log Schemas ====================

class ActivityLogBase(BaseModel):
    employee_id: str
    activity_type: str
    filepath: Optional[str] = None
    process_name: Optional[str] = None
    destination: Optional[str] = None
    risk_score: float = 0.0

class ActivityLogCreate(ActivityLogBase):
    pass

class ActivityLogResponse(ActivityLogBase):
    id: int
    timestamp: datetime
    model_config = ConfigDict(from_attributes=True)

# ==================== Policy Rule Schemas ====================

class PolicyRuleBase(BaseModel):
    name: str
    rule_type: str = Field(..., pattern="^(REGEX|EXTENSION|KEYWORD|PATH)$")
    pattern: str
    sensitivity_level: str = Field("CONFIDENTIAL", pattern="^(PUBLIC|INTERNAL|CONFIDENTIAL|HIGHLY_CONFIDENTIAL)$")
    is_active: bool = True

class PolicyRuleCreate(PolicyRuleBase):
    pass

class PolicyRuleResponse(PolicyRuleBase):
    id: int
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

# ==================== Dashboard & Analytics Schemas ====================

class DashboardStats(BaseModel):
    total_employees: int
    online_employees: int
    sensitive_files: int
    open_alerts: int
    critical_alerts: int
    active_incidents: int
    average_risk_score: float

class KeyValueCount(BaseModel):
    label: str
    count: int
    percentage: Optional[float] = 0.0

class EmployeeRiskRanking(BaseModel):
    employee_id: str
    username: str
    hostname: str
    risk_score: float
    risk_level: str
    alert_count: int
    last_seen: Optional[datetime] = None

class DashboardSummaryResponse(BaseModel):
    stats: DashboardStats
    risk_distribution: List[KeyValueCount]
    alerts_by_severity: List[KeyValueCount]
    files_by_classification: List[KeyValueCount]
    top_risk_employees: List[EmployeeRiskRanking]
    recent_alerts: List[AlertResponse]
    recent_activities: List[ActivityLogResponse]

# ==================== Detailed Employee Profile ====================

class EmployeeDetailResponse(BaseModel):
    employee: EmployeeResponse
    status: Optional[str] = "OFFLINE"
    devices: Optional[List[DeviceResponse]] = []
    monitoring: Optional[Dict[str, str]] = None
    monitoring_modules: Optional[Dict[str, str]] = None
    statistics: Optional[Dict[str, Any]] = None
    security_summary: Optional[Dict[str, Any]] = None
    activities: List[ActivityLogResponse] = []
    files: List[FileRecordResponse] = []
    alerts: List[AlertResponse] = []
    incidents: List[IncidentResponse] = []
    recent_events: Optional[List[Dict[str, Any]]] = []
    dlp_events: Optional[List[Dict[str, Any]]] = []
    risk_history: List[Dict[str, Any]] = []

# ==================== Unified DLP Event & Policy Schemas ====================

class DLPEventBase(BaseModel):
    model_config = ConfigDict(extra="ignore")
    event_id: Optional[str] = None
    employee_id: Optional[str] = None
    device_id: Optional[str] = None
    channel: str = "USB"
    application: Optional[str] = "Workstation App"
    destination: Optional[str] = None
    file_name: str = "unknown"
    file_hash: Optional[str] = ""
    file_size: Optional[int] = 0
    file_type: Optional[str] = ""
    sensitive_data_detected: Optional[bool] = False
    detection_type: Optional[str] = "REGEX"
    risk_score: Optional[float] = 0.0
    risk_level: Optional[str] = "LOW"
    action: Optional[str] = "ALLOW"
    status: Optional[str] = "SCANNED"
    details: Optional[Any] = None
    file_content_base64: Optional[str] = None
    file_path: Optional[str] = None
    extracted_text: Optional[str] = None

    @field_validator("channel", "risk_level", "action", "status", mode="before")
    @classmethod
    def normalize_strings(cls, v):
        if isinstance(v, str):
            return v.strip().upper()
        return v

class DLPEventCreate(DLPEventBase):
    pass

class DLPEventResponse(DLPEventBase):
    id: int
    event_id: str
    timestamp: datetime
    model_config = ConfigDict(from_attributes=True)

class BrowserDLPEventRequest(BaseModel):
    channel: str = "BROWSER"
    application: str = "Google Drive"
    domain: Optional[str] = "drive.google.com"
    file_name: str
    file_size: int = 0
    file_extension: Optional[str] = ""
    browser: Optional[str] = "Google Chrome"
    employee: Optional[str] = None
    employee_id: Optional[str] = None
    device: Optional[str] = None
    device_id: Optional[str] = None
    file_path: Optional[str] = None
    extracted_text: Optional[str] = ""
    file_content_base64: Optional[str] = None
    timestamp: Optional[str] = None
    status: Optional[str] = "PENDING_SCAN"

class EmailDLPEventRequest(BaseModel):
    channel: str = "EMAIL"
    application: str = "Corporate Mail"
    sender: str
    recipient: str
    file_name: Optional[str] = "attachment.dat"
    file_size: int = 0
    file_type: Optional[str] = ""
    subject: Optional[str] = ""
    body: Optional[str] = ""
    extracted_text: Optional[str] = ""
    file_content_base64: Optional[str] = None
    file_path: Optional[str] = None
    employee_id: Optional[str] = None
    device_id: Optional[str] = None
    timestamp: Optional[str] = None

class DLPGenericScanRequest(BaseModel):
    channel: str = Field("BROWSER", pattern="^(USB|BROWSER|CLOUD|EMAIL)$")
    application: str = "Cloud Storage"
    destination: Optional[str] = None
    file_name: str
    file_path: Optional[str] = None
    file_size: int = 0
    extracted_text: Optional[str] = ""
    file_content_base64: Optional[str] = None
    employee_id: Optional[str] = None
    device_id: Optional[str] = None

class DLPGenericScanResponse(BaseModel):
    event_id: str
    channel: str
    application: str
    destination: Optional[str]
    file_name: str
    file_hash: str
    file_size: int
    classification: str
    sensitivity_score: float
    sensitive_data_detected: bool
    detected_entities: List[Dict[str, Any]]
    detection_type: str
    risk_score: float
    risk_level: str
    action: str
    policy_name: str
    alert_created: bool
    alert_id: Optional[int] = None
    status: str
    message: str
    ocr: Optional[Dict[str, Any]] = None
    nlp: Optional[Dict[str, Any]] = None
    ml: Optional[Dict[str, Any]] = None
    ueba: Optional[Dict[str, Any]] = None
    reasons: Optional[List[str]] = None
    sensitive_entities: Optional[List[Dict[str, Any]]] = None

class DLPPolicyBase(BaseModel):
    name: str
    channel: str = Field("ALL", pattern="^(ALL|USB|BROWSER|CLOUD|EMAIL)$")
    min_risk_score: float = Field(60.0, ge=0.0, le=100.0)
    destination_type: str = Field("ALL", pattern="^(ALL|EXTERNAL|INTERNAL|REMOVABLE)$")
    require_sensitive_data: bool = True
    action: str = Field("BLOCK", pattern="^(ALLOW|WARN|BLOCK)$")
    create_alert: bool = True
    is_active: bool = True

class DLPPolicyCreate(DLPPolicyBase):
    pass

class DLPPolicyUpdate(BaseModel):
    name: Optional[str] = None
    channel: Optional[str] = Field(None, pattern="^(ALL|USB|BROWSER|CLOUD|EMAIL)$")
    min_risk_score: Optional[float] = Field(None, ge=0.0, le=100.0)
    destination_type: Optional[str] = Field(None, pattern="^(ALL|EXTERNAL|INTERNAL|REMOVABLE)$")
    require_sensitive_data: Optional[bool] = None
    action: Optional[str] = Field(None, pattern="^(ALLOW|WARN|BLOCK)$")
    create_alert: Optional[bool] = None
    is_active: Optional[bool] = None

class DLPPolicyResponse(DLPPolicyBase):
    id: int
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

class DLPStatisticsResponse(BaseModel):
    total_dlp_events: int
    usb_events: int
    browser_events: int
    email_events: int
    cloud_events: int
    blocked_transfers: int
    warned_transfers: int
    allowed_transfers: int
    critical_incidents: int
    events_by_channel: List[KeyValueCount]
    risk_distribution: List[KeyValueCount]
    top_destinations: List[KeyValueCount]
    top_sensitive_files: List[Dict[str, Any]]
    top_risk_users: List[Dict[str, Any]]


# ==================== AI, ML, NLP & UEBA Intelligence Schemas ====================

class SensitiveEntitySchema(BaseModel):
    entity_type: str
    category: str
    count: int = 1
    confidence: float = 1.0
    masked_sample: Optional[str] = None
    model_config = ConfigDict(from_attributes=True)


class DLPAnalysisRequest(BaseModel):
    text: Optional[str] = ""
    filename: Optional[str] = "inspection_sample.txt"
    channel: Optional[str] = "FILE"
    destination: Optional[str] = ""
    employee_id: Optional[str] = None
    device_id: Optional[str] = "WORKSTATION"


class DLPAnalysisResponse(BaseModel):
    id: Optional[int] = None
    event_id: Optional[str] = None
    employee_id: Optional[str] = None
    device_id: str = "WORKSTATION"
    filename: str
    file_hash: str
    file_size: int = 0
    file_type: Optional[str] = ""
    channel: str = "FILE"
    destination: Optional[str] = None
    classification: str
    confidence: float
    sensitivity_score: float
    ocr_used: bool = False
    nlp_used: bool = True
    ml_used: bool = True
    ueba_used: bool = False
    fast_path: bool = False
    anomaly_score: float = 0.0
    anomaly_level: str = "NORMAL"
    risk_score: float
    risk_level: str
    policy_action: str
    detected_entities: List[Dict[str, Any]] = []
    reasons: List[str] = []
    signals: Dict[str, Any] = {}
    timestamp: Optional[datetime] = None
    model_config = ConfigDict(from_attributes=True)


class DLPAnalysisListResponse(BaseModel):
    total: int
    items: List[DLPAnalysisResponse]


class AnalystFeedbackCreate(BaseModel):
    analysis_id: Optional[int] = None
    event_id: Optional[str] = None
    feedback_type: str = Field(..., pattern="^(TRUE_POSITIVE|FALSE_POSITIVE|CORRECT_CLASSIFICATION|INCORRECT_CLASSIFICATION)$")
    original_classification: str
    corrected_classification: Optional[str] = None
    notes: Optional[str] = None


class AnalystFeedbackResponse(BaseModel):
    id: int
    analysis_id: Optional[int]
    event_id: Optional[str]
    analyst_username: str
    feedback_type: str
    original_classification: str
    corrected_classification: Optional[str]
    notes: Optional[str]
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class UEBAProfileResponse(BaseModel):
    id: int
    employee_id: str
    department: Optional[str]
    total_events_observed: int
    mean_daily_files: float
    std_daily_files: float
    mean_daily_usb_copies: float
    mean_daily_external_uploads: float
    after_hours_ratio: float
    current_anomaly_score: float
    anomaly_status: str
    last_anomaly_at: Optional[datetime]
    last_calculated_at: Optional[datetime]
    model_config = ConfigDict(from_attributes=True)


class UEBAAnomalyResponse(BaseModel):
    id: int
    employee_id: str
    device_id: str
    anomaly_score: float
    anomaly_type: str
    severity: str
    description: str
    metric_name: Optional[str]
    observed_value: float
    expected_value: float
    z_score: float
    peer_group_avg: float
    timestamp: datetime
    model_config = ConfigDict(from_attributes=True)


class ModelMetadataResponse(BaseModel):
    id: int
    model_name: str
    model_version: str
    model_type: str
    status: str
    threshold: float
    precision_score: float
    recall_score: float
    f1_score: float
    feature_count: int
    training_sample_count: int
    trained_at: Optional[datetime]
    last_evaluated_at: Optional[datetime]
    model_config = ConfigDict(from_attributes=True)


