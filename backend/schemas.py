from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, EmailStr, Field, ConfigDict

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
    hostname: Optional[str] = "UNKNOWN_HOST"
    ip_address: Optional[str] = "127.0.0.1"
    operating_system: Optional[str] = "Windows"

class EmployeeCreate(EmployeeBase):
    pass

class EmployeeUpdate(BaseModel):
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    operating_system: Optional[str] = None
    status: Optional[str] = Field(None, pattern="^(ONLINE|OFFLINE|SUSPICIOUS)$")
    risk_score: Optional[float] = Field(None, ge=0.0, le=100.0)

class EmployeeResponse(EmployeeBase):
    id: int
    status: str
    last_seen: datetime
    risk_score: float
    model_config = ConfigDict(from_attributes=True)

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
    filename: Optional[str] = None
    model_config = ConfigDict(from_attributes=True)

class AlertHistoryStats(BaseModel):
    total_alerts: int
    open_alerts: int
    investigating_alerts: int
    resolved_alerts: int
    false_positive_alerts: int
    critical_alerts: int

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
    last_seen: datetime

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
    activities: List[ActivityLogResponse]
    files: List[FileRecordResponse]
    alerts: List[AlertResponse]
    incidents: List[IncidentResponse]
    risk_history: List[Dict[str, Any]]
