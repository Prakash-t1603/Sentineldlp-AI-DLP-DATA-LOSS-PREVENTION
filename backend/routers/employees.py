import json
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any

from backend.database import get_db
from backend.models import Employee, Device, FileRecord, Alert, Incident, ActivityLog, DLPEvent, User
from backend.schemas import (
    EmployeeCreate, EmployeeUpdate, EmployeeResponse, EmployeeDetailResponse,
    DeviceResponse, ActivityLogResponse, FileRecordResponse, AlertResponse, IncidentResponse,
    EmployeeBulkDeleteRequest, EmployeeBulkDeleteResponse
)
from backend.services.fleet_monitor import fleet_monitor_service
from backend.dependencies import require_analyst_or_admin, get_current_user_or_agent, require_admin
from backend.utils.helpers import get_logger

logger = get_logger("SentinelDLP.EmployeesRouter")
router = APIRouter(prefix="/employees", tags=["Employee Directory & Management"])

def _build_employee_response(emp: Employee, db: Session, now: datetime) -> EmployeeResponse:
    """Helper to convert Employee DB model into rich EmployeeResponse with live telemetry."""
    # Check linked devices
    linked_devices = db.query(Device).filter(Device.employee_id == emp.employee_id, Device.is_active == True).order_by(Device.last_seen.desc()).all()
    
    if linked_devices:
        status_name = fleet_monitor_service.evaluate_employee_status(emp, db, now)
        primary_dev = linked_devices[0].device_id
        effective_ip = linked_devices[0].ip_address or emp.ip_address or "127.0.0.1"
        effective_os = linked_devices[0].operating_system or emp.operating_system or "Linux"
        effective_host = linked_devices[0].hostname or emp.hostname or "WORKSTATION"
        monitoring_status = "ACTIVE" if status_name == "ONLINE" else ("STOPPED" if status_name == "OFFLINE" else "WARNING")
    else:
        status_name = "ONLINE" if (emp.last_seen and (now - (emp.last_seen.replace(tzinfo=timezone.utc) if emp.last_seen.tzinfo is None else emp.last_seen)).total_seconds() <= 30) else "OFFLINE"
        primary_dev = "NOT ASSIGNED"
        effective_ip = emp.ip_address if emp.ip_address and emp.ip_address not in ["127.0.0.1", "NOT_ASSIGNED"] else "NOT ASSIGNED"
        effective_os = emp.operating_system if emp.operating_system and emp.operating_system not in ["Windows", "Linux", "NOT_ASSIGNED"] else "NOT ASSIGNED"
        effective_host = emp.hostname if emp.hostname and emp.hostname not in ["UNKNOWN_HOST", "NOT_ASSIGNED"] else "NOT ASSIGNED"
        monitoring_status = "NOT REGISTERED" if not emp.last_seen else ("ACTIVE" if status_name == "ONLINE" else "STOPPED")

    diff_secs = max(0, int((now - (emp.last_seen.replace(tzinfo=timezone.utc) if emp.last_seen.tzinfo is None else emp.last_seen)).total_seconds())) if emp.last_seen else None
    
    # Active monitoring modules aggregation
    active_mods = {}
    for d in linked_devices:
        if d.active_modules:
            try:
                mods = json.loads(d.active_modules) if isinstance(d.active_modules, str) else d.active_modules
                active_mods.update(mods)
            except Exception:
                pass

    return EmployeeResponse(
        id=emp.id,
        employee_id=emp.employee_id,
        username=emp.username,
        full_name=emp.full_name or emp.username,
        email=emp.email,
        phone_number=emp.phone_number,
        department=emp.department or "Engineering",
        designation=emp.designation or "Endpoint Operator",
        manager=emp.manager,
        location=emp.location,
        joining_date=emp.joining_date,
        active=emp.active,
        hostname=effective_host,
        ip_address=effective_ip,
        operating_system=effective_os,
        status=status_name,
        last_seen=emp.last_seen,
        last_seen_seconds_ago=diff_secs or 0,
        risk_score=emp.risk_score,
        created_at=emp.created_at,
        updated_at=emp.updated_at,
        device_count=len(linked_devices),
        primary_device_id=primary_dev,
        monitoring_status=monitoring_status,
        active_modules=active_mods
    )

@router.get("", response_model=List[EmployeeResponse])
def list_employees(
    status_filter: Optional[str] = Query(None, alias="status"),
    department: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    os: Optional[str] = Query(None),
    min_risk: Optional[float] = Query(None, ge=0.0, le=100.0),
    skip: int = 0,
    limit: int = 200,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin)
):
    """
    List all employees with dynamic live status calculation and full multi-attribute filtering.
    """
    now = datetime.now(timezone.utc)
    query = db.query(Employee).filter(Employee.active == True)

    if department:
        query = query.filter(Employee.department.ilike(f"%{department}%"))
    if os:
        query = query.filter(Employee.operating_system.ilike(f"%{os}%"))
    if min_risk is not None:
        query = query.filter(Employee.risk_score >= min_risk)

    employees = query.order_by(Employee.risk_score.desc(), Employee.id.desc()).all()
    results = []

    for emp in employees:
        emp_resp = _build_employee_response(emp, db, now)
        
        # Apply runtime status filter
        if status_filter and emp_resp.status.upper() != status_filter.upper():
            continue
        
        # Apply search filter (employee_id, full_name, username, hostname, email, primary_device_id)
        if search:
            s = search.lower()
            match = (
                s in emp_resp.employee_id.lower() or
                s in (emp_resp.full_name or "").lower() or
                s in emp_resp.username.lower() or
                s in (emp_resp.email or "").lower() or
                s in (emp_resp.hostname or "").lower() or
                s in (emp_resp.primary_device_id or "").lower()
            )
            if not match:
                continue

        results.append(emp_resp)

    return results[skip : skip + limit]

@router.post("", response_model=EmployeeResponse, status_code=status.HTTP_201_CREATED)
def create_employee(
    emp_data: EmployeeCreate,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_admin)
):
    """
    Create a new employee record (Admin only).
    Initializes employee master record cleanly without fabricating fake devices or false heartbeats.
    """
    existing = db.query(Employee).filter(Employee.employee_id == emp_data.employee_id).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Employee with ID '{emp_data.employee_id}' already exists"
        )

    now = datetime.now(timezone.utc)
    employee = Employee(
        employee_id=emp_data.employee_id,
        username=emp_data.username,
        full_name=emp_data.full_name or emp_data.username,
        email=emp_data.email,
        phone_number=emp_data.phone_number,
        department=emp_data.department or "General",
        designation=emp_data.designation or "Employee",
        manager=emp_data.manager,
        location=emp_data.location or "Office",
        joining_date=emp_data.joining_date or now,
        hostname="NOT_ASSIGNED",
        ip_address="NOT_ASSIGNED",
        operating_system="NOT_ASSIGNED",
        status="OFFLINE",
        last_seen=None,
        created_at=now,
        updated_at=now,
        active=True,
        risk_score=0.0
    )
    db.add(employee)
    db.commit()
    db.refresh(employee)
    logger.info(f"Admin {admin_user.username} created new master employee: {employee.employee_id} ({employee.full_name})")
    return _build_employee_response(employee, db, now)

@router.put("/{employee_id}", response_model=EmployeeResponse)
def update_employee(
    employee_id: str,
    emp_data: EmployeeUpdate,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_admin)
):
    """
    Update employee details (Admin only).
    """
    employee = db.query(Employee).filter(Employee.employee_id == employee_id).first()
    if not employee:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Employee '{employee_id}' not found")

    update_dict = emp_data.model_dump(exclude_unset=True)
    for k, v in update_dict.items():
        if hasattr(employee, k):
            setattr(employee, k, v)

    now = datetime.now(timezone.utc)
    employee.updated_at = now
    db.commit()
    db.refresh(employee)
    logger.info(f"Admin {admin_user.username} updated employee {employee_id}")
    return _build_employee_response(employee, db, now)

@router.get("/{employee_id}", response_model=EmployeeDetailResponse)
def get_employee_detail(
    employee_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin)
):
    """
    Retrieve full 360-degree security profile of an employee.
    Includes Employee Info, Linked Devices, Monitoring Modules, Security Summary, Recent Activity, Alerts, Incidents & DLP Events.
    """
    employee = db.query(Employee).filter(Employee.employee_id == employee_id).first()
    if not employee:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Employee '{employee_id}' not found")

    now = datetime.now(timezone.utc)
    emp_resp = _build_employee_response(employee, db, now)

    # 1. Linked Devices
    db_devices = db.query(Device).filter(Device.employee_id == employee_id, Device.is_active == True).all()
    devices_resp = []
    active_monitoring_modules = {
        "usb": "STOPPED",
        "file": "STOPPED",
        "clipboard": "STOPPED",
        "process": "STOPPED",
        "browser": "STOPPED",
        "email": "STOPPED",
        "event": "STOPPED",
        "heartbeat": "ACTIVE" if emp_resp.status == "ONLINE" else "STOPPED"
    }

    for d in db_devices:
        d_status, diff_secs = fleet_monitor_service.evaluate_status(d.last_seen, now)
        mod_dict = {}
        if d.active_modules:
            try:
                mod_dict = json.loads(d.active_modules) if isinstance(d.active_modules, str) else d.active_modules
                for mod_k, mod_v in mod_dict.items():
                    if d_status == "ONLINE":
                        active_monitoring_modules[mod_k.lower()] = "ACTIVE"
            except Exception:
                pass

        devices_resp.append(DeviceResponse(
            id=d.id,
            device_id=d.device_id,
            hostname=d.hostname,
            employee_id=d.employee_id,
            employee_name=employee.full_name or employee.username,
            employee_username=employee.username,
            employee_department=employee.department,
            username=d.username or "employee_user",
            operating_system=d.operating_system,
            ip_address=d.ip_address,
            mac_address=d.mac_address,
            agent_version=d.agent_version,
            status=d_status,
            monitoring_enabled=d.monitoring_enabled,
            monitoring_status=d.monitoring_status if d_status == "ONLINE" else "STOPPED",
            active_modules=mod_dict,
            last_seen=d.last_seen,
            last_seen_seconds_ago=diff_secs or 0,
            registered_at=d.registered_at,
            updated_at=d.updated_at,
            is_active=d.is_active
        ))

    # 2. Activity Logs
    activities = db.query(ActivityLog).filter(
        ActivityLog.employee_id == employee_id
    ).order_by(ActivityLog.timestamp.desc()).limit(50).all()

    # 3. File Records
    files = db.query(FileRecord).filter(
        FileRecord.employee_id == employee_id
    ).order_by(FileRecord.sensitivity.desc()).limit(50).all()

    # 4. Alerts
    alerts = db.query(Alert).filter(
        Alert.employee_id == employee_id
    ).order_by(Alert.created_at.desc()).limit(50).all()

    # 5. Incidents
    incidents = db.query(Incident).filter(
        Incident.employee_id == employee_id
    ).order_by(Incident.created_at.desc()).limit(20).all()

    # 6. DLP Events
    dlp_events = db.query(DLPEvent).filter(
        DLPEvent.employee_id == employee_id
    ).order_by(DLPEvent.timestamp.desc()).limit(50).all()

    # Security Summary Metrics
    total_events = len(dlp_events) + len(activities)
    blocked_count = sum(1 for e in dlp_events if e.action == "BLOCK")
    warning_count = sum(1 for e in dlp_events if e.action == "WARN")
    last_event_time = dlp_events[0].timestamp.isoformat() if dlp_events else (activities[0].timestamp.isoformat() if activities else None)

    security_summary = {
        "total_events": total_events,
        "events": total_events,
        "dlp_events": len(dlp_events),
        "alerts": len(alerts),
        "incidents": len(incidents),
        "blocked_events": blocked_count,
        "blocked": blocked_count,
        "warnings": warning_count,
        "risk_score": employee.risk_score,
        "last_security_event": last_event_time
    }

    dlp_events_formatted = [
        {
            "id": ev.id,
            "event_id": ev.event_id,
            "employee_id": ev.employee_id,
            "device_id": ev.device_id,
            "channel": ev.channel,
            "application": ev.application,
            "file_name": ev.file_name,
            "destination": ev.destination,
            "risk_score": ev.risk_score,
            "risk_level": ev.risk_level,
            "action": ev.action,
            "timestamp": ev.timestamp.isoformat() if ev.timestamp else "",
            "details": ev.details
        }
        for ev in dlp_events
    ]

    risk_history = [
        {
            "timestamp": act.timestamp.isoformat() if act.timestamp else "",
            "activity_type": act.activity_type,
            "risk_score": act.risk_score
        }
        for act in activities[:15]
    ]

    return EmployeeDetailResponse(
        employee=emp_resp,
        status=emp_resp.status,
        devices=devices_resp,
        monitoring=active_monitoring_modules,
        monitoring_modules=active_monitoring_modules,
        statistics=security_summary,
        security_summary=security_summary,
        activities=[ActivityLogResponse.model_validate(a) for a in activities],
        files=[FileRecordResponse.model_validate(f) for f in files],
        alerts=[AlertResponse.model_validate(a) for a in alerts],
        incidents=[IncidentResponse.model_validate(i) for i in incidents],
        recent_events=dlp_events_formatted,
        dlp_events=dlp_events_formatted,
        risk_history=risk_history
    )

@router.get("/{employee_id}/devices", response_model=List[DeviceResponse])
def get_employee_devices(
    employee_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin)
):
    """
    Get all endpoint devices linked to a specific employee.
    """
    emp = db.query(Employee).filter(Employee.employee_id == employee_id).first()
    if not emp:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Employee '{employee_id}' not found")

    now = datetime.now(timezone.utc)
    devices = db.query(Device).filter(Device.employee_id == employee_id, Device.is_active == True).all()
    
    results = []
    for d in devices:
        d_status, diff_secs = fleet_monitor_service.evaluate_status(d.last_seen, now)
        mod_dict = {}
        if d.active_modules:
            try:
                mod_dict = json.loads(d.active_modules) if isinstance(d.active_modules, str) else d.active_modules
            except Exception:
                pass

        results.append(DeviceResponse(
            id=d.id,
            device_id=d.device_id,
            hostname=d.hostname,
            employee_id=d.employee_id,
            employee_name=emp.full_name or emp.username,
            employee_username=emp.username,
            employee_department=emp.department,
            username=d.username or "employee_user",
            operating_system=d.operating_system,
            ip_address=d.ip_address,
            mac_address=d.mac_address,
            agent_version=d.agent_version,
            status=d_status,
            monitoring_enabled=d.monitoring_enabled,
            monitoring_status=d.monitoring_status if d_status == "ONLINE" else "STOPPED",
            active_modules=mod_dict,
            last_seen=d.last_seen,
            last_seen_seconds_ago=diff_secs or 0,
            registered_at=d.registered_at,
            updated_at=d.updated_at,
            is_active=d.is_active
        ))
    return results

@router.get("/{employee_id}/alerts", response_model=List[AlertResponse])
def get_employee_alerts(
    employee_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin)
):
    """
    Get all security alerts associated with an employee.
    """
    emp = db.query(Employee).filter(Employee.employee_id == employee_id).first()
    if not emp:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Employee '{employee_id}' not found")
    alerts = db.query(Alert).filter(Alert.employee_id == employee_id).order_by(Alert.created_at.desc()).all()
    return [AlertResponse.model_validate(a) for a in alerts]

@router.get("/{employee_id}/incidents", response_model=List[IncidentResponse])
def get_employee_incidents(
    employee_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin)
):
    """
    Get all security incidents associated with an employee.
    """
    emp = db.query(Employee).filter(Employee.employee_id == employee_id).first()
    if not emp:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Employee '{employee_id}' not found")
    incidents = db.query(Incident).filter(Incident.employee_id == employee_id).order_by(Incident.created_at.desc()).all()
    return [IncidentResponse.model_validate(i) for i in incidents]

@router.get("/{employee_id}/events")
def get_employee_events(
    employee_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin)
):
    """
    Get all recent DLP and audit events associated with an employee.
    """
    emp = db.query(Employee).filter(Employee.employee_id == employee_id).first()
    if not emp:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Employee '{employee_id}' not found")
    dlp_events = db.query(DLPEvent).filter(DLPEvent.employee_id == employee_id).order_by(DLPEvent.timestamp.desc()).limit(100).all()
    activities = db.query(ActivityLog).filter(ActivityLog.employee_id == employee_id).order_by(ActivityLog.timestamp.desc()).limit(100).all()
    return {
        "employee_id": employee_id,
        "dlp_events": [
            {
                "id": ev.id,
                "event_id": ev.event_id,
                "channel": ev.channel,
                "application": ev.application,
                "destination": ev.destination,
                "file_name": ev.file_name,
                "risk_score": ev.risk_score,
                "risk_level": ev.risk_level,
                "action": ev.action,
                "timestamp": ev.timestamp.isoformat() if ev.timestamp else "",
                "details": ev.details
            }
            for ev in dlp_events
        ],
        "activities": [ActivityLogResponse.model_validate(a).model_dump() for a in activities]
    }

@router.get("/{employee_id}/status")
def get_employee_status(
    employee_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin)
):
    """
    Get live connection and sensor health status of an employee.
    """
    emp = db.query(Employee).filter(Employee.employee_id == employee_id).first()
    if not emp:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Employee '{employee_id}' not found")
    now = datetime.now(timezone.utc)
    resp = _build_employee_response(emp, db, now)
    return {
        "employee_id": emp.employee_id,
        "status": resp.status,
        "last_seen": resp.last_seen.isoformat() if resp.last_seen else None,
        "last_seen_seconds_ago": resp.last_seen_seconds_ago,
        "primary_device_id": resp.primary_device_id,
        "device_count": resp.device_count,
        "monitoring_status": resp.monitoring_status,
        "active_modules": resp.active_modules
    }

@router.post("/bulk-delete", response_model=EmployeeBulkDeleteResponse)
def bulk_delete_employees(
    req: EmployeeBulkDeleteRequest,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_admin)
):
    """
    Bulk deactivate or permanently delete employees (Admin only).
    """
    if not req.employee_ids:
        return EmployeeBulkDeleteResponse(message="No employees specified", deleted_count=0, deleted_ids=[])
    
    deleted_ids = []
    for emp_id in req.employee_ids:
        emp = db.query(Employee).filter(Employee.employee_id == emp_id).first()
        if emp:
            if req.hard_delete:
                db.delete(emp)
            else:
                emp.active = False
                emp.status = "OFFLINE"
            deleted_ids.append(emp_id)
    
    db.commit()
    action_str = "permanently deleted" if req.hard_delete else "deactivated"
    logger.info(f"Admin {admin_user.username} bulk {action_str} {len(deleted_ids)} employees: {deleted_ids}")
    return EmployeeBulkDeleteResponse(
        message=f"Successfully {action_str} {len(deleted_ids)} employee(s)",
        deleted_count=len(deleted_ids),
        deleted_ids=deleted_ids
    )

@router.delete("/{employee_id}", status_code=status.HTTP_200_OK)
def delete_or_disable_employee(
    employee_id: str,
    hard_delete: bool = Query(False),
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_admin)
):
    """
    Deactivate or permanently delete an employee record (Admin only).
    """
    employee = db.query(Employee).filter(Employee.employee_id == employee_id).first()
    if not employee:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Employee '{employee_id}' not found")

    if hard_delete:
        db.query(Device).filter(Device.employee_id == employee_id).delete()
        db.query(Alert).filter(Alert.employee_id == employee_id).delete()
        db.query(Incident).filter(Incident.employee_id == employee_id).delete()
        db.query(DLPEvent).filter(DLPEvent.employee_id == employee_id).delete()
        db.query(ActivityLog).filter(ActivityLog.employee_id == employee_id).delete()
        db.delete(employee)
        db.commit()
        logger.info(f"Admin {admin_user.username} permanently deleted employee {employee_id} and associated records")
        return {"message": f"Employee '{employee_id}' permanently deleted", "employee_id": employee_id}
    else:
        employee.active = False
        employee.status = "OFFLINE"
        db.commit()
        logger.info(f"Admin {admin_user.username} deactivated employee {employee_id}")
        return {"message": f"Employee '{employee_id}' deactivated successfully", "employee_id": employee_id}

@router.post("/register", response_model=EmployeeResponse, status_code=status.HTTP_200_OK)
def register_or_update_employee(
    emp_data: EmployeeCreate,
    db: Session = Depends(get_db),
    auth_caller: Optional[User] = Depends(get_current_user_or_agent)
):
    """Legacy endpoint registration for existing employees."""
    now = datetime.now(timezone.utc)
    employee = db.query(Employee).filter(Employee.employee_id == emp_data.employee_id).first()
    if not employee:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "EMPLOYEE_NOT_REGISTERED", "message": f"Employee '{emp_data.employee_id}' not found. Admin must register employee first."}
        )
    
    employee.hostname = emp_data.hostname or employee.hostname
    employee.ip_address = emp_data.ip_address or employee.ip_address
    employee.operating_system = emp_data.operating_system or employee.operating_system
    employee.status = "ONLINE"
    employee.last_seen = now
    db.commit()
    db.refresh(employee)
    return _build_employee_response(employee, db, now)

@router.post("/heartbeat/{employee_id}", response_model=EmployeeResponse)
def employee_heartbeat(
    employee_id: str,
    db: Session = Depends(get_db),
    auth_caller: Optional[User] = Depends(get_current_user_or_agent)
):
    """Legacy employee heartbeat endpoint."""
    employee = db.query(Employee).filter(Employee.employee_id == employee_id).first()
    if not employee:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "EMPLOYEE_NOT_REGISTERED", "message": f"Employee endpoint '{employee_id}' not found"}
        )
    
    now = datetime.now(timezone.utc)
    employee.status = "ONLINE"
    employee.last_seen = now
    db.commit()
    db.refresh(employee)
    return _build_employee_response(employee, db, now)
