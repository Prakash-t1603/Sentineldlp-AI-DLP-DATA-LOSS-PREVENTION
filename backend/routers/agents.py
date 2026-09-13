import json
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Header, Query
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any

from backend.database import get_db
from backend.models import Device, Employee, User
from backend.schemas import (
    DeviceRegisterRequest, DeviceRegisterResponse,
    DeviceHeartbeatRequest, DeviceHeartbeatResponse,
    AgentStatusEventRequest, DeviceResponse, DeviceFleetSummaryResponse,
    FleetStatusSummaryResponse
)
from backend.services.agent_service import agent_service
from backend.services.fleet_monitor import fleet_monitor_service
from backend.dependencies import get_current_user_or_agent, require_analyst_or_admin, require_admin
from backend.utils.helpers import get_logger

logger = get_logger("SentinelDLP.AgentsRouter")
router = APIRouter(prefix="/agents", tags=["Endpoint Fleet & Agents"])

@router.post("/register", response_model=DeviceRegisterResponse, status_code=status.HTTP_201_CREATED)
def register_agent_device(
    req: DeviceRegisterRequest,
    db: Session = Depends(get_db)
):
    """
    Register or re-authenticate an endpoint device, provisioning a unique cryptographic device token.
    Called on agent first-run or startup.
    """
    device, device_token = agent_service.register_device(db, req)
    return DeviceRegisterResponse(
        device_id=device.device_id,
        device_token=device_token,
        status=device.status,
        employee_id=device.employee_id,
        server_time=datetime.now(timezone.utc),
        heartbeat_interval_seconds=15,
        message=f"Endpoint device '{device.device_id}' registered successfully"
    )

@router.post("/heartbeat", response_model=DeviceHeartbeatResponse)
def agent_heartbeat(
    req: DeviceHeartbeatRequest,
    db: Session = Depends(get_db),
    auth_caller: Optional[User] = Depends(get_current_user_or_agent)
):
    """
    Process periodic heartbeat ping from an endpoint agent.
    Updates last seen timestamp, active monitoring modules, and maintains live online status.
    """
    device = agent_service.process_heartbeat(db, req)
    return DeviceHeartbeatResponse(
        device_id=device.device_id,
        status=device.status,
        acknowledged=True,
        server_time=datetime.now(timezone.utc)
    )

@router.post("/status", status_code=status.HTTP_200_OK)
def agent_status_event(
    req: AgentStatusEventRequest,
    db: Session = Depends(get_db),
    auth_caller: Optional[User] = Depends(get_current_user_or_agent)
):
    """
    Ingest operational lifecycle events from agent (AGENT_STARTED, MONITORING_STARTED, AGENT_STOPPED).
    Records audit entry in activity logs without generating false security alerts.
    """
    device = db.query(Device).filter(Device.device_id == req.device_id).first()
    emp_id = req.employee_id or (device.employee_id if device else "EMP-UNKNOWN")
    now = datetime.now(timezone.utc)

    if device:
        device.last_seen = now
        if req.event == "AGENT_STOPPED":
            device.status = "OFFLINE"
            device.monitoring_status = "STOPPED"
        elif req.event in ["AGENT_STARTED", "MONITORING_STARTED"]:
            device.status = "ONLINE"
            device.monitoring_status = "ACTIVE"
        db.commit()

    fleet_monitor_service.record_operational_event(
        db=db,
        employee_id=emp_id,
        activity_type=req.event,
        process_name="SentinelAgent",
        destination=req.details or f"Device: {req.device_id}"
    )

    return {
        "status": "acknowledged",
        "event": req.event,
        "device_id": req.device_id,
        "timestamp": now.isoformat()
    }

@router.get("", response_model=DeviceFleetSummaryResponse)
def list_fleet_devices(
    db: Session = Depends(get_db),
    auth_caller: Optional[User] = Depends(get_current_user_or_agent)
):
    """
    Retrieve fleet overview of all registered endpoint devices with real-time heartbeat status (ONLINE, WARNING, OFFLINE).
    """
    return agent_service.get_fleet_summary(db)

@router.get("/status", response_model=FleetStatusSummaryResponse)
def get_fleet_status_overview(
    db: Session = Depends(get_db),
    auth_caller: Optional[User] = Depends(get_current_user_or_agent)
):
    """
    Retrieve centralized fleet overview: employee statuses, device statuses, and module health counts.
    """
    summary = fleet_monitor_service.get_fleet_summary(db)
    dev_summary = agent_service.get_fleet_summary(db)
    summary["devices"] = dev_summary.devices
    return FleetStatusSummaryResponse(**summary)

@router.get("/live", response_model=List[DeviceResponse])
def get_live_devices(
    db: Session = Depends(get_db),
    auth_caller: Optional[User] = Depends(get_current_user_or_agent)
):
    """
    Retrieve all devices currently in ONLINE / LIVE status.
    """
    summary = agent_service.get_fleet_summary(db)
    return [d for d in summary.devices if d.status == "ONLINE"]

@router.get("/{device_id}", response_model=DeviceResponse)
def get_device_detail(
    device_id: str,
    db: Session = Depends(get_db),
    auth_caller: Optional[User] = Depends(get_current_user_or_agent)
):
    """
    Get detailed telemetry for a specific registered endpoint device.
    """
    device = db.query(Device).filter(Device.device_id == device_id).first()
    if not device:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device '{device_id}' not found")

    status_name, diff_secs = agent_service.evaluate_device_status(device.last_seen)
    mod_dict = {}
    if device.active_modules:
        try:
            mod_dict = json.loads(device.active_modules) if isinstance(device.active_modules, str) else device.active_modules
        except Exception:
            pass

    return DeviceResponse(
        id=device.id,
        device_id=device.device_id,
        hostname=device.hostname,
        employee_id=device.employee_id,
        employee_name=device.employee.full_name or device.employee.username if device.employee else None,
        employee_username=device.employee.username if device.employee else None,
        employee_department=device.employee.department if device.employee else None,
        username=device.username or "employee_user",
        operating_system=device.operating_system,
        ip_address=device.ip_address,
        mac_address=device.mac_address,
        agent_version=device.agent_version,
        status=status_name,
        monitoring_enabled=device.monitoring_enabled,
        monitoring_status=device.monitoring_status if status_name == "ONLINE" else "STOPPED",
        active_modules=mod_dict,
        last_seen=device.last_seen,
        last_seen_seconds_ago=diff_secs or 0,
        registered_at=device.registered_at,
        updated_at=device.updated_at,
        is_active=device.is_active
    )

@router.delete("/clear-all", status_code=status.HTTP_200_OK)
def clear_all_devices(
    db: Session = Depends(get_db),
    auth_caller: Optional[User] = Depends(get_current_user_or_agent)
):
    """
    Purge all registered endpoint devices from the database.
    """
    deleted_count = db.query(Device).delete()
    db.commit()
    logger.info(f"Purged all {deleted_count} fleet endpoint devices.")
    return {"message": f"Successfully removed all {deleted_count} fleet devices", "deleted_count": deleted_count}

@router.delete("/clear-offline", status_code=status.HTTP_200_OK)
def clear_offline_devices(
    db: Session = Depends(get_db),
    auth_caller: Optional[User] = Depends(get_current_user_or_agent)
):
    """
    Purge all offline / inactive devices from the fleet.
    """
    now = datetime.now(timezone.utc)
    devices = db.query(Device).all()
    deleted_ids = []
    for d in devices:
        status_name, _ = agent_service.evaluate_device_status(d.last_seen, now)
        if status_name == "OFFLINE" or not d.is_active:
            deleted_ids.append(d.device_id)
            db.delete(d)
    db.commit()
    logger.info(f"Purged {len(deleted_ids)} offline fleet devices: {deleted_ids}")
    return {"message": f"Successfully removed {len(deleted_ids)} offline device(s)", "deleted_count": len(deleted_ids), "deleted_ids": deleted_ids}

@router.delete("/{device_id}", status_code=status.HTTP_200_OK)
def deregister_device(
    device_id: str,
    hard_delete: bool = Query(True),
    db: Session = Depends(get_db),
    auth_caller: Optional[User] = Depends(get_current_user_or_agent)
):
    """
    Deregister and delete an endpoint device.
    """
    device = db.query(Device).filter(Device.device_id == device_id).first()
    if not device:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device '{device_id}' not found")

    if hard_delete:
        db.delete(device)
        db.commit()
        logger.info(f"Deleted device {device_id}")
        return {"message": f"Device '{device_id}' permanently deleted", "device_id": device_id}
    else:
        device.is_active = False
        device.status = "OFFLINE"
        device.monitoring_status = "STOPPED"
        db.commit()
        logger.info(f"Deactivated device {device_id}")
        return {"message": f"Device '{device_id}' deregistered successfully", "device_id": device_id}
