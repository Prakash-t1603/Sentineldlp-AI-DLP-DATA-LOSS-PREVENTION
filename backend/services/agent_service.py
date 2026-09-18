import json
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List, Tuple
from sqlalchemy.orm import Session

from fastapi import HTTPException, status
from backend.models import Device, Employee, User, ActivityLog
from backend.schemas import (
    DeviceRegisterRequest, DeviceHeartbeatRequest, DeviceResponse, DeviceFleetSummaryResponse,
    FleetStatusSummaryResponse
)
from backend.services.fleet_monitor import fleet_monitor_service
from backend.utils.helpers import get_logger

logger = get_logger("SentinelDLP.AgentService")

class AgentService:
    @staticmethod
    def generate_device_token(device_id: str) -> str:
        """Generate a cryptographically secure, unique device token."""
        raw_secret = f"dev-tok-{device_id}-{secrets.token_hex(24)}"
        return raw_secret

    @staticmethod
    def evaluate_device_status(last_seen: Optional[datetime], current_time: Optional[datetime] = None) -> Tuple[str, Optional[int]]:
        """Evaluate status using FleetMonitorService."""
        return fleet_monitor_service.evaluate_status(last_seen, current_time)

    def register_device(self, db: Session, req: DeviceRegisterRequest) -> Tuple[Device, str]:
        """
        Register a new endpoint device or update an existing one, provisioning a unique device token.
        Requires that the employee_id exists in the master employee directory.
        """
        # Server-side logging before database operations (safe telemetry without tokens/secrets)
        logger.info(
            f"Agent registration request received: employee_id='{req.employee_id}', "
            f"device_id='{req.preferred_device_id}', hostname='{req.hostname}', "
            f"ip='{req.ip_address}', os='{req.operating_system}', agent_version='{req.agent_version}'"
        )

        target_emp_id = req.employee_id
        if not target_emp_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "EMPLOYEE_ID_REQUIRED", "message": "Employee ID must be specified for agent registration."}
            )

        emp = db.query(Employee).filter(Employee.employee_id == target_emp_id).first()
        if not emp:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": "EMPLOYEE_NOT_REGISTERED",
                    "message": f"Employee '{target_emp_id}' does not exist. Register the employee before installing/activating the endpoint."
                }
            )

        if not emp.active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": "EMPLOYEE_INACTIVE",
                    "message": f"Employee '{target_emp_id}' is inactive. Cannot register device."
                }
            )

        now = datetime.now(timezone.utc)
        device_id = req.preferred_device_id
        if not device_id:
            device_id = f"DEV-{secrets.token_hex(4).upper()}"

        existing = db.query(Device).filter(Device.device_id == device_id).first()
        if existing and existing.employee_id and existing.employee_id != emp.employee_id:
            logger.warning(
                f"Device registration conflict: Device '{device_id}' is already registered to employee '{existing.employee_id}'. "
                f"Rejecting registration attempt by employee '{emp.employee_id}'."
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error": "DEVICE_ALREADY_REGISTERED",
                    "message": f"Device '{device_id}' is already registered to employee '{existing.employee_id}'. A new device identity is required or the administrator must reassign the device."
                }
            )

        if not existing:
            # Check by hostname if not matching device_id for the same employee
            existing = db.query(Device).filter(Device.hostname == req.hostname, Device.employee_id == emp.employee_id).first()

        device_token = self.generate_device_token(device_id)

        default_modules = json.dumps({
            "usb": "ACTIVE",
            "file": "ACTIVE",
            "clipboard": "ACTIVE",
            "process": "ACTIVE",
            "browser": "ACTIVE",
            "email": "ACTIVE",
            "event": "ACTIVE"
        })

        try:
            if existing:
                existing.device_id = device_id
                existing.hostname = req.hostname
                existing.username = req.username or existing.username or emp.username or "employee_user"
                existing.operating_system = req.operating_system or existing.operating_system or "Windows"
                existing.ip_address = req.ip_address or existing.ip_address or "127.0.0.1"
                if req.mac_address:
                    existing.mac_address = req.mac_address
                existing.agent_version = req.agent_version or existing.agent_version or "2.1.0"
                existing.employee_id = emp.employee_id
                existing.device_token = device_token
                existing.status = "ONLINE"
                existing.monitoring_status = "ACTIVE"
                if not existing.active_modules:
                    existing.active_modules = default_modules
                existing.last_seen = now
                existing.updated_at = now
                existing.is_active = True
                device = existing
            else:
                device = Device(
                    device_id=device_id,
                    hostname=req.hostname,
                    username=req.username or emp.username or "employee_user",
                    employee_id=emp.employee_id,
                    operating_system=req.operating_system or "Windows",
                    ip_address=req.ip_address or "127.0.0.1",
                    mac_address=req.mac_address,
                    agent_version=req.agent_version or "2.1.0",
                    status="ONLINE",
                    monitoring_enabled=True,
                    monitoring_status="ACTIVE",
                    active_modules=default_modules,
                    device_token=device_token,
                    last_seen=now,
                    registered_at=now,
                    updated_at=now,
                    is_active=True
                )
                db.add(device)

            # Update linked Master Employee record telemetry
            if req.hostname:
                emp.hostname = req.hostname
            if req.ip_address:
                emp.ip_address = req.ip_address
            if req.operating_system:
                emp.operating_system = req.operating_system
            emp.status = "ONLINE"
            emp.last_seen = now
            emp.updated_at = now

            db.commit()
            db.refresh(device)
            logger.info(f"Registered endpoint device '{device.device_id}' ({device.hostname}) for master employee {emp.employee_id} ({emp.full_name or emp.username})")
            return device, device_token
        except Exception as e:
            db.rollback()
            logger.error(f"Database transaction error during device registration for employee '{target_emp_id}': {e}")
            raise

    def process_heartbeat(self, db: Session, req: DeviceHeartbeatRequest) -> Device:
        """
        Process heartbeat ping from an endpoint agent and update its online status and monitoring telemetry.
        Heartbeat MUST NOT automatically create a new Employee.
        """
        # Server-side logging before database operations (safe telemetry without tokens/secrets)
        logger.info(
            f"Agent heartbeat received: device_id='{req.device_id}', employee_id='{req.employee_id}', "
            f"hostname='{req.hostname}', ip='{req.ip_address}', os='{req.operating_system}', agent_version='{req.agent_version}'"
        )

        if not req.device_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "DEVICE_ID_REQUIRED", "message": "Device ID must be specified for heartbeat."}
            )

        now = datetime.now(timezone.utc)
        device = db.query(Device).filter(Device.device_id == req.device_id).first()
        if not device and req.employee_id:
            # Check by hostname and employee_id
            device = db.query(Device).filter(Device.hostname == req.hostname, Device.employee_id == req.employee_id).first()

        if not device and req.employee_id:
            # Check if employee exists in master employee directory
            emp = db.query(Employee).filter(Employee.employee_id == req.employee_id).first()
            if emp and emp.active:
                device_token = self.generate_device_token(req.device_id)
                default_modules = json.dumps({
                    "usb": "ACTIVE",
                    "file": "ACTIVE",
                    "clipboard": "ACTIVE",
                    "process": "ACTIVE",
                    "browser": "ACTIVE",
                    "email": "ACTIVE",
                    "event": "ACTIVE"
                })
                device = Device(
                    device_id=req.device_id,
                    hostname=req.hostname or "WORKSTATION",
                    username=req.username or emp.username or "employee_user",
                    employee_id=emp.employee_id,
                    operating_system=req.operating_system or "Windows",
                    ip_address=req.ip_address or "127.0.0.1",
                    agent_version=req.agent_version or "2.1.0",
                    status="ONLINE",
                    monitoring_enabled=True,
                    monitoring_status="ACTIVE",
                    active_modules=default_modules,
                    device_token=device_token,
                    last_seen=now,
                    registered_at=now,
                    updated_at=now,
                    is_active=True
                )
                db.add(device)
                logger.info(f"Auto-bound device '{device.device_id}' ({device.hostname}) to existing master employee {emp.employee_id} ({emp.full_name or emp.username}) during heartbeat")

        if not device:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": "DEVICE_NOT_FOUND",
                    "message": f"Device '{req.device_id}' not found and employee '{req.employee_id}' is not registered."
                }
            )

        try:
            device.last_seen = now
            device.status = "ONLINE"
            if req.agent_version:
                device.agent_version = req.agent_version
            if req.hostname:
                device.hostname = req.hostname
            if req.ip_address:
                device.ip_address = req.ip_address
            if req.operating_system:
                device.operating_system = req.operating_system
            if req.username:
                device.username = req.username
            if req.monitoring_status:
                device.monitoring_status = req.monitoring_status
            if req.active_monitoring_modules:
                device.active_modules = json.dumps(req.active_monitoring_modules) if not isinstance(req.active_monitoring_modules, str) else req.active_monitoring_modules
            device.updated_at = now

            # Target employee resolution and sync (lookup existing employee only, never create fake employee)
            target_emp = None
            if device.employee_id:
                target_emp = db.query(Employee).filter(Employee.employee_id == device.employee_id).first()
                if req.employee_id and req.employee_id != device.employee_id:
                    logger.warning(
                        f"Heartbeat employee mismatch for device '{device.device_id}': "
                        f"device registered to '{device.employee_id}' but heartbeat reported '{req.employee_id}'. "
                        f"Retaining registered employee '{device.employee_id}'."
                    )
            elif req.employee_id:
                target_emp = db.query(Employee).filter(Employee.employee_id == req.employee_id).first()
                if target_emp:
                    device.employee_id = target_emp.employee_id

            if target_emp:
                target_emp.last_seen = now
                target_emp.status = "ONLINE"
                if req.hostname:
                    target_emp.hostname = req.hostname
                if req.ip_address:
                    target_emp.ip_address = req.ip_address
                if req.operating_system:
                    target_emp.operating_system = req.operating_system
                target_emp.updated_at = now

            db.commit()
            db.refresh(device)
            return device
        except Exception as e:
            db.rollback()
            logger.error(f"Database transaction error during heartbeat processing for device '{req.device_id}': {e}")
            raise

    def get_fleet_summary(self, db: Session) -> DeviceFleetSummaryResponse:
        """
        Retrieve all registered endpoint devices with real-time heartbeat status.
        """
        devices = db.query(Device).filter(Device.is_active == True).order_by(Device.last_seen.desc()).all()
        now = datetime.now(timezone.utc)
        
        online_count = 0
        warning_count = 0
        offline_count = 0
        results: List[DeviceResponse] = []

        for d in devices:
            calculated_status, diff_secs = self.evaluate_device_status(d.last_seen, now)
            if d.status != calculated_status:
                d.status = calculated_status
            
            if calculated_status == "ONLINE":
                online_count += 1
            elif calculated_status == "WARNING":
                warning_count += 1
            else:
                offline_count += 1

            mod_dict = {}
            if d.active_modules:
                try:
                    mod_dict = json.loads(d.active_modules) if isinstance(d.active_modules, str) else d.active_modules
                except Exception:
                    pass

            res = DeviceResponse(
                id=d.id,
                device_id=d.device_id,
                hostname=d.hostname,
                employee_id=d.employee_id,
                employee_name=d.employee.full_name or d.employee.username if d.employee else None,
                employee_username=d.employee.username if d.employee else None,
                employee_department=d.employee.department if d.employee else None,
                username=d.username or "employee_user",
                operating_system=d.operating_system,
                ip_address=d.ip_address,
                mac_address=d.mac_address,
                agent_version=d.agent_version,
                status=calculated_status,
                monitoring_enabled=d.monitoring_enabled,
                monitoring_status=d.monitoring_status if calculated_status == "ONLINE" else "STOPPED",
                active_modules=mod_dict,
                last_seen=d.last_seen,
                last_seen_seconds_ago=diff_secs or 0,
                registered_at=d.registered_at,
                updated_at=d.updated_at,
                is_active=d.is_active
            )
            results.append(res)

        try:
            db.commit()
        except Exception as e:
            db.rollback()
            logger.error(f"Database error committing fleet summary updates: {e}")
            raise

        return DeviceFleetSummaryResponse(
            total_devices=len(devices),
            online_devices=online_count,
            warning_devices=warning_count,
            offline_devices=offline_count,
            devices=results
        )

agent_service = AgentService()
