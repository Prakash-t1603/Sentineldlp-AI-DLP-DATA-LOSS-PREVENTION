import json
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List, Tuple
from sqlalchemy.orm import Session

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
        """
        now = datetime.now(timezone.utc)
        device_id = req.preferred_device_id
        if not device_id:
            device_id = f"DEV-{secrets.token_hex(4).upper()}"

        existing = db.query(Device).filter(Device.device_id == device_id).first()
        if not existing:
            # Check by hostname if not matching device_id
            existing = db.query(Device).filter(Device.hostname == req.hostname).first()

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

        if existing:
            existing.device_id = device_id
            existing.hostname = req.hostname
            existing.username = req.username or existing.username or "employee_user"
            existing.operating_system = req.operating_system or existing.operating_system
            existing.ip_address = req.ip_address or existing.ip_address
            existing.mac_address = req.mac_address or existing.mac_address
            existing.agent_version = req.agent_version or existing.agent_version
            existing.employee_id = req.employee_id or existing.employee_id
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
                username=req.username or "employee_user",
                employee_id=req.employee_id,
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

        # Ensure linked Employee is created/updated
        if req.employee_id:
            emp = db.query(Employee).filter(Employee.employee_id == req.employee_id).first()
            if not emp:
                emp = Employee(
                    employee_id=req.employee_id,
                    username=req.username or req.employee_id,
                    full_name=req.username or req.employee_id,
                    hostname=req.hostname,
                    ip_address=req.ip_address or "127.0.0.1",
                    operating_system=req.operating_system or "Windows",
                    status="ONLINE",
                    last_seen=now,
                    created_at=now,
                    updated_at=now,
                    active=True,
                    risk_score=0.0
                )
                db.add(emp)
            else:
                emp.hostname = req.hostname
                emp.ip_address = req.ip_address or emp.ip_address
                emp.status = "ONLINE"
                emp.last_seen = now
                emp.updated_at = now

        db.commit()
        db.refresh(device)
        logger.info(f"Registered endpoint device: {device.device_id} ({device.hostname})")
        return device, device_token

    def process_heartbeat(self, db: Session, req: DeviceHeartbeatRequest) -> Device:
        """
        Process heartbeat ping from an endpoint agent and update its online status and monitoring telemetry.
        """
        device = db.query(Device).filter(Device.device_id == req.device_id).first()
        if not device:
            # Auto-register if recognized
            device, _ = self.register_device(db, DeviceRegisterRequest(
                hostname=req.hostname or req.device_id,
                preferred_device_id=req.device_id,
                agent_version=req.agent_version,
                employee_id=req.employee_id,
                username=req.username
            ))

        now = datetime.now(timezone.utc)
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

        # Sync employee status
        if device.employee:
            device.employee.last_seen = now
            device.employee.status = "ONLINE"
            if req.hostname:
                device.employee.hostname = req.hostname
            if req.ip_address:
                device.employee.ip_address = req.ip_address

        db.commit()
        db.refresh(device)
        return device

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

        db.commit()

        return DeviceFleetSummaryResponse(
            total_devices=len(devices),
            online_devices=online_count,
            warning_devices=warning_count,
            offline_devices=offline_count,
            devices=results
        )

agent_service = AgentService()
