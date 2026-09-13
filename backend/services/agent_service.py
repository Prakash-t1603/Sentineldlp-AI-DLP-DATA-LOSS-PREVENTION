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
        now = datetime.now(timezone.utc)
        target_emp_id = req.employee_id
        if not target_emp_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "EMPLOYEE_ID_REQUIRED", "message": "Employee ID must be specified for agent registration."}
            )

        emp = db.query(Employee).filter(Employee.employee_id == target_emp_id).first()
        if not emp:
            if req.full_name or req.email:
                emp = Employee(
                    employee_id=target_emp_id,
                    username=req.username or target_emp_id.lower(),
                    full_name=req.full_name or target_emp_id,
                    email=req.email or f"{target_emp_id.lower()}@company.com",
                    department=req.department or "Operations",
                    designation=req.designation or "Endpoint User",
                    phone_number=req.phone_number or "N/A",
                    operating_system=req.operating_system or "Linux",
                    hostname=req.hostname or "NOT_ASSIGNED",
                    ip_address=req.ip_address or "127.0.0.1",
                    status="ONLINE",
                    risk_score=15,
                    risk_level="LOW",
                    last_seen=now,
                    is_active=True
                )
                db.add(emp)
                db.flush()
                logger.info(f"Auto-provisioned master employee record '{emp.employee_id}' ({emp.full_name}) from verified agent installation payload")
            else:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail={
                        "error": "EMPLOYEE_NOT_REGISTERED",
                        "message": f"Employee {target_emp_id} does not exist. Register the employee before installing/activating the endpoint."
                    }
                )

        device_id = req.preferred_device_id
        if not device_id:
            device_id = f"DEV-{secrets.token_hex(4).upper()}"

        existing = db.query(Device).filter(Device.device_id == device_id).first()
        if not existing:
            # Check by hostname if not matching device_id
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

        if existing:
            existing.device_id = device_id
            existing.hostname = req.hostname
            existing.username = req.username or existing.username or emp.username or "employee_user"
            existing.operating_system = req.operating_system or existing.operating_system
            existing.ip_address = req.ip_address or existing.ip_address
            existing.mac_address = req.mac_address or existing.mac_address
            existing.agent_version = req.agent_version or existing.agent_version
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
                operating_system=req.operating_system or "Linux",
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
        emp.hostname = req.hostname or (emp.hostname if emp.hostname != "NOT_ASSIGNED" else req.hostname)
        emp.ip_address = req.ip_address or (emp.ip_address if emp.ip_address != "NOT_ASSIGNED" else req.ip_address)
        emp.operating_system = req.operating_system or (emp.operating_system if emp.operating_system != "NOT_ASSIGNED" else req.operating_system)
        emp.status = "ONLINE"
        emp.last_seen = now
        emp.updated_at = now

        db.commit()
        db.refresh(device)
        logger.info(f"Registered endpoint device '{device.device_id}' ({device.hostname}) for master employee {emp.employee_id} ({emp.full_name})")
        return device, device_token

    def process_heartbeat(self, db: Session, req: DeviceHeartbeatRequest) -> Device:
        """
        Process heartbeat ping from an endpoint agent and update its online status and monitoring telemetry.
        """
        now = datetime.now(timezone.utc)
        device = db.query(Device).filter(Device.device_id == req.device_id).first()
        if not device:
            if req.employee_id:
                emp = db.query(Employee).filter(Employee.employee_id == req.employee_id).first()
                if not emp and (req.full_name or req.email):
                    emp = Employee(
                        employee_id=req.employee_id,
                        username=req.username or req.employee_id.lower(),
                        full_name=req.full_name or req.employee_id,
                        email=req.email or f"{req.employee_id.lower()}@company.com",
                        department=req.department or "Operations",
                        designation=req.designation or "Endpoint User",
                        phone_number=req.phone_number or "N/A",
                        operating_system=req.operating_system or "Linux",
                        hostname=req.hostname or "NOT_ASSIGNED",
                        ip_address=req.ip_address or "127.0.0.1",
                        status="ONLINE",
                        risk_score=15,
                        risk_level="LOW",
                        last_seen=now,
                        is_active=True
                    )
                    db.add(emp)
                    db.flush()
                    logger.info(f"Auto-provisioned master employee record '{emp.employee_id}' ({emp.full_name}) from verified agent heartbeat payload")

                if emp:
                    device, _ = self.register_device(db, DeviceRegisterRequest(
                        hostname=req.hostname or req.device_id,
                        preferred_device_id=req.device_id,
                        agent_version=req.agent_version,
                        employee_id=req.employee_id,
                        username=req.username,
                        full_name=req.full_name,
                        email=req.email,
                        department=req.department,
                        designation=req.designation,
                        phone_number=req.phone_number,
                        ip_address=req.ip_address,
                        operating_system=req.operating_system
                    ))
                else:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail={"error": "EMPLOYEE_NOT_REGISTERED", "message": f"Employee {req.employee_id} does not exist."}
                    )
            else:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Device '{req.device_id}' not found and employee_id was not provided"
                )

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

        # Target employee resolution and sync
        target_emp = None
        if req.employee_id:
            target_emp = db.query(Employee).filter(Employee.employee_id == req.employee_id).first()
            if not target_emp and (req.full_name or req.email):
                target_emp = Employee(
                    employee_id=req.employee_id,
                    username=req.username or req.employee_id.lower(),
                    full_name=req.full_name or req.employee_id,
                    email=req.email or f"{req.employee_id.lower()}@company.com",
                    department=req.department or "Cybersecurity",
                    designation=req.designation or "Endpoint User",
                    phone_number=req.phone_number or "N/A",
                    operating_system=req.operating_system or "Linux",
                    hostname=req.hostname or "NOT_ASSIGNED",
                    ip_address=req.ip_address or "127.0.0.1",
                    status="ONLINE",
                    risk_score=15,
                    risk_level="LOW",
                    last_seen=now,
                    is_active=True
                )
                db.add(target_emp)
                db.flush()

        if not target_emp and device.employee:
            target_emp = device.employee

        if target_emp:
            device.employee_id = target_emp.employee_id
            target_emp.last_seen = now
            target_emp.status = "ONLINE"
            if req.hostname:
                target_emp.hostname = req.hostname
            if req.ip_address:
                target_emp.ip_address = req.ip_address
            if req.operating_system:
                target_emp.operating_system = req.operating_system
            if req.full_name and (not target_emp.full_name or target_emp.full_name == target_emp.employee_id):
                target_emp.full_name = req.full_name
            if req.email and (not target_emp.email or target_emp.email.endswith("@company.local")):
                target_emp.email = req.email
            if req.department and (not target_emp.department or target_emp.department == "Operations"):
                target_emp.department = req.department
            if req.designation and (not target_emp.designation or target_emp.designation == "Endpoint User"):
                target_emp.designation = req.designation

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
