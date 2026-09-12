from pathlib import Path
from fastapi import FastAPI, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from contextlib import asynccontextmanager
from sqlalchemy.orm import Session

from backend.config import settings, BASE_DIR
from backend.database import engine, Base, SessionLocal, run_auto_migrations, get_db
from backend.models import User, PolicyRule, Employee, Device
from backend.utils.security import get_password_hash
from backend.utils.helpers import get_logger

from backend.routers import (
    auth, users, employees, files, alerts, incidents, reports, risk, dashboard, dlp, agents
)
from backend.services.policy_service import policy_service
from backend.services.fleet_monitor import fleet_monitor_service

logger = get_logger("SentinelDLP.Main")

def init_database():
    """Create database tables, run safe auto-migrations, and seed initial administrator account & policies."""
    logger.info("Initializing database schema and running auto-migrations...")
    Base.metadata.create_all(bind=engine)
    run_auto_migrations()

    db = SessionLocal()
    try:
        # 1. Seed Default Administrator Account
        admin = db.query(User).filter(User.username == settings.DEFAULT_ADMIN_USERNAME).first()
        if not admin:
            admin = User(
                username=settings.DEFAULT_ADMIN_USERNAME,
                email=settings.DEFAULT_ADMIN_EMAIL,
                password_hash=get_password_hash(settings.DEFAULT_ADMIN_PASSWORD),
                role="admin",
                is_active=True
            )
            db.add(admin)
            logger.info(f"Seeded default administrator: {settings.DEFAULT_ADMIN_EMAIL}")

        # 2. Seed Default Security Analyst Account
        analyst = db.query(User).filter(User.username == "analyst").first()
        if not analyst:
            analyst = User(
                username="analyst",
                email="analyst@sentineldlp.io",
                password_hash=get_password_hash("Analyst@123456"),
                role="security_analyst",
                is_active=True
            )
            db.add(analyst)
            logger.info("Seeded default security analyst: analyst@sentineldlp.io")

        # 3. Seed Default Policy Rules
        if db.query(PolicyRule).count() == 0:
            default_rules = [
                PolicyRule(name="Private Key Header Rule", rule_type="REGEX", pattern=r"-----BEGIN [A-Z ]*PRIVATE KEY-----", sensitivity_level="HIGHLY_CONFIDENTIAL"),
                PolicyRule(name="AWS Key Pattern Rule", rule_type="REGEX", pattern=r"AKIA[0-9A-Z]{16}", sensitivity_level="HIGHLY_CONFIDENTIAL"),
                PolicyRule(name="Credit Card Pattern Rule", rule_type="REGEX", pattern=r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b", sensitivity_level="HIGHLY_CONFIDENTIAL"),
                PolicyRule(name="Password File Pattern", rule_type="EXTENSION", pattern=".env;.pem;.key;.p12", sensitivity_level="HIGHLY_CONFIDENTIAL"),
                PolicyRule(name="Financial Document Rule", rule_type="KEYWORD", pattern="confidential;proprietary;internal only;trade secret", sensitivity_level="CONFIDENTIAL"),
            ]
            db.add_all(default_rules)
            logger.info("Seeded default DLP policy rules.")

        # 4. Seed Default DLP Channel Policies
        policy_service.seed_default_policies(db)

        # 5. Seed Initial Fleet Endpoint Devices if empty
        if db.query(Device).count() == 0:
            now = datetime.now(timezone.utc)
            sample_devices = [
                Device(
                    device_id="EMP-PC-001",
                    hostname="WORKSTATION-ALEX",
                    employee_id="EMP-DEV-01",
                    operating_system="Windows 11",
                    ip_address="192.168.1.101",
                    agent_version="2.1.0",
                    status="ONLINE",
                    monitoring_enabled=True,
                    monitoring_status="ACTIVE",
                    device_token="dev-tok-EMP-PC-001-master-sample-secret",
                    last_seen=now,
                    registered_at=now,
                    updated_at=now,
                    is_active=True
                ),
                Device(
                    device_id="EMP-PC-002",
                    hostname="FIN-LAPTOP-02",
                    employee_id="EMP-FIN-02",
                    operating_system="Windows 10",
                    ip_address="192.168.1.102",
                    agent_version="2.1.0",
                    status="ONLINE",
                    monitoring_enabled=True,
                    monitoring_status="ACTIVE",
                    device_token="dev-tok-EMP-PC-002-master-sample-secret",
                    last_seen=now,
                    registered_at=now,
                    updated_at=now,
                    is_active=True
                ),
                Device(
                    device_id="EMP-PC-003",
                    hostname="HR-STATION-03",
                    employee_id="EMP-HR-03",
                    operating_system="macOS Sonoma",
                    ip_address="192.168.1.103",
                    agent_version="2.1.0",
                    status="ONLINE",
                    monitoring_enabled=True,
                    monitoring_status="ACTIVE",
                    device_token="dev-tok-EMP-PC-003-master-sample-secret",
                    last_seen=now,
                    registered_at=now,
                    updated_at=now,
                    is_active=True
                )
            ]
            db.add_all(sample_devices)
            logger.info("Seeded initial endpoint fleet devices.")

        db.commit()
    except Exception as e:
        db.rollback()
        logger.error(f"Database initialization error: {e}")
    finally:
        db.close()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle management for Central DLP Server."""
    init_database()
    logger.info(f"{settings.PROJECT_NAME} v{settings.VERSION} Central Server started successfully on {settings.API_HOST}:{settings.API_PORT}")
    yield
    logger.info("SentinelDLP Central Server shutting down.")


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Enterprise Endpoint DLP & Employee Threat Intelligence Engine",
    lifespan=lifespan
)

# Enable CORS for cross-origin browser dashboards
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(auth.router, prefix=settings.API_PREFIX)
app.include_router(users.router, prefix=settings.API_PREFIX)
app.include_router(employees.router, prefix=settings.API_PREFIX)
app.include_router(employees.router, prefix="/api")  # Direct /api/employees compatibility
app.include_router(files.router, prefix=settings.API_PREFIX)
app.include_router(alerts.router, prefix=settings.API_PREFIX)
app.include_router(alerts.router, prefix="/api") # Direct /api/alerts/... compatibility
app.include_router(incidents.router, prefix=settings.API_PREFIX)
app.include_router(incidents.router, prefix="/api")
app.include_router(reports.router, prefix=settings.API_PREFIX)
app.include_router(reports.router, prefix="/api")
app.include_router(reports.router) # Support direct /reports/export/... endpoints
app.include_router(risk.router, prefix=settings.API_PREFIX)
app.include_router(risk.router, prefix="/api")
app.include_router(dashboard.router, prefix=settings.API_PREFIX)
app.include_router(agents.router, prefix=settings.API_PREFIX)
app.include_router(agents.router, prefix="/api")   # Direct /api/agents/... compatibility
app.include_router(agents.router, prefix="/api/v1/devices") # Direct /api/v1/devices compatibility
app.include_router(agents.router, prefix="/api/devices")
app.include_router(dlp.router, prefix=settings.API_PREFIX)
app.include_router(dlp.router, prefix="/api")  # Direct /api/dlp/... compatibility

@app.get("/api/v1/monitoring/status", tags=["Endpoint Fleet & Agents"])
@app.get("/api/monitoring/status", tags=["Endpoint Fleet & Agents"])
def get_monitoring_status_endpoint(db: Session = Depends(get_db)):
    """Fleet-wide monitoring status endpoint."""
    return fleet_monitor_service.get_fleet_summary(db)

@app.get("/api/v1/devices", tags=["Endpoint Fleet & Agents"])
@app.get("/api/devices", tags=["Endpoint Fleet & Agents"])
def list_devices_endpoint(db: Session = Depends(get_db)):
    """Direct devices endpoint."""
    from backend.services.agent_service import agent_service
    return agent_service.get_fleet_summary(db)

@app.api_route("/health", methods=["GET", "HEAD"], tags=["Health"])
def health_check():
    """Health check endpoint."""
    return {"status": "HEALTHY", "project": settings.PROJECT_NAME, "version": settings.VERSION}

# Mount Frontend Static Assets
frontend_dir = BASE_DIR / "frontend"
if frontend_dir.exists():
    app.mount("/static", StaticFiles(directory=str(frontend_dir)), name="static")

    @app.get("/favicon.ico", include_in_schema=False)
    async def serve_favicon():
        fav = frontend_dir / "favicon.svg"
        if fav.exists():
            return FileResponse(fav, media_type="image/svg+xml")
        return JSONResponse(content={}, status_code=204)

    @app.get("/", include_in_schema=False)
    async def serve_index():
        return FileResponse(frontend_dir / "index.html")

    @app.get("/login", include_in_schema=False)
    async def serve_login():
        return FileResponse(frontend_dir / "login.html")

    @app.get("/dashboard", include_in_schema=False)
    async def serve_dashboard():
        return FileResponse(frontend_dir / "dashboard.html")

    @app.get("/alerts", include_in_schema=False)
    async def serve_alerts():
        return FileResponse(frontend_dir / "alerts.html")

    @app.get("/alert-history", include_in_schema=False)
    @app.get("/alerts-history", include_in_schema=False)
    async def serve_alert_history():
        return FileResponse(frontend_dir / "alert_history.html")

    @app.get("/incidents", include_in_schema=False)
    async def serve_incidents():
        return FileResponse(frontend_dir / "incidents.html")

    @app.get("/employees", include_in_schema=False)
    async def serve_employees():
        return FileResponse(frontend_dir / "employees.html")

    @app.get("/files", include_in_schema=False)
    async def serve_files():
        return FileResponse(frontend_dir / "files.html")

    @app.get("/reports", include_in_schema=False)
    async def serve_reports():
        return FileResponse(frontend_dir / "reports.html")

    @app.get("/settings", include_in_schema=False)
    async def serve_settings():
        return FileResponse(frontend_dir / "settings.html")

    @app.get("/employee-portal", include_in_schema=False)
    async def serve_employee_portal():
        return FileResponse(frontend_dir / "employee_portal.html")

    @app.get("/dlp-simulation", include_in_schema=False)
    async def serve_dlp_simulation():
        sim_file = frontend_dir / "dlp_simulation.html"
        if sim_file.exists():
            return FileResponse(sim_file)
        return FileResponse(frontend_dir / "dashboard.html")
