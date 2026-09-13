from sqlalchemy import create_engine, event
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from typing import Generator
from backend.config import settings

# Engine configuration
connect_args = {}
if settings.DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    echo=False,
    pool_pre_ping=True
)

# Enable SQLite foreign keys & WAL mode for high concurrency
if settings.DATABASE_URL.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def run_auto_migrations():
    """
    Safely and non-destructively apply incremental schema migrations.
    Adds any missing columns to existing tables without dropping data or resetting database.
    """
    from sqlalchemy import inspect, text
    inspector = inspect(engine)
    table_names = inspector.get_table_names()

    # Column definitions to ensure exist on existing tables
    employee_cols = {
        "full_name": "VARCHAR(128)",
        "email": "VARCHAR(128)",
        "phone_number": "VARCHAR(32)",
        "department": "VARCHAR(64)",
        "designation": "VARCHAR(64)",
        "manager": "VARCHAR(128)",
        "location": "VARCHAR(128)",
        "joining_date": "DATETIME",
        "created_at": "DATETIME",
        "updated_at": "DATETIME",
        "active": "BOOLEAN DEFAULT 1"
    }

    device_cols = {
        "username": "VARCHAR(64) DEFAULT 'employee_user'",
        "mac_address": "VARCHAR(64)",
        "monitoring_enabled": "BOOLEAN DEFAULT 1",
        "monitoring_status": "VARCHAR(32) DEFAULT 'ACTIVE'",
        "active_modules": "TEXT DEFAULT '{\"usb\":\"ACTIVE\",\"file\":\"ACTIVE\",\"clipboard\":\"ACTIVE\",\"process\":\"ACTIVE\",\"browser\":\"ACTIVE\",\"email\":\"ACTIVE\",\"event\":\"ACTIVE\"}'",
        "updated_at": "DATETIME"
    }

    alert_cols = {
        "device_id": "VARCHAR(128)",
        "event_id": "VARCHAR(64)"
    }

    with engine.connect() as conn:
        # Check employees table
        if "employees" in table_names:
            cols = {c["name"]: c for c in inspector.get_columns("employees")}
            if "last_seen" in cols and not cols["last_seen"]["nullable"]:
                try:
                    conn.execute(text("PRAGMA foreign_keys=OFF"))
                    conn.execute(text("""
                        CREATE TABLE IF NOT EXISTS employees_migrated (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            employee_id VARCHAR(64) NOT NULL UNIQUE,
                            full_name VARCHAR(128),
                            email VARCHAR(128),
                            phone_number VARCHAR(32),
                            department VARCHAR(64),
                            designation VARCHAR(64),
                            username VARCHAR(64) NOT NULL,
                            status VARCHAR(32) NOT NULL DEFAULT 'OFFLINE',
                            manager VARCHAR(128),
                            location VARCHAR(128),
                            joining_date DATETIME,
                            created_at DATETIME NOT NULL,
                            updated_at DATETIME NOT NULL,
                            active BOOLEAN NOT NULL DEFAULT 1,
                            hostname VARCHAR(128) DEFAULT 'NOT_ASSIGNED',
                            ip_address VARCHAR(64) DEFAULT 'NOT_ASSIGNED',
                            operating_system VARCHAR(64) DEFAULT 'NOT_ASSIGNED',
                            last_seen DATETIME,
                            risk_score FLOAT NOT NULL DEFAULT 0.0
                        )
                    """))
                    conn.execute(text("""
                        INSERT OR IGNORE INTO employees_migrated (id, employee_id, full_name, email, phone_number, department, designation, username, status, manager, location, joining_date, created_at, updated_at, active, hostname, ip_address, operating_system, last_seen, risk_score)
                        SELECT id, employee_id, full_name, email, phone_number, department, designation, username, status, manager, location, joining_date, created_at, updated_at, active, hostname, ip_address, operating_system, last_seen, risk_score FROM employees
                    """))
                    conn.execute(text("DROP TABLE employees"))
                    conn.execute(text("ALTER TABLE employees_migrated RENAME TO employees"))
                    conn.execute(text("CREATE INDEX IF NOT EXISTS ix_employees_employee_id ON employees (employee_id)"))
                    conn.execute(text("CREATE INDEX IF NOT EXISTS ix_employees_username ON employees (username)"))
                    conn.execute(text("PRAGMA foreign_keys=ON"))
                    conn.commit()
                except Exception:
                    pass

            existing_cols = {c["name"] for c in inspector.get_columns("employees")}
            for col_name, col_type in employee_cols.items():
                if col_name not in existing_cols:
                    try:
                        conn.execute(text(f"ALTER TABLE employees ADD COLUMN {col_name} {col_type}"))
                        conn.commit()
                    except Exception:
                        pass

        # Check devices table
        if "devices" in table_names:
            existing_cols = {c["name"] for c in inspector.get_columns("devices")}
            for col_name, col_type in device_cols.items():
                if col_name not in existing_cols:
                    try:
                        conn.execute(text(f"ALTER TABLE devices ADD COLUMN {col_name} {col_type}"))
                        conn.commit()
                    except Exception:
                        pass

        # Check alerts table
        if "alerts" in table_names:
            existing_cols = {c["name"] for c in inspector.get_columns("alerts")}
            for col_name, col_type in alert_cols.items():
                if col_name not in existing_cols:
                    try:
                        conn.execute(text(f"ALTER TABLE alerts ADD COLUMN {col_name} {col_type}"))
                        conn.commit()
                    except Exception:
                        pass

def get_db() -> Generator[Session, None, None]:
    """Dependency that provides a database session per request and guarantees cleanup."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

