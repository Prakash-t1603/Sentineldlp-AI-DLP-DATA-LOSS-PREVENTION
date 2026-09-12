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

    with engine.connect() as conn:
        # Check employees table
        if "employees" in table_names:
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

def get_db() -> Generator[Session, None, None]:
    """Dependency that provides a database session per request and guarantees cleanup."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

