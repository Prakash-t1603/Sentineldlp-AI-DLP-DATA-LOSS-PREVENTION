import os
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List

# Base Directory of the Project
BASE_DIR = Path(__file__).resolve().parent.parent

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(BASE_DIR / ".env"),
        extra="ignore"
    )

    PROJECT_NAME: str = "SentinelDLP AI"
    VERSION: str = "2.0.0"
    API_PREFIX: str = "/api/v1"
    
    # Server Configuration (0.0.0.0 listens on primary network IP and localhost)
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    DEBUG: bool = True
    
    # Database Configuration (SQLite default with PostgreSQL compatibility)
    DATABASE_URL: str = f"sqlite:///{BASE_DIR}/sentinel.db"
    
    # JWT Security Configuration
    SECRET_KEY: str = "sentineldlp_enterprise_secret_key_change_in_production_2026"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours
    
    # Agent Security Token
    AGENT_SECRET_KEY: str = "sentinel_agent_telemetry_secure_token_key_9981"
    
    # Monitored and Upload Paths
    MONITOR_PATH: str = str(BASE_DIR / "monitored_data")
    UPLOAD_PATH: str = str(BASE_DIR / "uploads")
    LOGS_DIR: str = str(BASE_DIR / "logs")
    MODELS_DIR: str = str(BASE_DIR / "models")
    
    # Logging Configuration
    LOG_LEVEL: str = "INFO"
    
    # CORS
    CORS_ORIGINS: List[str] = ["*"]
    
    # Default Admin Credentials for initial setup
    DEFAULT_ADMIN_USERNAME: str = "admin"
    DEFAULT_ADMIN_EMAIL: str = "admin@sentineldlp.io"
    DEFAULT_ADMIN_PASSWORD: str = "Admin@123456"

settings = Settings()

# Ensure required directories exist
for path_str in [settings.MONITOR_PATH, settings.UPLOAD_PATH, settings.LOGS_DIR, settings.MODELS_DIR]:
    Path(path_str).mkdir(parents=True, exist_ok=True)
