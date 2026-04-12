"""Configuration management for BeigeBox Security."""

from typing import Optional
from pydantic_settings import BaseSettings


class SecurityConfig(BaseSettings):
    """Configuration for security tools."""

    class Config:
        env_file = ".env"
        env_prefix = "BEIGEBOX_SECURITY_"
        case_sensitive = False

    # Server
    host: str = "0.0.0.0"
    port: int = 8001
    debug: bool = False
    reload: bool = False

    # CORS
    cors_origins: list[str] = ["*"]

    # Security: RAG Poisoning Detection
    poisoning_detection_enabled: bool = True
    poisoning_sensitivity: str = "medium"  # low, medium, high
    poisoning_baseline_window: int = 1000

    # Security: MCP Parameter Validation
    parameter_validation_enabled: bool = True
    parameter_validation_allow_unsafe: bool = False
    parameter_validation_log_violations: bool = True

    # Security: API Anomaly Detection
    anomaly_detection_enabled: bool = True
    anomaly_detection_sensitivity: str = "medium"  # low, medium, high
    anomaly_detection_db_path: str = "./data/anomaly_baselines.db"
    anomaly_detection_min_baseline_size: int = 50

    # Security: Memory Integrity Validation
    memory_integrity_enabled: bool = True
    memory_integrity_db_path: str = "./data/memory_integrity.db"
    memory_integrity_strict_mode: bool = False  # Fail on tampering vs warn
    memory_integrity_key: Optional[str] = None  # Use env var BEIGEBOX_SECURITY_MEMORY_INTEGRITY_KEY

    # Storage
    data_dir: str = "./data"


def get_config() -> SecurityConfig:
    """Load and cache configuration."""
    return SecurityConfig()
