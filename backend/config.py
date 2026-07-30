"""
Application configuration — loaded from config/config.yaml with env-var overrides.
"""
import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import List

import yaml


@dataclass
class Settings:
    # Database
    DB_HOST: str = "localhost"
    DB_PORT: int = 5432
    DB_USER: str = "netguard"
    DB_PASSWORD: str = "netguard_pass"
    DB_NAME: str = "netguard"

    # SNMP
    SNMP_COMMUNITY: str = "public"
    SNMP_TIMEOUT: int = 5
    SNMP_RETRIES: int = 2
    SNMP_POLL_INTERVAL: int = 60  # seconds

    # Alerting
    SMTP_HOST: str = "localhost"
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = "noreply@company.local"
    SMTP_TIMEOUT: int = 30
    ALERT_EMAILS: List[str] = field(default_factory=list)

    # KakaoTalk (optional — disabled in offline mode)
    KAKAO_ENABLED: bool = False
    KAKAO_REST_KEY: str = ""
    KAKAO_CHANNEL_TOKEN: str = ""

    # Raspberry Pi sensor (optional)
    RPI_ENABLED: bool = False
    RPI_IP: str = ""
    RPI_PORT: int = 8765

    # SNMP environmental sensor custom OIDs (optional)
    ENV_TEMP_OID: str = ""
    ENV_HUMIDITY_OID: str = ""
    ENV_TEMP_SCALE: float = 1.0
    ENV_HUMIDITY_SCALE: float = 1.0

    # CVE / NVD
    NVD_CACHE_DIR: str = "data/nvd_cache"
    CVE_CHECK_INTERVAL: int = 3600  # seconds

    # Thresholds (defaults — overridable per-device in DB)
    CPU_WARN: float = 80.0
    CPU_CRIT: float = 95.0
    MEM_WARN: float = 75.0
    MEM_CRIT: float = 90.0
    DISK_WARN: float = 80.0
    DISK_CRIT: float = 90.0
    TEMP_WARN: float = 30.0
    TEMP_CRIT: float = 35.0
    HUMI_WARN_HIGH: float = 60.0
    UPS_BATT_WARN: float = 30.0
    UPS_BATT_CRIT: float = 15.0

    # Anomaly detection
    ANOMALY_ZSCORE_THRESHOLD: float = 3.0
    ANOMALY_WINDOW_MINUTES: int = 60

    # JWT Authentication (CHANGE JWT_SECRET before deploying to production!)
    JWT_SECRET: str = "netguard-default-secret-CHANGE-IN-PRODUCTION"
    JWT_EXPIRE_HOURS: int = 8


def load_settings() -> Settings:
    cfg_path = Path(__file__).parent.parent / "config" / "config.yaml"
    data: dict = {}
    if cfg_path.exists():
        with open(cfg_path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

    s = Settings()
    for key in vars(s):
        env_val = os.environ.get(f"NETGUARD_{key}")
        if env_val is not None:
            current = getattr(s, key)
            if isinstance(current, bool):
                setattr(s, key, env_val.lower() in ("1", "true", "yes"))
            elif isinstance(current, int):
                setattr(s, key, int(env_val))
            elif isinstance(current, float):
                setattr(s, key, float(env_val))
            elif isinstance(current, list):
                setattr(s, key, [v.strip() for v in env_val.split(",")])
            else:
                setattr(s, key, env_val)
        elif key.lower() in data:
            setattr(s, key, data[key.lower()])

    return s


settings = load_settings()
