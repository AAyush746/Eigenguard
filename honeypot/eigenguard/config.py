"""Central configuration for the EigenGuard honeypot.

Every value can be overridden with an environment variable so the same code
runs unchanged on a laptop, in Docker, or on a VPS.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Config:
    """Runtime configuration for the SSH honeypot and its API."""

    # --- SSH honeypot -------------------------------------------------
    ssh_host: str = os.environ.get("EG_SSH_HOST", "0.0.0.0")
    ssh_port: int = _env_int("EG_SSH_PORT", 2222)
    ssh_banner: str = os.environ.get(
        "EG_SSH_BANNER", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"
    )
    # Extra text printed after the banner to look like a real OpenSSH server.
    ssh_pre_auth_noise: str = os.environ.get(
        "EG_SSH_NOISE",
        "\r\nWelcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-105-generic x86_64)\r\n"
        "Documentation: https://help.ubuntu.com\r\n"
        "System load: 0.12, 0.05, 0.01\r\n",
    )
    # A session with at least this many failed auth attempts is brute force.
    brute_force_threshold: int = _env_int("EG_BRUTE_FORCE_THRESHOLD", 3)
    # Give up on a client after this many failed attempts and drop the socket.
    max_auth_attempts: int = _env_int("EG_MAX_AUTH_ATTEMPTS", 20)
    # Artificial delay before answering auth requests, in seconds. Defeats
    # fast parallel brute forcers slightly and looks more like real OpenSSH.
    auth_delay: float = _env_float("EG_AUTH_DELAY", 0.15)
    host_key_path: Path = BASE_DIR / "data" / "ssh_host_key"

    # --- FastAPI ------------------------------------------------------
    api_host: str = os.environ.get("EG_API_HOST", "0.0.0.0")
    api_port: int = _env_int("EG_API_PORT", 8000)
    api_cors_origins: list[str] = field(
        default_factory=lambda: [
            o.strip()
            for o in os.environ.get("EG_CORS_ORIGINS", "*").split(",")
            if o.strip()
        ]
    )
    max_attacks_in_response: int = _env_int("EG_MAX_ATTACKS", 500)

    # --- Storage ------------------------------------------------------
    db_path: Path = BASE_DIR / "data" / "honeypot.db"
    database_url: str = field(
        default_factory=lambda: os.environ.get(
            "EG_DATABASE_URL", f"sqlite:///{BASE_DIR / 'data' / 'honeypot.db'}"
        )
    )

    # --- GeoIP --------------------------------------------------------
    geoip_db_path: Path = BASE_DIR / "data" / "GeoLite2-City.mmdb"
    geoip_enabled: bool = _env_bool("EG_GEOIP_ENABLED", True)

    # --- Logging ------------------------------------------------------
    log_dir: Path = BASE_DIR / "logs"
    log_level: str = os.environ.get("EG_LOG_LEVEL", "INFO")

    def ensure_dirs(self) -> None:
        """Create the directories the honeypot writes into."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.host_key_path.parent.mkdir(parents=True, exist_ok=True)
        self.log_dir.mkdir(parents=True, exist_ok=True)


config = Config()