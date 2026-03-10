"""
Configuration file loading and parsing for GOATGuard server.

Finds the YAML file, reads it, builds typed config objects,
and validates values before returning.
"""

import logging
from pathlib import Path
from typing import Optional

import yaml

from src.config.models import (
    ConfigError,
    DatabaseConfig,
    LoggingConfig,
    NetworkConfig,
    PcapConfig,
    ServerConfig,
)

logger = logging.getLogger(__name__)


def load_config(file_path: Optional[Path] = None) -> ServerConfig:
    """Load, parse, and validate server configuration from YAML.

    Args:
        file_path: Path to YAML file. If None, searches default locations.

    Returns:
        Fully loaded and validated ServerConfig.

    Raises:
        ConfigError: If the file is missing, malformed, or has invalid values.
    """
    if file_path is None:
        file_path = _find_config_file()

    logger.info(f"Loading configuration from: {file_path}")
    raw = _load_yaml(file_path)
    config = _build_config(raw)
    _validate(config)

    logger.info(
        f"Configuration loaded: TCP={config.server.tcp_port}, "
        f"UDP={config.server.udp_port}, API={config.server.api_port}"
    )
    return config


def _find_config_file() -> Path:
    """Search default locations for the config file."""
    candidates = [
        Path("config") / "server_config.yaml",
        Path("server_config.yaml"),
    ]
    for path in candidates:
        if path.exists():
            return path

    searched = ", ".join(str(p) for p in candidates)
    raise ConfigError(f"Config file not found. Searched: {searched}")


def _load_yaml(file_path: Path) -> dict:
    """Read and parse a YAML file into a dictionary."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return data if isinstance(data, dict) else {}
    except yaml.YAMLError as e:
        raise ConfigError(f"YAML parse error in {file_path}: {e}")
    except OSError as e:
        raise ConfigError(f"Cannot read file {file_path}: {e}")


def _build_config(raw: dict) -> ServerConfig:
    """Build typed config objects from raw dictionary.

    Uses ** unpacking to pass YAML values directly to dataclass
    constructors. Missing fields fall back to dataclass defaults.
    No default values are repeated here (DRY principle).
    """
    return ServerConfig(
        server=NetworkConfig(**raw.get("server", {})),
        pcap=PcapConfig(**raw.get("pcap", {})),
        database=DatabaseConfig(**raw.get("database", {})),
        logging=LoggingConfig(**raw.get("logging", {})),
    )


def _validate(config: ServerConfig) -> None:
    """Validate configuration values."""
    for name, port in [
        ("tcp_port", config.server.tcp_port),
        ("udp_port", config.server.udp_port),
        ("api_port", config.server.api_port),
        ("db_port", config.database.port),
    ]:
        if not 1 <= port <= 65535:
            raise ConfigError(f"Invalid port '{name}': {port}")

    if config.pcap.rotation_seconds < 5:
        raise ConfigError("PCAP rotation interval must be >= 5 seconds")

    valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    if config.logging.level.upper() not in valid_levels:
        raise ConfigError(f"Invalid logging level: '{config.logging.level}'")