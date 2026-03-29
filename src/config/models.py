"""
Data models for GOATGuard server configuration.

Each dataclass maps to a section in server_config.yaml.
Default values are used when a field is missing from the YAML.
"""

from dataclasses import dataclass, field


class ConfigError(Exception):
    """Raised when server configuration is invalid or cannot be loaded."""
    pass


@dataclass
class SecurityConfig:
    """Security settings for authentication and encryption."""
    jwt_secret: str = "goatguard-dev-secret-change-in-production"
    jwt_algorithm: str = "HS256"
    jwt_expiration_hours: int = 24
    fernet_key: str = ""  # Cifrado TOTP secrets — generar con Fernet.generate_key()
    hibp_check_enabled: bool = True

@dataclass
class NetworkConfig:
    """Network ports and bind address for all server listeners."""
    tcp_port: int = 9999
    udp_port: int = 9998
    api_port: int = 8000
    host: str = "0.0.0.0"
    subnet: str = "192.168.1.0/24"


@dataclass
class PcapConfig:
    """PCAP file assembly and rotation settings.

    rotation_seconds: How often a new PCAP file is created.
        This defines the "near real-time" delay of the system.
        Every N seconds the current file closes, gets processed
        by Zeek, and results appear in the dashboard.
    max_file_size_mb: Safety limit to prevent disk exhaustion.
    """
    output_dir: str = "pcap_output"
    rotation_seconds: int = 30
    max_file_size_mb: int = 100


@dataclass
class DatabaseConfig:
    """PostgreSQL connection settings."""
    host: str = "localhost"
    port: int = 5432
    name: str = "goatguard"
    user: str = "goatguard"
    password: str = "goatguard"


@dataclass
class LoggingConfig:
    """Logging output settings."""
    level: str = "INFO"
    file: str = "goatguard_server.log"


@dataclass
class ServerConfig:
    """Root configuration object grouping all sections.

    Usage:
        config.server.tcp_port      -> 9999
        config.pcap.rotation_seconds -> 30
        config.database.host        -> "localhost"
    """
    server: NetworkConfig = field(default_factory=NetworkConfig)
    pcap: PcapConfig = field(default_factory=PcapConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)