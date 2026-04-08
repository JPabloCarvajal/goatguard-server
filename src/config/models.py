"""
Data models for GOATGuard server configuration.

Each dataclass maps to a section in server_config.yaml.
Default values are used when a field is missing from the YAML.
"""

from dataclasses import dataclass, field


class ConfigError(Exception):
    """Raised when server configuration is invalid or cannot be loaded."""
    pass


def _default_cors_origins() -> list[str]:
    """Orígenes permitidos por defecto para desarrollo local.

    En producción se debe sobrescribir desde ``server_config.yaml`` o
    variables de entorno con el dominio público de la app móvil.
    Nunca usar ``["*"]`` porque la API acepta credenciales (JWT).
    """
    return [
        "http://localhost",
        "http://localhost:3000",
        "http://localhost:8000",
        "http://127.0.0.1",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8000",
    ]


@dataclass
class SecurityConfig:
    """Security settings for authentication and encryption.

    ``fernet_key`` y ``hibp_check_enabled`` sostienen el flujo 2FA
    [RF-13]: el primero cifra los secretos TOTP (AES-128-CBC + HMAC),
    el segundo permite apagar la consulta a HaveIBeenPwned en redes
    aisladas donde el fail-open no aporta valor.
    """
    jwt_secret: str = "goatguard-dev-secret-change-in-production"
    jwt_algorithm: str = "HS256"
    jwt_expiration_hours: int = 24
    cors_origins: list[str] = field(default_factory=_default_cors_origins)
    # Clave Fernet para cifrar secretos TOTP. Vacía por defecto: debe
    # inyectarse vía server_config.yaml o env var antes de habilitar 2FA.
    # Generar con ``cryptography.fernet.Fernet.generate_key()``.
    fernet_key: str = ""
    # Verificación de passwords contra HaveIBeenPwned (k-anonymity).
    # Fail-open con warning cuando la red no permite alcanzar el servicio.
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
class FirebaseConfig:
    """Firebase Cloud Messaging settings for push notifications."""
    credentials_path: str = "config/firebase-service-account.json"
    enabled: bool = True


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
    firebase: FirebaseConfig = field(default_factory=FirebaseConfig)