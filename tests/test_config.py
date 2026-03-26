"""Unit tests for server configuration models."""
import sys
sys.path.insert(0, ".")

from src.config.models import (
    ServerConfig, NetworkConfig, PcapConfig,
    DatabaseConfig, SecurityConfig, LoggingConfig,
)


class TestNetworkConfig:
    """Tests for network configuration defaults."""

    def test_default_ports(self):
        net = NetworkConfig()
        assert net.tcp_port == 9999
        assert net.udp_port == 9998
        assert net.api_port == 8000

    def test_default_host_binds_all_interfaces(self):
        net = NetworkConfig()
        assert net.host == "0.0.0.0"

    def test_default_subnet(self):
        net = NetworkConfig()
        assert net.subnet == "192.168.1.0/24"


class TestDatabaseConfig:
    """Tests for database configuration defaults."""

    def test_default_connection_params(self):
        db = DatabaseConfig()
        assert db.host == "localhost"
        assert db.port == 5432
        assert db.name == "goatguard"


class TestSecurityConfig:
    """Tests for security configuration defaults."""

    def test_default_jwt_settings(self):
        sec = SecurityConfig()
        assert sec.jwt_algorithm == "HS256"
        assert sec.jwt_expiration_hours == 24

    def test_dev_secret_present(self):
        """Development default secret should exist but be obviously non-production."""
        sec = SecurityConfig()
        assert len(sec.jwt_secret) > 0
        assert "change" in sec.jwt_secret.lower() or "dev" in sec.jwt_secret.lower()


class TestServerConfig:
    """Tests for the root configuration object."""

    def test_groups_all_sections(self):
        config = ServerConfig()
        assert isinstance(config.server, NetworkConfig)
        assert isinstance(config.pcap, PcapConfig)
        assert isinstance(config.database, DatabaseConfig)
        assert isinstance(config.logging, LoggingConfig)
        assert isinstance(config.security, SecurityConfig)

    def test_pcap_defaults(self):
        config = ServerConfig()
        assert config.pcap.rotation_seconds == 30
        assert config.pcap.max_file_size_mb == 100