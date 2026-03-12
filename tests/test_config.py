"""Basic tests for server configuration."""
import sys
sys.path.insert(0, ".")

from src.config.models import ServerConfig, NetworkConfig, PcapConfig, DatabaseConfig, SecurityConfig


def test_default_config():
    """ServerConfig should have sensible defaults."""
    config = ServerConfig()
    assert config.server.tcp_port == 9999
    assert config.server.udp_port == 9998
    assert config.server.api_port == 8000


def test_network_config_defaults():
    """NetworkConfig defaults should match server_config.yaml."""
    net = NetworkConfig()
    assert net.host == "0.0.0.0"
    assert net.subnet == "192.168.1.0/24"


def test_security_config_defaults():
    """SecurityConfig should have development defaults."""
    sec = SecurityConfig()
    assert sec.jwt_algorithm == "HS256"
    assert sec.jwt_expiration_hours == 24
    assert len(sec.jwt_secret) > 0