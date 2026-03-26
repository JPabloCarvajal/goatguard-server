"""Integration tests for API endpoints using FastAPI TestClient."""
import sys
sys.path.insert(0, ".")

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.database.models import (
    Base, Device, Network, NetworkCurrentMetrics,
    DeviceCurrentMetrics, 
)
from src.api.dependencies import get_db
from src.api.app import create_app
from src.config.models import ServerConfig, SecurityConfig
from datetime import datetime

TEST_DATABASE_URL = "sqlite:///./test_goatguard.db"


@pytest.fixture(scope="module")
def test_app():
    """Create a test app with SQLite database."""
    engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    TestSession = sessionmaker(bind=engine, expire_on_commit=False)

    # Mock database object matching what create_app expects
    class MockDatabase:
        def get_session(self):
            return TestSession()

    mock_db = MockDatabase()

    # Config with test security settings
    config = ServerConfig()
    config.security = SecurityConfig(
        jwt_secret="test-secret-for-endpoint-testing-goatguard",
        jwt_algorithm="HS256",
        jwt_expiration_hours=24,
    )

    # Create app with required arguments
    app = create_app(database=mock_db, config=config)

    # Override DB dependency for endpoints
    def override_get_db():
        session = TestSession()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db

    # Seed test data
    session = TestSession()
    network = Network(name="Test LAN", subnet="192.168.1.0/24", gateway="192.168.1.1")
    session.add(network)
    session.commit()
    session.refresh(network)

    device = Device(
        network_id=network.id, ip="192.168.1.8", mac="00:0C:29:8D:4E:B2",
        hostname="test-device", status="active", has_agent=True,
        detected_type="VMware, Inc.",
    )
    session.add(device)
    session.commit()
    session.refresh(device)

    metrics = DeviceCurrentMetrics(
        device_id=device.id,
        timestamp=datetime.utcnow(),
        cpu_pct=15.0, ram_pct=42.0, bandwidth_in=500.0,
        bandwidth_out=100.0, tcp_retransmissions=0, failed_connections=2,
    )
    session.add(metrics)

    net_metrics = NetworkCurrentMetrics(
        network_id=network.id,
        timestamp=datetime.utcnow(),
        isp_latency_avg=11.5, packet_loss_pct=0.0, jitter=0.2,
        active_connections=50, failed_connections_global=5,
    )
    session.add(net_metrics)
    session.commit()

    # Save IDs before closing session
    network_id = network.id
    device_id = device.id
    session.close()

    client = TestClient(app)

    yield {
        "client": client,
        "engine": engine,
        "SessionLocal": TestSession,
        "network_id": network_id,
        "device_id": device_id,
    }

    # Cleanup
    Base.metadata.drop_all(bind=engine)
    engine.dispose()
    import os
    try:
        os.remove("test_goatguard.db")
    except OSError:
        pass


@pytest.fixture(scope="module")
def auth_token(test_app):
    """Login or register a user and return a valid JWT token."""
    client = test_app["client"]

    # Try login first (user might exist from test_register)
    response = client.post("/auth/login", json={
        "username": "testadmin",
        "password": "testpassword123",
    })

    if response.status_code == 200:
        return response.json()["access_token"]

    # If login fails, register
    response = client.post("/auth/register", json={
        "username": "testadmin",
        "password": "testpassword123",
    })

    assert response.status_code in (200, 201), f"Register failed: {response.text}"
    return response.json()["access_token"]


class TestAuthEndpoints:
    """Tests for /auth/* endpoints."""

    def test_register_returns_token(self, test_app):
        client = test_app["client"]

        response = client.post("/auth/register", json={
            "username": "newuser",
            "password": "password123",
        })

        assert response.status_code in (200, 201)
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"

    def test_register_duplicate_username(self, test_app):
        client = test_app["client"]

        # First registration
        client.post("/auth/register", json={
            "username": "duplicate",
            "password": "pass123",
        })

        # Second with same username
        response = client.post("/auth/register", json={
            "username": "duplicate",
            "password": "pass456",
        })

        assert response.status_code in (400, 409)

    def test_login_valid_credentials(self, test_app, auth_token):
        client = test_app["client"]

        response = client.post("/auth/login", json={
            "username": "testadmin",
            "password": "testpassword123",
        })

        assert response.status_code == 200
        assert "access_token" in response.json()

    def test_login_wrong_password(self, test_app):
        client = test_app["client"]

        response = client.post("/auth/login", json={
            "username": "testadmin",
            "password": "wrongpassword",
        })

        assert response.status_code == 401

    def test_protected_endpoint_without_token(self, test_app):
        client = test_app["client"]

        response = client.get("/devices/")

        assert response.status_code in (401, 403)


class TestDeviceEndpoints:
    """Tests for /devices/* endpoints."""

    def test_list_devices(self, test_app, auth_token):
        client = test_app["client"]

        response = client.get(
            "/devices/",
            headers={"Authorization": f"Bearer {auth_token}"},
        )

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) >= 1
        assert data[0]["ip"] == "192.168.1.8"

    def test_get_device_detail(self, test_app, auth_token):
        client = test_app["client"]
        device_id = test_app["device_id"]

        response = client.get(
            f"/devices/{device_id}",
            headers={"Authorization": f"Bearer {auth_token}"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["hostname"] == "test-device"
        assert data["has_agent"] is True
        assert "metrics" in data

    def test_get_nonexistent_device(self, test_app, auth_token):
        client = test_app["client"]

        response = client.get(
            "/devices/99999",
            headers={"Authorization": f"Bearer {auth_token}"},
        )

        assert response.status_code == 404

    def test_update_device_alias(self, test_app, auth_token):
        client = test_app["client"]
        device_id = test_app["device_id"]

        response = client.patch(
            f"/devices/{device_id}/alias",
            headers={"Authorization": f"Bearer {auth_token}"},
            json={"alias": "My Server"},
        )

        assert response.status_code == 200
        assert response.json()["alias"] == "My Server"


class TestNetworkEndpoints:
    """Tests for /network/* endpoints."""

    def test_get_network_metrics(self, test_app, auth_token):
        client = test_app["client"]

        response = client.get(
            "/network/metrics",
            headers={"Authorization": f"Bearer {auth_token}"},
        )

        assert response.status_code == 200
        data = response.json()
        assert "isp_latency_avg" in data
        assert data["isp_latency_avg"] == 11.5

    def test_get_top_talkers(self, test_app, auth_token):
        client = test_app["client"]

        response = client.get(
            "/network/top-talkers",
            headers={"Authorization": f"Bearer {auth_token}"},
        )

        assert response.status_code == 200
        assert isinstance(response.json(), list)

    def test_isp_health(self, test_app, auth_token):
        client = test_app["client"]

        response = client.get(
            "/network/isp-health",
            headers={"Authorization": f"Bearer {auth_token}"},
        )

        assert response.status_code == 200
        data = response.json()
        assert "latency" in data
        assert "packet_loss" in data
        assert "jitter" in data
        assert data["latency"]["current"] == 11.5


class TestDashboardEndpoint:
    """Tests for /dashboard/* endpoints."""

    def test_dashboard_summary(self, test_app, auth_token):
        client = test_app["client"]

        response = client.get(
            "/dashboard/summary",
            headers={"Authorization": f"Bearer {auth_token}"},
        )

        assert response.status_code == 200
        data = response.json()
        assert "network_status" in data
        assert "devices_total" in data
        assert "unseen_alerts" in data
        assert data["devices_total"] >= 1


class TestAlertEndpoints:
    """Tests for /alerts/* endpoints."""

    def test_list_alerts_empty(self, test_app, auth_token):
        client = test_app["client"]

        response = client.get(
            "/alerts/",
            headers={"Authorization": f"Bearer {auth_token}"},
        )

        assert response.status_code == 200
        assert isinstance(response.json(), list)

    def test_alert_count(self, test_app, auth_token):
        client = test_app["client"]

        response = client.get(
            "/alerts/count",
            headers={"Authorization": f"Bearer {auth_token}"},
        )

        assert response.status_code == 200
        data = response.json()
        assert "unseen_count" in data
        assert "total_count" in data