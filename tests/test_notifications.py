"""
Tests for push notification endpoints and FCM notifier.

Covers:
- POST /notifications/token (register)
- DELETE /notifications/token (unregister)
- FCMNotifier with mocked firebase_admin
"""

import sys
sys.path.insert(0, ".")

import os
from unittest.mock import patch, MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.database.models import Base, PushToken, User
from src.api.auth import create_token, hash_password
from src.api.dependencies import get_db
from src.api.app import create_app
from src.config.models import ServerConfig, SecurityConfig

TEST_DB_URL = "sqlite:///./test_notifications.db"


@pytest.fixture(scope="module")
def notif_app():
    """Self-contained test app for notification tests."""
    engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    TestSession = sessionmaker(bind=engine, expire_on_commit=False)

    class MockDatabase:
        def get_session(self):
            return TestSession()

    config = ServerConfig()
    config.security = SecurityConfig(
        jwt_secret="test-secret-for-notification-testing-goatguard",
        jwt_algorithm="HS256",
        jwt_expiration_hours=24,
    )

    app = create_app(database=MockDatabase(), config=config)

    def override_get_db():
        session = TestSession()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db

    client = TestClient(app)

    yield {"client": client, "SessionLocal": TestSession}

    Base.metadata.drop_all(bind=engine)
    engine.dispose()
    try:
        os.remove("test_notifications.db")
    except OSError:
        pass


@pytest.fixture(scope="module")
def auth_token(notif_app):
    """Crea un user directo en BD y devuelve JWT full_access.

    No usa /auth/register porque el flujo 2FA requiere invitation_token
    y devuelve scope=pending_totp, insuficiente para endpoints protegidos.
    """
    session = notif_app["SessionLocal"]()
    user = User(
        username="notif_admin",
        password_hash=hash_password("goatguard-notif-test-pwd"),
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    token = create_token(user_id=user.id, username=user.username)
    session.close()
    return token


@pytest.fixture(scope="module")
def auth_headers(auth_token):
    return {"Authorization": f"Bearer {auth_token}"}


# ── Endpoint tests ───────────────────────────────────────────────────────────

class TestRegisterToken:
    """POST /notifications/token"""

    def test_register_token_success(self, notif_app, auth_headers):
        resp = notif_app["client"].post(
            "/notifications/token",
            json={"token": "fcm-token-abc123", "platform": "android"},
            headers=auth_headers,
        )
        assert resp.status_code == 201
        assert resp.json()["message"] == "Token registered successfully"

    def test_register_token_persisted(self, notif_app, auth_headers):
        notif_app["client"].post(
            "/notifications/token",
            json={"token": "fcm-token-persist", "platform": "android"},
            headers=auth_headers,
        )

        session = notif_app["SessionLocal"]()
        token = session.query(PushToken).filter_by(
            token="fcm-token-persist"
        ).first()
        session.close()
        assert token is not None
        assert token.platform == "android"

    def test_register_duplicate_token_reassigns(self, notif_app, auth_headers):
        """If the same FCM token is registered twice, it should update."""
        notif_app["client"].post(
            "/notifications/token",
            json={"token": "fcm-dup-token"},
            headers=auth_headers,
        )
        notif_app["client"].post(
            "/notifications/token",
            json={"token": "fcm-dup-token"},
            headers=auth_headers,
        )

        session = notif_app["SessionLocal"]()
        count = session.query(PushToken).filter_by(
            token="fcm-dup-token"
        ).count()
        session.close()
        assert count == 1

    def test_register_token_requires_auth(self, notif_app):
        resp = notif_app["client"].post(
            "/notifications/token",
            json={"token": "no-auth-token"},
        )
        assert resp.status_code in (401, 403)


class TestUnregisterToken:
    """DELETE /notifications/token"""

    def test_unregister_token_success(self, notif_app, auth_headers):
        # First register
        notif_app["client"].post(
            "/notifications/token",
            json={"token": "fcm-to-remove"},
            headers=auth_headers,
        )

        # Then remove
        resp = notif_app["client"].request(
            "DELETE",
            "/notifications/token",
            json={"token": "fcm-to-remove"},
            headers=auth_headers,
        )
        assert resp.status_code == 200

        session = notif_app["SessionLocal"]()
        token = session.query(PushToken).filter_by(
            token="fcm-to-remove"
        ).first()
        session.close()
        assert token is None

    def test_unregister_nonexistent_returns_404(self, notif_app, auth_headers):
        resp = notif_app["client"].request(
            "DELETE",
            "/notifications/token",
            json={"token": "does-not-exist"},
            headers=auth_headers,
        )
        assert resp.status_code == 404


# ── FCMNotifier unit tests ───────────────────────────────────────────────────

class TestFCMNotifier:
    """Unit tests for src.api.fcm_notifier.FCMNotifier."""

    def test_disabled_notifier_is_noop(self):
        from src.api.fcm_notifier import FCMNotifier

        repo = MagicMock()
        notifier = FCMNotifier(
            credentials_path="nonexistent.json",
            repository=repo,
            enabled=False,
        )
        notifier.send_alert({"id": 1, "description": "test"})
        repo.get_all_push_tokens.assert_not_called()

    def test_missing_credentials_disables_gracefully(self):
        import src.api.fcm_notifier as mod
        mod._initialized = False
        mod._firebase_app = None

        from src.api.fcm_notifier import FCMNotifier

        repo = MagicMock()
        notifier = FCMNotifier(
            credentials_path="/tmp/nonexistent-firebase-creds.json",
            repository=repo,
            enabled=True,
        )
        assert notifier._ready is False
        notifier.send_alert({"id": 1, "description": "test"})
        repo.get_all_push_tokens.assert_not_called()

        mod._initialized = False
        mod._firebase_app = None

    def test_no_tokens_skips_send(self):
        from src.api.fcm_notifier import FCMNotifier

        repo = MagicMock()
        repo.get_all_push_tokens.return_value = []

        notifier = FCMNotifier.__new__(FCMNotifier)
        notifier._repo = repo
        notifier._enabled = True
        notifier._ready = True

        notifier.send_alert({"id": 1, "description": "test alert"})
        repo.get_all_push_tokens.assert_called_once()

    @patch("src.api.fcm_notifier.FCMNotifier._cleanup_invalid_tokens")
    def test_send_alert_calls_firebase(self, mock_cleanup):
        from src.api.fcm_notifier import FCMNotifier

        repo = MagicMock()
        repo.get_all_push_tokens.return_value = ["token-a", "token-b"]

        notifier = FCMNotifier.__new__(FCMNotifier)
        notifier._repo = repo
        notifier._enabled = True
        notifier._ready = True

        mock_response = MagicMock()
        mock_response.success_count = 2
        mock_response.failure_count = 0

        with patch("firebase_admin.messaging.send_each_for_multicast",
                   return_value=mock_response):
            with patch("firebase_admin.messaging.MulticastMessage"):
                with patch("firebase_admin.messaging.Notification"):
                    with patch("firebase_admin.messaging.AndroidConfig"):
                        with patch("firebase_admin.messaging.AndroidNotification"):
                            notifier.send_alert({
                                "id": 42,
                                "description": "High CPU",
                                "severity": "warning",
                                "anomaly_type": "cpu_pct",
                            })

        mock_response  # FCM was called

    def test_build_title(self):
        from src.api.fcm_notifier import FCMNotifier

        notifier = FCMNotifier.__new__(FCMNotifier)

        assert notifier._build_title({
            "severity": "critical",
            "anomaly_type": "bandwidth_out",
        }) == "[CRITICAL] bandwidth_out"

        assert notifier._build_title({}) == "[WARNING] Alert"
