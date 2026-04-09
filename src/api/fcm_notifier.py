"""
Firebase Cloud Messaging notifier for GOATGuard.

Sends push notifications to all registered mobile devices
when the detection engine creates a new alert.

Designed to be fault-tolerant: if Firebase credentials are
missing or invalid, the notifier logs a warning and becomes
a no-op — it never crashes the server.
"""

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# Lazy imports — firebase_admin is only loaded if enabled
_firebase_app = None
_initialized = False


class FCMNotifier:
    """Sends push notifications via Firebase Cloud Messaging V1 API.

    Args:
        credentials_path: Path to the Firebase service account JSON.
        repository: Database repository for reading/cleaning push tokens.
        enabled: If False, all calls become no-ops.
    """

    def __init__(self, credentials_path: str, repository,
                 enabled: bool = True) -> None:
        self._repo = repository
        self._enabled = enabled
        self._ready = False

        if not enabled:
            logger.info("FCM notifier disabled by configuration")
            return

        self._ready = self._initialize(credentials_path)

    def _initialize(self, credentials_path: str) -> bool:
        """Initialize the Firebase Admin SDK (once per process)."""
        global _firebase_app, _initialized

        if _initialized:
            self._ready = _firebase_app is not None
            return self._ready

        _initialized = True

        path = Path(credentials_path)
        if not path.exists():
            logger.warning(
                f"Firebase credentials not found at {path.absolute()}. "
                "Push notifications will be disabled."
            )
            return False

        try:
            import firebase_admin
            from firebase_admin import credentials

            cred = credentials.Certificate(str(path))
            _firebase_app = firebase_admin.initialize_app(cred)
            logger.info("Firebase Admin SDK initialized successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to initialize Firebase: {e}")
            return False

    def send_alert(self, alert_data: dict) -> None:
        """Send a push notification for a new alert to all registered devices.

        Args:
            alert_data: Alert dict with keys: id, description, severity,
                        anomaly_type, device_id, etc.
        """
        if not self._enabled or not self._ready:
            return

        tokens = self._repo.get_all_push_tokens()
        if not tokens:
            logger.debug("No push tokens registered — skipping FCM send")
            return

        try:
            from firebase_admin import messaging

            notification = messaging.Notification(
                title=self._build_title(alert_data),
                body=alert_data.get("description", "New alert detected"),
            )

            data_payload = {
                "alert_id": str(alert_data.get("id", "")),
                "severity": alert_data.get("severity", "warning"),
                "anomaly_type": alert_data.get("anomaly_type", ""),
                "type": "alert_created",
            }

            message = messaging.MulticastMessage(
                tokens=tokens,
                notification=notification,
                data=data_payload,
                android=messaging.AndroidConfig(
                    priority="high",
                    notification=messaging.AndroidNotification(
                        channel_id="goatguard_alerts",
                        priority="high",
                    ),
                ),
            )

            response = messaging.send_each_for_multicast(message)

            if response.failure_count > 0:
                self._cleanup_invalid_tokens(tokens, response.responses)

            logger.info(
                f"FCM sent: {response.success_count} ok, "
                f"{response.failure_count} failed "
                f"(alert_id={alert_data.get('id')})"
            )

        except Exception as e:
            logger.error(f"FCM send failed: {e}")

    def _build_title(self, alert_data: dict) -> str:
        """Build a notification title from alert data."""
        severity = alert_data.get("severity", "warning").upper()
        anomaly = alert_data.get("anomaly_type", "Alert")
        return f"[{severity}] {anomaly}"

    def _cleanup_invalid_tokens(self, tokens: list[str],
                                 responses: list) -> None:
        """Remove tokens that Firebase reported as invalid."""
        invalid = []
        for token, resp in zip(tokens, responses):
            if resp.exception is not None:
                error_code = getattr(resp.exception, "code", "")
                if error_code in (
                    "NOT_FOUND",
                    "UNREGISTERED",
                    "INVALID_ARGUMENT",
                ):
                    invalid.append(token)

        if invalid:
            self._repo.delete_push_tokens_batch(invalid)
            logger.info(f"Cleaned up {len(invalid)} invalid FCM tokens")
