"""
Script de prueba para enviar una push notification de prueba.

Uso:
    python3 test_push.py

Requisitos:
    - PostgreSQL corriendo (docker-compose up -d)
    - Al menos un token FCM registrado (login en la app)
    - firebase-service-account.json en config/
"""

import sys
import logging

sys.path.insert(0, ".")

logging.basicConfig(
    level=logging.DEBUG,
    format="%(levelname)s | %(name)s | %(message)s",
)

from src.config import load_config
from src.database.connection import Database
from src.database.models import Base, PushToken
from src.database.repository import Repository
from src.api.fcm_notifier import FCMNotifier


def main():
    config = load_config()

    # Connect to DB
    db = Database(
        host=config.database.host,
        port=config.database.port,
        name=config.database.name,
        user=config.database.user,
        password=config.database.password,
    )
    repo = Repository(db.get_session)

    # Check registered tokens
    tokens = repo.get_all_push_tokens()
    print(f"\n  Registered FCM tokens: {len(tokens)}")
    for i, t in enumerate(tokens):
        print(f"    [{i+1}] {t[:20]}...{t[-10:]}")

    if not tokens:
        print("\n  No tokens registered. Login in the app first!")
        print("  Then re-run this script.\n")
        return

    # Initialize FCM notifier
    notifier = FCMNotifier(
        credentials_path=config.firebase.credentials_path,
        repository=repo,
        enabled=config.firebase.enabled,
    )

    if not notifier._ready:
        print("\n  FCM not ready. Check firebase-service-account.json.\n")
        return

    # Send test alert
    test_alert = {
        "id": 9999,
        "anomaly_type": "test_notification",
        "description": "This is a test push from GOATGuard Server",
        "severity": "warning",
        "device_id": 1,
    }

    print(f"\n  Sending test push to {len(tokens)} device(s)...")
    notifier.send_alert(test_alert)
    print("  Done! Check your phone/emulator.\n")


if __name__ == "__main__":
    main()
