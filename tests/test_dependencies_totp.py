"""
Tests de las dependencias FastAPI del flujo 2FA [RF-13].

Validan sin montar la app completa:
- Inyección del ``SecurityConfig`` vía ``set_security_config`` /
  ``get_security_config``.
- ``get_current_user_totp_verified`` rechaza tokens ``pending_totp``
  con HTTP 403.
- ``get_current_user`` invalida tokens emitidos antes de un cambio
  de contraseña (``password_changed_at``) — evita que un atacante
  con un JWT antiguo siga navegando tras un reset forzado.
"""

import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, ".")

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from src.api.auth import create_token, init_auth
from src.api.dependencies import (
    get_current_user,
    get_current_user_totp_verified,
    get_security_config,
    set_security_config,
)
from src.config.models import SecurityConfig
from src.database.models import Base, User


TEST_SECRET = "goatguard-test-secret-key-for-pytest-suite"


@pytest.fixture(autouse=True)
def _init_auth_for_deps_tests():
    init_auth(
        jwt_secret=TEST_SECRET,
        jwt_algorithm="HS256",
        jwt_expiration_hours=1,
    )


@pytest.fixture()
def db_session():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()
    Base.metadata.drop_all(engine)


@pytest.fixture()
def seeded_user(db_session):
    user = User(username="alice", password_hash="fake-hash")
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


def _creds(token: str) -> HTTPAuthorizationCredentials:
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


class TestSecurityConfigInjection:
    def test_set_and_get_security_config_roundtrip(self):
        cfg = SecurityConfig()
        cfg.fernet_key = "injected-key-for-test"
        set_security_config(cfg)
        assert get_security_config() is cfg
        assert get_security_config().fernet_key == "injected-key-for-test"


class TestGetCurrentUserTotpVerified:
    def test_accepts_full_access_token(self, db_session, seeded_user):
        token = create_token(
            user_id=seeded_user.id,
            username=seeded_user.username,
            scope="full_access",
        )
        user = get_current_user(credentials=_creds(token), db=db_session)
        # El wrapper TOTP no debe levantar excepción con scope=full_access
        result = get_current_user_totp_verified(user=user)
        assert result.id == seeded_user.id

    def test_rejects_pending_totp_token_with_403(self, db_session, seeded_user):
        """Un token ``pending_totp`` debe recibir 403 en endpoints de negocio.

        Devolver 401 daría señal ambigua (credenciales inválidas); 403
        comunica correctamente que el usuario está autenticado pero no
        ha completado el segundo factor.
        """
        token = create_token(
            user_id=seeded_user.id,
            username=seeded_user.username,
            scope="pending_totp",
        )
        user = get_current_user(credentials=_creds(token), db=db_session)

        with pytest.raises(HTTPException) as exc_info:
            get_current_user_totp_verified(user=user)
        assert exc_info.value.status_code == 403


class TestPasswordChangedInvalidation:
    def test_token_issued_before_password_change_is_rejected(
        self, db_session, seeded_user
    ):
        """Cambiar la contraseña debe invalidar retroactivamente los tokens
        emitidos antes del cambio. Sin esto, un atacante con un JWT robado
        sigue teniendo acceso aunque el usuario resetee la contraseña.
        """
        token = create_token(
            user_id=seeded_user.id,
            username=seeded_user.username,
        )

        # Simular que el password se cambió DESPUÉS del iat del token.
        seeded_user.password_changed_at = datetime.now(timezone.utc) + timedelta(
            seconds=10
        )
        db_session.commit()

        with pytest.raises(HTTPException) as exc_info:
            get_current_user(credentials=_creds(token), db=db_session)
        assert exc_info.value.status_code == 401

    def test_token_issued_after_password_change_is_accepted(
        self, db_session, seeded_user
    ):
        """Un token nuevo emitido tras el cambio de password debe funcionar."""
        seeded_user.password_changed_at = datetime.now(timezone.utc) - timedelta(
            minutes=5
        )
        db_session.commit()

        token = create_token(
            user_id=seeded_user.id,
            username=seeded_user.username,
        )
        user = get_current_user(credentials=_creds(token), db=db_session)
        assert user.id == seeded_user.id
