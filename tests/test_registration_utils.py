"""
Tests unitarios de ``src.api.registration_utils`` [RF-13].

Validan la lógica de registro sin tocar la BD ni red real:
- Invitation tokens (URL-safe + SHA-256)
- Recovery codes (formato, hash bcrypt, normalización)
- Validación NIST SP 800-63B de contraseñas
- HaveIBeenPwned con k-anonymity, incluyendo el comportamiento
  fail-open cuando el servicio externo no responde
"""

import hashlib
import logging
import re
import sys
from unittest.mock import patch

import httpx
import pytest

sys.path.insert(0, ".")

from src.api.registration_utils import (
    check_password_hibp,
    generate_invitation_token,
    generate_recovery_code,
    hash_invitation_token,
    hash_recovery_code,
    validate_password_nist,
    verify_recovery_code,
)


class TestInvitationToken:
    def test_generate_invitation_token_is_url_safe(self):
        token = generate_invitation_token()
        # secrets.token_urlsafe(32) produce ~43 chars URL-safe base64
        assert len(token) >= 40
        assert re.fullmatch(r"[A-Za-z0-9_-]+", token)

    def test_tokens_are_unique(self):
        tokens = {generate_invitation_token() for _ in range(50)}
        assert len(tokens) == 50

    def test_hash_invitation_token_is_deterministic_sha256(self):
        token = "deadbeef"
        expected = hashlib.sha256(token.encode()).hexdigest()
        assert hash_invitation_token(token) == expected
        assert len(hash_invitation_token(token)) == 64  # 32 bytes hex


class TestRecoveryCode:
    def test_format_is_xxxx_xxxx_xxxx_xxxx(self):
        code = generate_recovery_code()
        pattern = re.compile(
            r"^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$"
        )
        assert pattern.match(code), f"formato inválido: {code}"

    def test_codes_are_unique(self):
        codes = {generate_recovery_code() for _ in range(50)}
        assert len(codes) == 50

    def test_hash_verify_roundtrip(self):
        code = "ABCD-EFGH-JKMN-PQRS"
        stored = hash_recovery_code(code)
        assert verify_recovery_code(code, stored) is True

    def test_verify_normalizes_dashes_and_case(self):
        original = "ABCD-EFGH-JKMN-PQRS"
        stored = hash_recovery_code(original)
        assert verify_recovery_code("abcd-efgh-jkmn-pqrs", stored) is True
        assert verify_recovery_code("ABCDEFGHJKMNPQRS", stored) is True

    def test_wrong_code_rejected(self):
        stored = hash_recovery_code("ABCD-EFGH-JKMN-PQRS")
        assert verify_recovery_code("WRNG-WRNG-WRNG-WRNG", stored) is False


class TestValidatePasswordNist:
    def test_accepts_15_char_password(self):
        ok, err = validate_password_nist("x" * 15)
        assert ok is True
        assert err is None

    def test_rejects_password_shorter_than_15(self):
        ok, err = validate_password_nist("x" * 14)
        assert ok is False
        assert err and "15" in err

    def test_rejects_password_longer_than_128(self):
        ok, err = validate_password_nist("x" * 129)
        assert ok is False
        assert err and "128" in err

    def test_accepts_128_char_boundary(self):
        ok, err = validate_password_nist("x" * 128)
        assert ok is True


class TestCheckPasswordHibp:
    """HIBP via k-anonymity (solo se envían 5 chars del SHA-1).

    Hash de "password" = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
    Prefix: 5BAA6, Suffix: 1E4C9B93F3F0682250B6CF8331B7EE68FD8
    """

    def test_compromised_password_returns_true(self):
        suffix = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"
        mock_response = httpx.Response(
            200, text=f"{suffix}:12345\nOTHERSUFFIX:1\n"
        )
        with patch("src.api.registration_utils.httpx.get", return_value=mock_response):
            assert check_password_hibp("password") is True

    def test_clean_password_returns_false(self):
        mock_response = httpx.Response(
            200, text="OTHERSUFFIX:1\nANOTHERSUFFIX:2\n"
        )
        with patch("src.api.registration_utils.httpx.get", return_value=mock_response):
            assert check_password_hibp("very-unlikely-unique-passphrase-99x") is False

    def test_hibp_network_failure_is_fail_open(self, caplog):
        """Si HIBP está caído (sin internet en LAN), NO bloquear registros
        — pero dejar un warning prominente en logs para auditoría [mejora #4].

        Fail-open es intencional: GOATGuard se despliega en redes
        potencialmente aisladas y bloquear el registro por no alcanzar
        un servicio externo sería un self-DoS. Fail-closed convertiría
        a pwnedpasswords.com en una dependencia de disponibilidad crítica.
        """
        with patch(
            "src.api.registration_utils.httpx.get",
            side_effect=httpx.ConnectError("Network unreachable"),
        ):
            with caplog.at_level(logging.WARNING, logger="src.api.registration_utils"):
                result = check_password_hibp("any-password-here")

        assert result is False  # Fail-open: no bloquear

        hibp_warnings = [
            r for r in caplog.records
            if "hibp" in r.getMessage().lower() or "pwned" in r.getMessage().lower()
        ]
        assert hibp_warnings, (
            "HIBP debe emitir logger.warning cuando falla la consulta. "
            "Sin el warning, un operador no puede saber que la verificación "
            "se está saltando silenciosamente."
        )
