"""
Tests unitarios de ``src.api.totp_utils`` [RF-13].

Validan la lógica TOTP sin depender de la BD ni del server:
- Generación y cifrado de secretos (Fernet)
- Verificación de códigos con valid_window=1
- Prevención de replay por time-step
- Generación y verificación de backup codes

Usan una clave Fernet efímera por test para aislar los casos.
"""

import base64
import re
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, ".")

import pyotp
import pytest
from cryptography.fernet import Fernet

from src.api.totp_utils import (
    decrypt_secret,
    encrypt_secret,
    generate_backup_codes,
    generate_qr_png_base64,
    generate_totp_secret,
    generate_totp_uri,
    hash_backup_code,
    verify_backup_code,
    verify_totp_code,
)


@pytest.fixture()
def fernet_key() -> str:
    """Clave Fernet efímera por test para aislar roundtrip de cifrado."""
    return Fernet.generate_key().decode()


class TestGenerateTotpSecret:
    def test_generates_base32_string(self):
        secret = generate_totp_secret()
        # pyotp usa base32 estándar: A-Z, 2-7
        assert re.fullmatch(r"[A-Z2-7]+", secret), secret

    def test_secrets_are_unique(self):
        """Dos llamadas no deben dar el mismo secreto (prob. colisión < 2^-80)."""
        secrets_set = {generate_totp_secret() for _ in range(20)}
        assert len(secrets_set) == 20


class TestEncryptDecryptSecret:
    def test_roundtrip(self, fernet_key):
        plain = "JBSWY3DPEHPK3PXP"  # Secret de ejemplo de la RFC 6238
        encrypted = encrypt_secret(plain, fernet_key)
        assert encrypted != plain  # No es plaintext
        assert decrypt_secret(encrypted, fernet_key) == plain

    def test_encryption_is_non_deterministic(self, fernet_key):
        """Fernet incluye un IV random: misma entrada → distinto ciphertext."""
        plain = "JBSWY3DPEHPK3PXP"
        c1 = encrypt_secret(plain, fernet_key)
        c2 = encrypt_secret(plain, fernet_key)
        assert c1 != c2
        assert decrypt_secret(c1, fernet_key) == plain
        assert decrypt_secret(c2, fernet_key) == plain

    def test_wrong_key_fails(self, fernet_key):
        plain = "JBSWY3DPEHPK3PXP"
        encrypted = encrypt_secret(plain, fernet_key)

        other_key = Fernet.generate_key().decode()
        with pytest.raises(Exception):
            decrypt_secret(encrypted, other_key)


class TestGenerateTotpUri:
    def test_uri_contains_issuer_and_username(self):
        secret = "JBSWY3DPEHPK3PXP"
        uri = generate_totp_uri(secret, "alice@example.com", issuer="GOATGuard")
        assert uri.startswith("otpauth://totp/")
        assert "GOATGuard" in uri
        assert "alice" in uri
        assert secret in uri


class TestGenerateQrPngBase64:
    def test_generates_non_empty_png(self):
        uri = "otpauth://totp/GOATGuard:alice?secret=JBSWY3DPEHPK3PXP&issuer=GOATGuard"
        png_b64 = generate_qr_png_base64(uri)
        raw = base64.b64decode(png_b64)
        # PNG magic number
        assert raw[:8] == b"\x89PNG\r\n\x1a\n"


class TestVerifyTotpCode:
    def test_valid_code_accepted(self, fernet_key):
        plain = generate_totp_secret()
        encrypted = encrypt_secret(plain, fernet_key)
        totp = pyotp.TOTP(plain)
        code = totp.now()

        assert verify_totp_code(encrypted, fernet_key, code, last_used_at=None) is True

    def test_invalid_code_rejected(self, fernet_key):
        plain = generate_totp_secret()
        encrypted = encrypt_secret(plain, fernet_key)

        assert verify_totp_code(encrypted, fernet_key, "000000", last_used_at=None) is False

    def test_replay_of_same_time_step_rejected(self, fernet_key):
        """Si el mismo time-step ya fue usado, un segundo intento
        con el mismo código debe rechazarse (prevención de replay)."""
        plain = generate_totp_secret()
        encrypted = encrypt_secret(plain, fernet_key)
        totp = pyotp.TOTP(plain)
        code = totp.now()

        # Primer uso: válido
        assert verify_totp_code(encrypted, fernet_key, code, last_used_at=None) is True

        # Simulamos que ya se usó hace 1 segundo (mismo time-step)
        last_used = datetime.now(timezone.utc)
        assert verify_totp_code(encrypted, fernet_key, code, last_used_at=last_used) is False

    def test_different_time_step_accepts_again(self, fernet_key):
        """Un código de un time-step distinto al último usado es válido."""
        plain = generate_totp_secret()
        encrypted = encrypt_secret(plain, fernet_key)
        totp = pyotp.TOTP(plain)
        code = totp.now()

        # last_used_at hace 5 minutos → time-step distinto
        last_used = datetime.now(timezone.utc) - timedelta(minutes=5)
        assert verify_totp_code(encrypted, fernet_key, code, last_used_at=last_used) is True

    def test_corrupted_ciphertext_returns_false(self, fernet_key):
        """Si el secret almacenado está corrupto, no explotar: devolver False."""
        assert verify_totp_code("not-a-real-token", fernet_key, "123456", None) is False


class TestGenerateBackupCodes:
    def test_default_generates_ten_codes(self):
        codes = generate_backup_codes()
        assert len(codes) == 10

    def test_codes_match_xxxx_xxxx_xxxx_format(self):
        codes = generate_backup_codes(5)
        pattern = re.compile(r"^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$")
        for code in codes:
            assert pattern.match(code), f"formato inválido: {code}"

    def test_codes_are_unique(self):
        codes = generate_backup_codes(50)
        assert len(set(codes)) == 50

    def test_charset_excludes_ambiguous_chars(self):
        """Sin O, 0, I, 1, L para evitar errores de transcripción."""
        codes = "".join(generate_backup_codes(20)).replace("-", "")
        for char in "O0I1L":
            assert char not in codes


class TestHashVerifyBackupCode:
    def test_hash_verify_roundtrip(self):
        code = "ABCD-EFGH-JKMN"
        stored = hash_backup_code(code)
        assert verify_backup_code(code, stored) is True

    def test_wrong_code_rejected(self):
        code = "ABCD-EFGH-JKMN"
        stored = hash_backup_code(code)
        assert verify_backup_code("WRONG-CODE-XXXX", stored) is False

    def test_normalization_strips_dashes_and_case(self):
        """``abcd-efgh-jkmn`` y ``ABCDEFGHJKMN`` deben verificar contra el mismo hash."""
        original = "ABCD-EFGH-JKMN"
        stored = hash_backup_code(original)
        assert verify_backup_code("abcd-efgh-jkmn", stored) is True
        assert verify_backup_code("ABCDEFGHJKMN", stored) is True
