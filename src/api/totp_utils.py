"""
Utilidades TOTP para autenticación de dos factores [RF-13].
Compatible con Google Authenticator y Microsoft Authenticator (RFC 6238).
"""

import base64
import io
import secrets
from datetime import datetime, timezone
from typing import Optional

import bcrypt
import pyotp
import qrcode
from cryptography.fernet import Fernet, InvalidToken

# Charset sin caracteres ambiguos (O, 0, I, 1, l) para legibilidad
_BACKUP_CHARSET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
_BACKUP_CODE_SEGMENT_LEN = 4
_BACKUP_CODE_SEGMENTS = 3


def generate_totp_secret() -> str:
    """Genera secreto base32 compatible con authenticators estándar."""
    return pyotp.random_base32()


def encrypt_secret(plain_secret: str, fernet_key: str) -> str:
    """
    Cifra el secreto TOTP con Fernet (AES-128-CBC + HMAC-SHA256).
    El secreto NO puede hashearse — debe ser recuperable para verificar códigos.
    """
    f = Fernet(fernet_key.encode())
    return f.encrypt(plain_secret.encode()).decode()


def decrypt_secret(encrypted_secret: str, fernet_key: str) -> str:
    """Descifra el secreto TOTP. Lanza InvalidToken si la clave es incorrecta."""
    f = Fernet(fernet_key.encode())
    return f.decrypt(encrypted_secret.encode()).decode()


def generate_totp_uri(
    secret: str, username: str, issuer: str = "GOATGuard",
) -> str:
    """Genera URI otpauth://totp/... para el QR code."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=issuer)


def generate_qr_png_base64(uri: str) -> str:
    """Genera PNG del QR code en base64 para enviar al frontend."""
    img = qrcode.make(uri)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    return base64.b64encode(buffer.getvalue()).decode()


def verify_totp_code(
    encrypted_secret: str,
    fernet_key: str,
    code: str,
    last_used_at: Optional[datetime],
) -> bool:
    """
    Verifica código TOTP de 6 dígitos.
    - valid_window=1: acepta +/-30s para compensar drift de reloj
    - Previene replay: rechaza código del mismo time-step si ya fue usado
    """
    try:
        secret = decrypt_secret(encrypted_secret, fernet_key)
    except InvalidToken:
        return False

    totp = pyotp.TOTP(secret)
    if not totp.verify(code, valid_window=1):
        return False

    # Prevención replay: comparar time-step actual con el del último uso
    if last_used_at is not None:
        now_step = int(datetime.now(timezone.utc).timestamp()) // 30
        last_step = int(last_used_at.timestamp()) // 30
        if now_step == last_step:
            return False

    return True


def generate_backup_codes(count: int = 10) -> list[str]:
    """
    Genera códigos de respaldo en formato XXXX-XXXX-XXXX.
    Entropía: ~60 bits por código. Sin caracteres ambiguos.
    """
    codes = []
    for _ in range(count):
        segments = [
            "".join(
                secrets.choice(_BACKUP_CHARSET)
                for _ in range(_BACKUP_CODE_SEGMENT_LEN)
            )
            for _ in range(_BACKUP_CODE_SEGMENTS)
        ]
        codes.append("-".join(segments))
    return codes


def hash_backup_code(plain_code: str) -> str:
    """Hash bcrypt de un código de respaldo para almacenamiento seguro."""
    normalized = plain_code.replace("-", "").upper().encode()
    return bcrypt.hashpw(normalized, bcrypt.gensalt()).decode()


def verify_backup_code(plain_code: str, stored_hash: str) -> bool:
    """Verifica un código de respaldo contra su hash bcrypt."""
    normalized = plain_code.replace("-", "").upper().encode()
    return bcrypt.checkpw(normalized, stored_hash.encode())
