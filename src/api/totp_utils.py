"""
Utilidades TOTP para autenticación de dos factores [RF-13].

Implementa el flujo completo de segundo factor compatible con Google
Authenticator, Microsoft Authenticator y cualquier cliente RFC 6238:

- Generación de secretos aleatorios en base32
- Cifrado de los secretos con Fernet (AES-128-CBC + HMAC-SHA256) — NO
  se hashean porque deben ser recuperables para verificar códigos
- URIs ``otpauth://`` para provisioning
- QR code en PNG/base64 listo para embebber en el frontend
- Verificación de códigos con tolerancia de ±30s (``valid_window=1``)
- Prevención de replay por time-step (anti-race en endpoints concurrentes)
- Backup codes en formato XXXX-XXXX-XXXX con charset sin caracteres
  ambiguos (O, 0, I, 1, L) y hash bcrypt para almacenamiento
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

# Charset sin caracteres ambiguos (O, 0, I, 1, L) para legibilidad en
# pantalla/papel. 31 símbolos → ~4.95 bits por caracter.
_BACKUP_CHARSET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
_BACKUP_CODE_SEGMENT_LEN = 4
_BACKUP_CODE_SEGMENTS = 3


def generate_totp_secret() -> str:
    """Genera secreto base32 compatible con authenticators estándar."""
    return pyotp.random_base32()


def encrypt_secret(plain_secret: str, fernet_key: str) -> str:
    """Cifra el secreto TOTP con Fernet (AES-128-CBC + HMAC-SHA256).

    El secreto NO puede hashearse — debe ser recuperable para verificar
    códigos en cada login. Fernet incluye IV aleatorio, por lo que dos
    cifrados del mismo plaintext producen ciphertexts distintos.
    """
    f = Fernet(fernet_key.encode())
    return f.encrypt(plain_secret.encode()).decode()


def decrypt_secret(encrypted_secret: str, fernet_key: str) -> str:
    """Descifra el secreto TOTP. Lanza ``InvalidToken`` si la clave es incorrecta."""
    f = Fernet(fernet_key.encode())
    return f.decrypt(encrypted_secret.encode()).decode()


def generate_totp_uri(
    secret: str,
    username: str,
    issuer: str = "GOATGuard",
) -> str:
    """Genera URI ``otpauth://totp/...`` para provisioning via QR."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=issuer)


def generate_qr_png_base64(uri: str) -> str:
    """Renderiza el URI como PNG base64 listo para embeber en el frontend."""
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
    """Verifica un código TOTP de 6 dígitos.

    - ``valid_window=1`` acepta ±30s para compensar drift de reloj entre
      el dispositivo del usuario y el servidor.
    - Si ``last_used_at`` cae en el mismo time-step de 30s que ahora,
      el código se rechaza para bloquear replays del mismo token válido
      (concurrencia entre dos requests legítimos o ataque activo).
    - Si el ciphertext está corrupto o la clave es inválida, retorna
      ``False`` en lugar de propagar la excepción — el caller es un
      endpoint HTTP y un 500 por un secret dañado sería peor que un 401.
    """
    try:
        secret = decrypt_secret(encrypted_secret, fernet_key)
    except InvalidToken:
        return False

    totp = pyotp.TOTP(secret)
    if not totp.verify(code, valid_window=1):
        return False

    # Prevención de replay: comparar time-step actual con el del último uso
    if last_used_at is not None:
        now_step = int(datetime.now(timezone.utc).timestamp()) // 30
        last_step = int(last_used_at.timestamp()) // 30
        if now_step == last_step:
            return False

    return True


def generate_backup_codes(count: int = 10) -> list[str]:
    """Genera ``count`` códigos de respaldo en formato ``XXXX-XXXX-XXXX``.

    Entropía: ~60 bits por código (12 caracteres * 4.95 bits/caracter).
    Charset diseñado para transcripción manual sin errores.
    """
    codes: list[str] = []
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
    """Hash bcrypt de un backup code para almacenamiento seguro.

    La normalización (sin guiones, uppercase) permite que el usuario
    escriba el código con o sin guiones, en mayúsculas o minúsculas.
    """
    normalized = plain_code.replace("-", "").upper().encode()
    return bcrypt.hashpw(normalized, bcrypt.gensalt()).decode()


def verify_backup_code(plain_code: str, stored_hash: str) -> bool:
    """Verifica un backup code contra su hash bcrypt. Constant-time."""
    normalized = plain_code.replace("-", "").upper().encode()
    return bcrypt.checkpw(normalized, stored_hash.encode())
