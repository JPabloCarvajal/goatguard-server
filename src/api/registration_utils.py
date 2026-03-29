"""
Utilidades de registro: invitation tokens, validación NIST, recovery codes [RF-13].
"""

import hashlib
import secrets
from typing import Optional

import bcrypt
import httpx

# Charset sin caracteres ambiguos para recovery codes
_RECOVERY_CHARSET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"


def generate_invitation_token() -> str:
    """Genera token de invitación URL-safe de 32 bytes."""
    return secrets.token_urlsafe(32)


def hash_invitation_token(plain_token: str) -> str:
    """SHA-256 del token. No necesita bcrypt: la entropía del token es suficiente."""
    return hashlib.sha256(plain_token.encode()).hexdigest()


def generate_recovery_code() -> str:
    """
    Genera código de recuperación XXXX-XXXX-XXXX-XXXX.
    Entropía: ~80 bits (16 chars x ~4.95 bits/char del charset de 31 símbolos).
    Sin caracteres que puedan confundirse al transcribir (O, 0, I, 1).
    """
    segments = [
        "".join(secrets.choice(_RECOVERY_CHARSET) for _ in range(4))
        for _ in range(4)
    ]
    return "-".join(segments)


def hash_recovery_code(plain_code: str) -> str:
    """Hash bcrypt del código de recuperación normalizado (sin guiones, uppercase)."""
    normalized = plain_code.replace("-", "").upper().encode()
    return bcrypt.hashpw(normalized, bcrypt.gensalt()).decode()


def verify_recovery_code(plain_code: str, stored_hash: str) -> bool:
    """Verifica código de recuperación contra hash almacenado."""
    normalized = plain_code.replace("-", "").upper().encode()
    return bcrypt.checkpw(normalized, stored_hash.encode())


def validate_password_nist(password: str) -> tuple[bool, Optional[str]]:
    """
    Valida contraseña según NIST SP 800-63B Rev. 4 (2025).
    Sin reglas de complejidad forzadas — solo longitud.
    Retorna (válida, mensaje_error).
    """
    if len(password) < 15:
        return False, "La contraseña debe tener al menos 15 caracteres"
    if len(password) > 128:
        return False, "La contraseña no puede exceder 128 caracteres"
    return True, None


def check_password_hibp(password: str) -> bool:
    """
    Verifica si la contraseña aparece en HaveIBeenPwned.
    Usa k-anonymity: solo se envían los primeros 5 chars del hash SHA-1.
    Retorna True si la contraseña está comprometida.
    """
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        resp = httpx.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            timeout=5.0,
        )
        return suffix in resp.text
    except httpx.RequestError:
        # Si HIBP no está disponible (red LAN sin internet), no bloquear
        return False
