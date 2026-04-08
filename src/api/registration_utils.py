"""
Utilidades de registro: invitation tokens, recovery codes y validación
de contraseñas según NIST SP 800-63B Rev. 4 (2025) [RF-13].

También implementa la verificación HaveIBeenPwned con k-anonymity:
solo se envían los primeros 5 caracteres del SHA-1 del password, por
lo que el servicio externo nunca recibe el password completo.
"""

import hashlib
import logging
import secrets
from typing import Optional

import bcrypt
import httpx

logger = logging.getLogger(__name__)

# Charset sin caracteres ambiguos para recovery codes (O, 0, I, 1, L)
_RECOVERY_CHARSET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"


def generate_invitation_token() -> str:
    """Genera token de invitación URL-safe de 32 bytes (~43 chars base64)."""
    return secrets.token_urlsafe(32)


def hash_invitation_token(plain_token: str) -> str:
    """SHA-256 del token plano.

    No necesita bcrypt: la entropía del token (256 bits) hace imposible
    un ataque de fuerza bruta, y SHA-256 permite lookup O(1) en BD.
    """
    return hashlib.sha256(plain_token.encode()).hexdigest()


def generate_recovery_code() -> str:
    """Genera código de recuperación ``XXXX-XXXX-XXXX-XXXX``.

    Entropía: ~80 bits (16 chars * 4.95 bits/caracter). Sin caracteres
    ambiguos para reducir errores al transcribir desde papel.
    """
    segments = [
        "".join(secrets.choice(_RECOVERY_CHARSET) for _ in range(4))
        for _ in range(4)
    ]
    return "-".join(segments)


def hash_recovery_code(plain_code: str) -> str:
    """Hash bcrypt del recovery code normalizado (sin guiones, uppercase)."""
    normalized = plain_code.replace("-", "").upper().encode()
    return bcrypt.hashpw(normalized, bcrypt.gensalt()).decode()


def verify_recovery_code(plain_code: str, stored_hash: str) -> bool:
    """Verifica recovery code contra hash bcrypt. Constant-time."""
    normalized = plain_code.replace("-", "").upper().encode()
    return bcrypt.checkpw(normalized, stored_hash.encode())


def validate_password_nist(password: str) -> tuple[bool, Optional[str]]:
    """Valida un password según NIST SP 800-63B Rev. 4 (2025).

    NIST abandonó las reglas de complejidad forzadas (mayúsculas, símbolos,
    etc.) en la revisión de 2017 y las reafirmó en 2025. El único requisito
    es longitud mínima. La única validación aquí es longitud: la verificación
    contra passwords comprometidos se hace aparte vía HIBP.
    """
    if len(password) < 15:
        return False, "La contraseña debe tener al menos 15 caracteres"
    if len(password) > 128:
        return False, "La contraseña no puede exceder 128 caracteres"
    return True, None


def check_password_hibp(password: str) -> bool:
    """Verifica si el password aparece en HaveIBeenPwned.

    Usa k-anonymity (RFC-adjacent): se envían solo los primeros 5 chars
    del SHA-1, el servicio devuelve todas las suffixes que matchean y
    el cliente compara localmente. El password completo nunca sale del
    server.

    Retorna ``True`` si está comprometido.

    **Fail-open intencional**: si la API no responde (red LAN aislada,
    timeout, DNS down), esta función retorna ``False`` pero emite un
    ``logger.warning`` prominente. Convertir HIBP en fail-closed haría
    del servicio externo una dependencia de disponibilidad crítica, lo
    que es peor que aceptar temporalmente un registro no auditado en un
    entorno donde los admins ya tienen invitation token. El warning
    permite al operador detectar que la verificación está caída.
    """
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        resp = httpx.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            timeout=5.0,
        )
    except httpx.RequestError as exc:
        logger.warning(
            "HIBP check fail-open: no se pudo consultar pwnedpasswords.com "
            "(%s). El registro continuará sin verificación de compromiso. "
            "Revisar conectividad si esto se repite.",
            exc,
        )
        return False

    if resp.status_code != 200:
        logger.warning(
            "HIBP check fail-open: pwnedpasswords.com respondió HTTP %s. "
            "El registro continuará sin verificación.",
            resp.status_code,
        )
        return False

    # La respuesta tiene formato "SUFFIX:count\nSUFFIX:count\n..."
    for line in resp.text.splitlines():
        candidate = line.split(":", 1)[0].strip()
        if candidate == suffix:
            return True
    return False
