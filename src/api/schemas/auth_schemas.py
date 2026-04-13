"""
Schemas Pydantic para el flujo de autenticación 2FA [RF-13, RF-16].

Las constraints declarativas (``min_length``, ``max_length``, ``pattern``)
rechazan requests mal formados en la capa de serialización, antes de
llegar a la lógica del endpoint. Esto simplifica los handlers y asegura
que los tests contra la API validen comportamiento, no formato.
"""

from typing import Optional

from pydantic import BaseModel, Field


class RegisterRequest(BaseModel):
    """Registro de un nuevo usuario mediante invitation token.

    Password con ventana NIST SP 800-63B: mínimo 15, máximo 128 chars.
    invitation_token es opcional: si la BD tiene 0 usuarios (bootstrap),
    se permite registro sin token. A partir del segundo usuario, se requiere.
    """

    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=15, max_length=128)
    invitation_token: Optional[str] = None


class BootstrapStatusResponse(BaseModel):
    """Estado de bootstrap del sistema."""

    needs_bootstrap: bool


class InvitationResponse(BaseModel):
    """Token de invitación generado por un admin."""

    invitation_token: str
    expires_at: str


class RegisterResponse(BaseModel):
    """Respuesta al registro exitoso.

    ``recovery_code``, ``totp_uri`` y ``qr_png_base64`` se muestran
    UNA SOLA VEZ. El backend no los devuelve en ninguna otra request:
    el frontend debe guardarlos (recovery code) o mostrarlos inmediatamente
    al usuario para enrollment en el authenticator.
    """

    access_token: str
    token_type: str = "bearer"
    username: str
    recovery_code: str
    totp_uri: str
    qr_png_base64: str


class LoginRequest(BaseModel):
    """Primer paso del login: credenciales básicas.

    No validamos longitud de ``password`` — aceptamos el input tal cual
    para que la verificación ocurra contra el hash bcrypt. Si en el futuro
    endurecemos las reglas NIST, los usuarios existentes con passwords
    más cortos siguen pudiendo autenticarse.
    """

    username: str
    password: str


class LoginStep1Response(BaseModel):
    """Respuesta tras password OK cuando queda pendiente el TOTP.

    El token devuelto tiene scope ``pending_totp`` — solo habilita los
    endpoints del segundo factor, no la API de negocio.
    """

    access_token: str
    token_type: str = "bearer"
    username: str
    totp_required: bool = True
    needs_enrollment: bool = False


class TokenResponse(BaseModel):
    """Acceso completo concedido tras verificar el segundo factor."""

    access_token: str
    token_type: str = "bearer"
    username: str


class TotpCodeRequest(BaseModel):
    """Código TOTP de 6 dígitos emitido por el authenticator.

    La regex ``^\\d{6}$`` descarta cualquier input alfanumérico antes
    de llegar a ``pyotp.verify``, lo que evita ruido en métricas de
    intentos fallidos.
    """

    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class BackupCodesResponse(BaseModel):
    """Lista de backup codes recién generados.

    Se devuelven en claro una única vez (inmediatamente tras enrollment
    o regeneración). El backend solo persiste hashes bcrypt.
    """

    backup_codes: list[str]


class BackupCodeVerifyRequest(BaseModel):
    """Verificación de un backup code en formato ``XXXX-XXXX-XXXX``.

    14 chars = 12 alfanuméricos + 2 guiones. La normalización (strip de
    guiones, uppercase) ocurre en ``verify_backup_code``.
    """

    backup_code: str = Field(min_length=14, max_length=14)


class RecoveryVerifyRequest(BaseModel):
    """Verificación del recovery code para iniciar reset de password.

    Formato ``XXXX-XXXX-XXXX-XXXX`` = 19 chars (16 alfanuméricos + 3 guiones).
    """

    username: str
    recovery_code: str = Field(min_length=19, max_length=19)


class RecoveryVerifyResponse(BaseModel):
    """Token corto con scope ``password_reset`` para consumir una vez."""

    reset_token: str


class ResetPasswordRequest(BaseModel):
    """Nuevo password tras flujo de recovery.

    Misma ventana NIST que en registro: 15-128 chars.
    """

    new_password: str = Field(min_length=15, max_length=128)


class RegenerateBackupCodesRequest(BaseModel):
    """Regeneración manual de backup codes autenticada por password actual."""

    current_password: str
