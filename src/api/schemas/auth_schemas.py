"""
Schemas Pydantic para endpoints de autenticación [RF-13, RF-16].
"""

from pydantic import BaseModel, Field


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=15, max_length=128)
    invitation_token: str


class RegisterResponse(BaseModel):
    """
    Respuesta al registro. recovery_code y totp_uri se muestran UNA SOLA VEZ.
    El backend no vuelve a enviarlos — el frontend debe guardarlos o mostrarlos.
    """
    access_token: str
    token_type: str = "bearer"
    username: str
    recovery_code: str
    totp_uri: str
    qr_png_base64: str


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginStep1Response(BaseModel):
    """Login con password OK, TOTP pendiente."""
    access_token: str
    token_type: str = "bearer"
    username: str
    totp_required: bool = True
    needs_enrollment: bool = False


class TokenResponse(BaseModel):
    """Acceso completo concedido (después de TOTP verificado)."""
    access_token: str
    token_type: str = "bearer"
    username: str


class TotpCodeRequest(BaseModel):
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class BackupCodesResponse(BaseModel):
    backup_codes: list[str]


class BackupCodeVerifyRequest(BaseModel):
    backup_code: str = Field(min_length=14, max_length=14)


class RecoveryVerifyRequest(BaseModel):
    username: str
    recovery_code: str = Field(min_length=19, max_length=19)


class RecoveryVerifyResponse(BaseModel):
    reset_token: str


class ResetPasswordRequest(BaseModel):
    new_password: str = Field(min_length=15, max_length=128)


class RegenerateBackupCodesRequest(BaseModel):
    current_password: str
