"""
Endpoints de autenticación para GOATGuard API [RF-13, RF-16].

POST /auth/register  — Registro con invitation token + setup TOTP
POST /auth/login     — Login con validación de credenciales

Estos son los únicos endpoints públicos (sin JWT).
"""

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session

from src.api.auth import (
    hash_password, verify_password, create_token, verify_token_scope,
)
from src.api.dependencies import get_db, get_security_config
from src.api.registration_utils import (
    hash_invitation_token, generate_recovery_code,
    hash_recovery_code, verify_recovery_code,
    validate_password_nist, check_password_hibp,
)
from src.api.totp_utils import (
    generate_totp_secret, encrypt_secret,
    generate_totp_uri, generate_qr_png_base64,
    verify_totp_code, generate_backup_codes,
    hash_backup_code, verify_backup_code,
)
from src.api.schemas.auth_schemas import (
    RegisterRequest, RegisterResponse,
    LoginRequest, LoginStep1Response, TokenResponse,
    TotpCodeRequest, BackupCodesResponse, BackupCodeVerifyRequest,
    RecoveryVerifyRequest, RecoveryVerifyResponse,
    ResetPasswordRequest, RegenerateBackupCodesRequest,
)
from src.api.dependencies import get_current_user, get_current_user_totp_verified
from src.database.models import User, InvitationToken, TotpBackupCode

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=RegisterResponse,
             status_code=status.HTTP_201_CREATED)
def register(request: RegisterRequest, db: Session = Depends(get_db)):
    """Registra un nuevo administrador con invitation token [RF-13].

    Flujo:
    1. Valida invitation token (SHA-256 lookup)
    2. Verifica username único
    3. Valida contraseña NIST + HIBP
    4. Crea user con TOTP secret cifrado + recovery code hasheado
    5. Retorna JWT scope=pending_totp + datos para enrollment
    """
    security = get_security_config()

    # 1. Validar invitation token
    token_hash = hash_invitation_token(request.invitation_token)
    invitation = db.query(InvitationToken).filter_by(
        token_hash=token_hash,
    ).first()

    # Mensaje genérico para no revelar estado del token ni existencia de usuarios
    _REGISTER_FAIL = "No se pudo completar el registro"

    if not invitation:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=_REGISTER_FAIL)

    now = datetime.now(timezone.utc)
    if invitation.used:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=_REGISTER_FAIL)
    if invitation.expires_at.replace(tzinfo=timezone.utc) < now:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=_REGISTER_FAIL)

    # 2. Username único
    existing = db.query(User).filter_by(username=request.username).first()
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=_REGISTER_FAIL)

    # 3. Validar contraseña NIST
    is_valid, error_msg = validate_password_nist(request.password)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_msg,
        )

    # 4. HIBP check (solo si habilitado)
    if security.hibp_check_enabled:
        is_compromised = check_password_hibp(request.password)
        if is_compromised:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Contraseña comprometida en filtraciones conocidas",
            )

    # 5. Crear user
    recovery_code = generate_recovery_code()
    totp_secret = generate_totp_secret()

    user = User(
        username=request.username,
        password_hash=hash_password(request.password),
        totp_secret_enc=encrypt_secret(totp_secret, security.fernet_key),
        totp_enabled=False,
        recovery_code_hash=hash_recovery_code(recovery_code),
    )
    db.add(user)

    # 6. Marcar invitation como usada
    invitation.used = True
    invitation.used_at = now

    db.commit()
    db.refresh(user)

    # 7. Generar QR y token
    totp_uri = generate_totp_uri(totp_secret, request.username)
    qr_base64 = generate_qr_png_base64(totp_uri)
    token = create_token(
        user.id, user.username,
        scope="pending_totp", expiration_minutes=60,
    )

    logger.info("Nuevo admin registrado: %s", request.username)

    return RegisterResponse(
        access_token=token,
        username=user.username,
        recovery_code=recovery_code,
        totp_uri=totp_uri,
        qr_png_base64=qr_base64,
    )


@router.post("/login")
def login(request: LoginRequest, db: Session = Depends(get_db)):
    """Autenticación por credenciales [RF-13, RF-16].

    Si TOTP está habilitado, retorna token scope=pending_totp.
    Si no, retorna token scope=full_access (no debería ocurrir post-registro).
    """
    user = db.query(User).filter_by(username=request.username).first()

    # Timing-safe: SIEMPRE ejecutar bcrypt aunque el usuario no exista
    stored_hash = user.password_hash if user else _DUMMY_BCRYPT_HASH
    password_ok = verify_password(request.password, stored_hash)

    if not user or not password_ok:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas",
        )

    if user.totp_enabled:
        token = create_token(
            user.id, user.username,
            scope="pending_totp", expiration_minutes=10,
        )
        logger.info("Login paso 1 OK (TOTP pendiente): %s", user.username)
        return LoginStep1Response(
            access_token=token,
            username=user.username,
            totp_required=True,
            needs_enrollment=False,
        )

    # TOTP secret creado pero enrollment no completado
    if user.totp_secret_enc and user.totp_enrolled_at is None:
        token = create_token(
            user.id, user.username,
            scope="pending_totp", expiration_minutes=60,
        )
        logger.info("Login: enrollment TOTP pendiente para %s", user.username)
        return LoginStep1Response(
            access_token=token,
            username=user.username,
            totp_required=True,
            needs_enrollment=True,
        )

    # Sin TOTP (usuarios legacy pre-2FA)
    token = create_token(user.id, user.username, scope="full_access")
    logger.info("Login completo: %s", user.username)
    return TokenResponse(access_token=token, username=user.username)


# ── TOTP Endpoints [RF-13] ────────────────────────────────────────────────────


@router.post("/totp/enroll/verify", response_model=BackupCodesResponse)
def totp_enroll_verify(
    request: TotpCodeRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Verifica primer código TOTP durante enrollment y genera backup codes."""
    security = get_security_config()

    if user.totp_enrolled_at is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="TOTP ya fue configurado para este usuario",
        )

    if not user.totp_secret_enc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No hay secreto TOTP para este usuario",
        )

    if not verify_totp_code(
        user.totp_secret_enc, security.fernet_key,
        request.code, last_used_at=None,
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Código TOTP inválido",
        )

    # Enrollment exitoso
    now = datetime.now(timezone.utc)
    user.totp_enabled = True
    user.totp_enrolled_at = now
    user.totp_last_used_at = now

    # Generar backup codes
    plain_codes = generate_backup_codes(10)
    for code in plain_codes:
        db.add(TotpBackupCode(
            user_id=user.id,
            code_hash=hash_backup_code(code),
        ))

    db.commit()
    logger.info("TOTP enrollment completado: %s", user.username)

    return BackupCodesResponse(backup_codes=plain_codes)


@router.post("/totp/verify", response_model=TokenResponse)
def totp_verify(
    request: TotpCodeRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Verifica código TOTP durante login — retorna token full_access."""
    security = get_security_config()

    if not user.totp_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="TOTP no está habilitado para este usuario",
        )

    # SELECT FOR UPDATE para prevenir race condition de replay [Security Fix #7]
    user = db.query(User).filter_by(id=user.id).with_for_update().first()

    if not verify_totp_code(
        user.totp_secret_enc, security.fernet_key,
        request.code, last_used_at=user.totp_last_used_at,
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Código TOTP inválido",
        )

    user.totp_last_used_at = datetime.now(timezone.utc)
    db.commit()

    token = create_token(user.id, user.username, scope="full_access")
    logger.info("TOTP verificado: %s", user.username)

    return TokenResponse(access_token=token, username=user.username)


@router.post("/totp/verify-backup", response_model=TokenResponse)
def totp_verify_backup(
    request: BackupCodeVerifyRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Verifica backup code como alternativa a TOTP — retorna token full_access."""
    backup_codes = db.query(TotpBackupCode).filter_by(
        user_id=user.id, used=False,
    ).all()

    matched = None
    for bc in backup_codes:
        if verify_backup_code(request.backup_code, bc.code_hash):
            matched = bc
            break

    if not matched:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Código de respaldo inválido o ya utilizado",
        )

    matched.used = True
    matched.used_at = datetime.now(timezone.utc)
    db.commit()

    token = create_token(user.id, user.username, scope="full_access")
    logger.info("Backup code usado: %s", user.username)

    return TokenResponse(access_token=token, username=user.username)


# ── Recovery Endpoints [RF-13] ─────────────────────────────────────────────────

# Hash bcrypt pre-calculado para timing-safe comparison cuando el usuario no existe
_DUMMY_BCRYPT_HASH = "$2b$12$QWqoZ1ivrOIGROvjPVftmO3nlAIBsuS4AS97EmbYfUT62Jy/VwkqC"


@router.post("/recovery/verify-code", response_model=RecoveryVerifyResponse)
def recovery_verify_code(
    request: RecoveryVerifyRequest,
    db: Session = Depends(get_db),
):
    """Verifica recovery code — timing-safe, rate limited por intentos en BD."""
    user = db.query(User).filter_by(username=request.username).first()

    # SIEMPRE ejecutar bcrypt aunque el usuario no exista (timing attack prevention)
    stored_hash = user.recovery_code_hash if user else _DUMMY_BCRYPT_HASH

    if not user or user.recovery_code_used:
        verify_recovery_code(request.recovery_code, stored_hash)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Credenciales de recuperación inválidas",
        )

    if user.recovery_code_attempts >= 5:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Código bloqueado por exceso de intentos",
        )

    is_valid = verify_recovery_code(request.recovery_code, stored_hash)

    if not is_valid:
        user.recovery_code_attempts += 1
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Credenciales de recuperación inválidas",
        )

    reset_token = create_token(
        user.id, user.username,
        scope="password_reset", expiration_minutes=15,
    )
    logger.info("Recovery code verificado para: %s", user.username)

    return RecoveryVerifyResponse(reset_token=reset_token)


@router.post("/recovery/reset-password", response_model=TokenResponse)
def recovery_reset_password(
    request: ResetPasswordRequest,
    db: Session = Depends(get_db),
    credentials=Depends(HTTPBearer()),
):
    """Resetea contraseña con reset_token (scope=password_reset)."""
    payload = verify_token_scope(credentials.credentials, "password_reset")
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token de reset inválido o expirado",
        )

    user = db.query(User).filter_by(id=int(payload["sub"])).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario no encontrado",
        )

    is_valid, error_msg = validate_password_nist(request.new_password)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_msg,
        )

    security = get_security_config()
    if security.hibp_check_enabled:
        if check_password_hibp(request.new_password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Contraseña comprometida en filtraciones conocidas",
            )

    user.password_hash = hash_password(request.new_password)
    user.password_changed_at = datetime.now(timezone.utc)
    user.recovery_code_used = True
    user.recovery_code_hash = None
    user.recovery_code_attempts = 0
    db.commit()

    scope = "full_access" if user.totp_enabled else "pending_totp"
    access_token = create_token(user.id, user.username, scope=scope)
    logger.info("Contraseña reseteada para: %s", user.username)

    return TokenResponse(access_token=access_token, username=user.username)


# ── Regenerate Backup Codes [RF-13] ───────────────────────────────────────────


@router.post("/totp/regenerate-backup-codes", response_model=BackupCodesResponse)
def regenerate_backup_codes(
    request: RegenerateBackupCodesRequest,
    user: User = Depends(get_current_user_totp_verified),
    db: Session = Depends(get_db),
):
    """Regenera backup codes — requiere scope=full_access + contraseña actual."""
    if not verify_password(request.current_password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Contraseña incorrecta",
        )

    # Marcar todos los existentes como usados
    db.query(TotpBackupCode).filter_by(
        user_id=user.id, used=False,
    ).update({"used": True, "used_at": datetime.now(timezone.utc)})

    # Generar nuevos
    plain_codes = generate_backup_codes(10)
    for code in plain_codes:
        db.add(TotpBackupCode(
            user_id=user.id,
            code_hash=hash_backup_code(code),
        ))

    db.commit()
    logger.info("Backup codes regenerados para: %s", user.username)

    return BackupCodesResponse(backup_codes=plain_codes)
