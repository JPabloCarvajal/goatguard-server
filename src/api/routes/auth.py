"""
Endpoints de autenticación con 2FA TOTP [RF-13, RF-16].

Flujo completo:
    POST /auth/register            — Registro con invitation token + setup TOTP
    POST /auth/login               — Paso 1: credenciales (devuelve pending_totp)
    POST /auth/totp/enroll/verify  — Verifica primer TOTP → genera backup codes
    POST /auth/totp/verify         — Paso 2: TOTP → devuelve full_access
    POST /auth/totp/verify-backup  — Paso 2 alternativo con backup code
    POST /auth/recovery/verify-code — Valida recovery code → devuelve reset_token
    POST /auth/recovery/reset-password — Cambia password con reset_token
    POST /auth/totp/regenerate-backup-codes — Regenera codes (scope=full_access)

Rate limiting con slowapi sobre todos los endpoints sensibles para
mitigar ataques de fuerza bruta y enumeración.
"""

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session

from src.api.auth import (
    create_token,
    hash_password,
    verify_password,
    verify_token_scope,
)
from src.api.dependencies import (
    get_current_user_pending_totp,
    get_current_user_totp_verified,
    get_db,
    get_security_config,
)
from src.api.rate_limit import limiter
from src.api.registration_utils import (
    check_password_hibp,
    generate_recovery_code,
    hash_invitation_token,
    hash_recovery_code,
    validate_password_nist,
    verify_recovery_code,
)
from src.api.schemas.auth_schemas import (
    BackupCodeVerifyRequest,
    BackupCodesResponse,
    LoginRequest,
    LoginStep1Response,
    RecoveryVerifyRequest,
    RecoveryVerifyResponse,
    RegenerateBackupCodesRequest,
    RegisterRequest,
    RegisterResponse,
    ResetPasswordRequest,
    TokenResponse,
    TotpCodeRequest,
)
from src.api.totp_utils import (
    encrypt_secret,
    generate_backup_codes,
    generate_qr_png_base64,
    generate_totp_secret,
    generate_totp_uri,
    hash_backup_code,
    verify_backup_code,
    verify_totp_code,
)
from src.database.models import InvitationToken, TotpBackupCode, User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication"])

# Mensajes genéricos para no filtrar estado interno via diferencias de respuesta
_REGISTER_FAIL = "No se pudo completar el registro"
_LOGIN_FAIL = "Credenciales inválidas"
_RECOVERY_FAIL = "Credenciales de recuperación inválidas"

# Hash bcrypt pre-calculado para timing-safe comparison cuando el usuario no
# existe. Sin esto, el timing del endpoint revela si el username es real
# (no invoca bcrypt) vs inválido (sí lo invoca).
_DUMMY_BCRYPT_HASH = (
    "$2b$12$QWqoZ1ivrOIGROvjPVftmO3nlAIBsuS4AS97EmbYfUT62Jy/VwkqC"
)


# ── Registro ──────────────────────────────────────────────────────────────────


@router.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
)
@limiter.limit("5/minute")
def register(
    request: Request,
    body: RegisterRequest,
    db: Session = Depends(get_db),
):
    """Registra un nuevo administrador con invitation token [RF-13].

    Rate limit: 5/minute para limitar enumeración de invitation tokens.

    Flujo:
    1. Invitation token válido (SHA-256 lookup, no usado, no expirado).
    2. Username no existente.
    3. Password cumple NIST + no aparece en HIBP (si está habilitado).
    4. Genera TOTP secret (cifrado) y recovery code (hash bcrypt).
    5. Marca invitation como usada atómicamente.
    6. Emite JWT scope=pending_totp para completar enrollment.
    """
    security = get_security_config()

    token_hash = hash_invitation_token(body.invitation_token)
    invitation = db.query(InvitationToken).filter_by(
        token_hash=token_hash,
    ).first()

    if not invitation:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=_REGISTER_FAIL,
        )

    now = datetime.now(timezone.utc)
    if invitation.used:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=_REGISTER_FAIL,
        )
    expires_at = invitation.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at < now:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=_REGISTER_FAIL,
        )

    existing = db.query(User).filter_by(username=body.username).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=_REGISTER_FAIL,
        )

    is_valid, error_msg = validate_password_nist(body.password)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=error_msg,
        )

    if security is not None and security.hibp_check_enabled:
        if check_password_hibp(body.password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Contraseña comprometida en filtraciones conocidas",
            )

    recovery_code = generate_recovery_code()
    totp_secret = generate_totp_secret()

    user = User(
        username=body.username,
        password_hash=hash_password(body.password),
        totp_secret_enc=encrypt_secret(totp_secret, security.fernet_key),
        totp_enabled=False,
        recovery_code_hash=hash_recovery_code(recovery_code),
    )
    db.add(user)

    invitation.used = True
    invitation.used_at = now

    db.commit()
    db.refresh(user)

    totp_uri = generate_totp_uri(totp_secret, body.username)
    qr_base64 = generate_qr_png_base64(totp_uri)
    token = create_token(
        user.id,
        user.username,
        scope="pending_totp",
        expiration_minutes=60,
    )

    logger.info("Nuevo admin registrado: %s", body.username)

    return RegisterResponse(
        access_token=token,
        username=user.username,
        recovery_code=recovery_code,
        totp_uri=totp_uri,
        qr_png_base64=qr_base64,
    )


# ── Login paso 1 ──────────────────────────────────────────────────────────────


@router.post("/login")
@limiter.limit("10/minute")
def login(
    request: Request,
    body: LoginRequest,
    db: Session = Depends(get_db),
):
    """Autenticación por credenciales — paso 1 del flujo 2FA [RF-13].

    Rate limit: 10/minute por IP para mitigar fuerza bruta sin romper
    usuarios legítimos que fallan el primer intento.

    Timing-safe: ejecuta bcrypt aunque el usuario no exista, usando un
    hash dummy pre-calculado. Sin esto, el atacante distingue usuarios
    válidos midiendo el tiempo de respuesta (bcrypt tarda ~100ms).
    """
    user = db.query(User).filter_by(username=body.username).first()

    stored_hash = user.password_hash if user else _DUMMY_BCRYPT_HASH
    password_ok = verify_password(body.password, stored_hash)

    if not user or not password_ok:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=_LOGIN_FAIL,
        )

    if user.totp_enabled:
        token = create_token(
            user.id,
            user.username,
            scope="pending_totp",
            expiration_minutes=10,
        )
        logger.info("Login paso 1 OK (TOTP pendiente): %s", user.username)
        return LoginStep1Response(
            access_token=token,
            username=user.username,
            totp_required=True,
            needs_enrollment=False,
        )

    # Usuario con secret generado pero enrollment incompleto
    if user.totp_secret_enc and user.totp_enrolled_at is None:
        token = create_token(
            user.id,
            user.username,
            scope="pending_totp",
            expiration_minutes=60,
        )
        logger.info(
            "Login paso 1 OK (enrollment TOTP pendiente): %s", user.username,
        )
        return LoginStep1Response(
            access_token=token,
            username=user.username,
            totp_required=True,
            needs_enrollment=True,
        )

    # Fallback para usuarios legacy pre-2FA (no debería ocurrir en deploys nuevos)
    token = create_token(user.id, user.username, scope="full_access")
    logger.info("Login completo (legacy sin TOTP): %s", user.username)
    return TokenResponse(access_token=token, username=user.username)


# ── TOTP endpoints ────────────────────────────────────────────────────────────


@router.post("/totp/enroll/verify", response_model=BackupCodesResponse)
@limiter.limit("5/minute")
def totp_enroll_verify(
    request: Request,
    body: TotpCodeRequest,
    user: User = Depends(get_current_user_pending_totp),
    db: Session = Depends(get_db),
):
    """Verifica el primer código TOTP del enrollment y emite backup codes.

    Rate limit: 5/minute — el atacante ya tiene un JWT pending_totp, pero
    limitamos intentos brute-force sobre el primer código.
    """
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
        user.totp_secret_enc,
        security.fernet_key,
        body.code,
        last_used_at=None,
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Código TOTP inválido",
        )

    now = datetime.now(timezone.utc)
    user.totp_enabled = True
    user.totp_enrolled_at = now
    user.totp_last_used_at = now

    plain_codes = generate_backup_codes(10)
    for code in plain_codes:
        db.add(
            TotpBackupCode(user_id=user.id, code_hash=hash_backup_code(code))
        )

    db.commit()
    logger.info("TOTP enrollment completado: %s", user.username)

    return BackupCodesResponse(backup_codes=plain_codes)


@router.post("/totp/verify", response_model=TokenResponse)
@limiter.limit("10/minute")
def totp_verify(
    request: Request,
    body: TotpCodeRequest,
    user: User = Depends(get_current_user_pending_totp),
    db: Session = Depends(get_db),
):
    """Verifica el código TOTP del segundo paso de login.

    Usa ``SELECT FOR UPDATE`` para prevenir que dos requests concurrentes
    con el mismo código válido pasen ambas (race de replay). En SQLite
    el lock es no-op, pero en Postgres bloquea la fila hasta el commit.
    """
    security = get_security_config()

    if not user.totp_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="TOTP no está habilitado para este usuario",
        )

    user = (
        db.query(User).filter_by(id=user.id).with_for_update().first()
    )

    if not verify_totp_code(
        user.totp_secret_enc,
        security.fernet_key,
        body.code,
        last_used_at=user.totp_last_used_at,
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
@limiter.limit("5/minute")
def totp_verify_backup(
    request: Request,
    body: BackupCodeVerifyRequest,
    user: User = Depends(get_current_user_pending_totp),
    db: Session = Depends(get_db),
):
    """Verifica un backup code como alternativa al TOTP.

    Cada backup code se invalida tras usarse (``used=True``) — one-shot.
    """
    backup_codes = (
        db.query(TotpBackupCode)
        .filter_by(user_id=user.id, used=False)
        .all()
    )

    matched = None
    for bc in backup_codes:
        if verify_backup_code(body.backup_code, bc.code_hash):
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
    logger.info("Backup code consumido: %s", user.username)

    return TokenResponse(access_token=token, username=user.username)


# ── Recovery endpoints ────────────────────────────────────────────────────────


@router.post("/recovery/verify-code", response_model=RecoveryVerifyResponse)
@limiter.limit("5/minute")
def recovery_verify_code(
    request: Request,
    body: RecoveryVerifyRequest,
    db: Session = Depends(get_db),
):
    """Verifica recovery code — timing-safe + contador de intentos en BD.

    El flujo de recovery NO usa un JWT previo (el usuario olvidó el
    password). El rate limit por IP + el contador por usuario (5 intentos
    máx antes de bloquear) mitigan brute-force sobre el código de 19 chars.
    """
    user = db.query(User).filter_by(username=body.username).first()

    stored_hash = user.recovery_code_hash if user else _DUMMY_BCRYPT_HASH

    if not user or user.recovery_code_used or stored_hash is None:
        # Ejecutamos verify aunque falle para no filtrar estado por timing
        if stored_hash:
            verify_recovery_code(body.recovery_code, stored_hash)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=_RECOVERY_FAIL,
        )

    if user.recovery_code_attempts >= 5:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Código bloqueado por exceso de intentos",
        )

    is_valid = verify_recovery_code(body.recovery_code, stored_hash)
    if not is_valid:
        user.recovery_code_attempts += 1
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=_RECOVERY_FAIL,
        )

    reset_token = create_token(
        user.id,
        user.username,
        scope="password_reset",
        expiration_minutes=15,
    )
    logger.info("Recovery code verificado: %s", user.username)

    return RecoveryVerifyResponse(reset_token=reset_token)


@router.post("/recovery/reset-password", response_model=TokenResponse)
@limiter.limit("5/minute")
def recovery_reset_password(
    request: Request,
    body: ResetPasswordRequest,
    db: Session = Depends(get_db),
    credentials=Depends(HTTPBearer()),
):
    """Cambia password usando un reset_token con scope=password_reset.

    Efectos colaterales en commit:
    - ``password_hash`` actualizado con nuevo bcrypt.
    - ``password_changed_at`` = now → invalida JWTs emitidos antes.
    - ``recovery_code_used`` = True, ``recovery_code_hash`` = None →
      previene reutilización del mismo código.
    - ``recovery_code_attempts`` = 0 → resetea el contador anti-brute.
    """
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

    is_valid, error_msg = validate_password_nist(body.new_password)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=error_msg,
        )

    security = get_security_config()
    if security is not None and security.hibp_check_enabled:
        if check_password_hibp(body.new_password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Contraseña comprometida en filtraciones conocidas",
            )

    user.password_hash = hash_password(body.new_password)
    user.password_changed_at = datetime.now(timezone.utc)
    user.recovery_code_used = True
    user.recovery_code_hash = None
    user.recovery_code_attempts = 0
    db.commit()

    scope = "full_access" if user.totp_enabled else "pending_totp"
    access_token = create_token(user.id, user.username, scope=scope)
    logger.info("Password reseteada: %s", user.username)

    return TokenResponse(access_token=access_token, username=user.username)


# ── Regenerate backup codes ───────────────────────────────────────────────────


@router.post(
    "/totp/regenerate-backup-codes",
    response_model=BackupCodesResponse,
)
@limiter.limit("3/minute")
def regenerate_backup_codes(
    request: Request,
    body: RegenerateBackupCodesRequest,
    user: User = Depends(get_current_user_totp_verified),
    db: Session = Depends(get_db),
):
    """Regenera los backup codes — requiere scope=full_access + password actual.

    Marca los existentes como usados y crea 10 nuevos. Re-auth por
    password evita que alguien con un token robado regenere codes.
    """
    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Contraseña incorrecta",
        )

    db.query(TotpBackupCode).filter_by(
        user_id=user.id, used=False,
    ).update(
        {"used": True, "used_at": datetime.now(timezone.utc)}
    )

    plain_codes = generate_backup_codes(10)
    for code in plain_codes:
        db.add(
            TotpBackupCode(user_id=user.id, code_hash=hash_backup_code(code))
        )

    db.commit()
    logger.info("Backup codes regenerados: %s", user.username)

    return BackupCodesResponse(backup_codes=plain_codes)
