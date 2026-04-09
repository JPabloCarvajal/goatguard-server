"""
Tests de regresión para el sistema de migraciones Alembic de GOATGuard.

Para qué sirven:
    Verifican que la cadena de migraciones produce exactamente el esquema
    que describe el ORM: ni más tablas, ni menos, ni columnas fantasma.
    Son tests de regresión: si alguien toca un migration script o los
    modelos sin actualizar el otro lado, estos tests lo detectan.

Por qué SQLite con archivo tmpfile en lugar de :memory::
    Alembic abre y cierra su propia conexión internamente. Si usáramos
    :memory:, la BD desaparecería en cuanto Alembic cerrara su conexión
    y el inspector del test vería una BD vacía. El tmpfile de pytest
    (``tmp_path``) persiste durante la ejecución del test y se limpia
    automáticamente al terminar, sin necesidad de teardown manual.

Por qué la API Python de Alembic en lugar de subprocess:
    ``subprocess.run(["alembic", "upgrade", "head"])`` depende del CWD,
    de que el virtualenv esté activo y del PATH. La API Python (``from
    alembic import command``) es determinista: recibe un ``Config``
    programático con ``script_location`` y ``sqlalchemy.url`` explícitos,
    por lo que los tests son herméticos y portables entre entornos CI/CD.

RF cubiertos: RF-05 (esquema de BD), RF-13 (tablas y columnas 2FA).
Commit C7 — Phase 2 RED.
"""

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

from src.database.models import Base

# ---------------------------------------------------------------------------
# Constantes de rutas — resueltas desde la ubicación de este archivo para
# que los tests funcionen independientemente del CWD al invocar pytest.
# ---------------------------------------------------------------------------

ALEMBIC_INI = Path(__file__).parent.parent / "alembic.ini"
SCRIPT_LOCATION = Path(__file__).parent.parent / "alembic"

# ---------------------------------------------------------------------------
# Nombres de tabla esperados — hardcoded intencionalmente.
#
# NO derivar esta lista de Base.metadata.tables.keys() aquí: si alguien
# rompe los modelos (borra una tabla del ORM), queremos que el test falle
# para actuar como guardrail de regresión. La comparación contra el ORM
# se hace por separado en test_upgrade_chain_matches_metadata.
# ---------------------------------------------------------------------------

_EXPECTED_TABLES: frozenset[str] = frozenset(
    {
        "recent_connection",
        "network",
        "device",
        "agent",
        "network_snapshot",
        "endpoint_snapshot",
        "top_talker",
        "alert",
        "user",
        "invitation_token",
        "totp_backup_code",
        "session",
        "push_token",
        "network_current_metrics",
        "device_current_metrics",
        "top_talker_current",
        "ml_prediction",
        "insight",
    }
)

# Columnas que el baseline 000_initial_schema debe crear en la tabla ``user``.
_BASELINE_USER_COLUMNS: frozenset[str] = frozenset(
    {"id", "username", "password_hash", "created_at"}
)

# Columnas 2FA que 001_add_auth_security_features agrega a ``user``.
_2FA_USER_COLUMNS: frozenset[str] = frozenset(
    {
        "totp_secret_enc",
        "totp_enabled",
        "totp_enrolled_at",
        "totp_last_used_at",
        "password_changed_at",
        "recovery_code_hash",
        "recovery_code_attempts",
        "recovery_code_used",
    }
)

# Tablas que la migración 001 agrega (no existen en el baseline).
_2FA_TABLES: frozenset[str] = frozenset({"invitation_token", "totp_backup_code"})


# ---------------------------------------------------------------------------
# Helpers locales — sin fixtures globales para mantener cada test aislado.
# ---------------------------------------------------------------------------


def _make_config(tmp_path: Path) -> Config:
    """Construye un Config Alembic apuntando a un sqlite tmpfile.

    Sobreescribe ``sqlalchemy.url`` y ``script_location`` para que el test
    sea hermético y no dependa del CWD ni de variables de entorno externas.
    """
    db_path = tmp_path / "alembic_test.db"
    cfg = Config(str(ALEMBIC_INI))
    cfg.set_main_option("script_location", str(SCRIPT_LOCATION))
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")
    return cfg


def _engine_for(tmp_path: Path):
    """Crea un engine SQLAlchemy para la BD generada por _make_config.

    El inspector debe abrir una nueva conexión porque Alembic ya cerró
    la suya al terminar el comando. Esta función garantiza que apuntamos
    al mismo archivo sqlite que _make_config.
    """
    db_path = tmp_path / "alembic_test.db"
    return create_engine(f"sqlite:///{db_path}")


# ---------------------------------------------------------------------------
# Suite de tests
# ---------------------------------------------------------------------------


class TestAlembicMigrations:
    """Verifica la cadena completa de migraciones Alembic para GOATGuard.

    Cada test usa ``tmp_path`` (fixture built-in de pytest) para obtener
    un directorio temporal único por test, garantizando aislamiento total
    sin necesidad de teardown manual.
    """

    def test_upgrade_head_creates_all_tables(self, tmp_path: Path) -> None:
        """Verifica que ``upgrade head`` crea las 18 tablas esperadas.

        QUÉ verifica: ejecutar todas las migraciones hasta ``head``
        produce exactamente (o más, con alembic_version) el conjunto de
        18 tablas definidas en _EXPECTED_TABLES.

        POR QUÉ: es el smoke test principal de la cadena de migraciones.
        Si una migración falla a mitad o una tabla se omite, falla aquí.
        Usamos ``>=`` porque SQLite/Alembic agrega la tabla interna
        ``alembic_version`` que no forma parte del modelo de negocio.
        """
        cfg = _make_config(tmp_path)

        command.upgrade(cfg, "head")

        engine = _engine_for(tmp_path)
        actual_tables = set(inspect(engine).get_table_names())

        assert actual_tables >= _EXPECTED_TABLES, (
            f"Faltan tablas tras upgrade head.\n"
            f"  Esperadas: {sorted(_EXPECTED_TABLES)}\n"
            f"  Obtenidas: {sorted(actual_tables)}\n"
            f"  Faltantes: {sorted(_EXPECTED_TABLES - actual_tables)}"
        )

    def test_upgrade_chain_matches_metadata(self, tmp_path: Path) -> None:
        """Verifica que las migraciones no tienen drift respecto al ORM.

        QUÉ verifica: después de ``upgrade head``, el conjunto de tablas
        en la BD es exactamente igual al de ``Base.metadata.tables``.
        No se permite ni una tabla de más ni una de menos.

        POR QUÉ: detecta el caso donde un modelo nuevo se agrega al ORM
        pero nadie escribe la migración correspondiente (o viceversa).
        La tabla ``alembic_version`` se excluye explícitamente porque
        no forma parte del ORM de negocio.
        """
        cfg = _make_config(tmp_path)

        command.upgrade(cfg, "head")

        engine = _engine_for(tmp_path)
        db_tables = set(inspect(engine).get_table_names()) - {"alembic_version"}
        orm_tables = set(Base.metadata.tables.keys())

        assert db_tables == orm_tables, (
            "Drift detectado entre migraciones y ORM.\n"
            f"  Solo en BD (huérfanas en migraciones): {sorted(db_tables - orm_tables)}\n"
            f"  Solo en ORM (sin migración): {sorted(orm_tables - db_tables)}"
        )

    def test_baseline_excludes_2fa(self, tmp_path: Path) -> None:
        """Verifica que el baseline 000_initial_schema no incluye 2FA.

        QUÉ verifica: aplicar solo la primera migración produce la tabla
        ``user`` con únicamente las 4 columnas base, y NO crea las tablas
        ``invitation_token`` ni ``totp_backup_code``.

        POR QUÉ: garantiza la correcta separación de responsabilidades
        entre migraciones. Si alguien fusiona 001 en 000 por error,
        este test falla y deja traza del problema.
        """
        cfg = _make_config(tmp_path)

        # Aplicar solo el baseline, NO head.
        command.upgrade(cfg, "000_initial_schema")

        engine = _engine_for(tmp_path)
        inspector = inspect(engine)
        tables = set(inspector.get_table_names())

        # Las tablas 2FA NO deben existir en el baseline.
        for table_2fa in _2FA_TABLES:
            assert table_2fa not in tables, (
                f"La tabla '{table_2fa}' no debería existir en el baseline "
                f"000_initial_schema. Pertenece a 001_add_auth_security_features."
            )

        # La tabla user SÍ debe existir desde el baseline.
        assert "user" in tables, (
            "La tabla 'user' debe crearse en el baseline 000_initial_schema."
        )

        # Verificar que user solo tiene las 4 columnas base en el baseline.
        user_columns = {col["name"] for col in inspector.get_columns("user")}

        assert _BASELINE_USER_COLUMNS <= user_columns, (
            f"Faltan columnas base en 'user' tras el baseline.\n"
            f"  Esperadas: {sorted(_BASELINE_USER_COLUMNS)}\n"
            f"  Obtenidas: {sorted(user_columns)}"
        )

        # Las columnas 2FA NO deben estar en el baseline.
        for col_2fa in _2FA_USER_COLUMNS:
            assert col_2fa not in user_columns, (
                f"La columna 'user.{col_2fa}' no debería existir tras el baseline. "
                f"Se agrega en 001_add_auth_security_features."
            )

    def test_downgrade_001_removes_2fa(self, tmp_path: Path) -> None:
        """Verifica que el downgrade de 001 revierte correctamente los cambios 2FA.

        QUÉ verifica: después de ``upgrade head`` seguido de ``downgrade -1``
        (equivale a bajar un paso desde head, es decir revertir 001),
        las tablas 2FA desaparecen y la tabla ``user`` pierde las columnas
        2FA pero sigue existiendo.

        POR QUÉ: los downgrade son el mecanismo de rollback en producción.
        Si ``downgrade_001`` no hace DROP de sus columnas y tablas, un
        rollback de emergencia dejará la BD en estado inconsistente con
        el código del baseline.
        """
        cfg = _make_config(tmp_path)

        # Llevar la BD al estado completo (head = 001 aplicado).
        command.upgrade(cfg, "head")

        # Revertir un solo paso: deshace 001_add_auth_security_features.
        command.downgrade(cfg, "-1")

        # El inspector debe abrir una nueva conexión — la de Alembic ya cerró.
        engine = _engine_for(tmp_path)
        inspector = inspect(engine)
        tables = set(inspector.get_table_names())

        # Las tablas 2FA deben haber desaparecido tras el downgrade.
        for table_2fa in _2FA_TABLES:
            assert table_2fa not in tables, (
                f"La tabla '{table_2fa}' debería haber sido eliminada por el "
                f"downgrade de 001_add_auth_security_features."
            )

        # La tabla user debe seguir existiendo (el downgrade no la elimina).
        assert "user" in tables, (
            "La tabla 'user' no debe eliminarse en el downgrade de 001. "
            "Solo se pierden las columnas 2FA que ese migration agregó."
        )

        # Las columnas 2FA deben haber sido eliminadas de user.
        user_columns = {col["name"] for col in inspector.get_columns("user")}

        for col_2fa in _2FA_USER_COLUMNS:
            assert col_2fa not in user_columns, (
                f"La columna 'user.{col_2fa}' debería haber sido eliminada "
                f"por el downgrade de 001_add_auth_security_features."
            )
