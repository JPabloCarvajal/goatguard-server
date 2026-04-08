"""
Tests para el factory ``create_app``.

Verifican las invariantes de construcción de la aplicación FastAPI
que no dependen de requests HTTP: registro de routers, configuración
de middleware y ciclo de vida.
"""
import sys
import warnings

sys.path.insert(0, ".")

from src.api.app import create_app
from src.config.models import ServerConfig


class _FakeDatabase:
    """Stub mínimo: create_app solo usa get_session y create_tables."""

    def get_session(self):
        return None

    def create_tables(self, base):
        pass


def _build_app():
    """Instancia la app con un fake DB y la config de test."""
    config = ServerConfig()
    # Mismo secreto que usa conftest.py para que init_auth no reviente.
    config.security.jwt_secret = "goatguard-test-secret-key-for-pytest-suite"
    return create_app(_FakeDatabase(), config)


def _collect_endpoints(app) -> list[tuple[str, str]]:
    """Devuelve (method, path) por cada ruta HTTP registrada.

    Ignora mounts y websockets (tienen estructura distinta) para
    que la comparación sea por endpoint HTTP real.
    """
    endpoints: list[tuple[str, str]] = []
    for route in app.router.routes:
        path = getattr(route, "path", None)
        methods = getattr(route, "methods", None)
        if not path or not methods:
            continue
        for method in methods:
            endpoints.append((method, path))
    return endpoints


class TestCORSConfiguration:
    """Invariantes de seguridad sobre el middleware CORS."""

    def test_cors_default_does_not_allow_wildcard_with_credentials(self):
        """La combinación ``allow_origins=["*"]`` + ``allow_credentials=True``
        viola la CORS spec (W3C Fetch §3.2.2) y los navegadores la rechazan.
        Debemos partir de una lista explícita de orígenes seguros.
        """
        app = _build_app()

        cors_middleware = None
        for middleware in app.user_middleware:
            if "CORS" in middleware.cls.__name__:
                cors_middleware = middleware
                break

        assert cors_middleware is not None, "CORSMiddleware no está registrado"

        kwargs = cors_middleware.kwargs
        allow_origins = kwargs.get("allow_origins", [])
        allow_credentials = kwargs.get("allow_credentials", False)

        if allow_credentials:
            assert "*" not in allow_origins, (
                "allow_origins=['*'] es incompatible con allow_credentials=True "
                "(los navegadores rechazan cross-origin con credentials + wildcard). "
                "Usar una lista explícita de orígenes desde config.security.cors_origins."
            )

    def test_cors_origins_configurable_via_security_config(self):
        """``config.security.cors_origins`` debe existir y ser usada por create_app."""
        config = ServerConfig()
        config.security.jwt_secret = "goatguard-test-secret-key-for-pytest-suite"
        custom_origins = ["https://goatguard.example.com", "http://localhost:3000"]
        config.security.cors_origins = custom_origins

        app = create_app(_FakeDatabase(), config)

        cors_middleware = next(
            (m for m in app.user_middleware if "CORS" in m.cls.__name__), None
        )
        assert cors_middleware is not None
        assert cors_middleware.kwargs.get("allow_origins") == custom_origins


class TestSeedScriptSecrets:
    """Guardrail contra credenciales hardcodeadas en ``seed.py``."""

    def test_seed_script_has_no_hardcoded_admin_password(self):
        """``seed.py`` no debe hardcodear ``admin123`` ni ningún literal obvio.

        El seed se usa tanto en desarrollo local como en CI y
        (accidentalmente) en despliegues iniciales. Un literal
        ``"admin123"`` en el repo abre la puerta a una toma de control
        trivial en cuanto alguien olvide cambiar el password.

        Fix esperado: leer el password desde ``GOATGUARD_ADMIN_PASSWORD``
        y abortar con ``SystemExit`` si no está definida.
        """
        import pathlib

        seed_path = (
            pathlib.Path(__file__).resolve().parent.parent / "seed.py"
        )
        content = seed_path.read_text(encoding="utf-8")

        forbidden_literals = ["admin123", "password123", "changeme"]
        found = [lit for lit in forbidden_literals if lit in content]

        assert found == [], (
            f"seed.py contiene credenciales hardcodeadas: {found}. "
            f"Leer desde GOATGUARD_ADMIN_PASSWORD en su lugar."
        )


class TestDeprecatedDatetime:
    """Guardrail contra ``datetime.utcnow()`` (deprecado en Python 3.12+).

    Python 3.12 deprecó ``datetime.utcnow()`` porque devuelve un naive
    datetime que se interpreta erróneamente como local time en muchas
    APIs. Debe reemplazarse por ``datetime.now(timezone.utc)``.
    """

    def test_src_has_no_datetime_utcnow_calls(self):
        import pathlib
        import re

        src_root = pathlib.Path(__file__).resolve().parent.parent / "src"
        # Captura tanto ``datetime.utcnow()`` como ``default=datetime.utcnow``
        # (este último es el uso como callable en Column de SQLAlchemy).
        pattern = re.compile(r"datetime\.utcnow\b")

        offenders: list[str] = []
        for py_file in src_root.rglob("*.py"):
            content = py_file.read_text(encoding="utf-8")
            for lineno, line in enumerate(content.splitlines(), start=1):
                if pattern.search(line):
                    rel = py_file.relative_to(src_root.parent)
                    offenders.append(f"{rel}:{lineno}: {line.strip()}")

        assert offenders == [], (
            "Se encontraron llamadas a ``datetime.utcnow()`` en src/. "
            "Reemplazar por ``datetime.now(timezone.utc)``:\n"
            + "\n".join(offenders)
        )


class TestLifespan:
    """Invariantes del ciclo de vida de la aplicación."""

    def test_create_app_does_not_use_deprecated_on_event(self):
        """``create_app`` no debe usar ``@app.on_event``.

        ``on_event`` está deprecado desde FastAPI 0.93 y será removido.
        Debemos usar el context manager ``lifespan=`` pasado al
        constructor de ``FastAPI``.
        """
        with warnings.catch_warnings(record=True) as captured:
            warnings.simplefilter("always")
            _build_app()

        on_event_warnings = [
            w for w in captured
            if "on_event is deprecated" in str(w.message)
        ]
        assert on_event_warnings == [], (
            f"create_app sigue usando @app.on_event (deprecado). "
            f"Migrar a lifespan=. Warnings capturados: "
            f"{[str(w.message) for w in on_event_warnings]}"
        )

    def test_app_has_lifespan_context(self):
        """La app debe exponer un ``lifespan_context`` custom, no el default."""
        app = _build_app()

        # Starlette asigna un default lifespan_context si no se pasa uno.
        # El nuestro debe ser diferente del sentinel por defecto.
        lifespan = app.router.lifespan_context
        assert lifespan is not None
        # El default de Starlette es ``default_lifespan``; el nuestro tiene
        # otro nombre o es una función definida en create_app.
        assert lifespan.__name__ != "default_lifespan", (
            "create_app no está pasando un lifespan custom al constructor de FastAPI"
        )


class TestRouterRegistration:
    """Invariantes sobre el registro de routers en ``create_app``."""

    def test_no_duplicate_http_endpoints(self):
        """Ningún (método, path) debe registrarse dos veces.

        Bug histórico: ``auth_routes.router`` se incluía dos veces
        en ``create_app``, duplicando todas las rutas /api/auth/*.
        Esto contamina ``app.routes`` y puede producir comportamiento
        imprevisto con middleware y generación de OpenAPI.
        """
        app = _build_app()
        endpoints = _collect_endpoints(app)

        # Un duplicado es cualquier endpoint que aparece >1 vez.
        seen: dict[tuple[str, str], int] = {}
        for endpoint in endpoints:
            seen[endpoint] = seen.get(endpoint, 0) + 1
        duplicates = {ep: count for ep, count in seen.items() if count > 1}

        assert duplicates == {}, (
            f"Se detectaron endpoints duplicados en create_app: "
            f"{duplicates}. Revisar llamadas a app.include_router."
        )
