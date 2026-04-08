"""
Rate limiting global con slowapi [RF-13].

Exponemos un único ``limiter`` a nivel de módulo para que los routers
puedan decorar sus endpoints con ``@limiter.limit("N/minute")`` sin
tener que pasar la instancia por dependency injection. ``create_app``
lo engancha a ``app.state.limiter`` y añade el ``SlowAPIMiddleware``
+ el handler de ``RateLimitExceeded``.

Storage backend: ``memory://`` (in-process). Suficiente para el
despliegue monolítico de GOATGuard; si en el futuro se escala a
multi-worker, migrar a Redis con ``storage_uri="redis://..."``.
"""

from slowapi import Limiter
from slowapi.util import get_remote_address

# Key por IP de origen. Para usuarios detrás de un proxy (Cloudflare Tunnel
# con X-Forwarded-For) el setup debe configurar el trusted proxy middleware
# de Starlette — en ese caso ``get_remote_address`` ya lee la IP real.
limiter = Limiter(
    key_func=get_remote_address,
    # Sin default_limits: solo aplicamos límites explícitos en los endpoints
    # sensibles. Limitar TODO globalmente rompería endpoints como /metrics
    # que el Android app pollea cada 5s.
    default_limits=[],
)
