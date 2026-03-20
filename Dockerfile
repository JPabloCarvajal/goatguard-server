# GOATGuard Server — Multi-stage Docker build
# Solo para la API REST (run_api.py), no el pipeline completo (run.py)

# ── Stage 1: build ──────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Stage 2: runtime ────────────────────────────────────────────
FROM python:3.12-slim

WORKDIR /app

# Copiar dependencias instaladas desde builder
COPY --from=builder /install /usr/local

# Copiar código fuente y configuración
COPY src/ src/
COPY run_api.py .
COPY config/ config/

# Variables de entorno (sin valores por defecto para secrets)
ENV PYTHONUNBUFFERED=1
ENV DATABASE_URL=""
ENV JWT_SECRET=""

EXPOSE 8000

# Healthcheck para orquestadores
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/docs')" || exit 1

CMD ["python", "run_api.py"]
