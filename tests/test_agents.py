"""
Tests para GET /agents/ — RF-037 Estado de agentes.

Cubre los 7 casos de prueba requeridos:
  TC-1: Sin JWT → 401 (HTTPBearer en FastAPI >=0.104 devuelve 401 sin header)
  TC-2: JWT válido → lista con los 8 campos correctos
  TC-3: ?status=active → solo agentes activos
  TC-4: ?status=inactive → solo agentes inactivos
  TC-5: ?status=invalid → 422 (validación de enum en FastAPI)
  TC-6: BD vacía → lista vacía []
  TC-7: hostname e ip provienen del JOIN con DEVICE

Edge case adicional:
  TC-8: Token JWT con user_id inexistente en BD → 401
"""
import sys
sys.path.insert(0, ".")

import pytest
from src.api.auth import create_token


# ── TC-1: Sin JWT ──────────────────────────────────────────────────────────────

def test_list_agents_without_jwt_returns_401(client):
    """
    Sin header Authorization la solicitud es rechazada con 401.

    FastAPI >= 0.104 unificó el comportamiento de HTTPBearer para devolver
    401 en todos los casos de autenticación fallida (incluyendo header ausente).
    En versiones anteriores devolvía 403 cuando faltaba el header; ese
    comportamiento ya no aplica con FastAPI 0.135 (versión en uso).

    RF-037 / RF-13 — autenticación obligatoria.
    """
    response = client.get("/agents/")
    assert response.status_code == 401


# ── TC-2: JWT válido → 8 campos correctos ─────────────────────────────────────

def test_list_agents_with_valid_jwt_returns_all_agents(client, seed_data, auth_headers):
    """
    Con JWT válido se devuelven todos los agentes. Cada elemento
    debe tener exactamente los 8 campos definidos en AgentResponse.

    RF-037 — lista de agentes con estado.
    """
    response = client.get("/agents/", headers=auth_headers)
    assert response.status_code == 200

    body = response.json()
    assert isinstance(body, list)
    assert len(body) == 3  # 3 agentes creados en seed_data

    expected_fields = {"id", "uid", "device_id", "hostname", "ip",
                       "status", "last_heartbeat", "registered_at"}
    for agent_data in body:
        assert set(agent_data.keys()) == expected_fields


# ── TC-3: Filtro status=active ─────────────────────────────────────────────────

def test_list_agents_filter_active_returns_only_active(client, seed_data, auth_headers):
    """
    ?status=active debe devolver únicamente los agentes con status="active".
    Con seed_data hay 2 activos y 1 inactivo.

    RF-037 — filtro por estado.
    """
    response = client.get("/agents/?status=active", headers=auth_headers)
    assert response.status_code == 200

    body = response.json()
    assert len(body) == 2
    for agent_data in body:
        assert agent_data["status"] == "active"


# ── TC-4: Filtro status=inactive ──────────────────────────────────────────────

def test_list_agents_filter_inactive_returns_only_inactive(client, seed_data, auth_headers):
    """
    ?status=inactive debe devolver únicamente los agentes con status="inactive".
    Con seed_data hay 1 inactivo.

    RF-037 — filtro por estado.
    """
    response = client.get("/agents/?status=inactive", headers=auth_headers)
    assert response.status_code == 200

    body = response.json()
    assert len(body) == 1
    assert body[0]["status"] == "inactive"
    assert body[0]["uid"] == "agent-uid-gamma"


# ── TC-5: Valor de enum inválido → 422 ────────────────────────────────────────

def test_list_agents_invalid_status_enum_returns_422(client, auth_headers, seed_data):
    """
    Pasar un valor fuera del enum AgentStatusFilter debe producir un
    error de validación 422 Unprocessable Entity generado por FastAPI/Pydantic,
    antes de llegar a la lógica del endpoint.

    RF-037 — validación de parámetros de query.
    """
    response = client.get("/agents/?status=invalid", headers=auth_headers)
    assert response.status_code == 422

    # FastAPI incluye el campo y el tipo de error en el detalle
    detail = response.json()["detail"]
    assert isinstance(detail, list)
    assert len(detail) > 0


# ── TC-6: BD vacía → lista vacía ──────────────────────────────────────────────

def test_list_agents_with_empty_db_returns_empty_list(client, db_session):
    """
    Si la tabla agent está vacía pero el JWT es válido, la respuesta
    debe ser una lista vacía [] con status 200.

    Este test NO usa el fixture seed_data — inserta solo el User necesario
    para generar el token sin agregar agentes.

    RF-037 — caso límite con inventario vacío.
    """
    from src.database.models import User
    from src.api.auth import hash_password, create_token

    user = User(username="admin_empty", password_hash=hash_password("pass"))
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    token = create_token(user_id=user.id, username=user.username)
    headers = {"Authorization": f"Bearer {token}"}

    response = client.get("/agents/", headers=headers)
    assert response.status_code == 200
    assert response.json() == []


# ── TC-7: hostname e ip vienen del JOIN con DEVICE ────────────────────────────

def test_list_agents_hostname_and_ip_come_from_device_join(
    client, seed_data, auth_headers
):
    """
    Los campos hostname e ip no están en la tabla agent — se obtienen
    mediante una consulta a device usando device_id. Verifica que los
    valores coincidan con los registrados en el device asociado.

    RF-037 — enriquecimiento por JOIN con DEVICE.
    """
    response = client.get("/agents/", headers=auth_headers)
    assert response.status_code == 200

    body = response.json()

    # Construye un índice por uid para búsqueda rápida
    agents_by_uid = {a["uid"]: a for a in body}

    # Verifica los tres agentes contra los devices del seed
    assert agents_by_uid["agent-uid-alpha"]["hostname"] == "endpoint-alpha"
    assert agents_by_uid["agent-uid-alpha"]["ip"] == "192.168.99.10"

    assert agents_by_uid["agent-uid-beta"]["hostname"] == "endpoint-beta"
    assert agents_by_uid["agent-uid-beta"]["ip"] == "192.168.99.20"

    assert agents_by_uid["agent-uid-gamma"]["hostname"] == "endpoint-gamma"
    assert agents_by_uid["agent-uid-gamma"]["ip"] == "192.168.99.30"


# ── TC-8 (edge case): Token JWT con user_id inexistente → 401 ─────────────────

def test_list_agents_jwt_with_nonexistent_user_returns_401(client, seed_data):
    """
    Edge case: el token está bien firmado pero el user_id embebido
    en 'sub' no existe en la tabla user. get_current_user debe devolver
    401 porque la consulta a BD no encuentra el usuario.

    Este escenario ocurre cuando se borra un usuario pero su token
    aún no ha expirado — es un caso real de seguridad.

    RF-037 / RF-13 — integridad de la sesión.
    """
    # user_id 99999 no existe en la BD de test
    token = create_token(user_id=99999, username="ghost")
    headers = {"Authorization": f"Bearer {token}"}

    response = client.get("/agents/", headers=headers)
    assert response.status_code == 401
    assert "not found" in response.json()["detail"].lower()
