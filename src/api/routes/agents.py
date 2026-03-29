"""
Agent endpoints for GOATGuard API.

GET /agents — List all registered capture agents with status

All endpoints require JWT authentication.
"""

import logging
from enum import Enum

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session, joinedload
from typing import Optional, List

from src.api.dependencies import get_db, get_current_user
from src.database.models import User, Agent, Device

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/agents", tags=["Agents"])


class AgentStatusFilter(str, Enum):
    """Valores válidos para el filtro de estado."""
    active = "active"
    inactive = "inactive"


class AgentResponse(BaseModel):
    """Agent info with device hostname and IP from JOIN."""
    id: int
    uid: str
    device_id: int
    hostname: Optional[str] = None
    ip: Optional[str] = None
    status: str
    last_heartbeat: Optional[str] = None
    registered_at: Optional[str] = None

    class Config:
        from_attributes = True


@router.get("/", response_model=List[AgentResponse])
def list_agents(
    status: Optional[AgentStatusFilter] = Query(
        default=None,
        description="Filter by agent status: active or inactive",
    ),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """List all registered capture agents.

    Returns agents with hostname and IP from the associated device
    (JOIN with DEVICE table). Ordered by most recent heartbeat.

    RF-037 — Estado de agentes
    """
    # Eager load device para evitar N+1 queries
    query = (
        db.query(Agent)
        .options(joinedload(Agent.device))
        .order_by(Agent.last_heartbeat.desc())
    )

    if status is not None:
        query = query.filter(Agent.status == status.value)

    agents = query.all()

    return [
        {
            "id": agent.id,
            "uid": agent.uid,
            "device_id": agent.device_id,
            "hostname": agent.device.hostname if agent.device else None,
            "ip": agent.device.ip if agent.device else None,
            "status": agent.status,
            "last_heartbeat": agent.last_heartbeat.isoformat() if agent.last_heartbeat else None,
            "registered_at": agent.registered_at.isoformat() if agent.registered_at else None,
        }
        for agent in agents
    ]
