"""
Push notification token endpoints for GOATGuard API.

POST   /notifications/token  — Register an FCM token
DELETE /notifications/token  — Remove an FCM token (logout)

All endpoints require JWT authentication.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from src.api.dependencies import get_db, get_current_user
from src.database.models import User, PushToken

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/notifications", tags=["Notifications"])


class TokenRequest(BaseModel):
    """Request body for registering/removing an FCM token."""
    token: str
    platform: str = "android"


@router.post("/token", status_code=status.HTTP_201_CREATED)
def register_token(
    request: TokenRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Register an FCM push token for the authenticated user.

    Called by the mobile app after login to enable push notifications.
    If the token already exists, it is reassigned to this user.
    """
    existing = db.query(PushToken).filter_by(token=request.token).first()

    if existing:
        existing.user_id = user.id
        existing.platform = request.platform
    else:
        entry = PushToken(
            user_id=user.id,
            token=request.token,
            platform=request.platform,
        )
        db.add(entry)

    db.commit()
    logger.info(f"FCM token registered for user {user.username} ({request.platform})")

    return {"message": "Token registered successfully"}


@router.delete("/token")
def unregister_token(
    request: TokenRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Remove an FCM push token. Called on logout.

    Only deletes the token if it belongs to the authenticated user.
    """
    deleted = db.query(PushToken).filter_by(
        token=request.token, user_id=user.id
    ).delete()

    db.commit()

    if deleted == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Token not found for this user",
        )

    logger.info(f"FCM token removed for user {user.username}")
    return {"message": "Token removed successfully"}
