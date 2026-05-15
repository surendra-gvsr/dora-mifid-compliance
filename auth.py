import logging
import os
from datetime import datetime
from typing import Optional

import jwt
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBasic, HTTPBasicCredentials, HTTPBearer
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import authenticate_user, create_user, get_db, User

logger = logging.getLogger(__name__)

JWT_SECRET = os.getenv("JWT_SECRET", "dora_compliance_jwt_secret_2025")
JWT_ALGORITHM = "HS256"

security = HTTPBasic()
bearer_scheme = HTTPBearer(auto_error=False)


def _decode_jwt(token: str):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except Exception:
        return None


def _make_jwt(user_id: str) -> str:
    return jwt.encode({"user_id": user_id}, JWT_SECRET, algorithm=JWT_ALGORITHM)


async def get_current_user(
    db: Session = Depends(get_db),
    credentials: Optional[HTTPBasicCredentials] = Depends(security),
    bearer: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
):
    if bearer and bearer.credentials:
        payload = _decode_jwt(bearer.credentials)
        if payload and "user_id" in payload:
            user = db.query(User).filter(User.user_id == payload["user_id"]).first()
            if user and user.is_active:
                return user

    if credentials:
        user = authenticate_user(db, credentials.username, credentials.password)
        if user:
            return user

    raise HTTPException(
        status_code=401,
        detail="Invalid credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


# ---------------------------------------------------------------------------
# Auth endpoint handlers
# ---------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    user_id: str
    password: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None


class LoginRequest(BaseModel):
    username: str
    password: str


async def register_user(request: Request, db: Session = Depends(get_db)):
    body = await request.json()
    user_id = body.get("user_id", "").lower().strip()
    password = body.get("password", "")
    if not user_id or not password:
        raise HTTPException(status_code=400, detail="user_id and password required")
    if db.query(User).filter(User.user_id == user_id).first():
        raise HTTPException(status_code=409, detail="User already exists")
    user = create_user(
        db, user_id, password,
        first_name=body.get("first_name"),
        last_name=body.get("last_name"),
    )
    token = _make_jwt(user.user_id)
    return {"message": "Registered successfully", "token": token, "user_id": user.user_id}


async def login_user(request: Request, db: Session = Depends(get_db)):
    body = await request.json()
    user_id = body.get("username", body.get("user_id", "")).lower().strip()
    password = body.get("password", "")
    user = authenticate_user(db, user_id, password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    user.last_login = datetime.utcnow()
    db.commit()
    token = _make_jwt(user.user_id)
    return {"token": token, "user_id": user.user_id}
