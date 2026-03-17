from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from jose import jwt
from passlib.context import CryptContext
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import settings
from src.core.models import User
from src.core.schemas import (
    LoginRequest,
    RefreshRequest,
    TokenPairResponse,
    UserCreate,
    UserRead,
)
from src.core.token_store import create_refresh_token, revoke_refresh_token, rotate_refresh_token

from .deps import get_current_user, get_db

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
limiter = Limiter(key_func=get_remote_address)


def create_access_token(user_id: str) -> str:
    expire = datetime.now(UTC) + timedelta(minutes=settings.access_token_expire_minutes)
    return jwt.encode(
        {"sub": user_id, "exp": expire},
        settings.secret_key,
        algorithm=settings.algorithm,
    )


@router.post("/login", response_model=TokenPairResponse)
@limiter.limit("5/minute")
async def login(request: Request, body: LoginRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == body.email))
    user = result.scalar_one_or_none()
    if not user or not pwd_context.verify(body.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    access_token = create_access_token(str(user.id))
    raw_refresh, _ = await create_refresh_token(db, user.id)

    return TokenPairResponse(access_token=access_token, refresh_token=raw_refresh)


@router.post("/refresh", response_model=TokenPairResponse)
@limiter.limit("10/minute")
async def refresh(request: Request, body: RefreshRequest, db: AsyncSession = Depends(get_db)):
    """Rotate refresh token and issue new access + refresh pair."""
    result = await rotate_refresh_token(db, body.refresh_token)
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token"
        )

    new_raw, new_record = result
    access_token = create_access_token(str(new_record.user_id))
    return TokenPairResponse(access_token=access_token, refresh_token=new_raw)


@router.post("/logout", status_code=204)
async def logout(body: RefreshRequest, db: AsyncSession = Depends(get_db)):
    """Revoke the refresh token."""
    await revoke_refresh_token(db, body.refresh_token)


@router.post("/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
async def register(
    body: UserCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User | None = None,
):
    # When registration is disabled, only admins can create users
    if not settings.registration_enabled:
        if current_user is None:
            # Try to get user from token

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Registration is disabled. Admin access required.",
            )

    existing = await db.execute(select(User).where(User.email == body.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already registered")

    user = User(
        email=body.email,
        hashed_password=pwd_context.hash(body.password),
        full_name=body.full_name,
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)
    return user


@router.post("/register-admin", response_model=UserRead, status_code=status.HTTP_201_CREATED)
async def register_by_admin(
    body: UserCreate,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_user),
):
    """Admin-only user creation (works even when registration is disabled)."""
    if not admin.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")

    existing = await db.execute(select(User).where(User.email == body.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already registered")

    user = User(
        email=body.email,
        hashed_password=pwd_context.hash(body.password),
        full_name=body.full_name,
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)
    return user


@router.get("/me", response_model=UserRead)
async def me(user: User = Depends(get_current_user)):
    return user
