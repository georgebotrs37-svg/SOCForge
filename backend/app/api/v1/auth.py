from datetime import UTC
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user
from app.core.security import create_access_token, hash_password, verify_password
from app.db.session import get_db
from app.domain.enums import UserRole
from app.models import User
from app.schemas.auth import LoginRequest, RegisterRequest, TokenResponse, UserRead

router = APIRouter(prefix="/auth", tags=["authentication"])
DatabaseSession = Annotated[Session, Depends(get_db)]
CurrentUser = Annotated[User, Depends(get_current_user)]


@router.post("/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def register_user(
    request: RegisterRequest,
    session: DatabaseSession,
) -> User:
    email = str(request.email).casefold()
    user = User(
        email=email,
        display_name=request.display_name,
        password_hash=hash_password(request.password),
        role=UserRole.TRAINEE.value,
    )
    session.add(user)
    try:
        session.commit()
    except IntegrityError as error:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists",
        ) from error
    session.refresh(user)
    return user


@router.post("/login", response_model=TokenResponse)
def login(
    request: LoginRequest,
    session: DatabaseSession,
) -> TokenResponse:
    email = str(request.email).casefold()
    user = session.scalar(select(User).where(func.lower(User.email) == email))
    if (
        user is None
        or not user.is_active
        or not verify_password(request.password, user.password_hash)
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token, expires_at = create_access_token(user.id)
    return TokenResponse(
        access_token=token,
        expires_at=expires_at.astimezone(UTC).isoformat(),
    )


@router.get("/me", response_model=UserRead)
def read_current_user(user: CurrentUser) -> User:
    return user
