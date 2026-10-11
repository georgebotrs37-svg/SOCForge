from collections.abc import Callable
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.security import decode_access_token
from app.db.session import get_db
from app.domain.enums import UserRole
from app.models import User

_bearer_scheme = HTTPBearer(auto_error=False)
BearerCredentials = Annotated[
    HTTPAuthorizationCredentials | None,
    Depends(_bearer_scheme),
]
DatabaseSession = Annotated[Session, Depends(get_db)]


def get_current_user(
    credentials: BearerCredentials,
    session: DatabaseSession,
) -> User:
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication is required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        claims = decode_access_token(credentials.credentials)
    except jwt.PyJWTError as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from error
    user_id = claims.get("sub")
    if not isinstance(user_id, str):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid access token subject",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = session.get(User, user_id)
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is unavailable",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def require_roles(*roles: UserRole) -> Callable[..., User]:
    allowed_roles = {role.value for role in roles}

    def check_role(user: Annotated[User, Depends(get_current_user)]) -> User:
        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="This role is not allowed to perform this operation",
            )
        return user

    return check_role
