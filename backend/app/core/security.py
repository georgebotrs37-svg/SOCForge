from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from pwdlib import PasswordHash

from app.core.config import get_settings

_password_hasher = PasswordHash.recommended()
_jwt_algorithm = "HS256"


def hash_password(password: str) -> str:
    return _password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return _password_hasher.verify(password, password_hash)


def create_access_token(user_id: str) -> tuple[str, datetime]:
    settings = get_settings()
    expires_at = datetime.now(UTC) + timedelta(minutes=settings.jwt_expire_minutes)
    token = jwt.encode(
        {"sub": user_id, "iat": datetime.now(UTC), "exp": expires_at},
        settings.jwt_secret,
        algorithm=_jwt_algorithm,
    )
    return token, expires_at


def decode_access_token(token: str) -> dict[str, Any]:
    return jwt.decode(
        token,
        get_settings().jwt_secret,
        algorithms=[_jwt_algorithm],
        options={"require": ["exp", "sub"]},
    )
