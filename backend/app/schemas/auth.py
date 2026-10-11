from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.domain.enums import UserRole


class RequestModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RegisterRequest(RequestModel):
    email: EmailStr
    display_name: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=12, max_length=128)

    @field_validator("display_name")
    @classmethod
    def display_name_must_not_be_blank(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Display name cannot be blank")
        return normalized


class LoginRequest(RequestModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    email: EmailStr
    display_name: str
    role: UserRole
    is_active: bool


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_at: str
