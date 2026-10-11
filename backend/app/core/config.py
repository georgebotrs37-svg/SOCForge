from functools import lru_cache
from typing import Literal
from urllib.parse import parse_qs, urlsplit

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SOCFORGE_",
        env_file=".env",
        extra="ignore",
    )

    database_url: str = "sqlite:///./socforge.db"
    jwt_secret: str = "development-only-change-me-please-set-env"
    environment: Literal["development", "test", "staging", "production"] = "development"
    jwt_expire_minutes: int = 30
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    allowed_hosts: str = "localhost,127.0.0.1,testserver"
    default_shift_duration_minutes: int = 30
    default_noise_events_per_minute: int = 12
    critical_alert_sla_seconds: int = 600
    max_query_rows: int = 100_000

    @field_validator("cors_origins")
    @classmethod
    def cors_origins_must_be_valid(cls, value: str) -> str:
        origins = [origin.strip() for origin in value.split(",") if origin.strip()]
        for origin in origins:
            parsed = urlsplit(origin)
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.netloc
                or parsed.path not in {"", "/"}
                or parsed.query
                or parsed.fragment
                or parsed.username
                or parsed.password
                or "*" in origin
            ):
                raise ValueError("SOCFORGE_CORS_ORIGINS must contain valid HTTP(S) origins")
        return ",".join(origins)

    @field_validator("allowed_hosts")
    @classmethod
    def allowed_hosts_must_be_valid(cls, value: str) -> str:
        hosts = [host.strip().casefold() for host in value.split(",") if host.strip()]
        if not hosts or any("/" in host or ":" in host or "*" in host for host in hosts):
            raise ValueError("SOCFORGE_ALLOWED_HOSTS must contain host names without ports")
        return ",".join(hosts)

    @model_validator(mode="after")
    def validate_security_settings(self) -> "Settings":
        if not 1 <= self.jwt_expire_minutes <= 60:
            raise ValueError("SOCFORGE_JWT_EXPIRE_MINUTES must be between 1 and 60")
        if not 5 <= self.default_shift_duration_minutes <= 240:
            raise ValueError("SOCFORGE_DEFAULT_SHIFT_DURATION_MINUTES must be between 5 and 240")
        if not 0 <= self.default_noise_events_per_minute <= 100:
            raise ValueError(
                "SOCFORGE_DEFAULT_NOISE_EVENTS_PER_MINUTE must be between 0 and 100"
            )
        if not 60 <= self.critical_alert_sla_seconds <= 86_400:
            raise ValueError("SOCFORGE_CRITICAL_ALERT_SLA_SECONDS must be between 60 and 86400")
        if not 1_000 <= self.max_query_rows <= 100_000:
            raise ValueError("SOCFORGE_MAX_QUERY_ROWS must be between 1000 and 100000")
        if self.environment != "production":
            return self

        if (
            len(self.jwt_secret) < 64
            or len(set(self.jwt_secret)) < 16
            or any(character.isspace() for character in self.jwt_secret)
        ):
            raise ValueError(
                "SOCFORGE_JWT_SECRET must contain at least 64 random characters in production"
            )
        database_url = urlsplit(self.database_url)
        if not database_url.scheme.startswith("postgresql"):
            raise ValueError("SOCFORGE_DATABASE_URL must use PostgreSQL in production")
        ssl_modes = parse_qs(database_url.query).get("sslmode", [])
        if not ssl_modes or ssl_modes[0] not in {"require", "verify-ca", "verify-full"}:
            raise ValueError("Production PostgreSQL connections must require TLS via sslmode")

        origins = self.cors_origin_list
        if not origins or any(not origin.startswith("https://") for origin in origins):
            raise ValueError("Production SOCFORGE_CORS_ORIGINS must contain HTTPS origins")
        if any(urlsplit(origin).hostname in {"localhost", "127.0.0.1"} for origin in origins):
            raise ValueError("Production SOCFORGE_CORS_ORIGINS must not include localhost")

        hosts = self.allowed_host_list
        if not hosts or any(host in {"localhost", "127.0.0.1", "testserver"} for host in hosts):
            raise ValueError("Production SOCFORGE_ALLOWED_HOSTS must list public host names")
        return self

    @property
    def cors_origin_list(self) -> list[str]:
        return [
            origin.strip().rstrip("/")
            for origin in self.cors_origins.split(",")
            if origin.strip()
        ]

    @property
    def allowed_host_list(self) -> list[str]:
        return [host.strip() for host in self.allowed_hosts.split(",") if host.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
