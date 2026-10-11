import pytest
from pydantic import ValidationError

from app.core.config import Settings


def test_development_settings_expose_safe_soc_defaults() -> None:
    settings = Settings(_env_file=None)

    assert settings.jwt_expire_minutes == 30
    assert settings.default_shift_duration_minutes == 30
    assert settings.default_noise_events_per_minute == 12
    assert settings.critical_alert_sla_seconds == 600
    assert settings.max_query_rows == 100_000
    assert settings.cors_origin_list == [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"jwt_expire_minutes": 61}, "between 1 and 60"),
        ({"default_shift_duration_minutes": 4}, "between 5 and 240"),
        ({"default_noise_events_per_minute": 101}, "between 0 and 100"),
        ({"critical_alert_sla_seconds": 30}, "between 60 and 86400"),
        ({"max_query_rows": 999}, "between 1000 and 100000"),
        ({"cors_origins": "*"}, "valid HTTP\\(S\\) origins"),
        ({"allowed_hosts": "*"}, "host names without ports"),
    ],
)
def test_invalid_operational_settings_are_rejected(
    overrides: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        Settings(_env_file=None, **overrides)


def test_production_requires_secure_deployment_values() -> None:
    valid_production = {
        "environment": "production",
        "jwt_secret": "aB3$Cd5!Ef7@Gh9#Jk1%Lm2^No4&" * 3,
        "database_url": (
            "postgresql+psycopg://socforge:secret@db.example.org/socforge?sslmode=require"
        ),
        "cors_origins": "https://soc.example.org",
        "allowed_hosts": "soc.example.org",
    }

    with pytest.raises(ValidationError, match="64 random characters"):
        Settings(_env_file=None, **{**valid_production, "jwt_secret": "short"})
    with pytest.raises(ValidationError, match="PostgreSQL"):
        Settings(_env_file=None, **{**valid_production, "database_url": "sqlite:///prod.db"})
    with pytest.raises(ValidationError, match="TLS"):
        Settings(
            _env_file=None,
            **{
                **valid_production,
                "database_url": "postgresql+psycopg://socforge:secret@db.example.org/socforge",
            },
        )
    with pytest.raises(ValidationError, match="HTTPS origins"):
        Settings(_env_file=None, **{**valid_production, "cors_origins": "http://soc.example.org"})
    with pytest.raises(ValidationError, match="public host names"):
        Settings(_env_file=None, **{**valid_production, "allowed_hosts": "localhost"})

    assert Settings(_env_file=None, **valid_production).environment == "production"
