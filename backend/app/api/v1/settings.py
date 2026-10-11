from typing import Annotated

from fastapi import APIRouter, Depends

from app.api.dependencies import get_current_user
from app.core.config import get_settings
from app.generators import AttackTemplate
from app.models import User
from app.schemas.api import SOCSettingsRead

router = APIRouter(prefix="/settings", tags=["settings"])
CurrentUser = Annotated[User, Depends(get_current_user)]


@router.get("/soc", response_model=SOCSettingsRead)
def read_soc_settings(_user: CurrentUser) -> SOCSettingsRead:
    settings = get_settings()
    return SOCSettingsRead(
        default_shift_duration_minutes=settings.default_shift_duration_minutes,
        default_noise_events_per_minute=settings.default_noise_events_per_minute,
        critical_alert_sla_seconds=settings.critical_alert_sla_seconds,
        max_query_rows=settings.max_query_rows,
        log_sources=[
            "windows_security",
            "sysmon",
            "dns",
            "proxy",
            "firewall",
            "edr",
            "email_gateway",
        ],
        attack_templates=[template.value for template in AttackTemplate],
    )
