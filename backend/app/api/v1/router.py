from fastapi import APIRouter

from app.api.v1 import auth, settings, shifts

router = APIRouter()
router.include_router(auth.router)
router.include_router(settings.router)
router.include_router(shifts.router)
