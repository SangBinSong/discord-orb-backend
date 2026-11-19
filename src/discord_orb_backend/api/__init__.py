"""HTTP API routers for RFC 8252 client authentication and message previews."""

from fastapi import APIRouter

from .auth_routes import router as auth_router
from .preview_routes import router as preview_router

router = APIRouter()
router.include_router(auth_router)
router.include_router(preview_router)

__all__ = ["router"]
