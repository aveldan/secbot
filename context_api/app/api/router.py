from fastapi import APIRouter
from app.api.routes import context
from app.api.routes import privacy

router = APIRouter()

router.include_router(context.router, prefix="/context")
router.include_router(privacy.router, prefix="")