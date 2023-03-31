from fastapi import Request
from fastapi.routing import APIRouter

from lib.shared.utils import get_timestamp

router: APIRouter = APIRouter(
    prefix="",
    tags=["Home"],
)

## Last Deployed Timestamp
last_updated: str = get_timestamp()


@router.get("/")
async def home(request: Request):
    return {
        "message": "Welcome to the Security Headers API",
        "last_updated": last_updated,
        "documentation":  f"{request.base_url}docs",
    }


