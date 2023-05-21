from fastapi import Depends, Request
from fastapi.routing import APIRouter
from lib.auth.auth_bearer import JWTBearer

from lib.shared.utils import get_timestamp

router: APIRouter = APIRouter(
    prefix="",
    tags=["Home"],
)

## Last Deployed Timestamp
last_updated: str = get_timestamp()


@router.get("/")
async def home(request: Request, credentials: tuple = Depends(JWTBearer())):
    user, token = credentials
    print(f"User: {user}")
    print(f"Token: {token}")
    return {
        "message": "Welcome to the Security Headers API",
        "last_updated": last_updated,
        "documentation":  f"{request.base_url}docs",
    }


