from typing import Annotated
from fastapi import Query, Response
from fastapi.routing import APIRouter
import requests
from lib.recon.security_headers import SecurityHeaders

router: APIRouter = APIRouter(
    prefix="/recon",
    tags=["Recon"],
)


@router.post("/security-headers")
async def security_headers( url: Annotated[str, Query(..., regex="^https?://")]):
    # validate url
    valid_url = requests.utils.urlparse(url)
    if not valid_url.scheme or not valid_url.netloc:
        return Response(status_code=400, content={"message": "Invalid URL"})

    response = requests.head(url)
    security_headers = SecurityHeaders(response.headers)
    analysis = security_headers.analyze()
    return analysis

