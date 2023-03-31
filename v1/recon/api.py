from fastapi import Request
from fastapi.routing import APIRouter
import requests
from lib.security_headers import SecurityHeaders

router: APIRouter = APIRouter(
    prefix="/recon",
    tags=["Recon"],
)



@router.post("/security-headers")
async def security_headers(request: Request,url: str):
    response = requests.head(url)
    security_headers = SecurityHeaders(response.headers)
    analysis = security_headers.analyze()
    return analysis

