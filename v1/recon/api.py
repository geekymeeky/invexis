from typing import Annotated
from fastapi import Query
from fastapi.routing import APIRouter
import requests
from lib.recon.security_headers import SecurityHeaders
from lib.recon.ssl_scanner import SSLScanner

router: APIRouter = APIRouter(
    prefix="/recon",
    tags=["Recon"],
)


@router.post("/security-headers")
async def security_headers(url: Annotated[str,
                                          Query(..., regex="^https?://")]):
    response = requests.head(url)
    security_headers = SecurityHeaders(response.headers)
    analysis = security_headers.analyze()
    return analysis


@router.post("/ssl-scanner")
async def ssl_scanner(url: Annotated[str, Query(..., regex="^https?://")]):
    analysis = SSLScanner(url).scan()
    return analysis
