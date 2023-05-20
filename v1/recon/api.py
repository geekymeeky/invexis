from typing import Annotated
from fastapi import Query
from fastapi.routing import APIRouter
from lib.recon.cors_misconfig.cors_scanner import CorsMisconfigScanner
from lib.recon.dnsscan import DNSScanner
from lib.recon.port_scanner.port_scanner import PORT_SCANNER_MODES, PortScanner
from lib.recon.security_headers import SecurityHeaders
from lib.recon.ssl_scanner import SSLScanner
from urllib3.util import parse_url

from lib.recon.subdomain.subdomain import SubdomainEnum

router: APIRouter = APIRouter(
    prefix="/recon",
    tags=["Recon"],
)


@router.post("/cors-misconfiguration")
async def cors_misconfiguration(
        url: Annotated[str, Query(..., regex="^https?://")]):
    scanner = CorsMisconfigScanner(url)
    analysis = scanner.scan()
    return analysis


@router.post("/port-scan")
def port_scan(url: str, mode: PORT_SCANNER_MODES):
    scanner = PortScanner(url, mode)
    analysis = scanner.scan()
    return analysis


@router.post("/dns")
async def dns(url: Annotated[str, Query(..., regex="^https?://")]):
    host = parse_url(url).hostname
    scanner = DNSScanner(host)
    analysis = scanner.scan()
    return analysis


@router.post("/security-headers")
async def security_headers(url: Annotated[str,
                                          Query(..., regex="^https?://")]):
    analysis = SecurityHeaders(url).scan()  # type: ignore
    return analysis


@router.post("/ssl-scanner")
async def ssl_scanner(url: Annotated[str, Query(..., regex="^https?://")]):
    analysis = SSLScanner(url).scan()  # type: ignore
    return analysis


@router.post("/subdomain")
async def subdomain(url: Annotated[str, Query(..., regex="^https?://")]):
    scanner = SubdomainEnum(url)
    analysis = scanner.run()
    return {"target": url, "subdomains": analysis}
