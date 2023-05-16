from typing import Annotated
from fastapi import Query
from fastapi.routing import APIRouter
from lib.recon.dnsscan import DNSScanner
from lib.recon.file_inclusion.file_inclusion import FileInclusionScanner
from lib.recon.port_scanner.port_scanner import PORT_SCANNER_MODES, PortScanner
from lib.recon.security_headers import SecurityHeaders
from lib.recon.ssl_scanner import SSLScanner
from urllib3.util import parse_url

from lib.recon.subdomain.subdomain import SubdomainEnum

router: APIRouter = APIRouter(
    prefix="/recon",
    tags=["Recon"],
)



@router.post("/dns")
async def dns(url: Annotated[str, Query(..., regex="^https?://")]):
    domain = parse_url(url).host
    scanner = DNSScanner(domain)
    analysis = scanner.scan()
    return analysis


@router.post("/file-inclusion")
async def file_inclusion(url: Annotated[str, Query(..., regex="^https?://")]):
    scanner = FileInclusionScanner(url)
    analysis = scanner.scan()
    return analysis


@router.post("/port-scan")
def port_scan(url:str,
              mode: PORT_SCANNER_MODES):
    scanner = PortScanner(url, mode)
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
