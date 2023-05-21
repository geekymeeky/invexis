from enum import Enum


class ScanTypes(Enum):
    CORS = 'cors'
    PORTS = 'ports'
    DNS = 'dns'
    SECURITY_HEADERS = 'securityHeaders'
    SSL = 'ssl'
    SUBDOMAINS = 'subdomains'
    