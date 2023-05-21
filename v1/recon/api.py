from datetime import datetime
from typing import Annotated
from fastapi import Depends, Query, Request
from fastapi.routing import APIRouter
from lib.auth.auth_bearer import JWTBearer
from lib.constants.scan_types import ScanTypes
from lib.recon.cors_misconfig.cors_scanner import CorsMisconfigScanner
from lib.recon.dnsscan import DNSScanner
from lib.recon.port_scanner.port_scanner import PORT_SCANNER_MODES, PortScanner
from lib.recon.security_headers import SecurityHeaders
from lib.recon.ssl_scanner import SSLScanner
from urllib3.util import parse_url
from bson import ObjectId
from fastapi import BackgroundTasks
from bson.objectid import ObjectId
import pydantic
from bson import json_util
from lib.constants.collections import *
pydantic.json.ENCODERS_BY_TYPE[ObjectId]=str



from lib.recon.subdomain.subdomain import SubdomainEnum

router: APIRouter = APIRouter(
    prefix="/recon",
    tags=["Recon"],
)

STATUS = {
    "pending" : "pending",
    "completed": "completed",
    "failed": "failed"
}


@router.post("/cors-misconfiguration")
async def cors_misconfiguration(request: Request,
        url: Annotated[str, Query(..., regex="^https?://")], scanId: Annotated[str, Query(...)], credentials: tuple = Depends(JWTBearer())):
    user, token = credentials
    scanner = CorsMisconfigScanner(url)
    try:
        analysis = scanner.scan()
        payload = {"scanId": ObjectId(scanId), "cors": analysis, "user":  ObjectId(oid=user["id"])}
        try:
            await request.app.mongodb[CORS_COLLECTION].insert_one(payload)
            await request.app.mongodb[SCANS_COLLECTION].update_one({"_id": ObjectId(scanId)}, {"$set": {"cors": STATUS["completed"]}})
            return {"message": "Report saved successfully."}
        except Exception as e:
            await request.app.mongodb[SCANS_COLLECTION].update_one({"_id": ObjectId(scanId)}, {"$set": {"cors": STATUS["failed"]}})
    except Exception as e:
        print(e)
        return {"message": "Error scanning.", "error": str(e)}


@router.post("/port-scan")
async def port_scan(request:Request, url: str, mode: PORT_SCANNER_MODES, scanId: Annotated[str, Query(...)], credentials: tuple = Depends(JWTBearer())):
    user, token = credentials
    scanner = PortScanner(url, mode)
    try:
        analysis = scanner.scan()
        payload = {"scanId": ObjectId(scanId), "ports": analysis, "user":  ObjectId(oid=user["id"])}
        await request.app.mongodb[PORTS_COLLECTION].insert_one(payload)
        await request.app.mongodb[SCANS_COLLECTION].update_one({"_id": ObjectId(scanId)}, {"$set": {"ports": STATUS["completed"]}})
        return {"message": "Report saved successfully."}
    except Exception as e:
        await request.app.mongodb[SCANS_COLLECTION].update_one({"_id": ObjectId(scanId)}, {"$set": {"ports": STATUS["failed"]}})
        return {"message": "Error scanning.", "error": str(e)}


@router.post("/dns")
async def dns(request: Request, url: Annotated[str, Query(..., regex="^https?://")], scanId: Annotated[str, Query(...)], credentials: tuple = Depends(JWTBearer())):
    user, token = credentials
    host = parse_url(url).hostname
    scanner = DNSScanner(host)
    try:
        analysis = scanner.scan()
        payload = {"target": url, "scanId": ObjectId(scanId), "dns": analysis["issues"], "user":  ObjectId(oid=user["id"])}
        await request.app.mongodb[DNS_COLLECTION].insert_one(payload)
        await request.app.mongodb[SCANS_COLLECTION].update_one({"_id": ObjectId(scanId)}, {"$set": {"dns": STATUS["completed"]}})
        return {"message": "Report saved successfully."}
    except Exception as e:
        await request.app.mongodb[SCANS_COLLECTION].update_one({"_id": ObjectId(scanId)}, {"$set": {"dns": STATUS["failed"]}})
        return {"message": "Error scanning.", "error": str(e)}


@router.post("/security-headers")
async def security_headers(request: Request, url: Annotated[str, Query(..., regex="^https?://")], scanId: Annotated[str, Query(...)], credentials: tuple = Depends(JWTBearer())):
    user, token = credentials
    try: 
        analysis = SecurityHeaders(url).scan()  # type: ignore
        payload = {"scanId": ObjectId(scanId), "securityHeaders": analysis, "user":  ObjectId(oid=user["id"])}
        await request.app.mongodb[SECURITY_HEADERS_COLLECTION].insert_one(payload)
        await request.app.mongodb[SCANS_COLLECTION].update_one({"_id": ObjectId(scanId)}, {"$set": {"securityHeaders": STATUS["completed"]}})
        return {"message": "Report saved successfully."}
    except Exception as e:
        await request.app.mongodb[SCANS_COLLECTION].update_one({"_id": ObjectId(scanId)}, {"$set": {"securityHeaders": STATUS["failed"]}})
        return {"message": "Error scanning.", "error": str(e)}
    


@router.post("/ssl-scanner")
async def ssl_scanner(request: Request, url: Annotated[str, Query(..., regex="^https?://")], scanId: Annotated[str, Query(...)], credentials: tuple = Depends(JWTBearer())):
    user, token = credentials
    try:
        analysis = SSLScanner(url).scan()
        payload = {"scanId": ObjectId(scanId), "ssl": analysis, "user":  ObjectId(oid=user["id"])}
        await request.app.mongodb[SSL_COLLECTION].insert_one(payload)
        await request.app.mongodb[SCANS_COLLECTION].update_one({"_id": ObjectId(scanId)}, {"$set": {"ssl": STATUS["completed"]}})
        return {"message": "Report saved successfully."}
    except Exception as e:
        await request.app.mongodb[SCANS_COLLECTION].update_one({"_id": ObjectId(scanId)}, {"$set": {"ssl": STATUS["failed"]}})
        return {"message": "Error scanning.", "error": str(e)}


@router.post("/subdomain")
async def subdomain(request: Request, url: Annotated[str, Query(..., regex="^https?://")], scanId: Annotated[str, Query(...)], credentials: tuple = Depends(JWTBearer())):
    user, token = credentials
    scanner = SubdomainEnum(url)
    try:
        analysis = scanner.run()
        payload = {"scanId": ObjectId(scanId), "subdomains": analysis, "user":  ObjectId(oid=user["id"])}
        await request.app.mongodb[SUBDOMAINS_COLLECTION].insert_one(payload)
        await request.app.mongodb[SCANS_COLLECTION].update_one({"_id": ObjectId(scanId)}, {"$set": {"subdomains": STATUS["completed"]}})
        return {"message": "Report saved successfully."}
    except Exception as e:
        await request.app.mongodb[SCANS_COLLECTION].update_one({"_id": ObjectId(scanId)}, {"$set": {"subdomains": STATUS["failed"]}})
        return {"message": "Error scanning.", "error": str(e)}
        


@router.post("/scan")
async def new_scans(request: Request, background_tasks: BackgroundTasks, url: Annotated[str, Query(..., regex="^https?://")], credentials: tuple = Depends(JWTBearer())):
    user, token = credentials
    payload = {
        "target": url,
        "user":  ObjectId(oid=user["id"]),
        "cors": "pending",
        "ports": "pending",
        "dns": "pending",
        "securityHeaders": "pending",
        "ssl": "pending",
        # "subdomains": "pending"
        "created_at": datetime.utcnow()
    }
    report = await request.app.mongodb[SCANS_COLLECTION].insert_one(payload)
    if report:
        background_tasks.add_task(cors_misconfiguration, request, url, str(report.inserted_id), credentials)
        background_tasks.add_task(port_scan, request, url, PORT_SCANNER_MODES.QUICK, str(report.inserted_id), credentials)
        background_tasks.add_task(dns, request, url, str(report.inserted_id), credentials)
        background_tasks.add_task(security_headers, request, url, str(report.inserted_id), credentials)
        background_tasks.add_task(ssl_scanner, request, url, str(report.inserted_id), credentials)
        # background_tasks.add_task(subdomain, request, url, str(report.inserted_id), credentials)

        return {"message": "Scan started successfully.", "id":  str(report.inserted_id)}
    else:
        return {"message": "Error starting scan."}
    

@router.get("/scans")
async def get_scans(request: Request, credentials: tuple = Depends(JWTBearer())):
    user, token = credentials
    cursor = request.app.mongodb["scans"].find({"user": ObjectId(oid=user["id"])})
    scans = await cursor.to_list(length=100)
    json = json_util.dumps(scans)
    return json_util.loads(json)
    # check if all scans are completed check in all collections
    # if completed then return status as completed

    
    # cursor = request.app.mongodb[SCANS_COLLECTION].find({"user": ObjectId(oid=user["id"])})
    # scans = await cursor.to_list(length=100)
    # json = json_util.dumps(scans)
    # scans = json_util.loads(json)

    # def is_completed(collection: str, scanId: str):
    #     status = "running"
    #     scan = request.app.mongodb[collection].find_one({"scanId": ObjectId(scanId), "user": ObjectId(oid=user["id"])})
    #     if scan:
    #         status = "completed"
    #     return status
    
    # ALL_COLLECTIONS = [CORS_COLLECTION, PORTS_COLLECTION, DNS_COLLECTION, SECURITY_HEADERS_COLLECTION, SSL_COLLECTION, SUBDOMAINS_COLLECTION]
    

    # for scan in scans:
    #     status = {}
    #     pool = ThreadPoolExecutor(max_workers=2)
    #     futures = []
    #     for collection in ALL_COLLECTIONS:
    #         futures.append({
    #             "collection": collection,
    #             "future": pool.submit(is_completed, collection, str(scan["_id"]))
    #         })
    #     for future in futures:
    #         status[future["collection"]] = "completed" if future["future"].result() else "running"

    #     scan["status"] = status

    # return scans

    



    

@router.get("/scan/{id}")
async def get_scan(request: Request, id: str, scanType: ScanTypes, credentials: tuple = Depends(JWTBearer())):
    user, _ = credentials
    if scanType == scanType.CORS:
        scan = await request.app.mongodb[CORS_COLLECTION].find_one({"scanId": ObjectId(id), "user": ObjectId(oid=user["id"])})
    elif scanType == scanType.PORTS:
        scan = await request.app.mongodb[PORTS_COLLECTION].find_one({"scanId": ObjectId(id), "user": ObjectId(oid=user["id"])})
    elif scanType == scanType.DNS:
        scan = await request.app.mongodb[DNS_COLLECTION].find_one({"scanId": ObjectId(id), "user": ObjectId(oid=user["id"])})
    elif scanType == scanType.SECURITY_HEADERS:
        scan = await request.app.mongodb[SECURITY_HEADERS_COLLECTION].find_one({"scanId": ObjectId(id), "user": ObjectId(oid=user["id"])})
    elif scanType == scanType.SSL:
        scan = await request.app.mongodb[SSL_COLLECTION].find_one({"scanId": ObjectId(id), "user": ObjectId(oid=user["id"])})
    elif scanType == scanType.SUBDOMAINS:
        scan = await request.app.mongodb[SUBDOMAINS_COLLECTION].find_one({"scanId": ObjectId(id), "user": ObjectId(oid=user["id"])})
    else:
        return {"message": "Invalid scan type."}
    
    if scan:
        json = json_util.dumps(scan)
        return json_util.loads(json)
    else:
        return {"message": "Scan not found."}
    

