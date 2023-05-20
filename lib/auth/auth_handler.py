from core.config import settings
import jwt
import time

def token_response(token: str):
    return {
        "access_token": token
    }

def decodeJWT(token: str) -> dict:
    try:
        decoded_token = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        return decoded_token if decoded_token["expires"] >= time.time() else None
    except:
        return {}