from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from core.config import settings

from v1.home.api import router as home_router
from v1.recon.api import router as recon_router

contact = {
    "name": "Srijan Gupta",
    "email": "gupta.srijan94@gmail.com",
    "url": "https://srijankgupta.vercel.app"
}

license = {
    "name": "MIT",
    "url": "https://github.com/geekymeeky/invexis/blob/main/LICENSE"
}


def init() -> FastAPI:
    _app: FastAPI = FastAPI(title=settings.PROJECT_NAME,
                            license_info=license,
                            docs_url="/",
                            contact=contact)

    _app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            str(origin) for origin in settings.BACKEND_CORS_ORIGINS
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    _app.include_router(home_router, prefix=settings.API_V1_STR)
    _app.include_router(recon_router, prefix=settings.API_V1_STR)

    return _app


app = init()
