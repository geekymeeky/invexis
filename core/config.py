from typing import Any, Dict, List, Optional, Union

from pydantic import AnyHttpUrl, BaseSettings, MongoDsn, validator


class Settings(BaseSettings):
    PROJECT_NAME: str
    BACKEND_CORS_ORIGINS: List[AnyHttpUrl] = []
    SENTRY_DSN: Optional[str] = None
    ENVIRONMENT: Optional[str] = "development"

    @validator("BACKEND_CORS_ORIGINS", pre=True)
    def assemble_cors_origins(
            cls, v: Union[str, List[str]]) -> Union[List[str], str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)

    MONGO_URI: str
    MONGO_DB: str
    JWT_SECRET: str
    JWT_ALGORITHM: str
    API_V1_STR: str = "/api/v1"

    @validator("API_V1_STR", pre=True)
    def assemble_api_v1_str(cls, v: str) -> str:
        return v if v.startswith("/") else f"/{v}"

    class Config:
        case_sensitive = True
        env_file = ".env"


settings = Settings()
