from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional

class Settings(BaseSettings):
    use_redis: bool = False
    redis_url: str = "redis://localhost:6379/0"
    
    throttle_threshold: float = 0.3
    block_threshold: float = 0.7
    injection_weight: float = 2.0
    
    block_ttl_risk: int = 3600
    
    flowra_jwt_secret: Optional[str] = None
    flowra_admin_key: Optional[str] = None
    
    openai_api_key: Optional[str] = None

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

settings = Settings()
