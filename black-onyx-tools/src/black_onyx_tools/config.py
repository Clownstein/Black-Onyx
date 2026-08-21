"""Environment-backed settings for Black Onyx MCP tools."""

from functools import lru_cache

import httpx
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configuration loaded from BLACK_ONYX_* environment variables."""

    model_config = SettingsConfigDict(env_prefix="BLACK_ONYX_", extra="ignore")

    base_url: str = "http://127.0.0.1:8000"
    mcp_service_key: str = ""
    default_tenant_id: str = "default"
    tools_allow_sandbox: bool = False
    connect_timeout: float = Field(default=10.0)
    read_timeout: float = Field(default=60.0)

    @property
    def timeout(self) -> httpx.Timeout:
        return httpx.Timeout(self.connect_timeout, read=self.read_timeout)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
