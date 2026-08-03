"""Application configuration; secrets are accepted only from the environment."""
from __future__ import annotations
from functools import lru_cache
from pydantic import Field, PostgresDsn, RedisDsn, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", env_nested_delimiter="__", extra="ignore")
    environment: str = Field(default="development")
    debug: bool = Field(default=False)
    api_base_url: str = Field(default="https://api.nogosec.id")
    database_url: PostgresDsn = Field(default="postgresql+asyncpg://openintel:openintel@localhost:5432/openintel")
    redis_url: RedisDsn = Field(default="redis://localhost:6379/0")
    argon2_time_cost: int = Field(default=3, ge=1, le=10)
    argon2_memory_cost: int = Field(default=64 * 1024, ge=8192)
    argon2_parallelism: int = Field(default=2, ge=1, le=16)
    api_key_prefix_platform: str = "ngs_live_"
    api_key_prefix_agent: str = "ngs_agnt_"
    default_rate_limit_per_hour: int = Field(default=1000, ge=1)
    agent_ca_cert_path: str | None = None
    agent_ca_key_path: str | None = None
    agent_ca_key_password: SecretStr | None = None
    agent_cert_ttl_days: int = Field(default=90, ge=1, le=825)
    agent_heartbeat_interval_seconds: int = Field(default=60, ge=15)
    agent_stale_after_missed: int = Field(default=5, ge=1)
    ransomware_live_api_key: SecretStr | None = None
    github_token: SecretStr | None = None
    nvd_api_key: SecretStr | None = None
    otx_api_key: SecretStr | None = None
    slack_webhook_url: SecretStr | None = None
    jira_base_url: str | None = None
    jira_email: str | None = None
    jira_api_token: SecretStr | None = None
    siem_webhook_url: SecretStr | None = None
    siem_webhook_token: SecretStr | None = None
    connector_delivery_timeout_seconds: float = Field(default=10.0, ge=1, le=60)
    connector_max_attempts: int = Field(default=5, ge=1, le=20)
    connector_poll_interval_seconds: int = Field(default=5, ge=1, le=300)
    alert_evaluation_interval_seconds: int = Field(default=30, ge=1, le=3600)
    intent_expiry_interval_seconds: int = Field(default=60, ge=1, le=3600)
    internal_automation_interval_seconds: int = Field(default=5, ge=1, le=300)
    command_signing_key: SecretStr | None = None
    llm_api_key: SecretStr | None = None
    llm_base_url: str = "https://api.openai.com/v1"
    llm_model: str = "gpt-4o-mini"
    embedding_model: str = "text-embedding-3-small"
    embedding_dimensions: int = Field(default=1536, ge=1)
    rag_top_k: int = Field(default=12, ge=1, le=50)
    llm_timeout_seconds: float = Field(default=120.0, ge=5, le=300)
    cors_origins: list[str] = Field(default=["http://localhost:3000", "https://app.nogosec.id"])

    @property
    def is_production(self) -> bool:
        return self.environment.lower() in {"production", "prod"}

@lru_cache
def get_settings() -> Settings:
    return Settings()
