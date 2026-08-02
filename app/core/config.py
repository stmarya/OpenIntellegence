"""Application configuration.

All secrets come from the environment. Nothing is hardcoded here — the
legacy collector scripts embedded a Ransomware.live PRO key in source,
which is exactly the failure mode this module exists to prevent.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field, PostgresDsn, RedisDsn, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_nested_delimiter="__",
        extra="ignore",
    )

    # --- Service ---------------------------------------------------------
    environment: str = Field(default="development")
    debug: bool = Field(default=False)
    api_base_url: str = Field(default="https://api.nogosec.id")

    # --- Datastores ------------------------------------------------------
    database_url: PostgresDsn = Field(
        default="postgresql+asyncpg://openintel:openintel@localhost:5432/openintel"
    )
    redis_url: RedisDsn = Field(default="redis://localhost:6379/0")

    # --- API keys --------------------------------------------------------
    # Argon2id parameters. Tuned for ~50ms on a 2-core container.
    argon2_time_cost: int = 3
    argon2_memory_cost: int = 64 * 1024
    argon2_parallelism: int = 2

    api_key_prefix_platform: str = "ngs_live_"
    api_key_prefix_agent: str = "ngs_agnt_"

    # --- Rate limiting ---------------------------------------------------
    default_rate_limit_per_hour: int = 1000

    # --- Agent gateway (mTLS) -------------------------------------------
    agent_ca_cert_path: str | None = None
    agent_ca_key_path: str | None = None
    agent_ca_key_password: SecretStr | None = None
    agent_cert_ttl_days: int = 90
    agent_heartbeat_interval_seconds: int = 60
    # An agent is "stale" after this many missed heartbeats.
    agent_stale_after_missed: int = 5

    # --- Connectors ------------------------------------------------------
    # Every one of these is optional; a missing key disables its connector
    # rather than crashing the ingest run.
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

    # --- AI layer --------------------------------------------------------
    llm_api_key: SecretStr | None = None
    # OpenAI-compatible base URL. Point this at a self-hosted gateway to
    # keep intelligence data off a third-party provider.
    llm_base_url: str = "https://api.openai.com/v1"
    llm_model: str = "gpt-4o-mini"
    embedding_model: str = "text-embedding-3-small"
    embedding_dimensions: int = 1536
    rag_top_k: int = 12

    # --- HTTP ------------------------------------------------------------
    # Explicit allowlist. A wildcard here combined with credentialed
    # requests would let any origin read a tenant's intelligence.
    cors_origins: list[str] = Field(default=["http://localhost:3000", "https://app.nogosec.id"])

    @property
    def is_production(self) -> bool:
        return self.environment.lower() in {"production", "prod"}


@lru_cache
def get_settings() -> Settings:
    return Settings()
