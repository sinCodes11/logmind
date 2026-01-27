"""Application settings using Pydantic."""

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Application
    app_name: str = "LogMind"
    log_level: str = "INFO"
    debug: bool = False

    # Redis
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_password: SecretStr | None = None
    redis_db: int = 0
    redis_stream_name: str = "logmind:logs"
    redis_consumer_group: str = "logmind-workers"

    # PostgreSQL
    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_user: str = "logmind"
    postgres_password: SecretStr = Field(default=SecretStr("logmind"))
    postgres_db: str = "logmind"

    # LLM Provider
    llm_provider: Literal["claude", "oci"] = "claude"
    llm_model: str = "claude-sonnet-4-20250514"
    llm_max_tokens: int = 4096
    llm_temperature: float = 0.1

    # Anthropic Claude
    anthropic_api_key: SecretStr | None = None

    # OCI Generative AI
    oci_config_file: str = "~/.oci/config"
    oci_config_profile: str = "DEFAULT"
    oci_compartment_id: str | None = None
    oci_genai_endpoint: str = "https://inference.generativeai.us-chicago-1.oci.oraclecloud.com"
    oci_genai_model: str = "cohere.command-r-plus"

    # Sigma Rules
    sigma_rules_path: str = "rules"

    # MITRE ATT&CK
    mitre_attack_data_path: str = "data/mitre/enterprise-attack.json"

    # Alerting
    slack_webhook_url: SecretStr | None = None
    slack_channel: str = "#security-alerts"

    # Processing
    batch_size: int = 100
    processing_interval: float = 1.0  # seconds

    @property
    def redis_url(self) -> str:
        """Build Redis connection URL."""
        password = ""
        if self.redis_password:
            password = f":{self.redis_password.get_secret_value()}@"
        return f"redis://{password}{self.redis_host}:{self.redis_port}/{self.redis_db}"

    @property
    def postgres_dsn(self) -> str:
        """Build PostgreSQL connection DSN."""
        password = self.postgres_password.get_secret_value()
        return (
            f"postgresql://{self.postgres_user}:{password}@"
            f"{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
