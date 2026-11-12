from pathlib import Path
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_ROOT_ENV = Path(__file__).resolve().parents[2] / ".env"
_PLACEHOLDER_SECRETS = {
    "development-only-change-this-secret-32-bytes",
    "replace-with-a-long-random-secret-at-least-32-bytes",
}


class Settings(BaseSettings):
    """Application runtime configuration loaded from environment variables or .env."""

    app_name: str = "PentaGen"
    app_env: str = "development"
    api_prefix: str = "/api/v1"
    database_url: str = "sqlite:///./pentagen-dev.db"
    redis_url: str = "redis://localhost:6379/0"
    jwt_secret: str = "development-only-change-this-secret-32-bytes"
    jwt_issuer: str = "pentagen-api"
    jwt_audience: str = "pentagen-client"
    access_token_minutes: int = 30
    refresh_token_days: int = 7
    cors_origins: str = "http://localhost:5173"
    artifacts_dir: str = str(Path(__file__).resolve().parents[2] / "data" / "artifacts")
    enable_semgrep_cli: bool = False
    scanner_timeout_seconds: float = 8.0
    ollama_base_url: str = "http://127.0.0.1:11434"
    ollama_default_model: str = "llama3.1"
    cloud_llm_base_url: str = "https://api.openai.com/v1"
    cloud_llm_model: str = "gpt-4o-mini"
    cloud_llm_api_key: str = ""
    ai_timeout_seconds: float = 20.0

    model_config = SettingsConfigDict(
        env_file=(".env", str(_ROOT_ENV)) if _ROOT_ENV.exists() else ".env",
        extra="ignore",
    )

    @field_validator("access_token_minutes")
    @classmethod
    def _positive_access_minutes(cls, value: int) -> int:
        if value < 1 or value > 1440:
            raise ValueError("access_token_minutes must be between 1 and 1440.")
        return value

    @field_validator("refresh_token_days")
    @classmethod
    def _positive_refresh_days(cls, value: int) -> int:
        if value < 1 or value > 90:
            raise ValueError("refresh_token_days must be between 1 and 90.")
        return value

    @property
    def cors_origins_list(self) -> list[str]:
        """Return parsed non-empty CORS origins."""
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    def validate_runtime_security(self) -> None:
        """Reject weak or placeholder secrets outside development and test environments."""
        if self.app_env.lower() in {"development", "test"}:
            return
        if len(self.jwt_secret.encode("utf-8")) < 32 or self.jwt_secret in _PLACEHOLDER_SECRETS:
            raise RuntimeError(
                "Refusing to start outside development/test with a weak or placeholder JWT_SECRET."
            )


settings = Settings()
