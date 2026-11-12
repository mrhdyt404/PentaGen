from ...models import LLMProviderConfig
from .base import BaseLLMProvider, LLMProviderError
from .cloud import CloudOpenAIAdapter
from .ollama import OllamaAdapter


def build_provider_adapter(config: LLMProviderConfig | None) -> BaseLLMProvider | None:
    """Instantiate the configured Cloud or Ollama adapter from an organization provider record."""
    if config is None or not config.is_active:
        return None
    if config.provider_type == "cloud_openai":
        return CloudOpenAIAdapter(
            base_url=config.base_url,
            model_name=config.model_name,
            api_key_env_var=config.api_key_env_var,
        )
    if config.provider_type == "ollama":
        return OllamaAdapter(
            base_url=config.base_url,
            model_name=config.model_name,
        )
    raise LLMProviderError(f"Unsupported provider_type '{config.provider_type}'.")

