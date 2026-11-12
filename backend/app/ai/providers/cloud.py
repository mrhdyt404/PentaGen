import os
from urllib.parse import urlparse
import httpx
from ...config import settings
from .base import BaseLLMProvider, LLMProviderError, extract_json_object


class CloudOpenAIAdapter(BaseLLMProvider):
    """Adapter for OpenAI-compatible cloud LLM Chat Completions APIs."""

    provider_name = "cloud_openai"

    def __init__(
        self,
        *,
        base_url: str | None = None,
        model_name: str | None = None,
        api_key: str | None = None,
        api_key_env_var: str | None = None,
        timeout_seconds: float | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        raw_url = (base_url or settings.cloud_llm_base_url).rstrip("/")
        parsed = urlparse(raw_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise LLMProviderError("Cloud LLM base_url must be a valid HTTP/HTTPS URL.")
        self.base_url = raw_url
        self.model_name = model_name or settings.cloud_llm_model
        resolved_key = api_key
        if resolved_key is None and api_key_env_var:
            resolved_key = os.environ.get(api_key_env_var, "")
        if not resolved_key:
            resolved_key = settings.cloud_llm_api_key
        self._api_key = resolved_key or ""
        self.timeout_seconds = timeout_seconds or settings.ai_timeout_seconds
        self._transport = transport

    def _headers(self) -> dict[str, str]:
        if not self._api_key:
            raise LLMProviderError("Cloud LLM API key is not configured.")
        return {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }

    async def complete_json(self, *, system_prompt: str, user_prompt: str) -> dict:
        payload = {
            "model": self.model_name,
            "temperature": 0.1,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        timeout = httpx.Timeout(self.timeout_seconds, connect=min(self.timeout_seconds, 5.0))
        try:
            async with httpx.AsyncClient(timeout=timeout, transport=self._transport) as client:
                resp = await client.post(
                    f"{self.base_url}/chat/completions",
                    headers=self._headers(),
                    json=payload,
                )
        except httpx.HTTPError as exc:
            raise LLMProviderError(f"Cloud LLM request failed: {type(exc).__name__}") from exc

        if resp.status_code >= 400:
            raise LLMProviderError(f"Cloud LLM returned HTTP {resp.status_code}.")

        try:
            body = resp.json()
            content = body["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise LLMProviderError("Unexpected response structure from Cloud LLM.") from exc

        return extract_json_object(content)

    async def health_check(self) -> dict:
        if not self._api_key:
            return {"status": "unconfigured", "provider": self.provider_name, "model": self.model_name}
        timeout = httpx.Timeout(min(self.timeout_seconds, 5.0))
        try:
            async with httpx.AsyncClient(timeout=timeout, transport=self._transport) as client:
                resp = await client.get(f"{self.base_url}/models", headers=self._headers())
            return {
                "status": "ok" if resp.status_code < 400 else f"http_{resp.status_code}",
                "provider": self.provider_name,
                "model": self.model_name,
            }
        except httpx.HTTPError as exc:
            return {
                "status": f"unreachable:{type(exc).__name__}",
                "provider": self.provider_name,
                "model": self.model_name,
            }

