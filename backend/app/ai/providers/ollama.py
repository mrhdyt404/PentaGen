from urllib.parse import urlparse
import httpx
from ...config import settings
from .base import BaseLLMProvider, LLMProviderError, extract_json_object


class OllamaAdapter(BaseLLMProvider):
    """Adapter for local Ollama chat inference with JSON mode enabled."""

    provider_name = "ollama"

    def __init__(
        self,
        *,
        base_url: str | None = None,
        model_name: str | None = None,
        timeout_seconds: float | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        raw_url = (base_url or settings.ollama_base_url).rstrip("/")
        parsed = urlparse(raw_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise LLMProviderError("Ollama base_url must be a valid HTTP/HTTPS URL.")
        self.base_url = raw_url
        self.model_name = model_name or settings.ollama_default_model
        self.timeout_seconds = timeout_seconds or settings.ai_timeout_seconds
        self._transport = transport

    async def complete_json(self, *, system_prompt: str, user_prompt: str) -> dict:
        payload = {
            "model": self.model_name,
            "stream": False,
            "format": "json",
            "options": {"temperature": 0.1},
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        timeout = httpx.Timeout(self.timeout_seconds, connect=min(self.timeout_seconds, 5.0))
        try:
            async with httpx.AsyncClient(timeout=timeout, transport=self._transport) as client:
                resp = await client.post(f"{self.base_url}/api/chat", json=payload)
        except httpx.HTTPError as exc:
            raise LLMProviderError(f"Ollama request failed: {type(exc).__name__}") from exc

        if resp.status_code >= 400:
            raise LLMProviderError(f"Ollama returned HTTP {resp.status_code}.")

        try:
            body = resp.json()
            content = body["message"]["content"]
        except (ValueError, KeyError, TypeError) as exc:
            raise LLMProviderError("Unexpected response structure from Ollama.") from exc

        return extract_json_object(content)

    async def health_check(self) -> dict:
        timeout = httpx.Timeout(min(self.timeout_seconds, 5.0))
        try:
            async with httpx.AsyncClient(timeout=timeout, transport=self._transport) as client:
                resp = await client.get(f"{self.base_url}/api/tags")
            if resp.status_code >= 400:
                return {"status": f"http_{resp.status_code}", "provider": self.provider_name, "model": self.model_name}
            models = [m.get("name") for m in (resp.json().get("models") or []) if isinstance(m, dict)]
            return {
                "status": "ok",
                "provider": self.provider_name,
                "model": self.model_name,
                "available_models": models[:20],
            }
        except httpx.HTTPError as exc:
            return {
                "status": f"unreachable:{type(exc).__name__}",
                "provider": self.provider_name,
                "model": self.model_name,
            }

