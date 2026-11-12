from abc import ABC, abstractmethod
import json
import re

_FENCED_JSON_RE = re.compile(r"```(?:json)?\s*(\{[\s\S]*?\})\s*```", re.IGNORECASE)


class LLMProviderError(RuntimeError):
    """Raised when an AI provider call fails, times out, or returns invalid JSON."""


def extract_json_object(raw_text: str) -> dict:
    """Parse a JSON object from raw LLM output, tolerating fenced markdown blocks."""
    text = (raw_text or "").strip()
    if not text:
        raise LLMProviderError("Provider returned empty response.")
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    fenced = _FENCED_JSON_RE.search(text)
    if fenced:
        try:
            parsed = json.loads(fenced.group(1))
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass

    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end > start:
        try:
            parsed = json.loads(text[start : end + 1])
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass

    raise LLMProviderError("Provider output did not contain a valid JSON object.")


class BaseLLMProvider(ABC):
    """Abstract adapter interface shared by cloud LLM and local Ollama providers."""

    provider_name: str = "base"

    @abstractmethod
    async def complete_json(self, *, system_prompt: str, user_prompt: str) -> dict:
        """Send prompts to the model and return a parsed JSON dictionary."""

    @abstractmethod
    async def health_check(self) -> dict:
        """Check reachability and model availability without exposing credentials."""

