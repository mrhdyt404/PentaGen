import re
from ..scanners.evidence import redact_sensitive_text

_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_TAG_ESCAPE_RE = re.compile(r"</?(?:untrusted_scan_data|system|assistant|user|instructions)\b[^>]*>", re.IGNORECASE)


def sanitize_untrusted_text(text: str | None, *, max_len: int = 1200) -> str:
    """Redact secrets, strip control bytes, and neutralize prompt-injection delimiters."""
    if not text:
        return ""
    cleaned = _CONTROL_CHARS_RE.sub("", text)
    cleaned = _TAG_ESCAPE_RE.sub("[ESCAPED_TAG]", cleaned)
    return redact_sensitive_text(cleaned, max_len=max_len)


def wrap_untrusted_block(label: str, text: str | None, *, max_len: int = 1200) -> str:
    """Wrap sanitized target-derived text inside explicit untrusted data boundaries."""
    safe = sanitize_untrusted_text(text, max_len=max_len)
    return f"<untrusted_scan_data field=\"{label}\">\n{safe}\n</untrusted_scan_data>"

