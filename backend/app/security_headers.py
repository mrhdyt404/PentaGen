from collections import defaultdict
import time
from typing import Callable
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from .config import settings

# In-memory sliding window rate limiter: {ip: {endpoint: [timestamps]}}
_RATE_LIMIT_STORE: dict[str, dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))

# Rate limit rules: endpoint prefix -> (max_requests, window_seconds)
RATE_LIMIT_RULES: dict[str, tuple[int, int]] = {
    "/api/v1/auth/login": (15, 60),
    "/api/v1/auth/register": (10, 60),
    "/api/v1/agents/pairing/pair": (15, 60),
}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Enforce defense-in-depth OWASP security headers on all HTTP responses."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response: Response = await call_next(request)

        # 1. Prevent MIME-sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # 2. Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"

        # 3. Referrer control
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # 4. Restrict dangerous browser features
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"

        # 5. Content Security Policy (CSP)
        csp = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self' http://127.0.0.1:* http://localhost:*; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )
        response.headers["Content-Security-Policy"] = csp

        # 6. HTTP Strict Transport Security (HSTS) in production
        if settings.app_env == "production":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Sliding-window IP rate limiter protecting sensitive authentication and pairing endpoints."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        path = request.url.path

        # Match rate limiting rules
        matched_rule = None
        for rule_path, config in RATE_LIMIT_RULES.items():
            if path == rule_path:
                matched_rule = config
                break

        if matched_rule is not None and getattr(settings, "rate_limit_enabled", True):
            max_requests, window_seconds = matched_rule
            client_ip = request.client.host if request.client else "127.0.0.1"
            now = time.time()

            # Filter out timestamps outside window
            timestamps = _RATE_LIMIT_STORE[client_ip][path]
            _RATE_LIMIT_STORE[client_ip][path] = [ts for ts in timestamps if now - ts < window_seconds]

            if len(_RATE_LIMIT_STORE[client_ip][path]) >= max_requests:
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Too many requests. Please slow down and try again later."},
                    headers={"Retry-After": str(window_seconds)},
                )

            _RATE_LIMIT_STORE[client_ip][path].append(now)

        return await call_next(request)
