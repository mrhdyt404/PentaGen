from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .config import settings
from .routers import audit, auth, scans, targets, users


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Validate runtime security configuration on application startup."""
    settings.validate_runtime_security()
    yield


app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    description="AI-assisted authorized security assessment.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.get("/health")
def health():
    """Public liveness probe endpoint."""
    return {"status": "ok", "service": "pentagen-api", "version": "0.1.0"}


app.include_router(auth.router, prefix=settings.api_prefix)
app.include_router(users.router, prefix=settings.api_prefix)
app.include_router(targets.router, prefix=settings.api_prefix)
app.include_router(scans.router, prefix=settings.api_prefix)
app.include_router(audit.router, prefix=settings.api_prefix)
