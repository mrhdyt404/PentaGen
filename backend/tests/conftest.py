import os
from pathlib import Path
import shutil
import sys
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Configure isolated test defaults before importing application modules.
os.environ["APP_ENV"] = "test"
os.environ["JWT_SECRET"] = "test-only-secret-key-with-more-than-32-bytes"
os.environ["DATABASE_URL"] = "sqlite:///./pentagen-test-bootstrap.db"

from backend.app.db import get_db
from backend.app.main import app


@pytest.fixture(scope="session")
def migrated_template_db(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Run Alembic head migration once per test session and reuse as a clean template."""
    db_file = tmp_path_factory.mktemp("alembic_template") / "template.db"
    alembic_cfg = Config(str(PROJECT_ROOT / "backend" / "alembic.ini"))
    alembic_cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_file.as_posix()}")
    command.upgrade(alembic_cfg, "head")
    return db_file


@pytest.fixture()
def db_url(tmp_path: Path, migrated_template_db: Path) -> str:
    """Copy the migrated SQLite template for fast per-test database isolation."""
    db_file = tmp_path / "test_pentagen.db"
    shutil.copyfile(migrated_template_db, db_file)
    return f"sqlite:///{db_file.as_posix()}"


@pytest.fixture()
def db_session_factory(db_url: str):
    """Provide an isolated SQLAlchemy sessionmaker bound to the migrated test DB."""
    engine = create_engine(db_url, connect_args={"check_same_thread": False})
    SessionTesting = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    try:
        yield SessionTesting
    finally:
        engine.dispose()


@pytest.fixture()
def client(db_session_factory):
    """Provide a FastAPI TestClient wired to the isolated test DB session."""

    def _override_get_db():
        db = db_session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = _override_get_db
    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.clear()
