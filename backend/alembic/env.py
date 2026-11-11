from logging.config import fileConfig
import os
from pathlib import Path
import sys
from alembic import context
from sqlalchemy import create_engine, pool

# Ensure the project root (containing the `backend` package) is importable.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.config import settings
from backend.app.db import Base
import backend.app.models  # noqa: F401  # Register all ORM models on Base.metadata

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _resolve_database_url() -> str:
    return (
        config.get_main_option("sqlalchemy.url")
        or os.environ.get("DATABASE_URL")
        or settings.database_url
    )


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode without creating a live DB connection."""
    url = _resolve_database_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True,
        render_as_batch=url.startswith("sqlite"),
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode using an engine connection."""
    url = _resolve_database_url()
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    connectable = create_engine(url, poolclass=pool.NullPool, connect_args=connect_args)

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            render_as_batch=url.startswith("sqlite"),
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

