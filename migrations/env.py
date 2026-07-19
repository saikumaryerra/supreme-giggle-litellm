from __future__ import annotations

import os

from alembic import context
from sqlalchemy import create_engine, pool

from litellm_ext.audit.models import Base

target_metadata = Base.metadata


def _database_url() -> str:
    url = os.environ.get("LITELLM_EXT_AUDIT_DB_URL", "")
    if not url:
        raise RuntimeError("LITELLM_EXT_AUDIT_DB_URL is required for migrations")
    # Alembic runs sync; strip the asyncpg driver marker.
    return url.replace("postgresql+asyncpg://", "postgresql://")


def run_migrations_offline() -> None:
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = create_engine(_database_url(), poolclass=pool.NullPool)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
