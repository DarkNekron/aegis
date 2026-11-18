"""Alembic environment for AEGIS.

The database URL comes from, in order:
1. ``config.attributes["connection"]``: an open connection passed by ``Database.migrate()``
2. ``config.attributes["connection_url"]``
3. AEGIS settings (``AEGIS_DATABASE_URL`` or ``<data_dir>/aegis.db``), for CLI use such as
   ``python -m alembic revision --autogenerate -m "..."``

``render_as_batch`` is enabled so ALTER TABLE operations work on SQLite.
"""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context

import app.models  # noqa: F401  (registers all tables)
from app.db.base import Base
from app.db.session import make_engine

config = context.config
target_metadata = Base.metadata

if config.config_file_name is not None and config.attributes.get("connection") is None:
    fileConfig(config.config_file_name, disable_existing_loggers=False)


def _url() -> str:
    url = config.attributes.get("connection_url")
    if url:
        return url
    from app.core.config import get_settings

    return get_settings().database_url


def _configure(connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        render_as_batch=True,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_offline() -> None:
    context.configure(url=_url(), target_metadata=target_metadata, literal_binds=True, render_as_batch=True,
                      dialect_opts={"paramstyle": "named"})
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connection = config.attributes.get("connection")
    if connection is not None:
        _configure(connection)
        return
    engine = make_engine(_url())
    with engine.connect() as conn:
        _configure(conn)
    engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
