"""Engine/session management and schema migration on startup."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, create_engine, event, text
from sqlalchemy.orm import Session, sessionmaker

BACKEND_DIR = Path(__file__).resolve().parents[2]


def _sqlite_pragmas(dbapi_connection, _record) -> None:
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")      # enforce FK + ON DELETE CASCADE
    cursor.execute("PRAGMA journal_mode=WAL")     # readers don't block the writer
    cursor.execute("PRAGMA synchronous=NORMAL")   # safe with WAL, much faster than FULL
    cursor.execute("PRAGMA busy_timeout=5000")    # wait instead of failing on brief lock contention
    cursor.close()


def make_engine(database_url: str) -> Engine:
    if database_url.startswith("sqlite"):
        db_path = database_url.split("///", 1)[-1]
        if db_path and db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        engine = create_engine(database_url, connect_args={"check_same_thread": False})
        event.listen(engine, "connect", _sqlite_pragmas)
        return engine
    return create_engine(database_url, pool_pre_ping=True)


class Database:
    def __init__(self, database_url: str):
        self.url = database_url
        self.engine = make_engine(database_url)
        self.session_factory = sessionmaker(bind=self.engine, expire_on_commit=False, autoflush=False)

    def migrate(self) -> None:
        """Bring the schema to the latest Alembic revision (idempotent)."""
        cfg = Config(str(BACKEND_DIR / "alembic.ini"))
        cfg.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
        cfg.attributes["connection_url"] = self.url
        with self.engine.begin() as connection:
            cfg.attributes["connection"] = connection
            command.upgrade(cfg, "head")

    def session(self) -> Session:
        return self.session_factory()

    def session_scope(self) -> Iterator[Session]:
        session = self.session_factory()
        try:
            yield session
        finally:
            session.close()

    def ping(self) -> bool:
        with self.engine.connect() as conn:
            return conn.execute(text("SELECT 1")).scalar() == 1

    def size_bytes(self) -> int | None:
        if not self.url.startswith("sqlite"):
            return None
        path = Path(self.url.split("///", 1)[-1])
        return sum(p.stat().st_size for p in (path, Path(f"{path}-wal")) if p.exists())

    def dispose(self) -> None:
        self.engine.dispose()
