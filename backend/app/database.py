"""Async SQLAlchemy 2.0 engine, session factory and schema bootstrap for SQLite."""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from sqlalchemy import event
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.config import get_settings


class Base(DeclarativeBase):
    """Declarative base for every ORM model."""


def _ensure_sqlite_directory(database_url: str) -> None:
    url = make_url(database_url)
    if url.get_backend_name() == "sqlite" and url.database and url.database != ":memory:":
        Path(url.database).parent.mkdir(parents=True, exist_ok=True)


def _build_engine() -> AsyncEngine:
    settings = get_settings()
    _ensure_sqlite_directory(settings.database_url)
    async_engine = create_async_engine(
        settings.database_url,
        echo=settings.database_echo,
        connect_args={"timeout": 30},
    )

    if async_engine.dialect.name == "sqlite":

        @event.listens_for(async_engine.sync_engine, "connect")
        def _configure_sqlite(dbapi_connection: Any, _connection_record: Any) -> None:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    return async_engine


engine: AsyncEngine = _build_engine()
SessionLocal: async_sessionmaker[AsyncSession] = async_sessionmaker(engine, expire_on_commit=False)


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency yielding a transactional session."""
    async with SessionLocal() as session:
        yield session


async def init_db() -> None:
    """Create all tables if they do not exist yet."""
    from app import models  # noqa: F401  (registers mappers on Base.metadata)

    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)


async def dispose_db() -> None:
    """Close every pooled connection."""
    await engine.dispose()
