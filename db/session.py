import os
from functools import lru_cache

from dotenv import load_dotenv
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

load_dotenv()


class Base(DeclarativeBase):
    """Base for all ORM models."""


class Settings:
    postgres_url: str
    pool_size: int
    max_overflow: int

    def __init__(self) -> None:
        self.postgres_url = os.getenv(
            "DATABASE_URL",
            "postgresql+asyncpg://postgres:postgres@localhost:5432/threat_monitor",
        )
        self.pool_size = int(os.getenv("DB_POOL_SIZE", "10"))
        self.max_overflow = int(os.getenv("DB_MAX_OVERFLOW", "20"))


@lru_cache
def get_engine():
    cfg = Settings()
    return create_async_engine(
        cfg.postgres_url,
        pool_size=cfg.pool_size,
        max_overflow=cfg.max_overflow,
        pool_pre_ping=True,
        future=True,
    )


@lru_cache
def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(
        bind=get_engine(),
        expire_on_commit=False,
        autoflush=False,
        autocommit=False,
    )


async def get_db() -> AsyncSession:
    """FastAPI dependency that yields an AsyncSession."""
    async_session = get_sessionmaker()
    async with async_session() as session:
        yield session
