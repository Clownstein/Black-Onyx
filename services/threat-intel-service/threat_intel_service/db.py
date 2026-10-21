from collections.abc import Generator

from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from threat_intel_service.config import settings


class Base(DeclarativeBase):
    pass


def _engine_kwargs(url: str) -> dict:
    kwargs: dict = {"pool_pre_ping": True}
    if url.startswith("sqlite"):
        from sqlalchemy.pool import StaticPool

        kwargs["connect_args"] = {"check_same_thread": False}
        if ":memory:" in url:
            kwargs["poolclass"] = StaticPool
    return kwargs


engine = create_engine(settings.database_url, **_engine_kwargs(settings.database_url))
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def ensure_schema() -> None:
    if settings.database_url.startswith("sqlite") and ":memory:" in settings.database_url:
        from threat_intel_service import models  # noqa: F401

        Base.metadata.create_all(bind=engine)
        return
    missing = {"indicators", "feed_health", "feed_checkpoints"} - set(
        inspect(engine).get_table_names()
    )
    if missing:
        raise RuntimeError(
            "threat-intel schema is not migrated; missing "
            f"{', '.join(sorted(missing))}"
        )


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
