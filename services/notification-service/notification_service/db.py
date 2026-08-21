from collections.abc import Generator

from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from notification_service.config import settings


class Base(DeclarativeBase):
    pass


connect_args: dict[str, object] = {}
if settings.database_url.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(settings.database_url, pool_pre_ping=True, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def ensure_schema() -> None:
    if settings.database_url.startswith("sqlite") and ":memory:" in settings.database_url:
        Base.metadata.create_all(bind=engine)
        return
    if "email_outbox" not in set(inspect(engine).get_table_names()):
        raise RuntimeError(
            "notification-service schema is not migrated; missing email_outbox"
        )
