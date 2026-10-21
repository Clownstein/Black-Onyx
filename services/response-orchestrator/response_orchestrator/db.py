from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from response_orchestrator.config import settings
from response_orchestrator.models import Base

if settings.database_url.startswith("sqlite"):
    engine = create_engine(
        settings.database_url,
        future=True,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
else:
    engine = create_engine(settings.database_url, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    if settings.database_url.startswith("sqlite") and ":memory:" in settings.database_url:
        Base.metadata.create_all(bind=engine)
        return
    present = set(inspect(engine).get_table_names())
    missing = {"response_requests", "response_audit"} - present
    if missing:
        raise RuntimeError(
            "response-orchestrator schema is not migrated; missing "
            f"{', '.join(sorted(missing))}"
        )
