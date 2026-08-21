from collections.abc import Generator
from functools import lru_cache

from sqlalchemy import create_engine, event, inspect
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool

from incident_api.config import settings


class Base(DeclarativeBase):
    pass


def _database_url() -> str:
    if settings.use_sqlite:
        path = settings.sqlite_path
        return f"sqlite+pysqlite:///{path}" if path != ":memory:" else "sqlite+pysqlite:///:memory:"
    return settings.database_url


@lru_cache(maxsize=1)
def get_engine() -> Engine:
    if settings.use_sqlite:
        eng = create_engine(
            _database_url(),
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )

        @event.listens_for(eng, "connect")
        def _sqlite_fk(dbapi_connection, _connection_record) -> None:  # type: ignore[no-untyped-def]
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

        return eng
    return create_engine(_database_url(), pool_pre_ping=True)


@lru_cache(maxsize=1)
def _session_factory():
    return sessionmaker(bind=get_engine(), autoflush=False, autocommit=False)


# Back-compat attribute used by alembic/tests.
@property  # type: ignore[misc]
def engine() -> Engine:  # noqa: A001 - keep historical name
    return get_engine()


class _EngineProxy:
    def __getattr__(self, name: str):
        return getattr(get_engine(), name)

    def connect(self, *args, **kwargs):
        return get_engine().connect(*args, **kwargs)

    def begin(self, *args, **kwargs):
        return get_engine().begin(*args, **kwargs)


engine = _EngineProxy()


def get_db() -> Generator[Session, None, None]:
    db = _session_factory()()
    try:
        yield db
    finally:
        db.close()


def create_session() -> Session:
    """Create a service-owned session for background workers."""

    return _session_factory()()


def ensure_schema(required_tables: set[str]) -> None:
    """Fail fast when deployable databases have not run Alembic migrations.

    Unit tests intentionally use in-memory SQLite and may build metadata
    directly. Runtime PostgreSQL databases must be migrated before startup.
    """
    if settings.use_sqlite:
        Base.metadata.create_all(bind=get_engine())
        return
    present = set(inspect(get_engine()).get_table_names())
    missing = sorted(required_tables - present)
    if missing:
        raise RuntimeError(
            "database schema is not migrated; missing tables "
            f"{', '.join(missing)}. Run `alembic upgrade head` before startup."
        )
