from __future__ import annotations

import sys
from collections.abc import Generator
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

SERVICE_ROOT = Path(__file__).resolve().parents[1]
service_root = str(SERVICE_ROOT)
if service_root in sys.path:
    sys.path.remove(service_root)
sys.path.insert(0, service_root)

for name in list(sys.modules):
    if name == "app" or name.startswith("app."):
        del sys.modules[name]


@pytest.fixture()
def db_session() -> Generator[Session, None, None]:
    from threat_intel_service.db import Base
    from threat_intel_service import models  # noqa: F401

    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    session = SessionLocal()
    try:
        yield session
        session.commit()
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)
