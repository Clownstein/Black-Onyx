"""Declarative bases for auth and tip Alembic targets."""

from sqlalchemy.orm import DeclarativeBase


class AuthBase(DeclarativeBase):
    pass


class TipBase(DeclarativeBase):
    pass
