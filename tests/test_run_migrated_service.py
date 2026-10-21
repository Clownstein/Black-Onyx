"""The shell-free Compose entrypoint must migrate before serving requests."""

from __future__ import annotations

import sys
from unittest.mock import patch

import pytest

from scripts import run_migrated_service


def test_migration_finishes_before_server_exec() -> None:
    calls: list[str] = []

    def migrate(*args: object, **kwargs: object) -> None:
        assert args == ([sys.executable, "-m", "alembic", "upgrade", "head"],)
        assert kwargs == {"check": True}
        calls.append("migrate")

    def serve(*args: object) -> None:
        assert args == (
            sys.executable,
            [
                sys.executable, "-m", "uvicorn", "example.main:app",
                "--host", "0.0.0.0", "--port", "8083",
            ],
        )
        calls.append("serve")

    with patch.object(sys, "argv", ["run_migrated_service.py", "example.main:app", "8083"]), \
         patch.object(run_migrated_service.subprocess, "run", side_effect=migrate), \
         patch.object(run_migrated_service.os, "execv", side_effect=serve):
        run_migrated_service.main()

    assert calls == ["migrate", "serve"]


@pytest.mark.parametrize("port", ["0", "65536", "invalid"])
def test_invalid_port_does_not_migrate(port: str) -> None:
    with patch.object(sys, "argv", ["run_migrated_service.py", "example.main:app", port]), \
         patch.object(run_migrated_service.subprocess, "run") as migrate:
        with pytest.raises((SystemExit, ValueError)):
            run_migrated_service.main()
        migrate.assert_not_called()
