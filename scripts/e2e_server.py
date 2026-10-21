"""Isolated local application server for Playwright authentication acceptance tests."""

from __future__ import annotations

import atexit
import os
import shutil
import sys
import tempfile
from pathlib import Path

project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root / "src"))
temp_parent = project_root / ".pytest-tmp"
temp_parent.mkdir(exist_ok=True)
state_dir = tempfile.mkdtemp(prefix="e2e-state-", dir=temp_parent)
atexit.register(shutil.rmtree, state_dir, ignore_errors=True)

os.environ["QDRANT_STORAGE__STATE_DIR"] = state_dir
os.environ["QDRANT_SECURITY__EXTERNAL_URL"] = "http://127.0.0.1:8765"
os.environ["QDRANT_SECURITY__ALLOWED_HOSTS"] = '["127.0.0.1","localhost"]'
# Browser acceptance covers local authentication, RBAC, and route delivery.
# Keep optional ingestion schedulers disabled so this hermetic server never
# reaches external feeds/connectors or requires a Qdrant sidecar.
os.environ["QDRANT_FEEDS__ENABLED"] = "false"
os.environ["QDRANT_CONNECTORS__ENABLED"] = "false"
os.environ["BLACK_ONYX_AUTH_SECRET"] = "e2e-only-authentication-secret-at-least-32-bytes"

from black_onyx.api.service import get_service
from black_onyx.auth.context import get_auth_service


class _UnavailableQdrant:
    """Fast, explicit offline boundary for auth/RBAC browser acceptance."""

    def get_server_version(self) -> str:
        return "e2e-unavailable"

    def list_collections(self) -> list[str]:
        return []

    def __getattr__(self, name: str):
        raise RuntimeError(f"Qdrant operation {name} is outside E2E auth scope")


# The acceptance server does not claim vector-store coverage. Avoid the normal
# best-effort Qdrant bootstrap and its retry delay; all exercised endpoints use
# the isolated SQLite state above.
service = get_service()
service._qdrant_store = _UnavailableQdrant()
service.ensure_default_collections = list  # type: ignore[method-assign]
get_auth_service().bootstrap_admin(
    "admin@example.com", "correct horse battery staple", "E2E Administrator"
)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("black_onyx.api.app:app", host="127.0.0.1", port=8765, log_level="warning")
