from __future__ import annotations

import os
import sys
from pathlib import Path

# Configure SQLite before any app imports.
os.environ["INCIDENT_API_USE_SQLITE"] = "true"
os.environ["INCIDENT_API_SQLITE_PATH"] = ":memory:"
os.environ["INCIDENT_API_OPENSEARCH_INDEXING"] = "false"
os.environ["ALLOW_DEMO_KEYS"] = "true"
# Unit tests use X-Tenant-Id / X-Role headers (OIDC-off). Production defaults remain fail-closed.
os.environ["OIDC_DISABLED"] = "true"

SERVICE_ROOT = Path(__file__).resolve().parents[1]
service_root = str(SERVICE_ROOT)
if service_root in sys.path:
    sys.path.remove(service_root)
sys.path.insert(0, service_root)

for name in list(sys.modules):
    if name == "app" or name.startswith("app."):
        del sys.modules[name]

# Settings may already be imported by a prior collection; force test auth mode.
from incident_api.config import settings  # noqa: E402

settings.oidc_disabled = True
settings.allow_demo_keys = True
