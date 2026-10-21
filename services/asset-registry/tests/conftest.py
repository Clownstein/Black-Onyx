from __future__ import annotations

import os
import sys
from pathlib import Path

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

from asset_registry.config import settings  # noqa: E402

settings.oidc_disabled = True
