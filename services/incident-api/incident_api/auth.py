"""Auth helpers — re-export tenant dependency for clarity."""

from incident_api.tenant import require_tenant

__all__ = ["require_tenant"]
