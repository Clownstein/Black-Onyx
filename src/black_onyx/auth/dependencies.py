"""FastAPI authentication dependencies."""

from __future__ import annotations

from fastapi import Depends, HTTPException, Request, status

from black_onyx.auth.service import Principal, Role


def current_principal(request: Request) -> Principal:
    principal = getattr(request.state, "principal", None)
    if principal is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    return principal


def require_roles(*roles: Role):
    def dependency(principal: Principal = Depends(current_principal)) -> Principal:
        if principal.role not in roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permission")
        return principal
    return dependency


require_authenticated = current_principal
require_admin = require_roles(Role.ADMIN)
require_analyst = require_roles(Role.ADMIN, Role.ANALYST)
require_viewer = require_roles(Role.ADMIN, Role.ANALYST, Role.VIEWER)
