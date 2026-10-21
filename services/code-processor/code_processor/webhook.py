from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Header, HTTPException, Request

from code_processor.config import settings
from code_processor.signature import verify_github_signature

router = APIRouter()


@router.post("/api/v1/integrations/code/{provider}/webhook")
async def code_webhook(
    provider: str,
    request: Request,
    x_hub_signature_256: str | None = Header(default=None),
) -> dict[str, Any]:
    body = await request.body()
    if not verify_github_signature(body, x_hub_signature_256 or "", settings.webhook_secret):
        raise HTTPException(status_code=401, detail="invalid signature")
    return {
        "status": "accepted",
        "provider": provider,
        "bytes": len(body),
        "note": "signature verified; prefer ingestion-gateway for Kafka publish",
    }
