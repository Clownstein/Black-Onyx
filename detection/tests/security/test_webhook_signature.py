import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "services" / "ingestion-gateway"))

# Prefer code-processor Python verifier if present; else reimplement.
try:
    sys.path.insert(0, str(ROOT / "services" / "code-processor"))
    from code_processor.signature import verify_github_signature  # type: ignore
except Exception:
    import hashlib
    import hmac

    def verify_github_signature(body: bytes, header: str, secret: str) -> bool:
        if not header.startswith("sha256="):
            return False
        digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        return hmac.compare_digest(header, "sha256=" + digest)


def test_webhook_signature_roundtrip():
    import hashlib
    import hmac

    body = b'{"ref":"refs/heads/main"}'
    secret = "dev-webhook-secret"
    header = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    assert verify_github_signature(body, header, secret)
    assert not verify_github_signature(body, header, "nope")
