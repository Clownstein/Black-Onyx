import hashlib
import hmac

from code_processor.signature import verify_github_signature


def test_verify_github_signature():
    secret = "topsecret"
    body = b'{"ref":"refs/heads/main"}'
    digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    assert verify_github_signature(body, f"sha256={digest}", secret)
    assert not verify_github_signature(body, "sha256=00", secret)
    assert not verify_github_signature(body, "", secret)
