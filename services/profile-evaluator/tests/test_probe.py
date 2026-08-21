from __future__ import annotations

import httpx
import respx
from profile_evaluator.novelty import vector_novelty_contributor, vector_novelty_score
from profile_evaluator.probe import probe_targets, probe_url


@respx.mock
def test_probe_detects_missing_security_headers() -> None:
    respx.get("https://app.test/").mock(
        return_value=httpx.Response(
            200,
            headers={"x-content-type-options": "nosniff"},
        )
    )
    with httpx.Client() as client:
        result = probe_url("https://app.test/", client=client)
    assert result["reachable"] is True
    assert result["tls"] is True
    assert result["status_code"] == 200
    assert "x-content-type-options" in result["present_security_headers"]
    assert "content-security-policy" in result["missing_security_headers"]


@respx.mock
def test_probe_soft_fails_on_transport_error() -> None:
    respx.get("https://down.test/").mock(side_effect=httpx.ConnectError("boom"))
    with httpx.Client() as client:
        results = probe_targets(["https://down.test/"], client=client)
    assert results[0]["reachable"] is False
    assert results[0]["error"] is not None


def test_probe_flags_non_tls_scheme() -> None:
    with respx.mock:
        respx.get("http://plain.test/").mock(return_value=httpx.Response(200))
        with httpx.Client() as client:
            result = probe_url("http://plain.test/", client=client)
    assert result["tls"] is False


def test_vector_novelty_disabled_is_zero() -> None:
    assert vector_novelty_score(False) == 0.0
    off = vector_novelty_contributor(False)
    assert off["enabled"] is False
    assert off["value"] == 0.0
    assert off["weight"] == 0.0


def test_vector_novelty_enabled_without_dependencies_is_degraded() -> None:
    score = vector_novelty_score(True, text="baseline-sample")
    assert score == 0.0
    on = vector_novelty_contributor(True, text="baseline-sample")
    assert on["enabled"] is True
    assert on["value"] == score
    assert on["weight"] == 0.0
    assert on["status"] == "degraded"
    assert on["active"] is False
