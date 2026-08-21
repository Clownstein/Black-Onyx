from threat_intel_service.config import settings
from threat_intel_service.semantic import semantic_match


def test_semantic_match_disabled_returns_empty(db_session, monkeypatch):
    monkeypatch.setattr(settings, "vector_search_enabled", False)
    result = semantic_match(
        db_session,
        [{"type": "ipv4", "value": "203.0.113.50"}],
        enabled=False,
        max_confidence=0.75,
    )
    assert result["match_type"] == "semantic"
    assert result["matches"] == []
    assert result["warnings"]
