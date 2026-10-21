from code_model.scorer import ChangeRiskModel


def _dataset():
    risky = {
        "diff_text": "+password = 'supersecret'\n+eval(x)\n",
        "files_changed": ["auth.py"],
        "diff_stats": {"added_lines": 2},
        "scanner_findings": [
            {
                "scanner": "semgrep",
                "rule_id": "hardcoded-credentials",
                "path": "auth.py",
                "start_line": 1,
                "message": "hardcoded password",
            }
        ],
    }
    safe = {
        "diff_text": "+def add(a, b):\n+    return a + b\n",
        "files_changed": ["math_utils.py"],
        "diff_stats": {"added_lines": 2},
        "scanner_findings": [],
    }
    samples = [risky] * 10 + [safe] * 10
    labels = [1] * 10 + [0] * 10
    return samples, labels, risky, safe


def test_predict_returns_required_fields():
    samples, labels, risky, _safe = _dataset()
    model = ChangeRiskModel()
    model.fit(samples, labels)
    result = model.predict(risky)
    assert "risk_score" in result
    assert "risk_categories" in result
    assert "evidence" in result
    assert result["advisory_only"] is True
    assert result["evidence"]
    assert result["evidence"][0].get("file")
    assert result["risk_score"] > 0.5


def test_safe_change_lower_score():
    samples, labels, risky, safe = _dataset()
    model = ChangeRiskModel()
    model.fit(samples, labels)
    assert model.predict(risky)["risk_score"] >= model.predict(safe)["risk_score"]
