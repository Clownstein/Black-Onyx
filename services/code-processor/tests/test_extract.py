from code_processor.diff_parse import parse_unified_diff
from code_processor.extract import extract_changed_functions, extract_python_functions
from code_processor.pipeline import CodePipeline, process_code_change
from code_processor.workspace import materialize_patch_workspace


def test_extract_python_functions_ast():
    src = "def foo():\n    return 1\n\ndef bar(x):\n    return x\n"
    fns = extract_python_functions(src)
    by_name = {f["name"]: f for f in fns}
    assert "foo" in by_name
    assert by_name["foo"]["start_line"] == 1
    assert by_name["foo"]["end_line"] >= 2
    assert "return 1" in by_name["foo"]["body"]
    assert "bar" in by_name


def test_extract_from_diff_and_workspace():
    diff = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -0,0 +1,3 @@
+def risky():
+    password = 'x'
+    return password
"""
    files = parse_unified_diff(diff)
    assert files[0]["path"] == "app.py"
    assert any("password" in line for line in files[0]["added_lines"])

    symbols = extract_changed_functions(diff)
    assert any(s["name"] == "risky" for s in symbols)

    with materialize_patch_workspace({"diff": diff}) as tmp:
        from pathlib import Path

        assert (Path(tmp) / "app.py").exists()

    result = process_code_change({"tenant_id": "t1", "asset_id": "repo", "diff": diff})
    assert result["feature"]["changed_symbols"]
    assert "scanner_findings" in result["finding"]

    features, findings = CodePipeline().process_events(
        [{"tenant_id": "t1", "asset": {"asset_id": "repo"}, "payload": {"diff": diff}}]
    )
    assert features[0]["changed_symbols"]
    assert "scanner_findings" in findings[0]
