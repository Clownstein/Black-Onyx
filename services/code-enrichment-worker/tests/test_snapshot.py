from code_enrichment_worker.snapshot import snapshot_repo


def test_snapshot_from_files():
    with snapshot_repo({"files": {"a/b.py": "print(1)\n"}}) as root:
        assert (root / "a" / "b.py").read_text(encoding="utf-8") == "print(1)\n"


def test_snapshot_from_diff():
    diff = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -0,0 +1,2 @@
+def foo():
+    return 1
"""
    with snapshot_repo({"diff": diff}) as root:
        text = (root / "app.py").read_text(encoding="utf-8")
        assert "def foo" in text
