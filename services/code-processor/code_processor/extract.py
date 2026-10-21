from __future__ import annotations

import ast
import re
from typing import Any


def extract_python_functions(source: str) -> list[dict[str, Any]]:
    """Extract top-level and nested functions via ``ast``.

    Returns list of ``{name, start_line, end_line, body}``.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return _regex_extract_functions(source)

    lines = source.splitlines()
    results: list[dict[str, Any]] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start = int(getattr(node, "lineno", 1) or 1)
            end = int(getattr(node, "end_lineno", start) or start)
            body = "\n".join(lines[start - 1 : end])
            results.append(
                {
                    "name": node.name,
                    "start_line": start,
                    "end_line": end,
                    "body": body,
                }
            )
    return results


def extract_functions_from_python(source: str, path: str = "unknown.py") -> list[dict[str, Any]]:
    """Backward-compatible symbol extraction used by the pipeline."""
    out: list[dict[str, Any]] = []
    for fn in extract_python_functions(source):
        out.append(
            {
                "path": path,
                "name": fn["name"],
                "kind": "FunctionDef",
                "lineno": fn["start_line"],
                "end_lineno": fn["end_line"],
                "body": fn["body"],
            }
        )
    # Also surface classes for older tests.
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return out
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            out.append(
                {
                    "path": path,
                    "name": node.name,
                    "kind": "ClassDef",
                    "lineno": getattr(node, "lineno", 1),
                    "end_lineno": getattr(node, "end_lineno", None),
                    "body": "",
                }
            )
    return out


_FUNC_DEF_RE = re.compile(
    r"^(?P<indent>\s*)(?P<kind>async\s+def|def)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)


def _regex_extract_functions(source: str) -> list[dict[str, Any]]:
    lines = source.splitlines()
    out: list[dict[str, Any]] = []
    matches = list(_FUNC_DEF_RE.finditer(source))
    for idx, match in enumerate(matches):
        start = source[: match.start()].count("\n") + 1
        if idx + 1 < len(matches):
            end = source[: matches[idx + 1].start()].count("\n")
        else:
            end = len(lines)
        end = max(start, end)
        out.append(
            {
                "name": match.group("name"),
                "start_line": start,
                "end_line": end,
                "body": "\n".join(lines[start - 1 : end]),
            }
        )
    return out


def extract_changed_functions(diff_text: str) -> list[dict[str, Any]]:
    """For Python files in a diff, extract functions from added lines."""
    from code_processor.diff_parse import parse_unified_diff

    symbols: list[dict[str, Any]] = []
    for file_diff in parse_unified_diff(diff_text):
        path = str(file_diff["path"])
        if not path.endswith(".py"):
            continue
        added_src = "\n".join(file_diff.get("added_lines") or [])
        if not added_src.strip():
            continue
        for sym in extract_functions_from_python(added_src, path=path):
            symbols.append(sym)
    return symbols
