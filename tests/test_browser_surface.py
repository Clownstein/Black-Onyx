"""Static guards on what the browser bundle is allowed to contain.

`web/src/AGENTS.md` and `web/src/detection/AGENTS.md` both carry MUST NOT rules
about the browser surface no service-to-service keys via `VITE_*`, no calls to
upstream microservices by non-BFF origins, no browser-held credentials. Those
rules had no automated enforcement, so nothing failed if a future change
reintroduced them. These tests read the shipped source and assert the rules.

Everything here is a source scan: it proves what the bundle *cannot* contain,
not that a running deployment is configured correctly.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
WEB_SRC = REPO_ROOT / "web" / "src"

# The detection console is the one surface that historically held S2S keys, so
# it is scanned alongside the shell rather than treated as a separate concern.
SOURCE_SUFFIXES = (".ts", ".tsx")


def browser_sources() -> list[Path]:
    """Every TypeScript source that ends up in the browser bundle.

    Test files are excluded: they may legitimately contain literals (fake
    tokens, absolute URLs in fixtures) that would trip the scans below, and
    they are not shipped.
    """
    files = [
        path
        for path in sorted(WEB_SRC.rglob("*"))
        if path.suffix in SOURCE_SUFFIXES
        and ".test." not in path.name
        and ".spec." not in path.name
    ]
    assert files, f"no browser sources found under {WEB_SRC}"
    return files


@pytest.fixture(scope="module")
def sources() -> list[tuple[Path, str]]:
    return [(path, path.read_text(encoding="utf-8")) for path in browser_sources()]


def rel(path: Path) -> str:
    return path.relative_to(REPO_ROOT).as_posix()


# ── No browser-held service credentials ───────────────────────────────────

# `import.meta.env.VITE_*` values are inlined into the bundle at build time and
# are therefore public. Path/feature overrides are fine; anything that reads
# like a credential is not.
SECRETISH = re.compile(r"(KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|PASSPHRASE)", re.IGNORECASE)

# `VITE_GRAFANA_URL` names an operator-visible link target, not a fetch base;
# it is allowed precisely because it is public information.
ALLOWED_VITE_VARS = {
    "VITE_GRAFANA_URL",
    "VITE_INTEGRATION_HUB_ENABLED",
}


def test_no_credential_shaped_build_time_env_vars(sources) -> None:
    """`VITE_*` values are public; none of them may look like a secret."""
    found: dict[str, str] = {}
    for path, text in sources:
        for name in re.findall(r"import\.meta\.env\.(VITE_[A-Z0-9_]+)", text):
            found.setdefault(name, rel(path))

    unexpected = {n: p for n, p in found.items() if n not in ALLOWED_VITE_VARS}
    assert not unexpected, (
        "new build-time env vars reach the browser bundle; confirm they are "
        f"public and add them to ALLOWED_VITE_VARS: {unexpected}"
    )
    secretish = {n: p for n, p in found.items() if SECRETISH.search(n)}
    assert not secretish, f"credential-shaped VITE_* var in browser source: {secretish}"


# Literal credentials. `Bearer ${...}` is a runtime interpolation and fine; a
# literal token after Bearer is not.
CREDENTIAL_LITERALS = [
    (re.compile(r"\bsk-[A-Za-z0-9]{16,}"), "OpenAI-style API key"),
    (re.compile(r"Bearer\s+(?!\$\{)[A-Za-z0-9._-]{20,}"), "literal bearer token"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private key block"),
    (re.compile(r"\b(?:api[_-]?key|secret|password)\s*[:=]\s*[\"'][^\"'$\s]{12,}[\"']", re.IGNORECASE),
     "hard-coded credential literal"),
]


def test_no_hard_coded_credentials_in_browser_source(sources) -> None:
    offenders: list[str] = []
    for path, text in sources:
        for pattern, label in CREDENTIAL_LITERALS:
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                offenders.append(f"{rel(path)}:{line} {label}")
    assert not offenders, offenders


# ── All browser egress is same-origin ─────────────────────────────────────

# A browser fetch must go to this origin so the session cookie, the CSRF check
# and the BFF's server-side credential injection all apply. An absolute URL
# bypasses every one of them.
ABSOLUTE_TARGET = re.compile(
    r"""(?:fetch|new\s+EventSource|new\s+WebSocket)\(\s*[`'"](?P<url>(?:https?:)?//[^`'"]*)""",
)


def test_browser_never_calls_an_absolute_origin(sources) -> None:
    offenders: list[str] = []
    for path, text in sources:
        for match in ABSOLUTE_TARGET.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            offenders.append(f"{rel(path)}:{line} -> {match.group('url')}")
    assert not offenders, (
        "browser code must reach upstream services through the same-origin BFF, "
        f"not by absolute URL: {offenders}"
    )


def test_detection_client_only_uses_bff_paths() -> None:
    """Every base path in the detection client is a `/api/v1/detection/*` proxy."""
    client = WEB_SRC / "detection" / "api" / "client.ts"
    text = client.read_text(encoding="utf-8")
    bases = re.findall(r"^const\s+\w*BASE\s*=\s*'([^']+)'", text, re.MULTILINE)
    assert bases, "no base-path constants found; did client.ts move?"
    bad = [base for base in bases if not base.startswith("/api/v1/detection/")]
    assert not bad, f"detection client base outside the BFF: {bad}"


def test_security_client_only_uses_bff_paths() -> None:
    client = WEB_SRC / "detection" / "api" / "security_client.ts"
    text = client.read_text(encoding="utf-8")
    targets = re.findall(r"fetchJson<[^>]*>\(\s*[`\"']([^`\"']+)", text)
    assert targets, "no fetchJson targets found; did security_client.ts move?"
    bad = [t for t in targets if not t.startswith("/api/v1/security/")]
    assert not bad, f"security client call outside the BFF: {bad}"


# ── No service-to-service or tenant headers from the browser ──────────────

# Headers the server derives from the authenticated session. If the browser
# sets one, it is asserting an identity rather than proving it.
FORBIDDEN_HEADERS = [
    "X-Service-Key",
    "X-Ingest-Key",
    "X-Detection-Token",
    "X-Tenant-Id",
    "X-Tenant",
    "X-Actor",
    "X-Actor-Email",
    "X-Actor-Role",
    "X-Internal-Auth",
    "X-Forwarded-User",
    "X-Impersonate",
]


def test_browser_sets_no_service_or_tenant_headers(sources) -> None:
    offenders: list[str] = []
    for path, text in sources:
        for header in FORBIDDEN_HEADERS:
            for match in re.finditer(re.escape(header), text, re.IGNORECASE):
                line = text.count("\n", 0, match.start()) + 1
                offenders.append(f"{rel(path)}:{line} {header}")
    assert not offenders, (
        "these headers are derived server-side from the session; the browser "
        f"must not send them: {offenders}"
    )


def test_api_key_header_name_is_only_ever_connector_config(sources) -> None:
    """`X-API-Key` may name a third-party connector's auth field, never ours.

    The connector form sends `header_name: "X-API-Key"` to the backend, which
    uses it when calling an external EDR. That is configuration data. The same
    string inside a request-header object would mean the browser is holding a
    key, which is what the MUST NOT forbids.
    """
    offenders: list[str] = []
    for path, text in sources:
        for number, line in enumerate(text.splitlines(), start=1):
            if "X-API-Key" not in line:
                continue
            if re.search(r"\bheaders\b", line):
                offenders.append(f"{rel(path)}:{number}: {line.strip()}")
    assert not offenders, offenders


# ── Client-side storage stays a known, non-sensitive set ──────────────────

# Pinned so a new key is a deliberate review decision rather than a drive-by.
# None of these hold credentials or server-trusted state.
KNOWN_STORAGE_KEYS = {
    "blackonyx_theme_v1",
    "blackonyx_gallery_mode",
    "blackonyx_gallery_offset_v4",
    "blackonyx_analytics_views_v1",
    "blackonyx_saved_queries_v1",
    "black-onyx.walkthrough.v1",
}


def test_client_side_storage_keys_are_the_known_set(sources) -> None:
    keys: dict[str, str] = {}
    for path, text in sources:
        # Keys are declared as module constants and passed to *Storage by name.
        for name, value in re.findall(
            r"^const\s+(\w*(?:STORAGE|VIEWS?|MODE)_KEY)\s*=\s*[\"']([^\"']+)[\"']",
            text,
            re.MULTILINE,
        ):
            keys.setdefault(value, f"{rel(path)} ({name})")
        # And occasionally inline.
        for value in re.findall(r"(?:local|session)Storage\.\w+Item\(\s*[\"']([^\"']+)[\"']", text):
            keys.setdefault(value, rel(path))

    unexpected = {k: v for k, v in keys.items() if k not in KNOWN_STORAGE_KEYS}
    assert not unexpected, (
        "new browser storage key; confirm it holds nothing sensitive and add it "
        f"to KNOWN_STORAGE_KEYS: {unexpected}"
    )


def test_theme_storage_contract_is_unchanged() -> None:
    """The plan fixes theme state on this key; a rename silently drops settings."""
    theme = (WEB_SRC / "theme" / "ThemeContext.tsx").read_text(encoding="utf-8")
    assert 'const STORAGE_KEY = "blackonyx_theme_v1"' in theme


# ── CSRF is applied to every mutating browser call ────────────────────────


def test_every_fetch_wrapper_sends_csrf_and_same_origin_credentials() -> None:
    """The three fetch wrappers are the only way out of the browser."""
    wrappers = {
        "web/src/api.ts": "api.ts",
        "web/src/detection/api/client.ts": "client.ts",
        "web/src/detection/api/security_client.ts": "security_client.ts",
    }
    for relative in wrappers:
        text = (REPO_ROOT / relative).read_text(encoding="utf-8")
        assert "X-CSRF-Token" in text, f"{relative} does not send a CSRF token"
        assert 'credentials: "same-origin"' in text or "credentials: 'same-origin'" in text, (
            f"{relative} does not pin credentials to same-origin"
        )
