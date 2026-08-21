# Black Onyx MCP tools

FastMCP servers that call the Black Onyx TIP and detection BFF over HTTP. Uses the official `mcp` Python SDK — no Harmony dependency.

## Install

```powershell
cd black-onyx-tools
pip install -e ".[dev]"
```

## Environment

| Variable | Default | Purpose |
| --- | --- | --- |
| `BLACK_ONYX_BASE_URL` | `http://127.0.0.1:8000` | Platform base URL |
| `BLACK_ONYX_MCP_SERVICE_KEY` | _(empty)_ | `X-MCP-Service-Key` header |
| `BLACK_ONYX_DEFAULT_TENANT_ID` | `default` | `X-Tenant-Id` header |
| `BLACK_ONYX_TOOLS_ALLOW_SANDBOX` | `false` | Enable lab URL sandbox tool |
| `BLACK_ONYX_CONNECT_TIMEOUT` | `10` | HTTP connect timeout (seconds) |
| `BLACK_ONYX_READ_TIMEOUT` | `60` | HTTP read timeout (seconds) |

## Servers

| Script | Tools |
| --- | --- |
| `black-onyx-tip-mcp` | evidence_search, ioc_enrich, case_assist, rule_draft, attack_map |
| `black-onyx-detection-mcp` | hunt, incident_brief, asset_context, response_draft, ti_match |
| `black-onyx-ops-mcp` | watchlist_decay, misp_taxii_draft, connector_pulse, feed_digest, model_ops, passive_dns_whois, url_screenshot_sandbox, certificate_transparency |

Run all three over **stdio** (Cursor default):

```powershell
python run_servers.py
```

Optional HTTP (SSE) for local debugging — binds tip **8200**, detection **8201**, ops **8202** on `127.0.0.1` with bearer auth:

```powershell
$env:BLACK_ONYX_TOOLS_MCP_HTTP_DANGEROUS = "true"
$env:BLACK_ONYX_TOOLS_MCP_HTTP_TOKEN = "<random-16+-chars>"
python run_servers.py --http
```

Clients must send `Authorization: Bearer <token>` (or `X-MCP-HTTP-Token`). Cursor MCP should keep using stdio entrypoints (`black-onyx-*-mcp`), not `--http`.

## Cursor MCP (stdio)

Copy [`cursor-mcp.example.json`](cursor-mcp.example.json) into Cursor MCP settings (or merge the `mcpServers` block). TIP must have matching env:

```text
BLACK_ONYX_MCP_SERVICE_KEY=<shared-secret>
BLACK_ONYX_MCP_ACTOR_USER_ID=<admin-or-analyst-user-uuid>
```

Example (after `uv sync` in `black-onyx-tools/`):

```json
{
  "mcpServers": {
    "black-onyx-tip": {
      "command": "uv",
      "args": ["run", "--directory", "black-onyx-tools", "black-onyx-tip-mcp"],
      "env": {
        "BLACK_ONYX_BASE_URL": "http://127.0.0.1:8000",
        "BLACK_ONYX_MCP_SERVICE_KEY": "<service-key>"
      }
    },
    "black-onyx-detection": {
      "command": "uv",
      "args": ["run", "--directory", "black-onyx-tools", "black-onyx-detection-mcp"],
      "env": {
        "BLACK_ONYX_BASE_URL": "http://127.0.0.1:8000",
        "BLACK_ONYX_MCP_SERVICE_KEY": "<service-key>"
      }
    },
    "black-onyx-ops": {
      "command": "uv",
      "args": ["run", "--directory", "black-onyx-tools", "black-onyx-ops-mcp"],
      "env": {
        "BLACK_ONYX_BASE_URL": "http://127.0.0.1:8000",
        "BLACK_ONYX_MCP_SERVICE_KEY": "<service-key>",
        "BLACK_ONYX_TOOLS_ALLOW_SANDBOX": "false"
      }
    }
  }
}
```

Use absolute `--directory` paths if Cursor’s cwd is not the monorepo root.

## Safety

- Mutating tools require `confirm=True`.
- `response_draft` never approves orchestrator actions.
- `url_screenshot_sandbox` is disabled unless `BLACK_ONYX_TOOLS_ALLOW_SANDBOX=true`.

## Tests

```powershell
pytest -q
```
