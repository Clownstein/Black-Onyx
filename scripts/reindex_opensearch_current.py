"""Build tenant-scoped current-state indices, verify parity, then switch read aliases.

This is an operator-run migration. Without ``--apply`` it only reports the
indices that would be read. It never deletes legacy indices; they remain the
rollback source after the atomic alias switch.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from typing import Any

import httpx

FAMILIES = {
    "finding": {
        "legacy": "black-onyx-findings",
        "target": "black-onyx-findings-v2",
        "alias": "black-onyx-findings-current",
    },
    "incident": {
        "legacy": "black-onyx-incidents",
        "target": "black-onyx-incidents-v2",
        "alias": "black-onyx-incidents-current",
    },
}
PAGE_SIZE = 500


def _document_id(tenant_id: str, kind: str, resource_id: str) -> str:
    canonical = "\0".join((tenant_id, kind, resource_id)).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _client() -> httpx.Client:
    url = os.environ.get("OPENSEARCH_URL", "").strip().rstrip("/")
    if not url:
        raise RuntimeError("OPENSEARCH_URL is required")
    username = os.environ.get("OPENSEARCH_USERNAME", "").strip()
    password = os.environ.get("OPENSEARCH_PASSWORD", "")
    auth = (username, password) if username else None
    verify = os.environ.get("OPENSEARCH_VERIFY_TLS", "true").strip().lower() not in {
        "0", "false", "no", "off",
    }
    client = httpx.Client(
        base_url=url,
        timeout=30.0,
        trust_env=False,
        verify=verify,
        auth=auth,
    )
    return client


def _legacy_indices(client: httpx.Client, prefix: str) -> list[str]:
    response = client.get(f"/_cat/indices/{prefix}-*", params={"format": "json", "h": "index"})
    response.raise_for_status()
    pattern = re.compile(rf"^{re.escape(prefix)}-\d{{4}}\.\d{{2}}\.\d{{2}}$")
    return sorted(
        str(row["index"])
        for row in response.json()
        if isinstance(row, dict) and pattern.fullmatch(str(row.get("index") or ""))
    )


def _bulk(client: httpx.Client, operations: list[str]) -> None:
    if not operations:
        return
    response = client.post(
        "/_bulk",
        content=("\n".join(operations) + "\n").encode("utf-8"),
        headers={"Content-Type": "application/x-ndjson"},
    )
    response.raise_for_status()
    body = response.json()
    if body.get("errors"):
        failures = [
            item for result in body.get("items", [])
            for item in result.values()
            if int(item.get("status", 500)) >= 300
        ]
        raise RuntimeError(f"OpenSearch bulk indexing failed for {len(failures)} documents")


def _copy_family(client: httpx.Client, kind: str, *, apply: bool) -> int:
    family = FAMILIES[kind]
    sources = _legacy_indices(client, family["legacy"])
    if not sources:
        raise RuntimeError(f"no legacy {kind} indices were found")
    expected_ids: set[str] = set()
    operations: list[str] = []
    for source in sources:
        page = client.post(
            f"/{source}/_search",
            params={"scroll": "2m"},
            json={"size": PAGE_SIZE, "sort": ["_doc"], "query": {"match_all": {}}},
        )
        page.raise_for_status()
        body = page.json()
        scroll_id = body.get("_scroll_id")
        hits = body.get("hits", {}).get("hits", [])
        while hits:
            for hit in hits:
                document = hit.get("_source") or {}
                tenant_id = str(document.get("tenant_id") or "").strip()
                resource_key = "finding_id" if kind == "finding" else "incident_id"
                resource_id = str(document.get(resource_key) or "").strip()
                if not tenant_id or not resource_id:
                    continue
                stable_id = _document_id(tenant_id, kind, resource_id)
                expected_ids.add(stable_id)
                if apply:
                    operations.append(json.dumps({
                        "index": {
                            "_index": family["target"],
                            "_id": stable_id,
                            "routing": tenant_id,
                        }
                    }, separators=(",", ":")))
                    operations.append(json.dumps(document, separators=(",", ":"), default=str))
                    if len(operations) >= PAGE_SIZE * 2:
                        _bulk(client, operations)
                        operations.clear()
            if not scroll_id:
                break
            page = client.post(
                "/_search/scroll",
                json={"scroll": "2m", "scroll_id": scroll_id},
            )
            page.raise_for_status()
            body = page.json()
            scroll_id = body.get("_scroll_id")
            hits = body.get("hits", {}).get("hits", [])
        if scroll_id:
            client.request("DELETE", "/_search/scroll", json={"scroll_id": [scroll_id]})
    _bulk(client, operations)

    if not apply:
        print(f"{kind}: {len(sources)} legacy indices; {len(expected_ids)} unique tenant-scoped documents")
        return len(expected_ids)

    client.post(f"/{family['target']}/_refresh").raise_for_status()
    count_response = client.get(f"/{family['target']}/_count")
    count_response.raise_for_status()
    actual = int(count_response.json().get("count", -1))
    if actual != len(expected_ids):
        raise RuntimeError(
            f"{kind} parity failed: {len(expected_ids)} expected documents, {actual} indexed"
        )
    print(f"{kind}: parity verified for {actual} current-state documents")
    return actual


def _alias_indices(client: httpx.Client, alias: str) -> list[str]:
    response = client.get(f"/_alias/{alias}")
    if response.status_code == 404:
        return []
    response.raise_for_status()
    return [
        index for index, body in response.json().items()
        if alias in (body.get("aliases") or {})
    ]


def _switch_aliases(client: httpx.Client) -> None:
    actions: list[dict[str, Any]] = []
    for family in FAMILIES.values():
        for current in _alias_indices(client, family["alias"]):
            actions.append({"remove": {"index": current, "alias": family["alias"]}})
        actions.append({"add": {"index": family["target"], "alias": family["alias"]}})
    response = client.post("/_aliases", json={"actions": actions})
    response.raise_for_status()
    if response.json().get("errors"):
        raise RuntimeError("OpenSearch rejected the atomic read-alias switch")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--apply", action="store_true",
        help="rebuild indices and atomically switch aliases; default is read-only preflight",
    )
    args = parser.parse_args()
    try:
        with _client() as client:
            counts = {
                kind: _copy_family(client, kind, apply=args.apply)
                for kind in FAMILIES
            }
            if args.apply:
                _switch_aliases(client)
                print("read aliases switched atomically; legacy indices retained for rollback")
            else:
                print("preflight only; rerun with --apply after reviewing the source counts")
            print(json.dumps(counts, sort_keys=True))
    except (httpx.HTTPError, ValueError, RuntimeError) as exc:
        print(f"OpenSearch migration failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
