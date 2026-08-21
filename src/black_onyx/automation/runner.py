"""Playbook runner — sequential SOAR-lite step execution."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

from black_onyx.automation.playbook_manager import PlaybookManager

logger = logging.getLogger(__name__)


class PlaybookRunner:
    """Execute playbook steps using injected application managers."""

    def __init__(
        self,
        playbook_manager: PlaybookManager,
        enrichment_manager: Any = None,
        case_manager: Any = None,
        sigma_generator: Any = None,
        qdrant_store: Any = None,
    ) -> None:
        self._playbooks = playbook_manager
        self._enrichment = enrichment_manager
        self._cases = case_manager
        self._sigma = sigma_generator
        self._qdrant_store = qdrant_store

    async def handle_trigger(
        self, trigger_type: str, context: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Start and execute all enabled playbooks for a trigger type."""
        results: list[dict[str, Any]] = []
        for playbook in self._playbooks.list_enabled_by_trigger(trigger_type):
            try:
                run = self._playbooks.start_run(playbook["id"], context or {})
                finished = await self.execute_run(run["run_id"])
                results.append(finished)
            except Exception:
                logger.exception(
                    "Playbook %s failed for trigger %s", playbook.get("id"), trigger_type,
                )
        return results

    async def execute_run(self, run_id: str) -> dict[str, Any]:
        """Execute remaining steps for a run until completion, failure, or approval wait."""
        run = self._playbooks.get_run(run_id)
        if run is None:
            raise ValueError("Run not found")
        playbook = self._playbooks.get_playbook(run["playbook_id"])
        if playbook is None:
            self._playbooks.set_run_status(run_id, "failed", finished=True)
            raise ValueError("Playbook not found")

        steps = playbook["steps"]
        context = dict(run.get("context") or {})
        start_index = self._playbooks.next_step_index(run_id)

        for index in range(start_index, len(steps)):
            step = steps[index] if isinstance(steps[index], dict) else {}
            step_type = str(step.get("type") or "")
            self._playbooks.record_step(run_id, index, step_type, "running")
            try:
                if step_type == "wait_approval":
                    self._playbooks.record_step(
                        run_id, index, step_type, "waiting",
                        {"message": "Awaiting analyst approval"},
                    )
                    self._playbooks.update_run_context(run_id, context)
                    self._playbooks.set_run_status(run_id, "waiting_approval", finished=False)
                    return self._playbooks.get_run(run_id)  # type: ignore[return-value]

                result = await self._execute_step(step_type, step, context)
                context.update(result.get("context_updates") or {})
                self._playbooks.record_step(
                    run_id, index, step_type, "completed", result.get("result"),
                )
                self._playbooks.update_run_context(run_id, context)
            except Exception as exc:
                logger.exception("Playbook run %s step %s failed", run_id, index)
                self._playbooks.record_step(
                    run_id, index, step_type, "failed",
                    {"error": str(exc)},
                )
                self._playbooks.set_run_status(run_id, "failed", finished=True)
                return self._playbooks.get_run(run_id)  # type: ignore[return-value]

        self._playbooks.set_run_status(run_id, "completed", finished=True)
        return self._playbooks.get_run(run_id)  # type: ignore[return-value]

    async def continue_after_approval(self, run_id: str) -> dict[str, Any]:
        """Mark a waiting step complete and resume execution."""
        run = self._playbooks.approve_run(run_id)
        if run is None:
            raise ValueError("Run not found")
        # Mark the waiting wait_approval step as completed
        for step in run.get("steps") or []:
            if step.get("status") == "waiting" and step.get("step_type") == "wait_approval":
                self._playbooks.record_step(
                    run_id,
                    step["step_index"],
                    "wait_approval",
                    "completed",
                    {"approved": True},
                )
                break
        return await self.execute_run(run_id)

    async def _execute_step(
        self,
        step_type: str,
        step: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any]:
        if step_type == "enrich":
            return await self._step_enrich(step, context)
        if step_type == "create_case":
            return self._step_create_case(step, context)
        if step_type == "notify_webhook":
            return await self._step_notify_webhook(step, context)
        if step_type == "generate_sigma":
            return self._step_generate_sigma(step, context)
        raise ValueError(f"Unknown step type: {step_type}")

    async def _step_enrich(
        self, step: dict[str, Any], context: dict[str, Any],
    ) -> dict[str, Any]:
        if self._enrichment is None:
            return {
                "result": {"skipped": True, "reason": "enrichment not available"},
                "context_updates": {},
            }
        iocs = self._collect_iocs(step, context)
        if not iocs:
            return {"result": {"enriched": []}, "context_updates": {}}
        batch = await self._enrichment.enrich_batch(iocs)
        serialized: dict[str, list[dict[str, Any]]] = {}
        for value, results in batch.items():
            serialized[value] = [
                r.to_dict() if hasattr(r, "to_dict") else dict(r) for r in results
            ]
        # Write the result onto the IOC's own point, not just the run's log —
        # otherwise "auto-enrich on match" only ever shows up in a playbook run
        # history, never on the IOC record itself (DataModel.enrichment_data,
        # already surfaced by the IOC workbench and search/graph views).
        collection = context.get("collection")
        point_id = context.get("point_id")
        if self._qdrant_store and collection and point_id:
            try:
                self._qdrant_store.set_payload(
                    collection, point_id, {"enrichment_data": serialized},
                )
            except Exception:
                logger.exception(
                    "Failed to write enrichment_data back to %s/%s", collection, point_id,
                )
        updates = {"enrichment": serialized}
        return {"result": {"enriched": serialized}, "context_updates": updates}

    def _step_create_case(
        self, step: dict[str, Any], context: dict[str, Any],
    ) -> dict[str, Any]:
        if self._cases is None:
            raise ValueError("case_manager not available")
        title = str(step.get("title") or context.get("title") or "Playbook case").strip()
        description = str(
            step.get("description") or context.get("description") or "Created by playbook"
        )
        priority = str(step.get("priority") or "medium")
        case = self._cases.create_case(
            title=title, description=description, priority=priority,
        )
        for ioc_type, ioc_value in self._collect_iocs(step, context):
            try:
                self._cases.add_ioc_to_case(case.case_id, ioc_type, ioc_value)
            except Exception:
                logger.debug("Failed to attach IOC to case", exc_info=True)
        return {
            "result": {"case_id": case.case_id, "title": case.title},
            "context_updates": {"case_id": case.case_id},
        }

    async def _step_notify_webhook(
        self, step: dict[str, Any], context: dict[str, Any],
    ) -> dict[str, Any]:
        endpoint_id = str(step.get("endpoint_id") or "")
        endpoint = None
        if endpoint_id:
            endpoint = self._playbooks.get_endpoint(endpoint_id)
        elif step.get("endpoint_name"):
            name = str(step["endpoint_name"])
            for ep in self._playbooks.list_endpoints():
                if ep["name"] == name:
                    endpoint = ep
                    break
        if endpoint is None:
            raise ValueError("Outbound endpoint not found")
        if not endpoint["enabled"]:
            raise ValueError("Outbound endpoint is disabled")

        payload = {
            "playbook_context": context,
            "step": {k: v for k, v in step.items() if k != "type"},
        }
        from black_onyx.net.safe_url import validate_public_https_url

        # Re-validate at send time so older/private URLs cannot be triggered.
        target_url = validate_public_https_url(
            endpoint["url"], purpose="Outbound endpoint URL",
        )
        timeout = float(step.get("timeout_seconds") or 30)
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, trust_env=False) as client:
            response = await client.post(
                target_url,
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            response.raise_for_status()
        return {
            "result": {
                "endpoint_id": endpoint["id"],
                "status_code": response.status_code,
            },
            "context_updates": {},
        }

    def _step_generate_sigma(
        self, step: dict[str, Any], context: dict[str, Any],
    ) -> dict[str, Any]:
        """Generate Sigma YAML only — never execute detection rules locally."""
        generator = self._sigma
        if generator is None:
            from black_onyx.threat.sigma_generator import SigmaRuleGenerator
            generator = SigmaRuleGenerator()

        ioc_dict: dict[str, list[str]] = {}
        for ioc_type, ioc_value in self._collect_iocs(step, context):
            key = {
                "ip": "ipv4", "ipv4": "ipv4", "ipv6": "ipv6",
                "domain": "domains", "url": "urls",
                "md5": "md5", "sha1": "sha1", "sha256": "sha256",
                "email": "emails", "cve": "cves", "hash": "sha256",
            }.get(ioc_type, ioc_type)
            ioc_dict.setdefault(key, []).append(ioc_value)

        title = str(step.get("title") or context.get("title") or "Playbook Sigma rule")
        description = str(step.get("description") or "Generated by Black Onyx playbook")
        level = str(step.get("level") or "medium")
        yaml_text = generator.generate_from_iocs(
            ioc_dict, title=title, description=description, level=level,
        )
        return {
            "result": {"sigma_yaml": yaml_text, "executed": False},
            "context_updates": {"sigma_yaml": yaml_text},
        }

    @staticmethod
    def _collect_iocs(
        step: dict[str, Any], context: dict[str, Any],
    ) -> list[tuple[str, str]]:
        collected: list[tuple[str, str]] = []
        if step.get("ioc_type") and step.get("ioc_value"):
            collected.append((str(step["ioc_type"]), str(step["ioc_value"])))
        for item in step.get("iocs") or context.get("iocs") or []:
            if isinstance(item, dict) and item.get("ioc_type") and item.get("ioc_value"):
                collected.append((str(item["ioc_type"]), str(item["ioc_value"])))
        alerts = context.get("alerts") or []
        if isinstance(alerts, list):
            for alert in alerts:
                if isinstance(alert, dict) and alert.get("ioc_type") and alert.get("ioc_value"):
                    collected.append((str(alert["ioc_type"]), str(alert["ioc_value"])))
        # Deduplicate while preserving order
        seen: set[tuple[str, str]] = set()
        unique: list[tuple[str, str]] = []
        for pair in collected:
            if pair not in seen:
                seen.add(pair)
                unique.append(pair)
        return unique


def run_async(coro: Any) -> Any:
    """Run a coroutine from sync context when no loop is running."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    return loop.create_task(coro)
