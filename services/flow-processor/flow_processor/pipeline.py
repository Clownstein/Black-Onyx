from __future__ import annotations

from typing import Any

from flow_processor.aws_flow_adapter import aws_flow_to_flow_event, is_aws_flow_event
from flow_processor.azure_flow_adapter import azure_flow_to_flow_events, is_azure_flow_event
from flow_processor.config import settings
from flow_processor.detectors import run_detectors
from flow_processor.dns_adapter import dns_to_flow_event, is_dns_event
from flow_processor.gcp_flow_adapter import gcp_flow_to_flow_event, is_gcp_flow_event
from flow_processor.normalize import normalize_flow
from flow_processor.windows import build_windows
from flow_processor.zeek_adapter import is_zeek_event, zeek_to_flow_event

try:
    from black_onyx_otel import inc_counter
except ImportError:  # pragma: no cover

    def inc_counter(name: str, amount: float = 1.0, **labels: str) -> None:
        return None


class FlowPipeline:
    """Stateful processor: normalize → window → detect → feature records."""

    def __init__(self) -> None:
        self.known_external_peers: dict[str, set[str]] = {}
        self.known_ja3: dict[str, set[str]] = {}
        self.known_ja4: dict[str, set[str]] = {}
        self.known_sni: dict[str, set[str]] = {}
        self.processed = 0
        self.published = 0
        self.errors = 0

    def process_events(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        flows: list[dict[str, Any]] = []
        for event in events:
            try:
                if is_azure_flow_event(event):
                    # 1:N fan-out — one NSG blob holds many flow tuples. Normalize
                    # into a local list first so a single bad tuple does not leave
                    # partial output appended while the blob is counted as an error.
                    sub_flows = [
                        normalize_flow(sub_event, settings.ip_hash_salt)
                        for sub_event in azure_flow_to_flow_events(event)
                    ]
                    flows.extend(sub_flows)
                    self.processed += 1
                    inc_counter("flow_processor_events_total", 1.0, status="ok")
                    continue
                if is_zeek_event(event):
                    event = zeek_to_flow_event(event)
                elif is_dns_event(event):
                    event = dns_to_flow_event(event)
                elif is_aws_flow_event(event):
                    event = aws_flow_to_flow_event(event)
                elif is_gcp_flow_event(event):
                    event = gcp_flow_to_flow_event(event)
                flows.append(normalize_flow(event, settings.ip_hash_salt))
                self.processed += 1
                inc_counter("flow_processor_events_total", 1.0, status="ok")
            except Exception:
                self.errors += 1
                inc_counter("flow_processor_events_total", 1.0, status="error")

        windows = build_windows(
            flows,
            duration_seconds=settings.window_duration_seconds,
            max_events=settings.max_events,
            stride_events=settings.stride_events,
            minimum_events=settings.minimum_events,
        )

        features: list[dict[str, Any]] = []
        for window in windows:
            asset_id = str(window.get("asset_id") or "unknown")
            known = self.known_external_peers.setdefault(asset_id, set())
            ja3_known = self.known_ja3.setdefault(asset_id, set())
            ja4_known = self.known_ja4.setdefault(asset_id, set())
            sni_known = self.known_sni.setdefault(asset_id, set())
            detections = run_detectors(
                window,
                known_external_peers=known,
                known_ja3=ja3_known,
                known_ja4=ja4_known,
                known_sni=sni_known,
            )
            # Update catalogs after detection so novelty is meaningful.
            for flow in window.get("flows") or []:
                if flow.get("dst_is_external"):
                    known.add(flow["peer_hash"])
                tls = flow.get("tls") if isinstance(flow.get("tls"), dict) else {}
                if tls.get("ja3"):
                    ja3_known.add(str(tls["ja3"]))
                if tls.get("ja4"):
                    ja4_known.add(str(tls["ja4"]))
                if tls.get("sni"):
                    sni_known.add(str(tls["sni"]))

            record = {
                **window,
                "flows": [
                    {
                        k: v
                        for k, v in flow.items()
                        if k
                        not in {
                            # keep hashes only; drop nothing essential for model
                        }
                    }
                    for flow in (window.get("flows") or [])
                ],
                "detections": detections,
                "feature_version": "network.features.v1",
            }
            # Trim bulky flow list for publish size while keeping aggregates + sample.
            if len(record["flows"]) > 32:
                record["flow_sample"] = record["flows"][:32]
                del record["flows"]
            features.append(record)
            self.published += 1
            inc_counter("flow_processor_features_total", 1.0)
            if detections:
                inc_counter("flow_processor_detections_total", float(len(detections)))
        return features
