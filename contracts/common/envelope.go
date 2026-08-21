package contracts

import "time"

// SourceRef identifies the collector that produced an event.
type SourceRef struct {
	CollectorID string `json:"collector_id"`
	SourceType  string `json:"source_type"`
}

// AssetRef links an event to a known or provisional asset.
type AssetRef struct {
	AssetID     string  `json:"asset_id"`
	ServiceID   *string `json:"service_id,omitempty"`
	Environment *string `json:"environment,omitempty"`
	Region      *string `json:"region,omitempty"`
}

// TraceRef carries optional distributed-trace identifiers.
type TraceRef struct {
	TraceID *string `json:"trace_id,omitempty"`
	SpanID  *string `json:"span_id,omitempty"`
}

// EventEnvelope is the common envelope required on every platform event.
type EventEnvelope struct {
	SchemaVersion string            `json:"schema_version"`
	EventID       string            `json:"event_id"`
	EventType     string            `json:"event_type"`
	TenantID      string            `json:"tenant_id"`
	SiteID        *string           `json:"site_id,omitempty"`
	OccurredAt    time.Time         `json:"occurred_at"`
	IngestedAt    time.Time         `json:"ingested_at"`
	Source        SourceRef         `json:"source"`
	Asset         AssetRef          `json:"asset"`
	Trace         *TraceRef         `json:"trace,omitempty"`
	Labels        map[string]string `json:"labels,omitempty"`
	Extensions    map[string]any    `json:"extensions,omitempty"`
}
