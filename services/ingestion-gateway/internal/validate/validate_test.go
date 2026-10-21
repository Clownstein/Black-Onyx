package validate

import (
	"testing"
	"time"

	contracts "github.com/black-onyx/contracts"
)

func TestValidateAcceptsGoodEnvelope(t *testing.T) {
	v := New(5*time.Minute, 24*time.Hour, 1)
	now := time.Now().UTC()
	env := &contracts.EventEnvelope{
		SchemaVersion: "1.0",
		EventID:       "01J3T5C0RB6GCYKAT1BFRX7A3Q",
		EventType:     "log.raw",
		TenantID:      "tenant-acme",
		OccurredAt:    now.Add(-time.Second),
		IngestedAt:    now,
		Source:        contracts.SourceRef{CollectorID: "c1", SourceType: "otel"},
		Asset:         contracts.AssetRef{AssetID: "host-1"},
	}
	if err := v.Validate(env); err != nil {
		t.Fatalf("expected valid envelope, got %v", err)
	}
}

func TestValidateRejectsFutureSkew(t *testing.T) {
	v := New(5*time.Minute, 24*time.Hour, 1)
	now := time.Now().UTC()
	env := &contracts.EventEnvelope{
		SchemaVersion: "1.0",
		EventID:       "01J3T5C0RB6GCYKAT1BFRX7A3Q",
		EventType:     "log.raw",
		TenantID:      "tenant-acme",
		OccurredAt:    now.Add(30 * time.Minute),
		IngestedAt:    now,
		Source:        contracts.SourceRef{CollectorID: "c1", SourceType: "otel"},
		Asset:         contracts.AssetRef{AssetID: "host-1"},
	}
	if err := v.Validate(env); err == nil {
		t.Fatal("expected future skew rejection")
	}
}
