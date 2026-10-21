package ingest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
)

type fakePcapStore struct {
	tenant string
	data   []byte
}

func (f *fakePcapStore) Put(
	_ context.Context,
	tenantID string,
	eventID string,
	filename string,
	data []byte,
) (PcapArtifact, error) {
	if tenantID == "" || eventID == "" {
		return PcapArtifact{}, errors.New("missing identity")
	}
	f.tenant = tenantID
	f.data = append([]byte(nil), data...)
	sum := sha256.Sum256(data)
	return PcapArtifact{
		URI:      "s3://pcap-artifacts/" + tenantID + "/" + eventID + "/capture.pcap",
		SHA256:   hex.EncodeToString(sum[:]),
		Size:     int64(len(data)),
		Filename: filename,
	}, nil
}

func (f *fakePcapStore) ValidateURI(tenantID string, uri string) error {
	if uri != "s3://pcap-artifacts/"+tenantID+"/existing.pcap" {
		return errors.New("tenant mismatch")
	}
	return nil
}

func TestStripPcapBytesRemovesInlineBlob(t *testing.T) {
	raw := []byte(`{
		"schema_version":"1.0",
		"event_id":"01HXEXAMPLE000000000000000",
		"event_type":"pcap.excerpt",
		"tenant_id":"t1",
		"pcap_b64":"AAAA",
		"payload":{"uri":"s3://bucket/a.pcap","pcap_b64":"BBBB","sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
	}`)
	out, err := stripPcapBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]any
	if err := json.Unmarshal(out, &obj); err != nil {
		t.Fatal(err)
	}
	if _, ok := obj["pcap_b64"]; ok {
		t.Fatal("expected root pcap_b64 removed")
	}
	payload, ok := obj["payload"].(map[string]any)
	if !ok {
		t.Fatal("expected payload object")
	}
	if _, ok := payload["pcap_b64"]; ok {
		t.Fatal("expected payload.pcap_b64 removed")
	}
	if payload["uri"] != "s3://bucket/a.pcap" {
		t.Fatalf("uri lost: %v", payload["uri"])
	}
}

func TestStripPcapBytesKeepsMetadataOnly(t *testing.T) {
	raw := []byte(`{"event_type":"pcap.excerpt","uri":"s3://b/x.pcap","sha256":"abc"}`)
	out, err := stripPcapBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) == "" {
		t.Fatal("empty output")
	}
}

func TestPrepareArtifactUploadsInlineBytesAndAddsMetadata(t *testing.T) {
	store := &fakePcapStore{}
	handler := &PcapExcerptHandler{objectStore: store}
	raw := json.RawMessage(`{
		"schema_version":"1.0",
		"event_id":"01HXEXAMPLE000000000000000",
		"event_type":"pcap.excerpt",
		"tenant_id":"tenant-a",
		"pcap_b64":"AQIDBA=="
	}`)
	out, err := handler.prepareArtifact(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]any
	if err := json.Unmarshal(out, &obj); err != nil {
		t.Fatal(err)
	}
	if store.tenant != "tenant-a" || len(store.data) != 4 {
		t.Fatalf("unexpected upload: tenant=%q bytes=%d", store.tenant, len(store.data))
	}
	if obj["uri"] == "" || obj["sha256"] == "" || obj["bytes"] != float64(4) {
		t.Fatalf("missing artifact metadata: %#v", obj)
	}
}

func TestPrepareArtifactRejectsCrossTenantURI(t *testing.T) {
	handler := &PcapExcerptHandler{objectStore: &fakePcapStore{}}
	raw := json.RawMessage(`{
		"event_id":"01HXEXAMPLE000000000000000",
		"tenant_id":"tenant-a",
		"uri":"s3://pcap-artifacts/tenant-b/existing.pcap"
	}`)
	if _, err := handler.prepareArtifact(context.Background(), raw); err == nil {
		t.Fatal("expected tenant ownership error")
	}
}
