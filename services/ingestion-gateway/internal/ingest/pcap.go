package ingest

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"strings"

	"github.com/black-onyx/ingestion-gateway/internal/kafka"
	"github.com/black-onyx/ingestion-gateway/internal/metrics"
	"github.com/black-onyx/ingestion-gateway/internal/validate"
)

const pcapEventType = "pcap.excerpt"

// PcapExcerptHandler uploads PCAP bytes to tenant-owned object storage and
// publishes only durable artifact metadata to Kafka (pcap.meta).
type PcapExcerptHandler struct {
	publisher    *kafka.Publisher
	validator    *validate.Validator
	topic        string
	maxBodyBytes int64
	maxBatchSize int
	objectStore  PcapObjectStore
}

func NewPcapExcerptHandler(
	publisher *kafka.Publisher,
	validator *validate.Validator,
	topic string,
	maxBodyBytes int64,
	maxBatchSize int,
	objectStores ...PcapObjectStore,
) *PcapExcerptHandler {
	var objectStore PcapObjectStore
	if len(objectStores) > 0 {
		objectStore = objectStores[0]
	}
	return &PcapExcerptHandler{
		publisher:    publisher,
		validator:    validator,
		topic:        topic,
		maxBodyBytes: maxBodyBytes,
		maxBatchSize: maxBatchSize,
		objectStore:  objectStore,
	}
}

func (h *PcapExcerptHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, h.maxBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"error":"request body too large or unreadable"}`, http.StatusRequestEntityTooLarge)
		return
	}

	events, err := h.parseEvents(r.Header.Get("Content-Type"), body)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(events) == 0 {
		writeJSONError(w, http.StatusBadRequest, "batch must contain at least one event")
		return
	}
	if len(events) > h.maxBatchSize {
		writeJSONError(w, http.StatusBadRequest, "batch exceeds max size")
		return
	}

	resp := batchResponse{Results: make([]eventResult, 0, len(events))}
	ctx := r.Context()

	for i, raw := range events {
		prepared, perr := h.prepareArtifact(ctx, raw)
		if perr != nil {
			h.rejectToDLQ(ctx, &resp, i, raw, "object_store_failed", perr)
			continue
		}

		sanitized, serr := stripPcapBytes(prepared)
		if serr != nil {
			h.rejectToDLQ(ctx, &resp, i, prepared, "validation_failed", serr)
			continue
		}

		env, verr := h.validator.ValidateBytes(sanitized)
		if verr != nil {
			h.rejectToDLQ(ctx, &resp, i, sanitized, "validation_failed", verr)
			continue
		}
		if env.EventType != pcapEventType {
			err := errors.New("unexpected event_type for PCAP endpoint")
			h.rejectToDLQ(ctx, &resp, i, sanitized, "validation_failed", err)
			continue
		}

		key := []byte(env.TenantID + ":" + env.EventID)
		if err := h.publisher.PublishRaw(ctx, h.topic, key, sanitized); err != nil {
			_ = h.publisher.PublishDLQ(ctx, key, sanitized, map[string]string{
				"error":  err.Error(),
				"reason": "publish_failed",
			})
			metrics.EventsRejected.Inc()
			metrics.EventsDLQ.Inc()
			resp.Rejected++
			resp.Results = append(resp.Results, eventResult{
				Index:   i,
				EventID: env.EventID,
				Status:  "rejected",
				Error:   "publish failed: " + err.Error(),
			})
			continue
		}

		metrics.EventsAccepted.Inc()
		resp.Accepted++
		resp.Results = append(resp.Results, eventResult{
			Index:   i,
			EventID: env.EventID,
			Status:  "accepted",
		})
	}

	w.Header().Set("Content-Type", "application/json")
	status := http.StatusOK
	if resp.Accepted == 0 {
		status = http.StatusUnprocessableEntity
	} else if resp.Rejected > 0 {
		status = http.StatusMultiStatus
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func (h *PcapExcerptHandler) rejectToDLQ(
	ctx context.Context,
	resp *batchResponse,
	index int,
	raw []byte,
	reason string,
	err error,
) {
	_ = h.publisher.PublishDLQ(ctx, []byte("invalid"), raw, map[string]string{
		"error":      err.Error(),
		"reason":     reason,
		"event_type": pcapEventType,
	})
	metrics.EventsRejected.Inc()
	metrics.EventsDLQ.Inc()
	resp.Rejected++
	resp.Results = append(resp.Results, eventResult{
		Index:  index,
		Status: "rejected",
		Error:  err.Error(),
	})
}

func (h *PcapExcerptHandler) parseEvents(
	contentType string,
	body []byte,
) ([]json.RawMessage, error) {
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err == nil && strings.HasPrefix(mediaType, "multipart/") {
		return parseMultipartPcap(body, params["boundary"])
	}
	tmp := &Handler{maxBatchSize: h.maxBatchSize}
	return tmp.parseBatch(body)
}

func parseMultipartPcap(body []byte, boundary string) ([]json.RawMessage, error) {
	if boundary == "" {
		return nil, errInvalidBatch
	}
	reader := multipart.NewReader(bytes.NewReader(body), boundary)
	var meta json.RawMessage
	var pcapBytes []byte
	var filename string
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errInvalidBatch
		}
		name := part.FormName()
		data, err := io.ReadAll(part)
		filenamePart := part.FileName()
		_ = part.Close()
		if err != nil {
			return nil, errInvalidBatch
		}
		switch name {
		case "event", "envelope", "metadata", "json":
			meta = json.RawMessage(data)
		case "pcap", "file", "pcap_file":
			pcapBytes = data
			filename = filenamePart
		}
	}
	if len(meta) == 0 {
		return nil, &batchError{"multipart pcap-excerpt requires an event/metadata JSON part"}
	}
	if len(pcapBytes) > 0 {
		attached, err := attachMultipartPcap(meta, pcapBytes, filename)
		if err != nil {
			return nil, err
		}
		meta = attached
	}
	return []json.RawMessage{meta}, nil
}

func attachMultipartPcap(
	raw json.RawMessage,
	data []byte,
	filename string,
) (json.RawMessage, error) {
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, &batchError{"invalid multipart metadata json"}
	}
	obj["pcap_b64"] = base64.StdEncoding.EncodeToString(data)
	obj["pcap_filename"] = safeFilename(filename)
	out, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func inlinePcapField(obj map[string]any) (string, string) {
	filename, _ := obj["pcap_filename"].(string)
	for _, key := range []string{"pcap_b64", "pcap_bytes"} {
		if value, ok := obj[key].(string); ok && strings.TrimSpace(value) != "" {
			return value, filename
		}
	}
	for _, container := range []string{"payload", "extensions"} {
		nested, ok := obj[container].(map[string]any)
		if !ok {
			continue
		}
		value, nestedFilename := inlinePcapField(nested)
		if value != "" {
			if nestedFilename != "" {
				filename = nestedFilename
			}
			return value, filename
		}
	}
	return "", filename
}

func artifactURI(obj map[string]any) string {
	if value, ok := obj["uri"].(string); ok {
		return strings.TrimSpace(value)
	}
	if payload, ok := obj["payload"].(map[string]any); ok {
		if value, ok := payload["uri"].(string); ok {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func (h *PcapExcerptHandler) prepareArtifact(
	ctx context.Context,
	raw json.RawMessage,
) (json.RawMessage, error) {
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, &batchError{"invalid pcap excerpt json"}
	}
	tenantID, _ := obj["tenant_id"].(string)
	eventID, _ := obj["event_id"].(string)
	if err := validateObjectIdentity(tenantID, eventID); err != nil {
		return nil, err
	}

	encoded, filename := inlinePcapField(obj)
	if encoded != "" {
		if h.objectStore == nil {
			return nil, errors.New("PCAP object store is not configured")
		}
		data, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, errors.New("pcap_b64 is not valid base64")
		}
		artifact, err := h.objectStore.Put(ctx, tenantID, eventID, filename, data)
		if err != nil {
			return nil, err
		}
		obj["uri"] = artifact.URI
		obj["sha256"] = artifact.SHA256
		obj["bytes"] = artifact.Size
		obj["pcap_filename"] = artifact.Filename
		if payload, ok := obj["payload"].(map[string]any); ok {
			payload["uri"] = artifact.URI
			payload["sha256"] = artifact.SHA256
			payload["bytes"] = artifact.Size
		}
	} else {
		uri := artifactURI(obj)
		if uri == "" {
			return nil, errors.New("PCAP bytes or tenant-owned uri is required")
		}
		if h.objectStore == nil {
			return nil, errors.New("PCAP object store is not configured for uri validation")
		}
		if err := h.objectStore.ValidateURI(tenantID, uri); err != nil {
			return nil, err
		}
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// stripPcapBytes removes inline PCAP blobs so Kafka only receives metadata.
func stripPcapBytes(raw []byte) (json.RawMessage, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, &batchError{"invalid pcap excerpt json"}
	}
	delete(obj, "pcap_b64")
	delete(obj, "pcap_bytes")
	delete(obj, "pcap_filename")
	if payloadRaw, ok := obj["payload"]; ok {
		var payload map[string]json.RawMessage
		if err := json.Unmarshal(payloadRaw, &payload); err == nil {
			delete(payload, "pcap_b64")
			delete(payload, "pcap_bytes")
			delete(payload, "pcap_filename")
			cleaned, err := json.Marshal(payload)
			if err != nil {
				return nil, err
			}
			obj["payload"] = cleaned
		}
	}
	if extRaw, ok := obj["extensions"]; ok {
		var ext map[string]json.RawMessage
		if err := json.Unmarshal(extRaw, &ext); err == nil {
			delete(ext, "pcap_b64")
			delete(ext, "pcap_bytes")
			delete(ext, "pcap_filename")
			cleaned, err := json.Marshal(ext)
			if err != nil {
				return nil, err
			}
			obj["extensions"] = cleaned
		}
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	return out, nil
}
