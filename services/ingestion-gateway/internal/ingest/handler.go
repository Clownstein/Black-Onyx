package ingest

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/black-onyx/ingestion-gateway/internal/kafka"
	"github.com/black-onyx/ingestion-gateway/internal/metrics"
	"github.com/black-onyx/ingestion-gateway/internal/validate"
)

type Handler struct {
	publisher    *kafka.Publisher
	validator    *validate.Validator
	topic        string
	eventType    string
	maxBodyBytes int64
	maxBatchSize int
}

func NewHandler(
	publisher *kafka.Publisher,
	validator *validate.Validator,
	topic string,
	eventType string,
	maxBodyBytes int64,
	maxBatchSize int,
) *Handler {
	return &Handler{
		publisher:    publisher,
		validator:    validator,
		topic:        topic,
		eventType:    eventType,
		maxBodyBytes: maxBodyBytes,
		maxBatchSize: maxBatchSize,
	}
}

type batchRequest struct {
	Events []json.RawMessage `json:"events"`
}

type eventResult struct {
	Index   int    `json:"index"`
	EventID string `json:"event_id,omitempty"`
	Status  string `json:"status"`
	Error   string `json:"error,omitempty"`
}

type batchResponse struct {
	Accepted int           `json:"accepted"`
	Rejected int           `json:"rejected"`
	Results  []eventResult `json:"results"`
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

	events, err := h.parseBatch(body)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}
	if len(events) == 0 {
		http.Error(w, `{"error":"batch must contain at least one event"}`, http.StatusBadRequest)
		return
	}
	if len(events) > h.maxBatchSize {
		http.Error(w, `{"error":"batch exceeds max size"}`, http.StatusBadRequest)
		return
	}

	resp := batchResponse{Results: make([]eventResult, 0, len(events))}
	ctx := r.Context()

	for i, raw := range events {
		env, verr := h.validator.ValidateBytes(raw)
		if verr != nil {
			_ = h.publisher.PublishDLQ(ctx, []byte("invalid"), raw, map[string]string{
				"error":      verr.Error(),
				"reason":     "validation_failed",
				"event_type": h.eventType,
			})
			metrics.EventsRejected.Inc()
			metrics.EventsDLQ.Inc()
			resp.Rejected++
			resp.Results = append(resp.Results, eventResult{
				Index:  i,
				Status: "rejected",
				Error:  verr.Error(),
			})
			continue
		}

		key := []byte(env.TenantID + ":" + env.EventID)
		if err := h.publisher.PublishRaw(ctx, h.topic, key, raw); err != nil {
			_ = h.publisher.PublishDLQ(ctx, key, raw, map[string]string{
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

func (h *Handler) parseBatch(body []byte) ([]json.RawMessage, error) {
	trimmed := trimSpace(body)
	if len(trimmed) == 0 {
		return nil, errInvalidBatch
	}
	if trimmed[0] == '{' {
		var wrapper batchRequest
		if err := json.Unmarshal(trimmed, &wrapper); err == nil && wrapper.Events != nil {
			return wrapper.Events, nil
		}
		return []json.RawMessage{json.RawMessage(trimmed)}, nil
	}
	if trimmed[0] == '[' {
		var events []json.RawMessage
		if err := json.Unmarshal(trimmed, &events); err != nil {
			return nil, errInvalidBatch
		}
		return events, nil
	}
	return nil, errInvalidBatch
}

var errInvalidBatch = &batchError{"invalid batch payload"}

type batchError struct{ msg string }

func (e *batchError) Error() string { return e.msg }

func trimSpace(b []byte) []byte {
	i, j := 0, len(b)
	for i < j && (b[i] == ' ' || b[i] == '\n' || b[i] == '\r' || b[i] == '\t') {
		i++
	}
	for j > i && (b[j-1] == ' ' || b[j-1] == '\n' || b[j-1] == '\r' || b[j-1] == '\t') {
		j--
	}
	return b[i:j]
}
