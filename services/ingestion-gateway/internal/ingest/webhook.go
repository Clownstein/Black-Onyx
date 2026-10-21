package ingest

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/black-onyx/ingestion-gateway/internal/kafka"
	"github.com/black-onyx/ingestion-gateway/internal/metrics"
)

// WebhookHandler accepts Git provider webhooks, verifies signatures, and publishes to code.raw.
type WebhookHandler struct {
	publisher    *kafka.Publisher
	topic        string
	secrets      map[string]string
	maxBodyBytes int64
}

func NewWebhookHandler(publisher *kafka.Publisher, topic string, secrets map[string]string, maxBodyBytes int64) *WebhookHandler {
	return &WebhookHandler{
		publisher:    publisher,
		topic:        topic,
		secrets:      secrets,
		maxBodyBytes: maxBodyBytes,
	}
}

func (h *WebhookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	provider := strings.ToLower(r.PathValue("provider"))
	if provider == "" {
		http.Error(w, `{"error":"provider required"}`, http.StatusBadRequest)
		return
	}
	secret, ok := h.secrets[provider]
	if !ok || secret == "" {
		http.Error(w, `{"error":"unknown provider"}`, http.StatusUnauthorized)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, h.maxBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"error":"request body too large or unreadable"}`, http.StatusRequestEntityTooLarge)
		return
	}

	if !verifyGitHubSignature(body, r.Header.Get("X-Hub-Signature-256"), secret) {
		http.Error(w, `{"error":"invalid signature"}`, http.StatusUnauthorized)
		return
	}

	eventName := r.Header.Get("X-GitHub-Event")
	delivery := r.Header.Get("X-GitHub-Delivery")
	if delivery == "" {
		delivery = time.Now().UTC().Format("20060102150405.000000000")
	}

	envelope := map[string]any{
		"schema_version": "1.0",
		"event_id":       ulidLike(delivery),
		"event_type":     "code.webhook",
		"tenant_id":      r.Header.Get("X-Tenant-Id"),
		"occurred_at":    time.Now().UTC().Format(time.RFC3339Nano),
		"ingested_at":    time.Now().UTC().Format(time.RFC3339Nano),
		"source": map[string]string{
			"collector_id": "github-webhook",
			"source_type":  provider,
		},
		"asset": map[string]string{
			"asset_id": "repo-unknown",
		},
		"provider":       provider,
		"provider_event": eventName,
		"delivery_id":    delivery,
		"payload":        json.RawMessage(body),
	}
	if envelope["tenant_id"] == "" {
		envelope["tenant_id"] = "tenant-default"
	}

	raw, err := json.Marshal(envelope)
	if err != nil {
		http.Error(w, `{"error":"encode failed"}`, http.StatusInternalServerError)
		return
	}

	key := []byte(envelope["tenant_id"].(string) + ":" + envelope["event_id"].(string))
	if err := h.publisher.PublishRaw(r.Context(), h.topic, key, raw); err != nil {
		_ = h.publisher.PublishDLQ(r.Context(), key, raw, map[string]string{
			"error":  err.Error(),
			"reason": "publish_failed",
		})
		metrics.EventsRejected.Inc()
		http.Error(w, `{"error":"publish failed"}`, http.StatusBadGateway)
		return
	}

	metrics.EventsAccepted.Inc()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"accepted": 1,
		"event_id": envelope["event_id"],
	})
}

func verifyGitHubSignature(body []byte, header, secret string) bool {
	if secret == "" || header == "" {
		return false
	}
	const prefix = "sha256="
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	sig, err := hex.DecodeString(strings.TrimPrefix(header, prefix))
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	expected := mac.Sum(nil)
	return hmac.Equal(expected, sig)
}

// ulidLike produces a stable 26-char Crockford-like id from a delivery string.
func ulidLike(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	out := make([]byte, 26)
	out[0] = '0'
	for i := 1; i < 26; i++ {
		out[i] = alphabet[int(sum[i])%32]
	}
	return string(out)
}
