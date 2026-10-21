package health

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/black-onyx/ingestion-gateway/internal/kafka"
)

type dependencyPinger interface {
	Ping(ctx context.Context) error
}

func Register(mux *http.ServeMux, publisher *kafka.Publisher) {
	mux.HandleFunc("/health/live", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "alive"})
	})

	mux.HandleFunc("/health/ready", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := publisher.Ping(ctx); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"status": "not_ready",
				"error":  err.Error(),
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	})

	mux.HandleFunc("/health/dependencies", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		deps := map[string]any{}
		status := http.StatusOK
		if err := ping(ctx, publisher); err != nil {
			deps["redpanda"] = map[string]string{"status": "down", "error": err.Error()}
			status = http.StatusServiceUnavailable
		} else {
			deps["redpanda"] = map[string]string{"status": "up"}
		}
		writeJSON(w, status, map[string]any{
			"status":       statusLabel(status),
			"dependencies": deps,
		})
	})
}

func ping(ctx context.Context, p dependencyPinger) error {
	return p.Ping(ctx)
}

func statusLabel(code int) string {
	if code == http.StatusOK {
		return "ok"
	}
	return "degraded"
}

func writeJSON(w http.ResponseWriter, code int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(payload)
}
