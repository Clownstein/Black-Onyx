package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	EventsAccepted = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ingestion_events_accepted_total",
		Help: "Events accepted and published to logs.raw",
	})
	EventsRejected = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ingestion_events_rejected_total",
		Help: "Events rejected by validation or publish failures",
	})
	EventsDLQ = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ingestion_events_dlq_total",
		Help: "Events published to logs.raw.dlq",
	})
)

func Register(mux *http.ServeMux) {
	mux.Handle("/metrics", promhttp.Handler())
}
