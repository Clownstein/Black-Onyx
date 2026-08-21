package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/black-onyx/ingestion-gateway/internal/auth"
	"github.com/black-onyx/ingestion-gateway/internal/config"
	"github.com/black-onyx/ingestion-gateway/internal/health"
	"github.com/black-onyx/ingestion-gateway/internal/ingest"
	"github.com/black-onyx/ingestion-gateway/internal/kafka"
	"github.com/black-onyx/ingestion-gateway/internal/metrics"
	"github.com/black-onyx/ingestion-gateway/internal/validate"
)

func main() {
	cfg := config.Load()
	log.Printf("starting ingestion-gateway on %s (brokers=%v)", cfg.ListenAddr, cfg.KafkaBrokers)

	publisher, err := kafka.NewPublisher(cfg.KafkaBrokers, cfg.RawTopics(), cfg.TopicDLQ)
	if err != nil {
		log.Fatalf("kafka publisher: %v", err)
	}
	defer publisher.Close()

	validator := validate.New(cfg.MaxFutureSkew, cfg.MaxEventAge, cfg.SupportedMajorVersion)
	authenticator := auth.NewAPIKey(cfg.APIKeys)
	pcapStore, err := ingest.NewMinioPcapStore(
		cfg.MinIOEndpoint,
		cfg.MinIOAccessKey,
		cfg.MinIOSecretKey,
		cfg.MinIOBucket,
		cfg.MinIORegion,
	)
	if err != nil {
		log.Fatalf("pcap object store: %v", err)
	}

	logsHandler := ingest.NewHandler(publisher, validator, cfg.TopicLogsRaw, "log.raw", cfg.MaxBodyBytes, cfg.MaxBatchSize)
	networkHandler := ingest.NewHandler(publisher, validator, cfg.TopicNetworkRaw, "network.flow", cfg.MaxBodyBytes, cfg.MaxBatchSize)
	metricsHandler := ingest.NewHandler(publisher, validator, cfg.TopicMetricsRaw, "metrics.sample", cfg.MaxBodyBytes, cfg.MaxBatchSize)
	deploymentsHandler := ingest.NewHandler(publisher, validator, cfg.TopicDeploymentsRaw, "deployment.event", cfg.MaxBodyBytes, cfg.MaxBatchSize)
	hostStateHandler := ingest.NewHandler(publisher, validator, cfg.TopicHostStateRaw, "host_state.process_event", cfg.MaxBodyBytes, cfg.MaxBatchSize)
	firewallHandler := ingest.NewHandler(publisher, validator, cfg.TopicFirewallRaw, "firewall.traffic", cfg.MaxBodyBytes, cfg.MaxBatchSize)
	zeekHandler := ingest.NewHandler(publisher, validator, cfg.TopicZeekRaw, "zeek.conn", cfg.MaxBodyBytes, cfg.MaxBatchSize)
	suricataHandler := ingest.NewHandler(publisher, validator, cfg.TopicSuricataRaw, "suricata.alert", cfg.MaxBodyBytes, cfg.MaxBatchSize)
	dnsHandler := ingest.NewHandler(publisher, validator, cfg.TopicDnsRaw, "dns.query", cfg.MaxBodyBytes, cfg.MaxBatchSize)
	pcapHandler := ingest.NewPcapExcerptHandler(
		publisher,
		validator,
		cfg.TopicPcapMeta,
		cfg.MaxBodyBytes,
		cfg.MaxBatchSize,
		pcapStore,
	)
	webhookHandler := ingest.NewWebhookHandler(publisher, cfg.TopicCodeRaw, cfg.WebhookSecrets, cfg.MaxBodyBytes)
	malwareProxy := ingest.NewMalwareProxyWithOptions(ingest.MalwareProxyOptions{
		TriageBaseURL: cfg.MalwareTriageURL,
		ServiceAPIKey: cfg.MalwareServiceAPIKey,
	})

	mux := http.NewServeMux()
	health.Register(mux, publisher)
	metrics.Register(mux)
	mux.Handle("/api/v1/ingest/logs", authenticator.Middleware(logsHandler))
	mux.Handle("/api/v1/ingest/network-flows", authenticator.Middleware(networkHandler))
	mux.Handle("/api/v1/ingest/metrics", authenticator.Middleware(metricsHandler))
	mux.Handle("/api/v1/ingest/deployments", authenticator.Middleware(deploymentsHandler))
	mux.Handle("/api/v1/ingest/host-state", authenticator.Middleware(hostStateHandler))
	mux.Handle("/api/v1/ingest/firewall", authenticator.Middleware(firewallHandler))
	mux.Handle("/api/v1/ingest/zeek", authenticator.Middleware(zeekHandler))
	mux.Handle("/api/v1/ingest/suricata", authenticator.Middleware(suricataHandler))
	mux.Handle("/api/v1/ingest/dns", authenticator.Middleware(dnsHandler))
	mux.Handle("/api/v1/ingest/pcap-excerpt", authenticator.Middleware(pcapHandler))
	mux.Handle("/api/v1/malware/", authenticator.Middleware(malwareProxy))
	mux.Handle("/api/v1/malware", authenticator.Middleware(malwareProxy))
	mux.Handle("/api/v1/integrations/code/{provider}/webhook", webhookHandler)

	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		// Malware proxy waits up to 60s for triage response headers; keep server
		// write deadline above that so large analyze uploads are not cut mid-proxy.
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 90 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Printf("shutdown error: %v", err)
	}
}
