package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds runtime settings for the ingestion gateway.
type Config struct {
	ListenAddr            string
	APIKeys               []string
	KafkaBrokers          []string
	TopicLogsRaw          string
	TopicNetworkRaw       string
	TopicMetricsRaw       string
	TopicDeploymentsRaw   string
	TopicCodeRaw          string
	TopicHostStateRaw     string
	TopicFirewallRaw      string
	TopicZeekRaw          string
	TopicSuricataRaw      string
	TopicDnsRaw           string
	TopicPcapMeta         string
	TopicDLQ              string
	MalwareTriageURL      string
	MalwareServiceAPIKey  string
	MinIOEndpoint         string
	MinIOAccessKey        string
	MinIOSecretKey        string
	MinIOBucket           string
	MinIORegion           string
	WebhookSecrets        map[string]string
	MaxBodyBytes          int64
	MaxBatchSize          int
	MaxFutureSkew         time.Duration
	MaxEventAge           time.Duration
	SupportedMajorVersion int
}

func Load() Config {
	return Config{
		ListenAddr:            getenv("LISTEN_ADDR", ":8080"),
		APIKeys:               splitCSV(getenv("API_KEYS", "")),
		KafkaBrokers:          splitCSV(getenv("KAFKA_BROKERS", "localhost:19092")),
		TopicLogsRaw:          getenv("TOPIC_LOGS_RAW", "logs.raw"),
		TopicNetworkRaw:       getenv("TOPIC_NETWORK_RAW", "network.raw"),
		TopicMetricsRaw:       getenv("TOPIC_METRICS_RAW", "metrics.raw"),
		TopicDeploymentsRaw:   getenv("TOPIC_DEPLOYMENTS_RAW", "deployments.raw"),
		TopicCodeRaw:          getenv("TOPIC_CODE_RAW", "code.raw"),
		TopicHostStateRaw:     getenv("TOPIC_HOST_STATE_RAW", "host-state.raw"),
		TopicFirewallRaw:      getenv("TOPIC_FIREWALL_RAW", "firewall.raw"),
		TopicZeekRaw:          getenv("TOPIC_ZEEK_RAW", "zeek.raw"),
		TopicSuricataRaw:      getenv("TOPIC_SURICATA_RAW", "suricata.raw"),
		TopicDnsRaw:           getenv("TOPIC_DNS_RAW", "dns.raw"),
		TopicPcapMeta:         getenv("TOPIC_PCAP_META", "pcap.meta"),
		TopicDLQ:              getenv("TOPIC_INGEST_DLQ", "ingest.dlq"),
		MalwareTriageURL:      getenv("MALWARE_TRIAGE_URL", "http://localhost:8112"),
		MalwareServiceAPIKey:  getenv("MALWARE_SERVICE_API_KEY", "dev-malware-key"),
		MinIOEndpoint:         getenv("MINIO_ENDPOINT", ""),
		MinIOAccessKey:        getenv("MINIO_ACCESS_KEY", ""),
		MinIOSecretKey:        getenv("MINIO_SECRET_KEY", ""),
		MinIOBucket:           getenv("MINIO_PCAP_BUCKET", "pcap-artifacts"),
		MinIORegion:           getenv("MINIO_REGION", "us-east-1"),
		WebhookSecrets:        parseWebhookSecrets(getenv("WEBHOOK_SECRETS", "github=dev-webhook-secret")),
		MaxBodyBytes:          int64(getenvInt("MAX_BODY_BYTES", 1<<20)), // 1 MiB
		MaxBatchSize:          getenvInt("MAX_BATCH_SIZE", 100),
		MaxFutureSkew:         time.Duration(getenvInt("MAX_FUTURE_SKEW_SECONDS", 300)) * time.Second,
		MaxEventAge:           time.Duration(getenvInt("MAX_EVENT_AGE_SECONDS", 86400)) * time.Second,
		SupportedMajorVersion: getenvInt("SUPPORTED_MAJOR_SCHEMA_VERSION", 1),
	}
}

func (c Config) RawTopics() []string {
	return []string{
		c.TopicLogsRaw,
		c.TopicNetworkRaw,
		c.TopicMetricsRaw,
		c.TopicDeploymentsRaw,
		c.TopicCodeRaw,
		c.TopicHostStateRaw,
		c.TopicFirewallRaw,
		c.TopicZeekRaw,
		c.TopicSuricataRaw,
		c.TopicDnsRaw,
		c.TopicPcapMeta,
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getenvInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parseWebhookSecrets parses "provider=secret,other=secret2".
func parseWebhookSecrets(value string) map[string]string {
	out := map[string]string{}
	for _, part := range splitCSV(value) {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(strings.ToLower(k))
		v = strings.TrimSpace(v)
		if k != "" && v != "" {
			out[k] = v
		}
	}
	return out
}
