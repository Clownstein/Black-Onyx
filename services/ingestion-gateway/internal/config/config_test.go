package config

import "testing"

func TestRawTopicsIncludesNetworkSensorTopics(t *testing.T) {
	cfg := Load()
	topics := cfg.RawTopics()
	want := []string{
		cfg.TopicLogsRaw,
		cfg.TopicNetworkRaw,
		cfg.TopicMetricsRaw,
		cfg.TopicDeploymentsRaw,
		cfg.TopicCodeRaw,
		cfg.TopicHostStateRaw,
		cfg.TopicFirewallRaw,
		cfg.TopicZeekRaw,
		cfg.TopicSuricataRaw,
		cfg.TopicDnsRaw,
		cfg.TopicPcapMeta,
	}
	if len(topics) != len(want) {
		t.Fatalf("RawTopics len=%d want %d: %v", len(topics), len(want), topics)
	}
	for i := range want {
		if topics[i] != want[i] {
			t.Fatalf("RawTopics[%d]=%q want %q", i, topics[i], want[i])
		}
	}
	if cfg.TopicZeekRaw != "zeek.raw" {
		t.Fatalf("TopicZeekRaw=%q", cfg.TopicZeekRaw)
	}
	if cfg.TopicSuricataRaw != "suricata.raw" {
		t.Fatalf("TopicSuricataRaw=%q", cfg.TopicSuricataRaw)
	}
	if cfg.TopicDnsRaw != "dns.raw" {
		t.Fatalf("TopicDnsRaw=%q", cfg.TopicDnsRaw)
	}
	if cfg.TopicPcapMeta != "pcap.meta" {
		t.Fatalf("TopicPcapMeta=%q", cfg.TopicPcapMeta)
	}
}
