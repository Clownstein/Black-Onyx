"""Tests for MITRE ATT&CK mapper, STIX exporter, Sigma/YARA generators, and graph builder."""


from black_onyx.threat.attack_mapper import AttackMapper
from black_onyx.threat.stix_exporter import STIXExporter
from black_onyx.threat.sigma_generator import SigmaRuleGenerator
from black_onyx.threat.yara_generator import YARARuleGenerator
from black_onyx.threat.graph_builder import GraphBuilder


class TestAttackMapper:
    def test_init_with_fallback(self):
        mapper = AttackMapper()
        assert mapper is not None

    def test_get_technique(self):
        mapper = AttackMapper()
        tech = mapper.get_technique("T1059")
        assert tech is not None
        assert "name" in tech

    def test_search(self):
        mapper = AttackMapper()
        results = mapper.search_techniques("execution")
        assert len(results) > 0

    def test_extract_from_text(self):
        mapper = AttackMapper()
        results = mapper.extract_techniques_from_text("Uses T1059 for execution and T1566 for phishing")
        technique_ids = [r["technique_id"] if isinstance(r, dict) else r for r in results]
        assert "T1059" in technique_ids
        assert "T1566" in technique_ids


class TestSTIXExporter:
    def test_export_basic(self):
        exporter = STIXExporter()
        iocs = [
            {"ioc_type": "ipv4", "ioc_value": "1.2.3.4"},
            {"ioc_type": "domain", "ioc_value": "evil.com"},
        ]
        bundle = exporter.export_bundle(iocs=iocs)
        assert bundle["type"] == "bundle"
        assert bundle["id"].startswith("bundle--")
        assert len(bundle["objects"]) >= 3  # identity + 2 indicators

    def test_export_empty(self):
        exporter = STIXExporter()
        bundle = exporter.export_bundle(iocs=[])
        assert bundle["type"] == "bundle"
        assert len(bundle["objects"]) >= 1  # at least identity


class TestSigmaGenerator:
    def test_generate_basic(self):
        gen = SigmaRuleGenerator()
        iocs = {"ipv4": ["1.2.3.4"], "domains": ["evil.com"]}
        rule = gen.generate_from_iocs(iocs, title="Test Rule")
        assert "title: Test Rule" in rule
        assert "1.2.3.4" in rule

    def test_generate_empty(self):
        gen = SigmaRuleGenerator()
        rule = gen.generate_from_iocs({}, title="Empty Rule")
        assert "title: Empty Rule" in rule


class TestYARAGenerator:
    def test_generate_basic(self):
        gen = YARARuleGenerator()
        iocs = {"md5": ["d41d8cd98f00b204e9800998ecf8427e"]}
        rule = gen.generate_from_iocs(iocs, rule_name="TestYara")
        assert "rule TestYara" in rule
        assert "d41d8cd98f00b204e9800998ecf8427e" in rule

    def test_generate_with_strings(self):
        gen = YARARuleGenerator()
        iocs = {"domains": ["evil.com"]}
        rule = gen.generate_from_iocs(iocs, rule_name="StringTest")
        assert "evil.com" in rule


class TestGraphBuilder:
    def test_build_from_payloads(self):
        builder = GraphBuilder()
        payloads = [
            {"source_file": "doc1.txt", "iocs_ipv4": ["1.2.3.4"], "iocs_domain": ["evil.com"]},
            {"source_file": "doc2.txt", "iocs_ipv4": ["1.2.3.4"], "iocs_domain": ["bad.com"]},
        ]
        graph = builder.build_from_payloads(payloads)
        assert "nodes" in graph
        assert "edges" in graph
        assert len(graph["nodes"]) > 0

    def test_build_empty(self):
        builder = GraphBuilder()
        graph = builder.build_from_payloads([])
        assert len(graph["nodes"]) == 0
        assert len(graph["edges"]) == 0
