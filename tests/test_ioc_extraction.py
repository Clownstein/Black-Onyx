"""Tests for IOC extraction module."""


from black_onyx.extraction.ioc import (
    defang_ioc,
    refang_ioc,
    extract_iocs,
)


class TestDefangRefang:
    def test_defang_url(self):
        assert defang_ioc("http://evil.com") == "hxxp://evil[.]com"

    def test_defang_ip(self):
        assert defang_ioc("192.168.1.1") == "192[.]168[.]1[.]1"

    def test_defang_domain(self):
        assert defang_ioc("evil.com") == "evil[.]com"

    def test_refang_url(self):
        assert refang_ioc("hxxp://evil[.]com") == "http://evil.com"

    def test_refang_ip(self):
        assert refang_ioc("192[.]168[.]1[.]1") == "192.168.1.1"

    def test_refang_domain(self):
        assert refang_ioc("evil[.]com") == "evil.com"

    def test_roundtrip(self):
        original = "http://malicious-site.com/path"
        defanged = defang_ioc(original)
        refanged = refang_ioc(defanged)
        assert refanged == original


class TestExtractIOCs:
    def test_extract_ipv4(self):
        result = extract_iocs("Connect to 192.168.1.100 for C2")
        assert "192.168.1.100" in result.ipv4

    def test_extract_multiple_types(self):
        text = "Visit http://evil.com on 10.0.0.1 with hash d41d8cd98f00b204e9800998ecf8427e"
        result = extract_iocs(text)
        assert len(result.ipv4) >= 1
        assert len(result.urls) >= 1
        assert len(result.md5) >= 1

    def test_extract_sha256(self):
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        result = extract_iocs(f"File hash: {sha256}")
        assert sha256 in result.sha256

    def test_extract_cve(self):
        result = extract_iocs("Affected by CVE-2024-12345")
        assert "CVE-2024-12345" in result.cves

    def test_extract_domain(self):
        result = extract_iocs("C2 server at evil-domain.com")
        assert "evil-domain.com" in result.domains

    def test_extract_defanged(self):
        result = extract_iocs("Visit hxxp[://]evil[.]com")
        # Defanged domains should be refanged into domains list
        assert any("evil.com" in d for d in result.domains) or any("evil.com" in d for d in result.defanged_iocs)

    def test_extract_empty(self):
        result = extract_iocs("No IOCs here, just regular text.")
        assert result.total_count == 0

    def test_extract_dedup(self):
        result = extract_iocs("192.168.1.1 and 192.168.1.1 again")
        assert len(result.ipv4) == 1

    def test_to_dict(self):
        result = extract_iocs("IP: 1.2.3.4 Domain: test.com")
        d = result.to_dict()
        assert "ipv4" in d
        assert "domains" in d
        assert "1.2.3.4" in d["ipv4"]

    def test_total_count(self):
        result = extract_iocs("1.2.3.4 5.6.7.8 test.com")
        assert result.total_count == 3
