"""Tests for metadata extraction and regex patterns."""

from black_onyx.extraction.metadata import (
    extract_metadata_from_html,
    extract_metadata_from_text,
    map_crypto_to_fields,
)


class TestMetadataExtraction:
    def test_email_extraction(self):
        """Test email extraction from text."""
        metadata = extract_metadata_from_text("Contact: test@example.com")
        assert "test@example.com" in metadata["emails"]

    def test_phone_extraction(self):
        """Test phone number extraction."""
        metadata = extract_metadata_from_text("Call: +1-555-123-4567")
        assert len(metadata["phone_numbers"]) > 0

    def test_bitcoin_extraction(self):
        """Test Bitcoin address extraction."""
        metadata = extract_metadata_from_text("Address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
        cryptos = metadata["cryptos"]
        assert "bitcoin" in cryptos
        assert "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" in cryptos["bitcoin"]

    def test_ethereum_extraction(self):
        """Test Ethereum address extraction."""
        metadata = extract_metadata_from_text("ETH: 0x742d35Cc6634C0532925a3b844Bc454e4438f44e")
        cryptos = metadata["cryptos"]
        assert "ethereum" in cryptos

    def test_ip_extraction(self):
        """Test IP address extraction."""
        metadata = extract_metadata_from_text("Server: 192.168.1.1")
        assert "192.168.1.1" in metadata["ip_addresses"]

    def test_url_extraction(self):
        """Test URL extraction from text."""
        metadata = extract_metadata_from_text("Visit https://example.com for more info")
        assert len(metadata["urls"]) > 0
        assert any("example.com" in u for u in metadata["urls"])

    def test_discord_invite(self):
        """Test Discord invite link extraction."""
        metadata = extract_metadata_from_text("Join: https://discord.gg/abc123")
        assert len(metadata["discord_invite"]) > 0

    def test_html_metadata(self):
        """Test HTML metadata extraction."""
        html = """
        <html>
        <head>
            <title>Test Page</title>
            <meta name="description" content="A test page">
        </head>
        <body>
            <a href="https://example.com">Link</a>
            <img src="image.png">
        </body>
        </html>
        """
        metadata = extract_metadata_from_html(html)
        assert metadata["title"] == "Test Page"
        assert len(metadata["urls"]) > 0
        assert "https://example.com" in metadata["urls"]
        assert "image.png" in metadata["image_urls"]

    def test_social_media_extraction(self):
        """Test social media profile extraction."""
        metadata = extract_metadata_from_text("Follow: https://twitter.com/testuser")
        social = metadata["social_profiles"]
        assert "twitter" in social

    def test_map_crypto_to_fields(self):
        """Test crypto pattern name to DataModel field mapping."""
        cryptos = {
            "bitcoin": ["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"],
            "ethereum": ["0x742d35Cc6634C0532925a3b844Bc454e4438f44e"],
            "ripple": ["rDsbeomae4FXwgQTJp9Rs64Qg9vDiTCdBv"],  # Not in field map
        }
        fields = map_crypto_to_fields(cryptos)
        assert "bitcoin_address" in fields
        assert "ethereum_address" in fields
        assert "ripple" not in fields  # Ripple is not mapped to a specific field
