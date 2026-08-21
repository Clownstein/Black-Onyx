"""Test fixtures and configuration."""

import sys
from pathlib import Path

import pytest

# Add src to path for testing
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))


@pytest.fixture
def tmp_data_dir(tmp_path: Path) -> Path:
    """Create a temporary data directory with sample files."""
    data_dir = tmp_path / "data"
    data_dir.mkdir()

    # Create a sample text file
    (data_dir / "sample.txt").write_text(
        "This is a test file with an email: test@example.com\n"
        "And a phone number: +1-555-123-4567\n"
        "Bitcoin address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n"
    )

    # Create a sample HTML file
    (data_dir / "sample.html").write_text(
        "<html><head><title>Test Page</title></head>"
        "<body><p>Contact: admin@test.com</p>"
        "<a href='https://example.com'>Link</a></body></html>"
    )

    # Create a sample JSON file
    (data_dir / "sample.json").write_text('{"key": "value", "number": 42}')

    return data_dir


@pytest.fixture
def mock_settings():
    """Create mock settings for testing (without loading actual models)."""
    from black_onyx.config import Settings
    return Settings()
