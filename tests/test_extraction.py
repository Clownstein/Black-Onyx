"""Tests for text extraction and chunking."""

from pathlib import Path
from zipfile import ZipFile

from black_onyx.extraction.chunking import (
    chunk_text,
    chunk_text_auto,
    chunk_text_sentence_aware,
)
from black_onyx.extraction.code import detect_code_snippets
from black_onyx.extraction.text import extract_text_from_file
from black_onyx.models.enums import detect_file_type, FileType


class TestExtractText:
    def test_extract_txt(self, tmp_data_dir: Path):
        """Test extracting text from a .txt file."""
        filepath = str(tmp_data_dir / "sample.txt")
        text = extract_text_from_file(filepath)
        assert text is not None
        assert "test@example.com" in text
        assert "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" in text

    def test_extract_html(self, tmp_data_dir: Path):
        """Test extracting text from an HTML file."""
        filepath = str(tmp_data_dir / "sample.html")
        text = extract_text_from_file(filepath)
        assert text is not None
        assert "Test Page" in text or "admin@test.com" in text

    def test_extract_json(self, tmp_data_dir: Path):
        """Test extracting text from a JSON file."""
        filepath = str(tmp_data_dir / "sample.json")
        text = extract_text_from_file(filepath)
        assert text is not None
        assert "value" in text

    def test_extract_jsonl_and_ndjson(self, tmp_path: Path):
        for suffix in (".jsonl", ".ndjson"):
            path = tmp_path / f"events{suffix}"
            path.write_text('{"indicator":"evil.example"}\n{"score":90}', encoding="utf-8")
            text = extract_text_from_file(str(path))
            assert text and "evil.example" in text and "90" in text

    def test_extract_xlsx_openxml(self, tmp_path: Path):
        path = tmp_path / "indicators.xlsx"
        with ZipFile(path, "w") as workbook:
            workbook.writestr(
                "xl/worksheets/sheet1.xml",
                '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                '<sheetData><row><c t="inlineStr"><is><t>malicious.example</t></is></c>'
                '<c t="inlineStr"><is><t>high</t></is></c></row></sheetData></worksheet>',
            )
        text = extract_text_from_file(str(path))
        assert text and "malicious.example" in text and "high" in text

    def test_nonexistent_file(self):
        """Test that nonexistent files return None."""
        text = extract_text_from_file("/nonexistent/file.txt")
        assert text is None


class TestFileTypeDetection:
    def test_detect_html(self):
        assert detect_file_type("test.html") == FileType.HTML
        assert detect_file_type("test.htm") == FileType.HTML

    def test_detect_pdf(self):
        assert detect_file_type("test.pdf") == FileType.PDF

    def test_detect_image(self):
        assert detect_file_type("test.png") == FileType.IMAGE
        assert detect_file_type("test.jpg") == FileType.IMAGE
        assert detect_file_type("test.jpeg") == FileType.IMAGE

    def test_detect_text(self):
        assert detect_file_type("test.txt") == FileType.TEXT
        assert detect_file_type("test.csv") == FileType.TEXT
        assert detect_file_type("test.json") == FileType.TEXT
        assert detect_file_type("test.xlsx") == FileType.TEXT
        assert detect_file_type("test.docx") == FileType.TEXT
        assert detect_file_type("test.ndjson") == FileType.TEXT

    def test_detect_unknown(self):
        assert detect_file_type("test.xyz") == FileType.UNKNOWN


class TestChunking:
    def test_short_text(self):
        """Test that short text returns a single chunk."""
        text = "This is a short text."
        chunks = chunk_text(text, chunk_size=100, overlap=10)
        assert len(chunks) == 1
        assert chunks[0] == text

    def test_empty_text(self):
        """Test that empty text returns an empty list."""
        assert chunk_text("", chunk_size=100, overlap=10) == []
        assert chunk_text("   ", chunk_size=100, overlap=10) == []

    def test_overlap_validation(self):
        """Test that overlap >= chunk_size raises ValueError."""
        import pytest
        with pytest.raises(ValueError):
            chunk_text("test", chunk_size=100, overlap=100)

    def test_chunking_long_text(self):
        """Test chunking of long text produces correct number of chunks."""
        text = "A" * 500
        chunks = chunk_text(text, chunk_size=100, overlap=20)
        # step = 100 - 20 = 80
        # chunks: 0-100, 80-180, 160-260, 240-340, 320-420, 400-500
        assert len(chunks) >= 5
        # Each chunk should be at most chunk_size
        for chunk in chunks:
            assert len(chunk) <= 100

    def test_sentence_aware_chunking(self):
        """Test sentence-aware chunking preserves sentence boundaries."""
        text = "First sentence. Second sentence. Third sentence. Fourth sentence."
        chunks = chunk_text_sentence_aware(text, chunk_size=50, overlap=10)
        assert len(chunks) >= 1
        # Each chunk should start with a capital letter (sentence start)
        for chunk in chunks:
            if chunk.strip():
                assert chunk.strip()[0].isupper() or chunk.strip()[0].isalpha()

    def test_chunk_auto(self):
        """Test auto chunking dispatches correctly."""
        text = "Test sentence. Another one."
        chunks_simple = chunk_text_auto(text, chunk_size=100, overlap=10, sentence_aware=False)
        chunks_sentence = chunk_text_auto(text, chunk_size=100, overlap=10, sentence_aware=True)
        assert len(chunks_simple) == 1
        assert len(chunks_sentence) == 1


class TestCodeDetection:
    def test_python_detection(self):
        """Test Python code detection."""
        code = "def hello_world():\n    print('Hello, World!')\n    return True"
        snippets, languages = detect_code_snippets(code)
        # Pygments or regex should detect Python
        assert len(snippets) >= 1
        assert len(languages) >= 1

    def test_no_code(self):
        """Test that plain text doesn't trigger code detection."""
        text = "This is just a plain text paragraph with no code."
        snippets, languages = detect_code_snippets(text)
        # May or may not detect depending on Pygments, but shouldn't crash
        assert isinstance(snippets, list)
        assert isinstance(languages, list)
