"""Windows guard for the protobuf-incompatible PaddleOCR 2.x stack."""

from black_onyx.extraction.ocr import OCREngine


def test_paddle_backend_fails_closed_on_windows(monkeypatch) -> None:
    monkeypatch.setattr("black_onyx.extraction.ocr.sys.platform", "win32")
    engine = OCREngine(backend="paddle")

    assert engine.is_available is False
    assert "disabled on Windows" in (engine.load_error or "")
