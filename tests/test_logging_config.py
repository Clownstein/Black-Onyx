"""Tests for structured logging configuration (logging_config.py)."""

import json
import logging

import pytest

from black_onyx.core.logging_config import (
    StructuredFormatter,
    HumanReadableFormatter,
    setup_logging,
    retry_with_logging,
)


class TestStructuredFormatter:
    def test_format_json(self):
        formatter = StructuredFormatter()
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg="Test message %s", args=("arg",), exc_info=None,
        )
        output = formatter.format(record)
        data = json.loads(output)
        assert data["level"] == "INFO"
        assert data["message"] == "Test message arg"
        assert data["logger"] == "test"
        assert "timestamp" in data

    def test_format_with_exception(self):
        formatter = StructuredFormatter()
        try:
            raise ValueError("test error")
        except ValueError:
            import sys
            record = logging.LogRecord(
                name="test", level=logging.ERROR, pathname="", lineno=0,
                msg="Error occurred", args=(), exc_info=sys.exc_info(),
            )
        output = formatter.format(record)
        data = json.loads(output)
        assert "exception" in data
        assert data["exception"]["type"] == "ValueError"


class TestHumanReadableFormatter:
    def test_format_contains_message(self):
        formatter = HumanReadableFormatter()
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg="Hello %s", args=("world",), exc_info=None,
        )
        output = formatter.format(record)
        assert "Hello world" in output
        assert "INFO" in output


class TestSetupLogging:
    def test_setup_logging_default(self):
        setup_logging(level="INFO", structured=False)
        logger = logging.getLogger()
        assert logger.level == logging.INFO

    def test_setup_logging_debug(self):
        setup_logging(level="DEBUG", structured=False)
        logger = logging.getLogger()
        assert logger.level == logging.DEBUG

    def test_setup_logging_structured(self):
        setup_logging(level="INFO", structured=True)
        logger = logging.getLogger()
        assert logger.level == logging.INFO
        # Check that handlers have StructuredFormatter
        has_structured = any(
            isinstance(h.formatter, StructuredFormatter)
            for h in logger.handlers
        )
        assert has_structured


class TestRetryWithLogging:
    def test_retry_succeeds_on_first_try(self):
        call_count = 0

        @retry_with_logging(max_retries=3, delay=0.01)
        def succeed():
            nonlocal call_count
            call_count += 1
            return "ok"

        result = succeed()
        assert result == "ok"
        assert call_count == 1

    def test_retry_succeeds_after_failure(self):
        call_count = 0

        @retry_with_logging(max_retries=3, delay=0.01, backoff=1.0)
        def fail_then_succeed():
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise ValueError("fail")
            return "ok"

        result = fail_then_succeed()
        assert result == "ok"
        assert call_count == 2

    def test_retry_exhausted(self):
        @retry_with_logging(max_retries=2, delay=0.01, backoff=1.0)
        def always_fail():
            raise ValueError("always fails")

        with pytest.raises(ValueError, match="always fails"):
            always_fail()

    def test_retry_specific_exception(self):
        @retry_with_logging(max_retries=3, delay=0.01, exceptions=(ValueError,))
        def raise_type_error():
            raise TypeError("wrong type")

        with pytest.raises(TypeError):
            raise_type_error()  # Should not retry on TypeError
