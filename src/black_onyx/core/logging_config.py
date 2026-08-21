"""Structured logging configuration with JSON output and retry utilities.

Provides:
- setup_logging(): Configure structured logging (JSON or human-readable)
- get_logger(): Get a configured logger
- retry_with_logging(): Decorator for retrying operations with structured logs
"""

from __future__ import annotations

import functools
import json
import logging
import sys
import time
from datetime import datetime, timezone
from typing import Any, Callable, TypeVar

F = TypeVar("F", bound=Callable[..., Any])


class StructuredFormatter(logging.Formatter):
    """JSON-structured log formatter for production use."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info and record.exc_info[1]:
            log_entry["exception"] = {
                "type": type(record.exc_info[1]).__name__,
                "message": str(record.exc_info[1]),
            }
        # Include extra fields
        for key, value in record.__dict__.items():
            if key not in (
                "name", "msg", "args", "levelname", "levelno", "pathname",
                "filename", "module", "exc_info", "exc_text", "stack_info",
                "lineno", "funcName", "created", "msecs", "relativeCreated",
                "thread", "threadName", "processName", "process", "message",
                "taskName",
            ):
                try:
                    json.dumps(value)
                    log_entry[key] = value
                except (TypeError, ValueError):
                    log_entry[key] = str(value)
        return json.dumps(log_entry, default=str)


class HumanReadableFormatter(logging.Formatter):
    """Human-readable formatter with color support for development."""

    COLORS = {
        "DEBUG": "\033[36m",
        "INFO": "\033[32m",
        "WARNING": "\033[33m",
        "ERROR": "\033[31m",
        "CRITICAL": "\033[35m",
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, "")
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        msg = f"{color}{timestamp} [{record.levelname}] {record.name}: {record.getMessage()}{self.RESET}"
        if record.exc_info and record.exc_info[1]:
            msg += f"\n{self.formatException(record.exc_info)}"
        return msg


def setup_logging(
    level: str = "INFO",
    structured: bool = False,
    log_file: str | None = None,
) -> None:
    """Configure logging for the application.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        structured: If True, output JSON-structured logs. If False, human-readable.
        log_file: Optional file path for log output. If None, logs to stderr only.
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)

    formatter = StructuredFormatter() if structured else HumanReadableFormatter()

    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        handlers.append(file_handler)

    for handler in handlers:
        handler.setFormatter(formatter)
        handler.setLevel(numeric_level)

    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)
    # Remove existing handlers to avoid duplicates
    root_logger.handlers.clear()
    for handler in handlers:
        root_logger.addHandler(handler)

    # Reduce noise from third-party libraries
    for noisy in ("urllib3", "httpx", "httpcore", "asyncio", "sentence_transformers"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Get a configured logger by name."""
    return logging.getLogger(name)


def retry_with_logging(
    max_retries: int = 3,
    delay: float = 1.0,
    backoff: float = 2.0,
    exceptions: tuple[type[Exception], ...] = (Exception,),
    logger_name: str = __name__,
) -> Callable[[F], F]:
    """Decorator that retries a function on failure with structured logging.

    Args:
        max_retries: Maximum number of retry attempts.
        delay: Initial delay between retries in seconds.
        backoff: Multiplier applied to delay after each retry.
        exceptions: Tuple of exception types to catch and retry on.
        logger_name: Logger name for retry messages.

    Returns:
        Decorated function with retry logic.
    """
    log = get_logger(logger_name)

    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if max_retries < 1:
                return func(*args, **kwargs)
            current_delay = delay
            last_exception: Exception | None = None
            for attempt in range(1, max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    if attempt < max_retries:
                        log.warning(
                            "Retry %d/%d for %s: %s",
                            attempt,
                            max_retries,
                            func.__name__,
                            str(e),
                            extra={
                                "retry_attempt": attempt,
                                "max_retries": max_retries,
                                "function": func.__name__,
                                "next_delay": current_delay,
                            },
                        )
                        time.sleep(current_delay)
                        current_delay *= backoff
                    else:
                        log.error(
                            "All %d retries exhausted for %s: %s",
                            max_retries,
                            func.__name__,
                            str(e),
                            extra={
                                "retry_attempt": attempt,
                                "max_retries": max_retries,
                                "function": func.__name__,
                                "exhausted": True,
                            },
                        )
            raise last_exception  # type: ignore[misc]

        return wrapper  # type: ignore[return-value]

    return decorator
