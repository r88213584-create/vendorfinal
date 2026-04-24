"""Structured logging configuration for VendorGuard AI.

Provides a configured logger with JSON-like structured output for production
and human-readable output for development.
"""
from __future__ import annotations

import logging
import sys
import time
from typing import Any

from app.config import settings


class StructuredFormatter(logging.Formatter):
    """Formats log records with timestamp, level, module, and message."""

    def format(self, record: logging.LogRecord) -> str:
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created))
        module = record.name.replace("app.modules.", "").replace("app.", "")
        return f"[{ts}] {record.levelname:<7} [{module}] {record.getMessage()}"


def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(StructuredFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG if settings.app_env == "dev" else logging.INFO)
    return logger


def audit_log(action: str, vendor: str, **kwargs: Any) -> None:
    """Write an audit-trail entry for compliance-sensitive operations."""
    logger = get_logger("audit")
    details = " ".join(f"{k}={v}" for k, v in kwargs.items())
    logger.info(f"AUDIT action={action} vendor={vendor} {details}")
