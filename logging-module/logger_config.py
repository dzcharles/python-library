"""Logger

Provides a single entry point for configuring application logging,
with a human-readable console format  and a JSON format for production.

The console handler uses the requested level, while the optional file
handler always records JSON at DEBUG level so that a failed run can be
diagnosed afterwards.

Safeguards:
- `SensitiveDataFilter` scrubs sensitive-looking values out of every record before it reaches a handler
"""

import logging
import logging.config
import re
import time
from typing import Any
from pathlib import Path

_REGEX_PATTERNS = [
    # Private key blocks (PEM), (?s) lets . match newlines
    r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    # Credentials in URLs: https://user:pass@host
    r"(?<=://)[^:/\s@]+:[^@/\s]+(?=@)",
    # Bearer / Basic tokens in Authorization headers
    r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9\-._~+/]+=*",
    # JSON Web Tokens
    r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
    # AWS access keys
    r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
    # GitHub tokens
    r"\bgh[pousr]_[A-Za-z0-9]{36,}\b",
    r"\bgithub_pat_[A-Za-z0-9_]{22,}\b",
    # Stripe keys
    r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b",
    # OpenAI / Anthropic style keys
    r"\bsk-[A-Za-z0-9_-]{20,}",
    # Credit card numbers (with dashes, spaces or nothing)
    r"\b(?:\d{4}[ -]?){3}\d{4}\b",
    # IBAN
    r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b",
]

_SENSITIVE_KEY_WORDS = [
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "api",
    "authorization"
]

_REDACTED = "***REDACTED***"

class SensitiveDataFilter(logging.Filter):
    redacted = _REDACTED
    patterns = [re.compile(p) for p in _REGEX_PATTERNS]
    keyword_patterns = [
        re.compile(
            # Checks the first part (key) for "", '' or no quotes. And keyword anywhere (for example: api checks for api, x-api-key,...)
            rf"""(?i)(["']?[\w-]*{re.escape(kw)}[\w-]*["']?\s*[:=]\s*)"""
            # Checks the second part (value) for "",'' or no quotes
            rf"""("[^"]*"|'[^']*'|[^\s,;&}}]+)"""
        )
        for kw in _SENSITIVE_KEY_WORDS
    ]

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.msg = self.mask_sensitive_data(record.getMessage())
            record.args = None
        except Exception:
            # Don't crash the application if masking fails
            pass
        return True

    def mask_sensitive_data(self, message: str) -> str:
        for pattern in self.patterns:
            message = pattern.sub(self.redacted, message)

        for pattern in self.keyword_patterns:
            # keep the key, replace only the value
            message = pattern.sub(r"\1" + self.redacted, message)
        return message

_DEFAULT_LOG_CONFIG: dict[str, Any] = {
    "version": 1,
    "disable_existing_loggers": False,
    "filters":{
        "sensitive_data_filter": {
            "()": SensitiveDataFilter
        }
    },
    "formatters": {
        "basic": {
            "format": "%(asctime)s - %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S%z"
        },
        "default": {
            "format": (
                "%(asctime)s %(levelname)-8s "
                "%(name)s %(filename)s:%(lineno)d "
                "%(funcName)s - %(message)s"
            ),
            "datefmt": "%Y-%m-%d %H:%M:%S%z"
        },
        "application": {
            "format": (
                "%(asctime)s %(levelname)-8s "
                "%(name)s %(filename)s:%(lineno)d "
                "%(module)s - %(funcName)s() - %(message)s"
            ),
            "datefmt": "%Y-%m-%d %H:%M:%S%z"
        },
        "json": {
            "format": (
                '{"logger": "%(name)s", '
                '"level": "%(levelname)s", '
                '"time": "%(asctime)s", '
                '"file": "%(filename)s", '
                '"line": %(lineno)d, '
                '"function": "%(funcName)s", '
                '"message": "%(message)s"}'
            ),
            "datefmt": "%Y-%m-%d %H:%M:%S%z"
        }
    },
    "handlers":{
        "console":{
            "class": "logging.StreamHandler",
            "level": "DEBUG",
            "formatter": "basic",
            "stream": "ext://sys.stdout",
            "filters": ["sensitive_data_filter"],
        },
        "local_file_server_log":{
            "class": "logging.handlers.RotatingFileHandler",
            "level": "DEBUG",
            "formatter": "default",
            "filters": ["sensitive_data_filter"],
            "filename": "logs/server.log",
            "maxBytes": 5242880,    # 5 MB
            "backupCount": 5,         
            "encoding": "utf8",
            "delay" : True,
            "mode": "a"
        },
        "local_file_application_log":{
            "class": "logging.handlers.RotatingFileHandler",
            "level": "DEBUG",
            "formatter": "application",
            "filters": ["sensitive_data_filter"],
            "filename": "logs/application.log",
            "maxBytes": 5242880,    # 5 MB
            "backupCount": 5,         
            "encoding": "utf8",
            "delay" : True,
            "mode": "a"
        },
        "local_file_json":{
            "class": "logging.handlers.RotatingFileHandler",
            "level": "DEBUG",
            "formatter": "json",
            "filters": ["sensitive_data_filter"],
            "filename": "logs/log.json",
            "maxBytes": 10485760,    # 10 MB
            "backupCount": 5,         
            "encoding": "utf8",
            "delay" : True,
            "mode": "a"
        },
        "basic_file_log": {
            "class": "logging.handlers.RotatingFileHandler",
            "level": "DEBUG",
            "formatter": "basic",
            "filters": ["sensitive_data_filter"],
            "filename": "logs/log.log",
            "maxBytes": 5242880,    # 5 MB
            "backupCount": 5,         
            "encoding": "utf8",
            "delay" : True,
            "mode": "a"
        }
    },
    "loggers":{
        # Fine-grained logging configuration for individual modules or classes
        # Call in code, example: userlog = logging.getLogger(name="userlogs")
        "basic": {
            "level": "DEBUG",
            "handlers": ["basic_file_log"],
            "propagate": True     # propages default logs to the root handler's file
        },  
        "json": {
            "level": "DEBUG",
            "handlers": ["local_file_json"],
            "propagate": True     # propages json logs to the root handler's file
        },
        "serverlogs": {
            "level": "DEBUG",
            "handlers": ["local_file_server_log"],
            "propagate": True     # propages server logs to the root handler's file
        },
        "applicationlogs": {
            "level": "DEBUG",
            "handlers": ["local_file_application_log"],
            "propagate": True      # propages application logs to the root handler's file
        }
    },
    "root": {
        # Default value for all other logs
        "level": "INFO",
        "handlers": ["console"]
    }
}

def setup_logging() -> None:
    """Setup the logging configuration based on the default settings."""

    Path("logs").mkdir(parents=True, exist_ok=True)

    #Set timezone to UTC Time
    logging.Formatter.converter = time.gmtime
    #Load the _DEFAULT_LOG_CONFIG
    logging.config.dictConfig(_DEFAULT_LOG_CONFIG)