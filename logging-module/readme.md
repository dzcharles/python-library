# Logging Module

A reusable logging configuration for Python applications. It configures the standard-library `logging` package with console output, rotating log files, source-location details, and sensitive-data redaction.

## Features

- UTC timestamps
- Console output through the root logger
- Rotating log files with a 5 MB limit and five backups
- A 10 MB JSON log with five backups
- Source logger, filename, line number, module, and function in file formats
- Redaction of common secrets, including passwords, tokens, API keys, bearer tokens, private keys, credit card numbers, and IBANs
- Automatic creation of the `logs/` directory

## Requirements

The module uses only the Python standard library. Python 3.9 or newer is recommended because the configuration uses built-in generic type annotations.

## Usage

Call `setup_logging()` once when the application starts, before writing log messages:

```python
import logging

from logger_config import setup_logging

setup_logging()

logger = logging.getLogger(__name__)

logger.info("Server started")
logger.warning("A warning was raised")

try:
	raise RuntimeError("Example failure")
except RuntimeError:
	logger.exception("The server failed")
```

Run the included example from this directory:

```bash
python example.py
```

## Named Loggers

The configuration provides named loggers for applications that want separate log files:

```python
import logging

basic_logger = logging.getLogger("basic")
json_logger = logging.getLogger("json")
server_logger = logging.getLogger("serverlogs")
application_logger = logging.getLogger("applicationlogs")
```

The logger names map to these files:

| Logger | File | Format |
| --- | --- | --- |
| root / `__name__` | Console | Basic text |
| `basic` | `logs/log.log` | Basic text |
| `json` | `logs/log.json` | JSON-formatted text |
| `serverlogs` | `logs/server.log` | Detailed text |
| `applicationlogs` | `logs/application.log` | Detailed application text |

Named loggers propagate to the root logger, so their messages are also displayed on the console. The root logger itself writes to the console only.

## Log Location

The module creates `logs/` relative to the process working directory when `setup_logging()` runs. The files use delayed opening, so a file is physically created when its first message is emitted.

To use a different directory, update the handler `filename` values in `_DEFAULT_LOG_CONFIG` before calling `setup_logging()`. The current implementation does not load `.env` values automatically.

## Sensitive Data Redaction

The `SensitiveDataFilter` is attached to every configured handler. It redacts matching values before they are written to the console or log files:

```python
logger.info("request password=hunter2 token=abc123")
```

The output will replace the sensitive values with `***REDACTED***`. Redaction is pattern-based and cannot guarantee detection of every possible secret, so applications should still avoid logging credentials whenever possible.

## Log Rotation

The rotating file handlers use these defaults:

- Basic, server, and application logs: 5 MB per file, five backups
- JSON log: 10 MB per file, five backups

## Project Files

- `logger_config.py`: logging configuration and `setup_logging()`
- `example.py`: small usage example
- `readme.md`: module documentation
