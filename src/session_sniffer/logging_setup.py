"""Logging setup using Rich with console + rotating file handler.

Console outputs INFO+ with Rich formatting (app loggers only).
All log records go to a single debug.log file; severity is readable from each line's level field.
Supports rotating log files, stderr capture, and safe flushing.
"""
import atexit
import logging
import sys
from logging.handlers import RotatingFileHandler
from typing import TYPE_CHECKING

from rich.logging import RichHandler

from session_sniffer.constants.local import CURRENT_VERSION, DEBUG_LOG_PATH

if TYPE_CHECKING:
    from collections.abc import Callable

__all__ = ['get_logger', 'register_secret_provider', 'setup_logging']

# --- Handler names for idempotency ---
_CONSOLE_HANDLER_NAME = 'console_handler'
_DEBUG_FILE_HANDLER_NAME = 'debug_file_handler'

# --- Suppress noisy third-party retry spam ---
_SUPPRESSED_URLLIB3_SUBSTRINGS = (
    'ReadTimeoutError',
    'RemoteDisconnected',
    'ConnectionResetError',
)

# --- Suppress benign Scapy datalink-type warning for virtual/VPN adapters ---
_SUPPRESSED_SCAPY_SUBSTRINGS = (
    'Unable to guess datalink type',
)


def _urllib3_noise_filter(record: logging.LogRecord) -> bool:
    """Suppress noisy third-party retry warnings."""
    return not (record.name.startswith('urllib3.') and any(s in record.getMessage() for s in _SUPPRESSED_URLLIB3_SUBSTRINGS))


def _scapy_noise_filter(record: logging.LogRecord) -> bool:
    """Suppress benign Scapy datalink-type warnings captured via stderr redirection."""
    return not (record.name == 'session_sniffer.stderr' and any(s in record.getMessage() for s in _SUPPRESSED_SCAPY_SUBSTRINGS))


def _app_only_filter(record: logging.LogRecord) -> bool:
    """Pass only records from the app's own loggers (session_sniffer.*)."""
    return record.name == 'session_sniffer' or record.name.startswith('session_sniffer.')


class _SecretRedactFilter(logging.Filter):  # pylint: disable=too-few-public-methods
    """Redact sensitive setting values (API keys, passwords) from all log records.

    Reads secrets dynamically from registered provider callables so that
    `logging_setup` never imports `settings.settings` (which would create a
    cyclic import). Providers are registered via `register_secret_provider()`.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        """Scrub known secret values from the log record message in-place."""
        secrets = [v for fn in _secret_providers if (v := fn())]
        if not secrets:
            return True
        msg = record.getMessage()
        for secret in secrets:
            msg = msg.replace(secret, '<redacted>')
        record.msg = msg
        record.args = None
        return True


_REDACT_FILTER_NAME = 'secret_redact_filter'

# Callables registered by the application layer to supply secret values at
# emit time.  Populated via `register_secret_provider()` after Settings load.
_secret_providers: list[Callable[[], str | None]] = []


def register_secret_provider(fn: Callable[[], str | None]) -> None:
    """Register a callable that returns a secret string (or `None`) to redact from logs."""
    _secret_providers.append(fn)


class _StderrToLogger:
    """Redirect stderr writes to the logging system."""

    def __init__(self, logger: logging.Logger, level: int) -> None:
        self._logger = logger
        self._level = level

    def write(self, message: str) -> None:
        """Write a message to the logger."""
        message = message.strip()
        if message:
            self._logger.log(self._level, message)

    def flush(self) -> None:
        """Flush (no-op for logging)."""


# --- Default console level ---
DEFAULT_CONSOLE_LEVEL = logging.INFO

_FILE_FORMATTER = logging.Formatter(
    '%(asctime)s - %(levelname)s - %(name)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)


def setup_logging(
    console_level: int = DEFAULT_CONSOLE_LEVEL,
) -> None:
    """Configure root logging with Rich console + rotating file handler (idempotent).

    Handlers:
        - console: INFO+ with Rich formatting (app loggers only).
        - debug.log: DEBUG+ on pre-release; INFO+ on stable (10 MiB, 5 backups).

    Args:
        console_level: Minimum log level for the console handler.
    """
    root = logging.getLogger()

    # --- Rich console handler ---
    if not any(h.name == _CONSOLE_HANDLER_NAME for h in root.handlers):
        rich_handler = RichHandler(
            rich_tracebacks=True,
            show_time=True,
            show_path=True,
            markup=False,
        )
        rich_handler.name = _CONSOLE_HANDLER_NAME
        rich_handler.setLevel(console_level)
        rich_handler.addFilter(_urllib3_noise_filter)
        rich_handler.addFilter(_scapy_noise_filter)
        rich_handler.addFilter(_app_only_filter)
        root.addHandler(rich_handler)

    # --- Rotating file handler: debug.log (DEBUG+ on pre-release; INFO+ on stable) ---
    if not any(h.name == _DEBUG_FILE_HANDLER_NAME for h in root.handlers):
        DEBUG_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        _is_prerelease = CURRENT_VERSION.pre is not None
        debug_handler = RotatingFileHandler(
            DEBUG_LOG_PATH,
            maxBytes=10_485_760,  # 10 MiB
            backupCount=5,
            encoding='utf-8',
        )
        debug_handler.name = _DEBUG_FILE_HANDLER_NAME
        debug_handler.setLevel(logging.DEBUG if _is_prerelease else logging.INFO)
        debug_handler.addFilter(_urllib3_noise_filter)
        debug_handler.addFilter(_scapy_noise_filter)
        debug_handler.setFormatter(_FILE_FORMATTER)
        root.addHandler(debug_handler)

    # --- Root logger must be permissive enough to reach all handlers ---
    root.setLevel(min(console_level, logging.DEBUG))

    # --- Redact secrets from all log output ---
    if not any(isinstance(f, logging.Filter) and f.name == _REDACT_FILTER_NAME for f in root.filters):
        redact_filter = _SecretRedactFilter(name=_REDACT_FILTER_NAME)
        root.addFilter(redact_filter)

    # --- Redirect Python warnings to logging ---
    logging.captureWarnings(capture=True)

    # --- Redirect stderr to logging (captures scapy, ctypes, PyQt internal errors) ---
    if sys.stderr is not None and not isinstance(sys.stderr, _StderrToLogger):
        sys.stderr = _StderrToLogger(logging.getLogger('session_sniffer.stderr'), logging.ERROR)

    # --- Ensure logs flush on exit ---
    atexit.register(logging.shutdown)


def get_logger(name: str | None = None) -> logging.Logger:
    """Return a logger, ensuring logging is configured (idempotent).

    Args:
        name: The logger name (default: root logger).

    Returns:
        The configured logger.
    """
    setup_logging()
    return logging.getLogger(name)
