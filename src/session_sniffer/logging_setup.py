"""Logging setup using Rich with console + split rotating file handlers.

Console outputs INFO+ with Rich formatting (app loggers only).
File handlers split by severity: debug.log (DEBUG/INFO), warnings.log (WARNING only), and errors.log (ERROR+).
Supports rotating log files, stderr capture, and safe flushing.
"""
import atexit
import logging
import sys
from logging.handlers import RotatingFileHandler
from typing import TYPE_CHECKING

from rich.logging import RichHandler

from session_sniffer.constants.local import CURRENT_VERSION, DEBUG_LOG_PATH, ERRORS_LOG_PATH, WARNINGS_LOG_PATH

if TYPE_CHECKING:
    from collections.abc import Callable

__all__ = ['get_logger', 'setup_logging']

# --- Handler names for idempotency ---
_CONSOLE_HANDLER_NAME = 'console_handler'
_DEBUG_FILE_HANDLER_NAME = 'debug_file_handler'
_WARNINGS_FILE_HANDLER_NAME = 'warnings_file_handler'
_ERRORS_FILE_HANDLER_NAME = 'errors_file_handler'

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


def _max_level_filter(max_level: int) -> Callable[[logging.LogRecord], bool]:
    """Return a filter that passes only records at or below `max_level`."""
    def _filter(record: logging.LogRecord) -> bool:
        return record.levelno <= max_level
    return _filter


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
    """Configure root logging with Rich console + split rotating file handlers (idempotent).

    Handlers:
        - console: INFO+ with Rich formatting (app loggers only).
        - debug.log: DEBUG/INFO on pre-release; INFO only on stable (5 MiB, 3 backups).
        - warnings.log: WARNING only (1 MiB, 3 backups).
        - errors.log: ERROR and above (2 MiB, 5 backups).

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

    # --- Rotating file handler: debug.log (DEBUG/INFO on pre-release; INFO only on stable) ---
    if not any(h.name == _DEBUG_FILE_HANDLER_NAME for h in root.handlers):
        DEBUG_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        _is_prerelease = CURRENT_VERSION.pre is not None
        debug_handler = RotatingFileHandler(
            DEBUG_LOG_PATH,
            maxBytes=5_242_880,  # 5 MiB
            backupCount=3,
            encoding='utf-8',
        )
        debug_handler.name = _DEBUG_FILE_HANDLER_NAME
        debug_handler.setLevel(logging.DEBUG if _is_prerelease else logging.INFO)
        debug_handler.addFilter(_max_level_filter(logging.INFO))
        debug_handler.addFilter(_urllib3_noise_filter)
        debug_handler.addFilter(_app_only_filter)
        debug_handler.setFormatter(_FILE_FORMATTER)
        root.addHandler(debug_handler)

    # --- Rotating file handler: warnings.log (WARNING only) ---
    if not any(h.name == _WARNINGS_FILE_HANDLER_NAME for h in root.handlers):
        WARNINGS_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        warnings_handler = RotatingFileHandler(
            WARNINGS_LOG_PATH,
            maxBytes=1_048_576,  # 1 MiB
            backupCount=3,
            encoding='utf-8',
        )
        warnings_handler.name = _WARNINGS_FILE_HANDLER_NAME
        warnings_handler.setLevel(logging.WARNING)
        warnings_handler.addFilter(_max_level_filter(logging.WARNING))
        warnings_handler.addFilter(_urllib3_noise_filter)
        warnings_handler.addFilter(_scapy_noise_filter)
        warnings_handler.setFormatter(_FILE_FORMATTER)
        root.addHandler(warnings_handler)

    # --- Rotating file handler: errors.log (ERROR+) ---
    if not any(h.name == _ERRORS_FILE_HANDLER_NAME for h in root.handlers):
        ERRORS_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        errors_handler = RotatingFileHandler(
            ERRORS_LOG_PATH,
            maxBytes=2_097_152,  # 2 MiB
            backupCount=5,
            encoding='utf-8',
        )
        errors_handler.name = _ERRORS_FILE_HANDLER_NAME
        errors_handler.setLevel(logging.ERROR)
        errors_handler.addFilter(_urllib3_noise_filter)
        errors_handler.addFilter(_scapy_noise_filter)
        errors_handler.setFormatter(_FILE_FORMATTER)
        root.addHandler(errors_handler)

    # --- Root logger must be permissive enough to reach all handlers ---
    root.setLevel(min(console_level, logging.DEBUG))

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
