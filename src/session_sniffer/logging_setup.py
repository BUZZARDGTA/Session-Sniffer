"""Logging setup using Rich with console + split rotating file handlers.

Console shows all messages with source file information.
File handlers split by severity: warnings.log (WARNING only) and errors.log (ERROR+).
Supports rotating log files, Rich formatting, stderr capture, and safe flushing.
"""
import atexit
import logging
import sys
from logging.handlers import RotatingFileHandler

from rich.console import Console

from session_sniffer.constants.local import CURRENT_VERSION, DEBUG_LOG_PATH, ERRORS_LOG_PATH, LIBS_DEBUG_LOG_PATH, WARNINGS_LOG_PATH

__all__ = ['console', 'get_logger', 'setup_logging']

# --- Shared Rich console instance ---
console: Console = Console()

# --- Handler names for idempotency ---
_DEBUG_FILE_HANDLER = 'debug_file_handler'
_LIBS_DEBUG_FILE_HANDLER = 'libs_debug_file_handler'
_WARNINGS_FILE_HANDLER = 'warnings_file_handler'
_ERRORS_FILE_HANDLER = 'errors_file_handler'

# --- Patterns to suppress from all handlers (noisy third-party retry spam) ---
_SUPPRESSED_URLLIB3_SUBSTRINGS = (
    'ReadTimeoutError',
    'RemoteDisconnected',
)

# --- Scapy stderr noise: benign datalink-type warning emitted for virtual/VPN adapters ---
_SUPPRESSED_SCAPY_SUBSTRINGS = (
    'Unable to guess datalink type',
)


def _urllib3_noise_filter(record: logging.LogRecord) -> bool:
    """Suppress noisy third-party retry warnings from all handlers."""
    return not (record.name.startswith('urllib3.') and any(s in record.getMessage() for s in _SUPPRESSED_URLLIB3_SUBSTRINGS))


def _scapy_noise_filter(record: logging.LogRecord) -> bool:
    """Suppress benign Scapy datalink-type warnings captured via stderr redirection."""
    return not (record.name == 'session_sniffer.stderr' and any(s in record.getMessage() for s in _SUPPRESSED_SCAPY_SUBSTRINGS))


def _app_only_filter(record: logging.LogRecord) -> bool:
    """Pass only records from the app's own loggers (session_sniffer.*)."""
    return record.name == 'session_sniffer' or record.name.startswith('session_sniffer.')


def _libs_only_filter(record: logging.LogRecord) -> bool:
    """Pass only records from third-party library loggers (not session_sniffer.*)."""
    return record.name != 'session_sniffer' and not record.name.startswith('session_sniffer.')


class _LevelFilter(logging.Filter):  # pylint: disable=too-few-public-methods
    """Filter log records by exact level, minimum level, or maximum level."""

    def __init__(self, *, exact: int | None = None, min_level: int | None = None, max_level: int | None = None) -> None:
        super().__init__()
        self._exact = exact
        self._min_level = min_level
        self._max_level = max_level

    def filter(self, record: logging.LogRecord) -> bool:
        if self._exact is not None:
            return record.levelno == self._exact
        passes = True
        if self._min_level is not None:
            passes = passes and record.levelno >= self._min_level
        if self._max_level is not None:
            passes = passes and record.levelno <= self._max_level
        return passes


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

# --- Module-level flag to register atexit only once ---
_atexit_registered = False


_FILE_FORMATTER = logging.Formatter(
    '%(asctime)s - %(levelname)s - %(pathname)s:%(lineno)d - %(name)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M',
)


def setup_logging(
    console_level: int = DEFAULT_CONSOLE_LEVEL,
) -> None:
    """Configure root logging with split rotating file handlers (idempotent).

    Handlers:
        - warnings.log: WARNING only (1 MiB, 3 backups).
        - errors.log: ERROR and above (2 MiB, 5 backups).

    Args:
        console_level: Minimum log level for the root logger.
    """
    global _atexit_registered

    root = logging.getLogger()

    # --- Rotating file handler: debug.log (DEBUG+INFO on pre-release, INFO only on stable) ---
    if not any(h.name == _DEBUG_FILE_HANDLER for h in root.handlers):
        DEBUG_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        _is_prerelease = CURRENT_VERSION.pre is not None
        debug_handler = RotatingFileHandler(
            DEBUG_LOG_PATH,
            maxBytes=5_242_880,  # 5 MiB
            backupCount=3,
            encoding='utf-8',
        )
        debug_handler.name = _DEBUG_FILE_HANDLER
        debug_handler.setLevel(logging.DEBUG if _is_prerelease else logging.INFO)
        debug_handler.addFilter(_LevelFilter(min_level=logging.DEBUG if _is_prerelease else logging.INFO, max_level=logging.INFO))
        debug_handler.addFilter(_urllib3_noise_filter)
        debug_handler.addFilter(_app_only_filter)
        debug_handler.setFormatter(_FILE_FORMATTER)
        root.addHandler(debug_handler)

    # --- Rotating file handler: libs_debug.log (DEBUG and INFO, third-party only) ---
    if not any(h.name == _LIBS_DEBUG_FILE_HANDLER for h in root.handlers):
        LIBS_DEBUG_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        libs_debug_handler = RotatingFileHandler(
            LIBS_DEBUG_LOG_PATH,
            maxBytes=5_242_880,  # 5 MiB
            backupCount=3,
            encoding='utf-8',
        )
        libs_debug_handler.name = _LIBS_DEBUG_FILE_HANDLER
        libs_debug_handler.setLevel(logging.INFO)
        libs_debug_handler.addFilter(_LevelFilter(min_level=logging.INFO))
        libs_debug_handler.addFilter(_urllib3_noise_filter)
        libs_debug_handler.addFilter(_libs_only_filter)
        libs_debug_handler.setFormatter(_FILE_FORMATTER)
        root.addHandler(libs_debug_handler)

    # --- Rotating file handler: warnings.log (WARNING only) ---
    if not any(h.name == _WARNINGS_FILE_HANDLER for h in root.handlers):
        WARNINGS_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        warnings_handler = RotatingFileHandler(
            WARNINGS_LOG_PATH,
            maxBytes=1_048_576,  # 1 MiB
            backupCount=3,
            encoding='utf-8',
        )
        warnings_handler.name = _WARNINGS_FILE_HANDLER
        warnings_handler.setLevel(logging.WARNING)
        warnings_handler.addFilter(_LevelFilter(exact=logging.WARNING))
        warnings_handler.addFilter(_urllib3_noise_filter)
        warnings_handler.addFilter(_scapy_noise_filter)
        warnings_handler.setFormatter(_FILE_FORMATTER)
        root.addHandler(warnings_handler)

    # --- Rotating file handler: errors.log (ERROR+) ---
    if not any(h.name == _ERRORS_FILE_HANDLER for h in root.handlers):
        ERRORS_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        errors_handler = RotatingFileHandler(
            ERRORS_LOG_PATH,
            maxBytes=2_097_152,  # 2 MiB
            backupCount=5,
            encoding='utf-8',
        )
        errors_handler.name = _ERRORS_FILE_HANDLER
        errors_handler.setLevel(logging.ERROR)
        errors_handler.addFilter(_LevelFilter(min_level=logging.ERROR))
        errors_handler.addFilter(_urllib3_noise_filter)
        errors_handler.addFilter(_scapy_noise_filter)
        errors_handler.setFormatter(_FILE_FORMATTER)
        root.addHandler(errors_handler)

    # --- Root logger must be permissive enough to let all configured handlers see their messages ---
    root.setLevel(min(console_level, logging.DEBUG))

    # --- Redirect Python warnings to logging ---
    logging.captureWarnings(capture=True)

    # --- Redirect stderr to logging (captures scapy, ctypes, PyQt internal errors) ---
    if sys.stderr is not None and not isinstance(sys.stderr, _StderrToLogger):
        sys.stderr = _StderrToLogger(logging.getLogger('session_sniffer.stderr'), logging.ERROR)

    # --- Ensure logs flush on exit ---
    if not _atexit_registered:
        atexit.register(logging.shutdown)
        _atexit_registered = True


def get_logger(name: str | None = None) -> logging.Logger:
    """Return a logger, ensuring logging is configured (idempotent).

    Args:
        name: The logger name (default: root logger).

    Returns:
        The configured logger.
    """
    setup_logging()
    return logging.getLogger(name)
