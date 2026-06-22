"""Logging setup using Rich with console + rotating file handler.

Console outputs INFO+ with Rich formatting (app loggers only).
All log records go to a single debug.log file; severity is readable from each line's level field.
Supports rotating log files, stderr capture, and safe flushing.
"""

import atexit
import logging
import sys
from logging.handlers import RotatingFileHandler
from threading import Event, RLock, local
from typing import TYPE_CHECKING, Self, TextIO, cast, override

from rich.logging import RichHandler

from session_sniffer.constants.local import CURRENT_VERSION, DEBUG_LOG_PATH

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence
    from types import TracebackType


__all__ = ['get_logger', 'register_secret_provider', 'setup_logging']

# --- Handler names for idempotency ---
_CONSOLE_HANDLER_NAME = 'console_handler'
_DEBUG_FILE_HANDLER_NAME = 'debug_file_handler'
_APP_LOGGER_NAME = 'session_sniffer'
_STDERR_LOGGER_NAME = f'{_APP_LOGGER_NAME}.stderr'
_REDACTION_TEXT = '<redacted>'
_DEBUG_LOG_MAX_BYTES = 10_485_760  # 10 MiB
_DEBUG_LOG_BACKUP_COUNT = 5

_setup_lock = RLock()
_secret_provider_lock = RLock()
_stderr_reentry_state = local()
_atexit_registered = Event()

# --- Suppress noisy third-party retry spam ---
_SUPPRESSED_URLLIB3_SUBSTRINGS = (
    'ReadTimeoutError',
    'RemoteDisconnected',
    'ConnectionResetError',
)

# --- Suppress benign Scapy datalink-type warning for virtual/VPN adapters ---
_SUPPRESSED_SCAPY_SUBSTRINGS = ('Unable to guess datalink type',)


def _urllib3_noise_filter(record: logging.LogRecord) -> bool:
    """Suppress noisy third-party retry warnings."""
    return not (record.name.startswith('urllib3.') and any(substring in record.getMessage() for substring in _SUPPRESSED_URLLIB3_SUBSTRINGS))


def _scapy_noise_filter(record: logging.LogRecord) -> bool:
    """Suppress benign Scapy datalink-type warnings captured via stderr redirection."""
    return not (record.name == _STDERR_LOGGER_NAME and any(substring in record.getMessage() for substring in _SUPPRESSED_SCAPY_SUBSTRINGS))


def _app_only_filter(record: logging.LogRecord) -> bool:
    """Pass only records from the app's own loggers (session_sniffer.*)."""
    return record.name == _APP_LOGGER_NAME or record.name.startswith(f'{_APP_LOGGER_NAME}.')


# Callables registered by the application layer to supply secret values at
# emit time.  Populated via `register_secret_provider()` after Settings load.
_secret_providers: list[Callable[[], str | None]] = []


def _get_secret_values() -> tuple[str, ...]:
    """Return current secret values, de-duplicated and ordered longest-first."""
    with _secret_provider_lock:
        providers = tuple(_secret_providers)

    secrets: set[str] = set()
    for provider in providers:
        try:
            secret = provider()
        except Exception:  # pylint: disable=broad-exception-caught  # noqa: BLE001
            secret = None
        if secret:
            secrets.add(secret)

    return tuple(sorted(secrets, key=len, reverse=True))


def _redact_text(value: str, secrets: tuple[str, ...] | None = None) -> str:
    """Replace known secret values in a string."""
    secret_values = _get_secret_values() if secrets is None else secrets
    for secret in secret_values:
        value = value.replace(secret, _REDACTION_TEXT)
    return value


def _redact_value(value: object, secrets: tuple[str, ...]) -> object:
    """Redact secrets from common logging values."""
    if isinstance(value, str):
        return _redact_text(value, secrets)
    if isinstance(value, tuple):
        return tuple(_redact_value(item, secrets) for item in cast('Sequence[object]', value))
    if isinstance(value, list):
        return [_redact_value(item, secrets) for item in cast('Sequence[object]', value)]
    if isinstance(value, dict):
        pairs = cast('Mapping[object, object]', value)
        return {key: _redact_value(value, secrets) for key, value in pairs.items()}
    return value


def _redact_args(args: tuple[object, ...] | Mapping[str, object], secrets: tuple[str, ...]) -> tuple[object, ...] | Mapping[str, object]:
    """Redact secrets from typed logging arguments."""
    if isinstance(args, tuple):
        return tuple(_redact_value(item, secrets) for item in args)
    return {key: _redact_value(value, secrets) for key, value in args.items()}


class _SecretRedactFilter(logging.Filter):  # pylint: disable=too-few-public-methods
    """Scrub known secret values from log records before handlers emit them."""

    @override
    def filter(self, record: logging.LogRecord) -> bool:
        """Redact record message fields in-place and keep the record."""
        secrets = _get_secret_values()
        if not secrets:
            return True

        record.msg = _redact_value(record.msg, secrets)
        if record.args:
            record.args = _redact_args(record.args, secrets)
        if record.exc_text:
            record.exc_text = _redact_text(record.exc_text, secrets)
        if record.stack_info:
            record.stack_info = _redact_text(record.stack_info, secrets)
        return True


_SECRET_REDACT_FILTER = _SecretRedactFilter()


class _RedactingFormatter(logging.Formatter):
    """Formatter that redacts the final formatted line, including exception text."""

    @override
    def format(self, record: logging.LogRecord) -> str:
        """Format a record and redact any secrets that appeared during formatting."""
        formatted = super().format(record)
        secrets = _get_secret_values()
        if not secrets:
            return formatted
        return _redact_text(formatted, secrets)


def register_secret_provider(fn: Callable[[], str | None]) -> None:
    """Register a callable that returns a secret string (or `None`) to redact from logs."""
    with _secret_provider_lock:
        if fn not in _secret_providers:
            _secret_providers.append(fn)


class _StderrToLogger:
    """Redirect stderr writes to the logging system."""

    encoding = getattr(sys.__stderr__, 'encoding', 'utf-8')
    errors = getattr(sys.__stderr__, 'errors', 'replace')

    def __init__(self, logger: logging.Logger, level: int, fallback: TextIO | None = None) -> None:
        self._logger = logger
        self._level = level
        self._fallback = fallback
        self._buffer = ''
        self._lock = RLock()

    def write(self, message: str) -> int:
        """Write a message to the logger."""
        if not message:
            return 0

        if getattr(_stderr_reentry_state, 'active', False):
            self._write_fallback(message)
            return len(message)

        with self._lock:
            self._buffer += message
            lines = self._buffer.splitlines(keepends=True)
            if lines and not lines[-1].endswith(('\n', '\r')):
                self._buffer = lines.pop()
            else:
                self._buffer = ''

        for line in lines:
            self._log_line(line)

        return len(message)

    def flush(self) -> None:
        """Flush any buffered partial stderr line."""
        with self._lock:
            if not self._buffer:
                return
            line = self._buffer
            self._buffer = ''
        self._log_line(line)

    def isatty(self) -> bool:
        """Return whether the stream is attached to a terminal."""
        return False

    def writable(self) -> bool:
        """Return whether writes are supported."""
        return True

    def fileno(self) -> int:
        """Return the fallback stream file descriptor when available."""
        if self._fallback is None:
            raise OSError
        return self._fallback.fileno()

    def close(self) -> None:
        """Flush buffered stderr text without closing the fallback stream."""
        self.flush()

    def __enter__(self) -> Self:
        """Return this stream for context manager compatibility."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        """Flush buffered stderr text when leaving a context manager."""
        self.flush()

    def _log_line(self, line: str) -> None:
        """Emit a complete stderr line while guarding against logging recursion."""
        message = line.rstrip('\r\n')
        if not message:
            return

        _stderr_reentry_state.active = True
        try:
            self._logger.log(self._level, message)
        finally:
            _stderr_reentry_state.active = False

    def _write_fallback(self, message: str) -> None:
        """Write directly to the original stderr stream during recursive logging."""
        if self._fallback is None:
            return
        try:
            self._fallback.write(message)
            self._fallback.flush()
        except Exception:  # noqa: BLE001  # pylint: disable=broad-exception-caught
            return


# --- Default console level ---
DEFAULT_CONSOLE_LEVEL = logging.INFO

_FILE_FORMATTER = _RedactingFormatter(
    '%(asctime)s - %(levelname)s - %(name)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)


def _find_handler(logger: logging.Logger, name: str) -> logging.Handler | None:
    """Find a handler by name on a logger."""
    return next((handler for handler in logger.handlers if handler.name == name), None)


def _add_filter_once(handler: logging.Handler, filter_: logging.Filter | Callable[[logging.LogRecord], bool]) -> None:
    """Attach a filter only once."""
    if filter_ not in handler.filters:
        handler.addFilter(filter_)


def _configure_common_filters(handler: logging.Handler) -> None:
    """Install filters shared by all managed handlers."""
    _add_filter_once(handler, _SECRET_REDACT_FILTER)
    _add_filter_once(handler, _urllib3_noise_filter)
    _add_filter_once(handler, _scapy_noise_filter)


def _register_shutdown_once() -> None:
    """Register logging shutdown exactly once for this module."""
    if _atexit_registered.is_set():
        return
    atexit.register(logging.shutdown)
    _atexit_registered.set()


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
    with _setup_lock:
        root = logging.getLogger()

        # --- Rich console handler ---
        rich_handler = _find_handler(root, _CONSOLE_HANDLER_NAME)
        if rich_handler is None:
            rich_handler = RichHandler(
                rich_tracebacks=True,
                show_time=True,
                show_path=True,
                markup=False,
            )
            rich_handler.name = _CONSOLE_HANDLER_NAME
            root.addHandler(rich_handler)
        rich_handler.setLevel(console_level)
        _configure_common_filters(rich_handler)
        _add_filter_once(rich_handler, _app_only_filter)

        # --- Rotating file handler: debug.log (DEBUG+ on pre-release; INFO+ on stable) ---
        debug_handler = _find_handler(root, _DEBUG_FILE_HANDLER_NAME)
        if debug_handler is None:
            DEBUG_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
            debug_handler = RotatingFileHandler(
                DEBUG_LOG_PATH,
                maxBytes=_DEBUG_LOG_MAX_BYTES,
                backupCount=_DEBUG_LOG_BACKUP_COUNT,
                encoding='utf-8',
            )
            debug_handler.name = _DEBUG_FILE_HANDLER_NAME
            root.addHandler(debug_handler)
        debug_handler.setLevel(logging.DEBUG if CURRENT_VERSION.pre is not None else logging.INFO)
        debug_handler.setFormatter(_FILE_FORMATTER)
        _configure_common_filters(debug_handler)
        for handler in root.handlers:
            _add_filter_once(handler, _SECRET_REDACT_FILTER)

        # --- Root logger must be permissive enough to reach all handlers ---
        root.setLevel(min(console_level, logging.DEBUG))

        # --- Redirect Python warnings to logging ---
        logging.captureWarnings(capture=True)

        # --- Redirect stderr to logging (captures scapy, ctypes, PyQt internal errors) ---
        if sys.stderr is not None and not isinstance(sys.stderr, _StderrToLogger):
            sys.stderr = _StderrToLogger(logging.getLogger(_STDERR_LOGGER_NAME), logging.ERROR, fallback=cast('TextIO', sys.stderr))

        # --- Ensure logs flush on exit ---
        _register_shutdown_once()


def get_logger(name: str | None = None) -> logging.Logger:
    """Return a logger, ensuring logging is configured (idempotent).

    Args:
        name: The logger name (default: root logger).

    Returns:
        The configured logger.
    """
    setup_logging()
    return logging.getLogger(name)
