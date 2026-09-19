"""Logging setup with console + rotating file handler.

Console outputs INFO+ with ANSI formatting (app loggers only).
All log records go to a single debug.log file; severity is readable from each line's level field.
Supports rotating log files, stderr capture, and safe flushing.
"""

import atexit
import logging
import os
import sys
import time
from logging.handlers import RotatingFileHandler
from threading import Event, RLock, local
from typing import TYPE_CHECKING, Self, TextIO, cast, override

from session_sniffer.constants.local import CURRENT_VERSION, DEBUG_LOG_PATH

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence
    from types import TracebackType


__all__ = ['clear_secret_cache', 'get_logger', 'register_secret_provider', 'setup_logging']

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

_SECRETS_CACHE_TTL_SECONDS = 2.0
_cached_secrets: tuple[str, ...] = ()
_cached_secrets_expiry: float = 0.0  # pylint: disable=invalid-name

# --- Suppress noisy third-party retry spam ---
_SUPPRESSED_URLLIB3_SUBSTRINGS = (
    'ReadTimeoutError',
    'RemoteDisconnected',
    'ConnectionResetError',
)


def _urllib3_noise_filter(record: logging.LogRecord) -> bool:
    """Suppress noisy third-party retry warnings."""
    return not (record.name.startswith('urllib3.') and any(substring in record.getMessage() for substring in _SUPPRESSED_URLLIB3_SUBSTRINGS))


def _app_only_filter(record: logging.LogRecord) -> bool:
    """Pass only records from the app's own loggers (session_sniffer.*)."""
    return record.name == _APP_LOGGER_NAME or record.name.startswith(f'{_APP_LOGGER_NAME}.')


# Callables registered by the application layer to supply secret values at
# emit time.  Populated via `register_secret_provider()` after Settings load.
_secret_providers: list[Callable[[], str | None]] = []


def _invalidate_secret_cache() -> None:
    """Expire the cache immediately so the next `_get_secret_values()` call re-evaluates all providers.

    Must be called with `_secret_provider_lock` held.
    """
    global _cached_secrets_expiry  # noqa: PLW0603
    _cached_secrets_expiry = 0.0


def clear_secret_cache() -> None:
    """Expire the secret-value cache, forcing providers to be re-queried on the next log emit.

    Call this whenever an underlying secret changes — for example, immediately after saving
    a settings file that contains an API key or token — so that the new value is redacted
    without waiting for the TTL (`_SECRETS_CACHE_TTL_SECONDS`) to elapse.
    """
    with _secret_provider_lock:
        _invalidate_secret_cache()


def _get_secret_values() -> tuple[str, ...]:
    """Return current secret values, de-duplicated and sorted longest-first for correct substring replacement.

    Results are cached for `_SECRETS_CACHE_TTL_SECONDS` seconds.  The cache is shared across all threads.
    Providers are re-invoked only after the TTL expires, after a new provider is registered, or after
    `clear_secret_cache()` is called.  A provider that raises is silently skipped for that cycle.
    """
    global _cached_secrets, _cached_secrets_expiry  # noqa: PLW0603

    current_time = time.monotonic()
    if current_time < _cached_secrets_expiry:
        return _cached_secrets

    with _secret_provider_lock:
        if current_time < _cached_secrets_expiry:
            return _cached_secrets

        providers = tuple(_secret_providers)
        secrets: set[str] = set()
        for provider in providers:
            try:
                secret = provider()
            except Exception:  # pylint: disable=broad-exception-caught  # noqa: BLE001
                secret = None
            if secret:
                secrets.add(secret)

        _cached_secrets = tuple(sorted(secrets, key=len, reverse=True))
        _cached_secrets_expiry = time.monotonic() + _SECRETS_CACHE_TTL_SECONDS
        return _cached_secrets


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
        if getattr(record, 'secrets_redacted', False):
            return True

        secrets = _get_secret_values()
        if not secrets:
            record.secrets_redacted = True
            return True

        record.msg = _redact_value(record.msg, secrets)
        if record.args:
            record.args = _redact_args(record.args, secrets)
        if record.exc_text:
            record.exc_text = _redact_text(record.exc_text, secrets)
        if record.stack_info:
            record.stack_info = _redact_text(record.stack_info, secrets)
        record.secrets_redacted = True
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
    """Register a callable that returns a secret string (or `None`) to redact from log output.

    The callable is invoked at most once per `_SECRETS_CACHE_TTL_SECONDS` window and must be
    cheap and non-blocking.  Returning `None` or an empty string is safe and means no secret is
    currently active for that provider.  Registering a new provider immediately invalidates the
    cache so the new secret takes effect on the very next log emit.

    Each callable is registered at most once; duplicate registrations are silently ignored.
    """
    with _secret_provider_lock:
        if fn not in _secret_providers:
            _secret_providers.append(fn)
            _invalidate_secret_cache()


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
            buffered_log_line = self._buffer
            self._buffer = ''
        self._log_line(buffered_log_line)

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

_ANSI_RESET = '\033[0m'
_LEVEL_COLORS: dict[int, str] = {
    logging.DEBUG: '\033[36m',
    logging.INFO: '\033[32m',
    logging.WARNING: '\033[33m',
    logging.ERROR: '\033[31m',
    logging.CRITICAL: '\033[1;31m',
}


def _should_use_colors() -> bool:
    """Return True when standard output is attached to a terminal and color is not disabled."""
    if os.getenv('NO_COLOR'):
        return False
    return bool(hasattr(sys.stdout, 'isatty') and sys.stdout.isatty())


class _ConsoleFormatter(_RedactingFormatter):
    """Console log formatter with optional ANSI level coloring and secret redaction."""

    @override
    def format(self, record: logging.LogRecord) -> str:
        """Format a record with optional ANSI coloring for the level name."""
        level_color = _LEVEL_COLORS.get(record.levelno, '') if _should_use_colors() else ''
        original_levelname = record.levelname
        if level_color:
            record.levelname = f'{level_color}{original_levelname}{_ANSI_RESET}'
        try:
            return super().format(record)
        finally:
            record.levelname = original_levelname


_CONSOLE_FORMATTER = _ConsoleFormatter(
    '%(asctime)s [%(levelname)s] %(name)s (%(filename)s:%(lineno)d): %(message)s',
    datefmt='%H:%M:%S',
)

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


def _register_shutdown_once() -> None:
    """Register logging shutdown exactly once for this module."""
    if _atexit_registered.is_set():
        return
    atexit.register(logging.shutdown)
    _atexit_registered.set()


def setup_logging(
    console_level: int = DEFAULT_CONSOLE_LEVEL,
) -> None:
    """Configure root logging with console + rotating file handler (idempotent).

    Handlers:
        - console: INFO+ with ANSI formatting (app loggers only).
        - debug.log: DEBUG+ on pre-release; INFO+ on stable (10 MiB, 5 backups).

    Args:
        console_level: Minimum log level for the console handler.
    """
    with _setup_lock:
        root = logging.getLogger()

        # --- Console handler ---
        console_handler = _find_handler(root, _CONSOLE_HANDLER_NAME)
        if console_handler is None:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.name = _CONSOLE_HANDLER_NAME
            root.addHandler(console_handler)
        console_handler.setLevel(console_level)
        console_handler.setFormatter(_CONSOLE_FORMATTER)
        _configure_common_filters(console_handler)
        _add_filter_once(console_handler, _app_only_filter)

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

        # --- Redirect stderr to logging (captures ctypes, PySide6 internal errors) ---
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
