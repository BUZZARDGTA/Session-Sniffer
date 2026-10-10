"""Logging setup with console + rotating file handler.

Console outputs INFO+ with ANSI formatting (app loggers only).
All log records go to a single debug.log file; severity is readable from each line's level field.
Supports rotating log files, stderr capture, and safe flushing.
"""

import atexit
import contextlib
import ctypes
import faulthandler
import logging
import os
import sys
import threading
import time
import traceback
from dataclasses import dataclass
from logging.handlers import RotatingFileHandler
from pathlib import Path
from threading import Event, RLock, local
from typing import TYPE_CHECKING, Any, Self, TextIO, cast, override

from session_sniffer.constants.local import CRASH_LOG_PATH, CURRENT_VERSION, DEBUG_LOG_PATH

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence
    from types import FrameType, TracebackType


__all__ = ['clear_secret_cache', 'dump_crash_diagnostics', 'flush_all_loggers', 'register_diagnostic_provider', 'register_secret_provider', 'setup_logging']

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


@dataclass
class _LoggingState:
    """Mutable module-level state shared by the logging, secret-redaction, and crash-diagnostic helpers."""

    crash_log_file: TextIO | None = None
    cached_secrets: tuple[str, ...] = ()
    cached_secrets_expiry: float = 0.0
    win32_crt_handlers_installed: bool = False
    # CRT callback objects must stay referenced for the process lifetime so ctypes does not free them.
    c_invalid_param_handler: Any = None
    c_purecall_handler: Any = None
    c_sigabrt_handler: Any = None
    prev_sigabrt_handler: int = 0


_state = _LoggingState()

if sys.platform == 'win32':
    _INVALID_PARAM_HANDLER_TYPE = ctypes.CFUNCTYPE(
        None,
        ctypes.c_wchar_p,  # expression
        ctypes.c_wchar_p,  # function
        ctypes.c_wchar_p,  # file
        ctypes.c_uint,     # line
        ctypes.c_void_p,   # pReserved
    )
    _PURECALL_HANDLER_TYPE = ctypes.CFUNCTYPE(None)
    _SIGNAL_HANDLER_TYPE = ctypes.CFUNCTYPE(None, ctypes.c_int)
else:
    _INVALID_PARAM_HANDLER_TYPE = None
    _PURECALL_HANDLER_TYPE = None
    _SIGNAL_HANDLER_TYPE = None


def _win32_invalid_param_handler(
    expression: str | None,
    function: str | None,
    file: str | None,
    line: int,
    _reserved: int | None,
) -> None:
    msg = f'CRT invalid parameter detected: function={function}, file={file}:{line}, expression={expression}'
    dump_crash_diagnostics(msg)


def _win32_purecall_handler() -> None:
    dump_crash_diagnostics('CRT pure virtual function call detected')


def _win32_sigabrt_handler(sig: int) -> None:
    dump_crash_diagnostics('SIGABRT received (C runtime abort)')
    if _state.prev_sigabrt_handler and _state.prev_sigabrt_handler not in (0, 1):
        with contextlib.suppress(Exception):
            prev_fn = _SIGNAL_HANDLER_TYPE(_state.prev_sigabrt_handler)
            prev_fn(sig)


def _capture_win32_native_stack(max_frames: int = 32) -> list[str]:
    """Capture native C/C++ return addresses and module offsets for the current thread."""
    lines: list[str] = []
    if sys.platform != 'win32':
        return lines
    try:
        kernel32 = ctypes.windll.kernel32
        frames = (ctypes.c_void_p * max_frames)()
        captured_count: int = int(kernel32.RtlCaptureStackBackTrace(0, max_frames, frames, None))
        module_handle_flag = 0x00000004  # GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
        buffer = ctypes.create_unicode_buffer(512)
        h_module = ctypes.c_void_p()
        lines.append(f'Native C/C++ stack trace ({captured_count} frames):')
        for index in range(captured_count):
            address = frames[index]
            if not address:
                continue
            if kernel32.GetModuleHandleExW(module_handle_flag, ctypes.c_void_p(address), ctypes.byref(h_module)):
                kernel32.GetModuleFileNameW(h_module, buffer, 512)
                module_name = Path(buffer.value).name
                base_address = h_module.value or 0
                offset = address - base_address
                lines.append(f'  #{index:02d}: 0x{address:016x} -> {module_name}+0x{offset:x}')
            else:
                lines.append(f'  #{index:02d}: 0x{address:016x}')
    except (AttributeError, OSError, ctypes.ArgumentError) as e:
        lines.append(f'  Failed to capture native stack: {e}')
    return lines


def _install_win32_crt_handlers() -> None:
    """Install Windows CRT diagnostic handlers to intercept and log low-level aborts and asserts."""
    if sys.platform != 'win32' or _state.win32_crt_handlers_installed:
        return
    try:
        ucrt = ctypes.cdll.ucrtbase
        _state.c_invalid_param_handler = _INVALID_PARAM_HANDLER_TYPE(_win32_invalid_param_handler)
        ucrt['_set_invalid_parameter_handler'](_state.c_invalid_param_handler)

        _state.c_purecall_handler = _PURECALL_HANDLER_TYPE(_win32_purecall_handler)
        ucrt['_set_purecall_handler'](_state.c_purecall_handler)

        with contextlib.suppress(AttributeError, OSError):
            vcruntime_set_purecall_handler = ctypes.cdll.LoadLibrary('vcruntime140.dll')['_set_purecall_handler']
            vcruntime_set_purecall_handler.argtypes = [_PURECALL_HANDLER_TYPE]
            vcruntime_set_purecall_handler.restype = ctypes.c_void_p
            vcruntime_set_purecall_handler(_state.c_purecall_handler)

        _state.c_sigabrt_handler = _SIGNAL_HANDLER_TYPE(_win32_sigabrt_handler)
        _state.prev_sigabrt_handler = int(ucrt.signal(22, _state.c_sigabrt_handler))
        _state.win32_crt_handlers_installed = True
    except (AttributeError, OSError) as e:
        logging.getLogger(_APP_LOGGER_NAME).debug('Failed to install Win32 CRT diagnostic handlers: %s', e)


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

# Callables registered by subsystems to provide diagnostic thread state dumps.
_diagnostic_providers: list[Callable[[], list[str]]] = []
_diagnostic_provider_lock = RLock()


def register_diagnostic_provider(fn: Callable[[], list[str]]) -> None:
    """Register a callable that returns diagnostic lines when an abnormal thread error occurs."""
    with _diagnostic_provider_lock:
        if fn not in _diagnostic_providers:
            _diagnostic_providers.append(fn)


def _invalidate_secret_cache() -> None:
    """Expire the cache immediately so the next `_get_secret_values()` call re-evaluates all providers.

    Must be called with `_secret_provider_lock` held.
    """
    _state.cached_secrets_expiry = 0.0


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
    current_time = time.monotonic()
    if current_time < _state.cached_secrets_expiry:
        return _state.cached_secrets

    with _secret_provider_lock:
        if current_time < _state.cached_secrets_expiry:
            return _state.cached_secrets

        providers = tuple(_secret_providers)
        secrets: set[str] = set()
        for provider in providers:
            secret: str | None = None
            with contextlib.suppress(Exception):
                secret = provider()
            if secret is not None and secret:
                secrets.add(secret)

        _state.cached_secrets = tuple(sorted(secrets, key=len, reverse=True))
        _state.cached_secrets_expiry = time.monotonic() + _SECRETS_CACHE_TTL_SECONDS
        return _state.cached_secrets


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


def _secret_redact_filter(record: logging.LogRecord) -> bool:
    """Scrub known secret values from a log record in-place before handlers emit it, and keep the record."""
    if getattr(record, 'secrets_redacted', False):
        return True

    secrets = _get_secret_values()
    if not secrets:
        record.secrets_redacted = True
        return True

    record.msg = _redact_value(record.msg, secrets)
    if record.args is not None and record.args:
        record.args = _redact_args(record.args, secrets)
    if record.exc_text is not None and record.exc_text:
        record.exc_text = _redact_text(record.exc_text, secrets)
    if record.stack_info is not None and record.stack_info:
        record.stack_info = _redact_text(record.stack_info, secrets)
    record.secrets_redacted = True
    return True


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


def flush_all_loggers() -> None:
    """Flush all logging handlers, standard streams, and crash log stream."""
    root = logging.getLogger()
    for handler in list(root.handlers):
        with contextlib.suppress(Exception):
            handler.flush()
    for stream in (sys.stdout, sys.stderr, sys.__stdout__, sys.__stderr__):
        if stream is not None:
            with contextlib.suppress(Exception):
                stream.flush()
    if _state.crash_log_file is not None:
        with contextlib.suppress(OSError):
            _state.crash_log_file.flush()


def dump_crash_diagnostics(reason: str) -> None:
    """Dump active threads and call stacks directly to crash.log, raw stderr, and the logger."""
    lines: list[str] = [
        f'=== THREAD DIAGNOSTIC DUMP (triggered by: {reason}) ===',
        f'Active Python threads count: {threading.active_count()}',
    ]
    try:
        get_current_frames = cast('Callable[[], dict[int, FrameType]] | None', getattr(sys, '_current_frames', None))
        current_frames: dict[int, FrameType] = get_current_frames() if callable(get_current_frames) else {}
        for thread in threading.enumerate():
            native_id = getattr(thread, 'native_id', None)
            lines.append(f'Thread name="{thread.name}", ident={thread.ident}, native_id={native_id}, daemon={thread.daemon}, alive={thread.is_alive()}')
            frame = current_frames.get(thread.ident or 0)
            if frame is not None:
                stack = ''.join(traceback.format_stack(frame))
                lines.append(f'  Call stack:\n{stack.rstrip()}')

        with _diagnostic_provider_lock:
            providers = list(_diagnostic_providers)
        for provider in providers:
            try:
                lines.extend(provider())
            except (RuntimeError, OSError, ValueError, TypeError) as e:
                lines.append(f'Diagnostic provider error: {e}')
        if sys.platform == 'win32':
            lines.extend(_capture_win32_native_stack())
    except (RuntimeError, OSError) as e:
        lines.append(f'Failed to collect thread diagnostics: {e}')

    lines.append('=== END THREAD DIAGNOSTIC DUMP ===')
    dump_text = '\n'.join(lines) + '\n'

    # 1. Write unbuffered directly to raw standard error
    if sys.__stderr__ is not None:
        with contextlib.suppress(Exception):
            sys.__stderr__.write(dump_text)
            sys.__stderr__.flush()

    # 2. Append directly to crash.log
    try:
        CRASH_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with CRASH_LOG_PATH.open('a', encoding='utf-8') as f:
            f.write(dump_text)
            f.flush()
    except OSError as e:
        if sys.__stderr__ is not None:
            with contextlib.suppress(Exception):
                sys.__stderr__.write(f'Failed to write to crash.log: {e}\n')
                sys.__stderr__.flush()

    # 3. Write through application logger if not in recursive state
    if not getattr(_stderr_reentry_state, 'active', False):
        with contextlib.suppress(Exception):
            stderr_logger = logging.getLogger(_STDERR_LOGGER_NAME)
            for diag_line in lines:
                stderr_logger.critical('%s', diag_line)

    # 4. Flush all loggers and files
    flush_all_loggers()


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
            if any(marker in message for marker in ('QThread: Destroyed', 'Fatal Python error')):
                dump_crash_diagnostics(message)
        finally:
            _stderr_reentry_state.active = False

    def _write_fallback(self, message: str) -> None:
        """Write directly to the original stderr stream during recursive logging."""
        if self._fallback is None:
            return
        with contextlib.suppress(OSError, ValueError):
            self._fallback.write(message)
            self._fallback.flush()


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
    if bool(os.getenv('NO_COLOR')):
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
    _add_filter_once(handler, _secret_redact_filter)
    _add_filter_once(handler, _urllib3_noise_filter)


def _close_crash_log() -> None:
    """Disable faulthandler and close the crash log file cleanly on exit."""
    if _state.crash_log_file is not None:
        try:
            faulthandler.disable()
            _state.crash_log_file.close()
        except OSError:
            pass
        _state.crash_log_file = None


def _register_shutdown_once() -> None:
    """Register logging shutdown exactly once for this module."""
    if _atexit_registered.is_set():
        return
    atexit.register(logging.shutdown)
    atexit.register(_close_crash_log)
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
            _add_filter_once(handler, _secret_redact_filter)

        # --- Root logger must be permissive enough to reach all handlers ---
        root.setLevel(min(console_level, logging.DEBUG))

        # --- Mute noisy third-party debug logging ---
        logging.getLogger('urllib3').setLevel(logging.WARNING)

        # --- Redirect Python warnings to logging ---
        logging.captureWarnings(capture=True)

        # --- Redirect stderr to logging (captures ctypes, PySide6 internal errors) ---
        if sys.stderr is not None and not isinstance(sys.stderr, _StderrToLogger):
            sys.stderr = _StderrToLogger(logging.getLogger(_STDERR_LOGGER_NAME), logging.ERROR, fallback=cast('TextIO', sys.stderr))

        # --- Ensure logs flush on exit ---
        _register_shutdown_once()

        # --- Native crash fault handler (captures fatal C/C++ exceptions and signals) ---
        if _state.crash_log_file is None:
            CRASH_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
            _state.crash_log_file = CRASH_LOG_PATH.open('a', encoding='utf-8')
            faulthandler.enable(file=_state.crash_log_file, all_threads=True)
            if sys.platform == 'win32':
                _install_win32_crt_handlers()


def purge_debug_log() -> None:
    """Safely truncate debug.log while handling the active RotatingFileHandler."""
    root = logging.getLogger()
    handler = _find_handler(root, _DEBUG_FILE_HANDLER_NAME)
    if isinstance(handler, RotatingFileHandler):
        handler.acquire()
        try:
            handler.flush()
            handler.close()  # Clears `handler.stream`; the next emit reopens the file in append mode.
            DEBUG_LOG_PATH.write_text('', encoding='utf-8')
        finally:
            handler.release()
    else:
        DEBUG_LOG_PATH.write_text('', encoding='utf-8')


def purge_crash_log() -> None:
    """Safely truncate crash.log while handling the active faulthandler file descriptor."""
    faulthandler.disable()
    if _state.crash_log_file is not None:
        try:
            _state.crash_log_file.flush()
            _state.crash_log_file.close()
        except OSError:
            pass
        _state.crash_log_file = None
    CRASH_LOG_PATH.write_text('', encoding='utf-8')
    _state.crash_log_file = CRASH_LOG_PATH.open('a', encoding='utf-8')
    faulthandler.enable(file=_state.crash_log_file, all_threads=True)
    if sys.platform == 'win32':
        _install_win32_crt_handlers()
