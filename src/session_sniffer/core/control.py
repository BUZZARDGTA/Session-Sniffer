"""Crash state tracking, exception handling and process termination."""

import logging
import signal
import sys
import threading
from threading import Lock
from types import TracebackType
from typing import TYPE_CHECKING, ClassVar, Literal, NamedTuple

from session_sniffer.constants.local import APP_DIR_LOCAL, APP_DIR_ROAMING
from session_sniffer.gta5.suspend_manager import GTASuspendManager
from session_sniffer.guis.crash_dialog import show_crash_dialog
from session_sniffer.logging_setup import dump_crash_diagnostics, flush_all_loggers
from session_sniffer.rdr2.suspend_manager import RDR2SuspendManager
from session_sniffer.utils import ensure_app_dir_ownership, terminate_process_tree

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import FrameType

logger = logging.getLogger(__name__)


class ExceptionInfo(NamedTuple):
    """Store exception details for crash reporting and logging."""

    exc_type: type[BaseException]
    exc_value: BaseException
    exc_traceback: TracebackType | None


class ScriptControl:
    """Track global crash state and crash message across threads."""

    _lock: ClassVar[Lock] = Lock()
    _crashed: ClassVar[bool] = False
    _termination_hooks: ClassVar[list[Callable[[], None]]] = []

    @classmethod
    def register_termination_hook(cls, hook: Callable[[], None]) -> None:
        """Register a callback to run synchronously during process termination."""
        with cls._lock:
            if hook not in cls._termination_hooks:
                cls._termination_hooks.append(hook)

    @classmethod
    def run_termination_hooks(cls) -> None:
        """Execute all registered termination hooks."""
        with cls._lock:
            hooks = list(cls._termination_hooks)
        for hook in hooks:
            try:
                hook()
            except (OSError, RuntimeError, ValueError, TypeError):
                logger.exception('Termination hook %r failed', hook)

    @classmethod
    def set_crashed(cls) -> bool:
        """Atomically mark the process as crashed and return True only for the first caller."""
        with cls._lock:
            if cls._crashed:
                return False
            cls._crashed = True
            return True

    @classmethod
    def has_crashed(cls) -> bool:
        """Return whether the process has been marked as crashed."""
        with cls._lock:
            return cls._crashed


def terminate_script(
    terminate_method: Literal['EXIT', 'SIGINT', 'SIGTERM', 'SIGBREAK', 'THREAD_RAISED'],
    exception_info: ExceptionInfo | None = None,
) -> None:
    """Terminate the application and optionally display crash information."""
    caller_thread = threading.current_thread()
    is_crash = exception_info is not None or terminate_method == 'THREAD_RAISED'
    caller_native_id = getattr(caller_thread, 'native_id', 'unknown')
    logger.debug(
        'terminate_script invoked: method=%s, is_crash=%s, caller_thread=%s (native_id=%s, ident=%s)',
        terminate_method,
        is_crash,
        caller_thread.name,
        caller_native_id,
        caller_thread.ident,
    )
    active_thread_names = [f'{thread.name} (native_id={getattr(thread, "native_id", "unknown")})' for thread in threading.enumerate()]
    logger.debug('Active threads at terminate_script (%d): %s', len(active_thread_names), active_thread_names)

    if not ScriptControl.set_crashed():
        if exception_info is not None:
            logger.critical(
                'Secondary uncaught exception in %s (method=%s) while termination is already in progress:',
                caller_thread.name,
                terminate_method,
                exc_info=(exception_info.exc_type, exception_info.exc_value, exception_info.exc_traceback),
            )
            flush_all_loggers()
        return

    if exception_info is not None:
        logger.critical(
            'Uncaught exception in %s (method=%s):',
            caller_thread.name,
            terminate_method,
            exc_info=(exception_info.exc_type, exception_info.exc_value, exception_info.exc_traceback),
        )
        dump_crash_diagnostics(
            f'Uncaught exception in {caller_thread.name} (method={terminate_method}): {exception_info.exc_type.__name__}: {exception_info.exc_value}',
            exc_info=(exception_info.exc_type, exception_info.exc_value, exception_info.exc_traceback),
        )
    elif is_crash:
        dump_crash_diagnostics(f'terminate_script (method={terminate_method}, thread={caller_thread.name})')

    GTASuspendManager.shutdown()
    RDR2SuspendManager.shutdown()
    ScriptControl.run_termination_hooks()

    if is_crash:
        flush_all_loggers()
        show_crash_dialog(
            thread_name=caller_thread.name,
            terminate_method=terminate_method,
            exc_info=(exception_info.exc_type, exception_info.exc_value, exception_info.exc_traceback) if exception_info is not None else None,
        )

    flush_all_loggers()
    ensure_app_dir_ownership(APP_DIR_LOCAL)
    ensure_app_dir_ownership(APP_DIR_ROAMING)
    terminate_process_tree()


def handle_exception(exc_type: type[BaseException], exc_value: BaseException, exc_traceback: TracebackType | None) -> None:
    """Handle exceptions for the main script (not threads)."""
    if issubclass(exc_type, KeyboardInterrupt):
        return

    exception_info = ExceptionInfo(exc_type, exc_value, exc_traceback)
    terminate_script(
        'EXIT',
        exception_info=exception_info,
    )


def handle_sigint(_sig: int, _frame: FrameType | None) -> None:
    """Handle Ctrl+C by terminating the script if not already crashing."""
    if not ScriptControl.has_crashed():
        # Block CTRL+C if script is already crashing under control
        logger.info('Ctrl+C pressed. Exiting script...')
        terminate_script('SIGINT')


def terminate_on_uncaught_exception(exc: BaseException) -> None:
    """Crash the app with the standard uncaught-thread-exception message.

    Shared helper used by pool-task callbacks, QThread wrappers, and asyncio
    exception handlers so the crash call is not duplicated across modules.
    """
    terminate_script(
        'THREAD_RAISED',
        exception_info=ExceptionInfo(type(exc), exc, exc.__traceback__),
    )


def _handle_thread_exception(args: threading.ExceptHookArgs) -> None:
    """Handle uncaught exceptions in threads."""
    if args.exc_type is SystemExit:
        return

    exc_value = args.exc_value if args.exc_value is not None else RuntimeError('Unknown thread error')
    exception_info = ExceptionInfo(args.exc_type, exc_value, args.exc_traceback)
    terminate_script(
        'THREAD_RAISED',
        exception_info=exception_info,
    )


def handle_sigterm(sig: int, _frame: FrameType | None) -> None:
    """Handle termination signals (SIGTERM / SIGBREAK)."""
    if not ScriptControl.has_crashed():
        sig_name: Literal['SIGBREAK', 'SIGTERM'] = 'SIGBREAK' if hasattr(signal, 'SIGBREAK') and sig == signal.SIGBREAK else 'SIGTERM'
        logger.info('Termination signal %s (sig=%d) received. Exiting script...', sig_name, sig)
        terminate_script(sig_name)


def install_exception_handlers() -> None:
    """Install global exception and termination signal handlers."""
    sys.excepthook = handle_exception
    threading.excepthook = _handle_thread_exception
    signal.signal(signal.SIGINT, handle_sigint)
    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, handle_sigterm)
    if hasattr(signal, 'SIGBREAK'):
        signal.signal(signal.SIGBREAK, handle_sigterm)


# Install global exception/signal handlers at import time
install_exception_handlers()
