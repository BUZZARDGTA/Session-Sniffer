"""Crash state tracking, exception handling and process termination."""

import logging
import signal
import sys
import threading
import time
import traceback
from threading import Lock
from types import TracebackType
from typing import TYPE_CHECKING, ClassVar, Literal, NamedTuple

from session_sniffer import msgbox
from session_sniffer.constants.standalone import GITHUB_ISSUES_URL, TITLE
from session_sniffer.gta5.suspend_manager import GTASuspendManager
from session_sniffer.utils import terminate_process_tree

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
            hook()

    @classmethod
    def set_crashed(cls) -> None:
        """Mark the process as crashed."""
        with cls._lock:
            cls._crashed = True

    @classmethod
    def has_crashed(cls) -> bool:
        """Return whether the process has been marked as crashed."""
        with cls._lock:
            return cls._crashed


def terminate_script(
    terminate_method: Literal['EXIT', 'SIGINT', 'SIGTERM', 'SIGBREAK', 'THREAD_RAISED'],
    msgbox_crash_text: str | None = None,
    stdout_crash_text: str | None = None,
    exception_info: ExceptionInfo | None = None,
) -> None:
    """Terminate the application and optionally display crash information."""
    caller_thread = threading.current_thread()
    caller_native_id = getattr(caller_thread, 'native_id', 'unknown')
    logger.debug(
        'terminate_script invoked: method=%s, caller_thread=%s (native_id=%s, ident=%s)',
        terminate_method,
        caller_thread.name,
        caller_native_id,
        caller_thread.ident,
    )
    caller_stack = ''.join(traceback.format_stack()[:-1])
    logger.debug('terminate_script caller stack:\n%s', caller_stack.rstrip())
    active_thread_names = [f'{t.name} (native_id={getattr(t, "native_id", "unknown")})' for t in threading.enumerate()]
    logger.debug('Active threads at terminate_script (%d): %s', len(active_thread_names), active_thread_names)

    GTASuspendManager.shutdown()
    ScriptControl.run_termination_hooks()

    ScriptControl.set_crashed()

    if exception_info:
        logger.error(
            'Uncaught exception: %s: %s',
            exception_info.exc_type.__name__,
            exception_info.exc_value,
            exc_info=(exception_info.exc_type, exception_info.exc_value, exception_info.exc_traceback),
        )

    if msgbox_crash_text is not None:
        msgbox_title = TITLE
        msgbox_message = msgbox_crash_text
        msgbox_style = msgbox.Style.MB_OK | msgbox.Style.MB_ICONERROR | msgbox.Style.MB_SYSTEMMODAL

        msgbox.show(msgbox_title, msgbox_message, msgbox_style)
        time.sleep(1)

    # If the termination method is a normal exit/signal, do not sleep unless crash messages are present
    need_sleep = True
    if terminate_method in ('EXIT', 'SIGINT', 'SIGTERM', 'SIGBREAK') and msgbox_crash_text is None and stdout_crash_text is None:
        need_sleep = False
    if need_sleep:
        time.sleep(3)

    terminate_process_tree()


def handle_exception(exc_type: type[BaseException], exc_value: BaseException, exc_traceback: TracebackType | None) -> None:
    """Handle exceptions for the main script (not threads)."""
    if issubclass(exc_type, KeyboardInterrupt):
        return

    logger.critical(
        'handle_exception invoked for main script: %s: %s',
        exc_type.__name__,
        exc_value,
        exc_info=(exc_type, exc_value, exc_traceback),
    )
    exception_info = ExceptionInfo(exc_type, exc_value, exc_traceback)
    terminate_script(
        'EXIT',
        f'An unexpected (uncaught) error occurred.\n\nPlease kindly report it to:\n{GITHUB_ISSUES_URL}',
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

    Shared helper used by pool-task callbacks and QThread wrappers so the
    crash call is not duplicated across modules.
    """
    current_thread = threading.current_thread()
    logger.critical(
        'terminate_on_uncaught_exception invoked from thread %s (native_id: %s): %s',
        current_thread.name,
        getattr(current_thread, 'native_id', 'unknown'),
        exc,
        exc_info=(type(exc), exc, exc.__traceback__),
    )
    terminate_script(
        'THREAD_RAISED',
        f'An unexpected (uncaught) error occurred.\n\nPlease kindly report it to:\n{GITHUB_ISSUES_URL}',
        exception_info=ExceptionInfo(type(exc), exc, exc.__traceback__),
    )


def _handle_thread_exception(args: threading.ExceptHookArgs) -> None:
    """Handle uncaught exceptions in threads."""
    if args.exc_type is SystemExit:
        return

    thread_name = getattr(args.thread, 'name', 'unknown')
    exc_value = args.exc_value if args.exc_value is not None else RuntimeError('Unknown thread error')
    exc_type = args.exc_type
    logger.critical(
        '_handle_thread_exception invoked for thread %s: %s: %s',
        thread_name,
        exc_type.__name__,
        exc_value,
        exc_info=(exc_type, exc_value, args.exc_traceback),
    )
    exception_info = ExceptionInfo(exc_type, exc_value, args.exc_traceback)
    terminate_script(
        'THREAD_RAISED',
        (f'An unexpected (uncaught) error occurred.\n\nPlease kindly report it to:\n{GITHUB_ISSUES_URL}'),
        exception_info=exception_info,
    )


def handle_sigterm(sig: int, _frame: FrameType | None) -> None:
    """Handle termination signals (SIGTERM / SIGBREAK)."""
    if not ScriptControl.has_crashed():
        sig_name: Literal['SIGBREAK', 'SIGTERM'] = 'SIGBREAK' if hasattr(signal, 'SIGBREAK') and sig == signal.SIGBREAK else 'SIGTERM'
        logger.info('Termination signal %s (sig=%d) received. Exiting script...', sig_name, sig)
        terminate_script(sig_name)


# Install global exception/signal handlers at import time
sys.excepthook = handle_exception
threading.excepthook = _handle_thread_exception
signal.signal(signal.SIGINT, handle_sigint)
if hasattr(signal, 'SIGTERM'):
    signal.signal(signal.SIGTERM, handle_sigterm)
if hasattr(signal, 'SIGBREAK'):
    signal.signal(signal.SIGBREAK, handle_sigterm)
