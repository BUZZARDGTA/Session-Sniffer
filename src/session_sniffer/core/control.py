"""Crash state tracking, exception handling and process termination."""

import signal
import sys
import threading
import time
from threading import Lock
from types import TracebackType
from typing import TYPE_CHECKING, ClassVar, Literal, NamedTuple

from session_sniffer import msgbox
from session_sniffer.constants.standalone import GITHUB_ISSUES_URL, TITLE
from session_sniffer.gta5.suspend_manager import GTASuspendManager
from session_sniffer.logging_setup import get_logger
from session_sniffer.utils import terminate_process_tree

if TYPE_CHECKING:
    from types import FrameType

logger = get_logger(__name__)


class ExceptionInfo(NamedTuple):
    """Store exception details for crash reporting and logging."""

    exc_type: type[BaseException]
    exc_value: BaseException
    exc_traceback: TracebackType | None


class ScriptControl:
    """Track global crash state and crash message across threads."""

    _lock: ClassVar[Lock] = Lock()
    _crashed: ClassVar[bool] = False

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
    terminate_method: Literal['EXIT', 'SIGINT', 'THREAD_RAISED'],
    msgbox_crash_text: str | None = None,
    stdout_crash_text: str | None = None,
    exception_info: ExceptionInfo | None = None,
) -> None:
    """Terminate the application and optionally display crash information."""
    def should_terminate_gracefully() -> bool:
        # TODO(BUZZARDGTA): Gracefully exit the script even when the `capture` module is running.
        return False

    GTASuspendManager.shutdown()

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

    # If the termination method is "EXIT", do not sleep unless crash messages are present
    need_sleep = True
    if terminate_method == 'EXIT' and msgbox_crash_text is None and stdout_crash_text is None:
        need_sleep = False
    if need_sleep:
        time.sleep(3)

    if should_terminate_gracefully():
        exit_code = 1 if terminate_method == 'THREAD_RAISED' else 0
        sys.exit(exit_code)

    terminate_process_tree()


def handle_exception(exc_type: type[BaseException], exc_value: BaseException, exc_traceback: TracebackType | None) -> None:
    """Handle exceptions for the main script (not threads)."""
    if issubclass(exc_type, KeyboardInterrupt):
        return

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
    terminate_script(
        'THREAD_RAISED',
        f'An unexpected (uncaught) error occurred.\n\nPlease kindly report it to:\n{GITHUB_ISSUES_URL}',
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
        (
            f'An unexpected (uncaught) error occurred.\n\n'
            f'Please kindly report it to:\n'
            f'{GITHUB_ISSUES_URL}'
        ),
        exception_info=exception_info,
    )


# Install global exception/signal handlers at import time
sys.excepthook = handle_exception
threading.excepthook = _handle_thread_exception
signal.signal(signal.SIGINT, handle_sigint)
