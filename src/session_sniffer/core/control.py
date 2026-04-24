"""Crash state tracking, exception handling and process termination."""

import signal
import sys
import threading
import time
from threading import Lock
from types import TracebackType
from typing import TYPE_CHECKING, ClassVar, Literal, NamedTuple

from session_sniffer import msgbox
from session_sniffer.background.suspend_manager import ProcessSuspendManager
from session_sniffer.constants.standalone import TITLE
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
    _crash_message: ClassVar[str | None] = None

    @classmethod
    def set_crashed(cls, message: str | None = None) -> None:
        """Mark the process as crashed and store an optional crash message."""
        with cls._lock:
            cls._crashed = True
            cls._crash_message = message

    @classmethod
    def reset_crashed(cls) -> None:
        """Clear the crash flag and any stored crash message."""
        with cls._lock:
            cls._crashed = False
            cls._crash_message = None

    @classmethod
    def has_crashed(cls) -> bool:
        """Return whether the process has been marked as crashed."""
        with cls._lock:
            return cls._crashed

    @classmethod
    def get_crash_message(cls) -> str | None:
        """Return the stored crash message, if any."""
        with cls._lock:
            return cls._crash_message


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

    ProcessSuspendManager.shutdown()

    ScriptControl.set_crashed(None if stdout_crash_text is None else f'\n\n{stdout_crash_text}\n')

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
        'An unexpected (uncaught) error occurred.\n\nPlease kindly report it to:\nhttps://github.com/BUZZARDGTA/Session-Sniffer/issues',
        exception_info=exception_info,
    )


def handle_sigint(_sig: int, _frame: FrameType | None) -> None:
    """Handle Ctrl+C by terminating the script if not already crashing."""
    if not ScriptControl.has_crashed():
        # Block CTRL+C if script is already crashing under control
        logger.info('Ctrl+C pressed. Exiting script ...')
        terminate_script('SIGINT')


class ThreadsExceptionHandler:
    """Handle exceptions raised within threads and provide additional functionality for managing thread execution.

    This class is designed to overcome the limitation where threads run independently from the main process, which continues execution without waiting for thread completion.

    Attributes:
        raising_function: The name of the function where the exception was raised.
        raising_exc_type: The type of the raised exception.
        raising_exc_value: The value of the raised exception.
        raising_exc_traceback: The traceback information for the raised exception.
    """
    raising_function: ClassVar[str | None] = None
    raising_exc_type: ClassVar[type[BaseException] | None] = None
    raising_exc_value: ClassVar[BaseException | None] = None
    raising_exc_traceback: ClassVar[TracebackType | None] = None

    def __enter__(self) -> None:
        """Enter the runtime context related to this object."""

    def __exit__(self, exc_type: type[BaseException] | None, exc_value: BaseException | None, exc_traceback: TracebackType | None) -> bool:
        """Exit method called upon exiting the 'with' block.

        Args:
            exc_type: The type of the raised exception.
            exc_value: The value of the raised exception.
            exc_traceback: The traceback information of the raised exception.

        Returns:
            Whether to suppress the exception from propagating further.
        """
        # Return False to allow normal execution if no exception occurred
        if exc_type is None or exc_value is None:
            return False

        # Handle exception details
        ThreadsExceptionHandler.raising_exc_type = exc_type
        ThreadsExceptionHandler.raising_exc_value = exc_value
        ThreadsExceptionHandler.raising_exc_traceback = exc_traceback

        # Extract the failed function name from the traceback safely
        if exc_traceback is not None:
            tb = exc_traceback
            while tb.tb_next:
                tb = tb.tb_next
            ThreadsExceptionHandler.raising_function = tb.tb_frame.f_code.co_name
        else:
            ThreadsExceptionHandler.raising_function = '<unknown>'

        # Create the exception info and terminate the script
        exception_info = ExceptionInfo(exc_type, exc_value, exc_traceback)
        terminate_script(
            'THREAD_RAISED',
            (
                'An unexpected (uncaught) error occurred.\n\n'
                'Please kindly report it to:\n'
                'https://github.com/BUZZARDGTA/Session-Sniffer/issues'
            ),
            exception_info=exception_info,
        )

        # Suppress the exception from propagating
        return True


def _handle_thread_exception(args: threading.ExceptHookArgs) -> None:
    """Handle uncaught exceptions in threads not wrapped by ThreadsExceptionHandler."""
    if args.exc_type is SystemExit:
        return

    exc_value = args.exc_value if args.exc_value is not None else RuntimeError('Unknown thread error')
    exception_info = ExceptionInfo(args.exc_type, exc_value, args.exc_traceback)
    terminate_script(
        'THREAD_RAISED',
        (
            'An unexpected (uncaught) error occurred.\n\n'
            'Please kindly report it to:\n'
            'https://github.com/BUZZARDGTA/Session-Sniffer/issues'
        ),
        exception_info=exception_info,
    )


# Install global exception/signal handlers at import time
sys.excepthook = handle_exception
threading.excepthook = _handle_thread_exception
signal.signal(signal.SIGINT, handle_sigint)
