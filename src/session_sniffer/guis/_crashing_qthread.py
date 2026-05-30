"""QThread base that crashes the app when `run()` raises an unhandled exception.

PyQt6's SIP layer silently swallows Python exceptions that escape `QThread.run()`,
preventing `threading.excepthook` from firing. This base class wraps each subclass
`run()` at class-creation time so that any unhandled exception terminates the app
via the same crash path used by plain `threading.Thread` exceptions.
"""

import functools
from typing import TYPE_CHECKING

from PyQt6.QtCore import QThread

from session_sniffer.constants.standalone import GITHUB_ISSUES_URL
from session_sniffer.core import ExceptionInfo, terminate_script

if TYPE_CHECKING:
    from collections.abc import Callable


def _wrap_qthread_run[T: QThread](original_run: Callable[[T], None]) -> Callable[[T], None]:
    @functools.wraps(original_run)
    def run(self: T) -> None:
        try:
            original_run(self)
        except BaseException as exc:  # pylint: disable=broad-exception-caught  # noqa: BLE001
            if isinstance(exc, SystemExit):
                return
            terminate_script(
                'THREAD_RAISED',
                f'An unexpected (uncaught) error occurred.\n\nPlease kindly report it to:\n{GITHUB_ISSUES_URL}',
                exception_info=ExceptionInfo(type(exc), exc, exc.__traceback__),
            )
    return run


class CrashingQThread(QThread):  # pylint: disable=too-few-public-methods
    """QThread that crashes the app when `run()` raises an unhandled exception.

    Inherit from this instead of `QThread`. Any unhandled exception escaping `run()`
    is forwarded to `terminate_script` — the same crash path triggered by
    `_handle_thread_exception` for plain `threading.Thread` exceptions.
    """

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        if 'run' in cls.__dict__:
            setattr(cls, 'run', _wrap_qthread_run(cls.__dict__['run']))  # noqa: B010
