"""QThread base that crashes the app when `_run()` raises an unhandled exception.

PyQt6's SIP layer silently swallows Python exceptions that escape `QThread.run()`,
preventing `threading.excepthook` from firing. This base class overrides `run()` with
a try/except wrapper that delegates to `_run()`, which subclasses implement instead.
"""

from PyQt6.QtCore import QThread

from session_sniffer.core import terminate_on_uncaught_exception


class CrashingQThread(QThread):
    """QThread that crashes the app when `_run()` raises an unhandled exception.

    Inherit from this instead of `QThread` and override `_run()` instead of `run()`.
    Any unhandled exception escaping `_run()` is forwarded to `terminate_on_uncaught_exception` —
    the same crash path triggered by `_handle_thread_exception` for plain `threading.Thread` exceptions.
    """

    def run(self) -> None:
        """Run the thread, forwarding unhandled exceptions to `terminate_on_uncaught_exception`."""
        try:
            self._run()
        except SystemExit:
            return
        except BaseException as exc:  # pylint: disable=broad-exception-caught  # noqa: BLE001
            terminate_on_uncaught_exception(exc)

    def _run(self) -> None:
        """Override in subclasses to define the thread's work."""
