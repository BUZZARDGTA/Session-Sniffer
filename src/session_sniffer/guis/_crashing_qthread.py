"""QThread base that crashes the app when `_run()` raises an unhandled exception.

PySide6's SIP layer silently swallows Python exceptions that escape `QThread.run()`,
preventing `threading.excepthook` from firing. This base class overrides `run()` with
a try/except wrapper that delegates to `_run()`, which subclasses implement instead.
"""

from typing import ClassVar, override

from PySide6.QtCore import QObject, QThread

from session_sniffer.core import terminate_on_uncaught_exception


class CrashingQThread(QThread):
    """QThread that crashes the app when `_run()` raises an unhandled exception.

    Inherit from this instead of `QThread` and override `_run()` instead of `run()`.
    Any unhandled exception escaping `_run()` is forwarded to `terminate_on_uncaught_exception` —
    the same crash path triggered by `_handle_thread_exception` for plain `threading.Thread` exceptions.
    Strong references to running threads are retained in `_active_threads` until their `finished`
    signal fires, preventing 'QThread: Destroyed while thread is still running' fatal app exits.
    """

    _active_threads: ClassVar[set[CrashingQThread]] = set()

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.finished.connect(self._on_thread_finished)

    @override
    def start(self, priority: QThread.Priority = QThread.Priority.InheritPriority) -> None:
        """Start thread execution and retain a strong reference until termination."""
        CrashingQThread._active_threads.add(self)
        super().start(priority)

    def _on_thread_finished(self) -> None:
        """Discard the strong reference once the native thread has finished."""
        CrashingQThread._active_threads.discard(self)

    @override
    def run(self) -> None:
        """Run the thread, forwarding unhandled exceptions to `terminate_on_uncaught_exception`."""
        try:
            self._run()
        except SystemExit:
            return
        except BaseException as e:  # pylint: disable=broad-exception-caught  # noqa: BLE001
            terminate_on_uncaught_exception(e)

    def _run(self) -> None:
        """Override in subclasses to define the thread's work."""
