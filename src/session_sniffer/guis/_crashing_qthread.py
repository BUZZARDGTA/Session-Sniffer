"""QThread base that crashes the app when `_run()` raises an unhandled exception.

PySide6's SIP layer silently swallows Python exceptions that escape `QThread.run()`,
preventing `threading.excepthook` from firing. This base class overrides `run()` with
a try/except wrapper that delegates to `_run()`, which subclasses implement instead.
"""

import atexit
import logging
import threading
import time
from typing import ClassVar, override

import shiboken6
from PySide6.QtCore import QCoreApplication, QObject, QThread, QTimer

from session_sniffer.background.events import gui_closed__event
from session_sniffer.core import terminate_on_uncaught_exception
from session_sniffer.logging_setup import register_diagnostic_provider

logger = logging.getLogger(__name__)


class CrashingQThread(QThread):
    """QThread that crashes the app when `_run()` raises an unhandled exception.

    Inherit from this instead of `QThread` and override `_run()` instead of `run()`.
    Any unhandled exception escaping `_run()` is forwarded to `terminate_on_uncaught_exception` —
    the same crash path triggered by `_handle_thread_exception` for plain `threading.Thread` exceptions.
    Strong references to running threads are retained in `_active_threads` while active and
    deferred-discarded after `finished` fires, ensuring the underlying native OS thread has completely
    terminated and exited before C++ `~QThread()` destruction. This prevents
    'QThread: Destroyed while thread is still running' fatal app exits and 'QWaitCondition: Destroyed while threads are still waiting'.
    """

    _active_threads: ClassVar[set[CrashingQThread]] = set()

    def __init__(self, parent: QObject | None = None, *, name: str | None = None) -> None:
        super().__init__(parent)
        self._thread_name = name or self.__class__.__name__
        self.setObjectName(self._thread_name)
        self._native_id: int | None = None
        try:
            cpp_ptr_val = shiboken6.getCppPointer(self)
            self._cpp_ptr: str = hex(cpp_ptr_val[0]) if cpp_ptr_val else 'unknown'
        except (TypeError, ValueError, RuntimeError):
            self._cpp_ptr = 'unknown'
        self.finished.connect(self._on_thread_finished)
        logger.debug('CrashingQThread initialized: %s (cpp_ptr: %s, py_id: 0x%x, parent: %s)', self._thread_name, self._cpp_ptr, id(self), parent)

    @property
    def thread_name(self) -> str:
        """Return the friendly name assigned to this thread."""
        return self._thread_name

    @property
    def cpp_ptr(self) -> str:
        """Return the underlying C++ pointer for this QThread as a hex string."""
        return self._cpp_ptr

    @classmethod
    def get_active_threads(cls) -> list[CrashingQThread]:
        """Return a snapshot of all currently registered active CrashingQThread instances."""
        return list(cls._active_threads)

    @override
    def start(self, priority: QThread.Priority = QThread.Priority.InheritPriority) -> None:
        """Start thread execution and retain a strong reference until termination."""
        CrashingQThread._active_threads.add(self)
        logger.debug(
            'CrashingQThread starting: %s (cpp_ptr: %s, py_id: 0x%x, active count: %d)',
            self._thread_name,
            self._cpp_ptr,
            id(self),
            len(CrashingQThread._active_threads),
        )
        super().start(priority)

    def cancel(self, timeout_ms: int = 2000) -> bool:
        """Request interruption, quit event loop, and wait for termination."""
        logger.debug('CrashingQThread cancel requested: %s (cpp_ptr: %s, timeout: %d ms, running: %s)', self._thread_name, self._cpp_ptr, timeout_ms, self.isRunning())
        self.requestInterruption()
        self.quit()
        if timeout_ms <= 0:
            return not self.isRunning()
        result = self.wait(timeout_ms)
        logger.debug('CrashingQThread cancel wait result: %s for %s (cpp_ptr: %s, running: %s)', result, self._thread_name, self._cpp_ptr, self.isRunning())
        return result

    @classmethod
    def stop_all_active_threads(cls, timeout_ms: int = 3000) -> None:
        """Interrupt, quit, and wait for all active threads to terminate before destruction."""
        active_threads = [thread for thread in cls._active_threads if thread.isRunning()]
        logger.debug(
            'CrashingQThread stop_all_active_threads: stopping %d active threads: %s',
            len(active_threads),
            [(t.thread_name, t.cpp_ptr) for t in active_threads],
        )
        for thread in active_threads:
            thread.requestInterruption()
            thread.quit()
        for thread in active_threads:
            if thread.isRunning():
                logger.debug('CrashingQThread stop_all_active_threads: waiting for %s (cpp_ptr: %s)', thread.thread_name, thread.cpp_ptr)
                wait_ok = thread.wait(timeout_ms)
                logger.debug(
                    'CrashingQThread stop_all_active_threads: wait finished for %s (cpp_ptr: %s, wait_ok: %s, running: %s)',
                    thread.thread_name,
                    thread.cpp_ptr,
                    wait_ok,
                    thread.isRunning(),
                )
        if active_threads:
            time.sleep(0.05)
        cls._active_threads = {thread for thread in cls._active_threads if thread.isRunning() or not thread.wait(50)}
        if cls._active_threads:
            logger.warning(
                'CrashingQThread stop_all_active_threads: %d thread(s) still running after wait, retaining references to prevent crash: %s',
                len(cls._active_threads),
                [(t.thread_name, t.cpp_ptr) for t in cls._active_threads],
            )
        logger.debug('CrashingQThread stop_all_active_threads completed')

    def _discard_if_stopped(self) -> None:
        """Discard the strong reference if the thread has fully terminated, or reschedule."""
        if self.isRunning() or not self.wait(100):
            logger.debug(
                'CrashingQThread _discard_if_stopped: thread %s (cpp_ptr: %s) still running or terminating, rescheduling discard',
                self._thread_name,
                self._cpp_ptr,
            )
            if QCoreApplication.instance() is not None and not gui_closed__event.is_set():
                QTimer.singleShot(500, self._discard_if_stopped)
            return

        logger.debug(
            'CrashingQThread _discard_if_stopped: thread %s (cpp_ptr: %s) has terminated, discarding reference',
            self._thread_name,
            self._cpp_ptr,
        )
        CrashingQThread._active_threads.discard(self)

    def _on_thread_finished(self) -> None:
        """Join the native OS thread and defer discarding the strong reference."""
        logger.debug('CrashingQThread _on_thread_finished signal fired: %s (cpp_ptr: %s), joining native thread via wait()', self._thread_name, self._cpp_ptr)
        try:
            wait_ok = self.wait(5000)
            logger.debug('CrashingQThread _on_thread_finished: native thread joined (wait_ok: %s) for %s (cpp_ptr: %s)', wait_ok, self._thread_name, self._cpp_ptr)
        finally:
            if QCoreApplication.instance() is not None and not gui_closed__event.is_set():
                logger.debug('CrashingQThread _on_thread_finished: scheduling discard check for %s (cpp_ptr: %s)', self._thread_name, self._cpp_ptr)
                QTimer.singleShot(1000, self._discard_if_stopped)
            else:
                self._discard_if_stopped()

    @override
    def run(self) -> None:
        """Run the thread, forwarding unhandled exceptions to `terminate_on_uncaught_exception`."""
        if self._thread_name:
            threading.current_thread().name = self._thread_name
        self._native_id = threading.get_native_id()
        logger.debug('CrashingQThread run() started: %s (cpp_ptr: %s, native id: %s)', self._thread_name, self._cpp_ptr, self._native_id)
        try:
            self._run()
            logger.debug('CrashingQThread _run() returned cleanly: %s (cpp_ptr: %s, native id: %s)', self._thread_name, self._cpp_ptr, self._native_id)
        except SystemExit:
            logger.debug('CrashingQThread _run() raised SystemExit: %s (cpp_ptr: %s, native id: %s)', self._thread_name, self._cpp_ptr, self._native_id)
            return
        except BaseException as e:  # pylint: disable=broad-exception-caught
            logger.exception(
                'CrashingQThread _run() raised unhandled exception in %s (cpp_ptr: %s, native id: %s)',
                self._thread_name,
                self._cpp_ptr,
                self._native_id,
            )
            terminate_on_uncaught_exception(e)

    def _run(self) -> None:
        """Override in subclasses to define the thread's work."""


def _crashing_qthread_diagnostic_provider() -> list[str]:
    """Provide status lines for all active CrashingQThreads to the logging diagnostics."""
    active = CrashingQThread.get_active_threads()
    lines: list[str] = [f'Active CrashingQThreads count: {len(active)}']
    lines.extend(
        f'  CrashingQThread name="{thread.thread_name}", cpp_ptr={thread.cpp_ptr}, isRunning={thread.isRunning()}, isFinished={thread.isFinished()}' for thread in active
    )
    return lines


register_diagnostic_provider(_crashing_qthread_diagnostic_provider)
atexit.register(CrashingQThread.stop_all_active_threads)
