"""Centralized process suspend manager for all protection types.

All code paths that need to suspend a process (global protections, UserIP protections,
event protections) register "reasons" through this single manager.

Guarantees:
- Only ONE `psutil.Process.suspend()` / `.resume()` per process, regardless of
  how many protections fire simultaneously.
- One monitor thread per process that polls all active reasons.
- Process resumes only when ALL reasons are satisfied:
  every hostile player has left AND every per-reason minimum duration has elapsed.
- Player rejoins are handled automatically (`left_event.clear()` keeps suspension alive).
- Proper error handling for NoSuchProcess / AccessDenied / unexpected failures.
- Clean shutdown: all suspended processes are resumed when the application exits.
"""

import time
from dataclasses import dataclass, field
from threading import Event, Lock, Thread
from typing import TYPE_CHECKING, ClassVar, Literal

import psutil

from session_sniffer.logging_setup import get_logger
from session_sniffer.utils import get_pid_by_path

if TYPE_CHECKING:
    from pathlib import Path

logger = get_logger(__name__)

_MONITOR_POLL_INTERVAL = 0.2  # seconds between monitor checks


@dataclass(slots=True)
class _SuspendReason:
    """A single reason to keep a process suspended."""

    left_event: Event
    min_duration: float
    added_at: float
    manual: bool
    require_left_event: bool


@dataclass(slots=True)
class _ProcessState:
    """Tracking state for a single suspended process."""

    path_key: str
    pid: int
    suspended: bool = False
    reasons: dict[str, _SuspendReason] = field(default_factory=dict[str, _SuspendReason])


class ProcessSuspendManager:
    """Singleton manager for process suspension across all protection types.

    Instead of each protection type spawning its own suspend / resume threads,
    all protections register "reasons" with this manager.  The manager:

    1. Suspends the process **once** when the first reason is added.
    2. Runs **one** monitor thread per process.
    3. Resumes the process when **all** reasons are satisfied:
       - `left_event` is set (the hostile player left), **and**
       - `min_duration` seconds have elapsed since the reason was added.
       - Reasons with `manual=True` are never auto-satisfied.
     4. Handles errors (process died, access denied) gracefully.
     5. Resumes everything on :meth:`shutdown`.
    """

    _states: ClassVar[dict[str, _ProcessState]] = {}
    _lock: ClassVar[Lock] = Lock()
    _shutdown_event: ClassVar[Event] = Event()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @classmethod
    def request_suspend(
        cls,
        process_path: Path,
        reason_key: str,
        left_event: Event,
        duration: int | Literal['Auto', 'Manual'],
    ) -> None:
        """Register a suspend reason for *process_path*.

        If the process is not yet suspended, it is suspended immediately
        and a monitor thread is started.  If it is already suspended the
        reason is added / updated and the existing monitor keeps running.

        Args:
            process_path: Absolute path to the target executable.
            reason_key:   Unique key for this reason (e.g. `"global:vpn:1.2.3.4"`).
            left_event:   The player's `left_event`; set when the player disconnects.
            duration:     `'Auto'` (resume when player leaves),
                          `'Manual'` (never auto-resume),
                          or a positive `int` (minimum seconds before resume).
        """
        if cls._shutdown_event.is_set():
            return

        path_key = str(process_path.resolve()).lower()

        manual = duration == 'Manual'
        require_left_event = isinstance(duration, str)
        min_dur = 0.0 if isinstance(duration, str) else max(0.0, float(duration))

        reason = _SuspendReason(
            left_event=left_event,
            min_duration=min_dur,
            added_at=time.monotonic(),
            manual=manual,
            require_left_event=require_left_event,
        )

        with cls._lock:
            state = cls._states.get(path_key)

            if state is not None:
                # Already tracking — add / update the reason.
                state.reasons[reason_key] = reason
                if not state.suspended and cls._try_suspend_pid(state.pid, f'new reason added: {reason_key}'):
                    state.suspended = True
                return

            # --- First time for this process ---
            pid = get_pid_by_path(process_path)
            if pid is None:
                logger.warning('Cannot suspend %s: process not running', process_path.name)
                return

            if not cls._try_suspend_pid(pid, f'first reason: {reason_key}'):
                return

            state = _ProcessState(path_key=path_key, pid=pid, suspended=True)
            state.reasons[reason_key] = reason
            cls._states[path_key] = state

        # Start the monitor outside the lock (Thread.start is safe).
        Thread(
            target=cls._monitor,
            name=f'SuspendMonitor-{process_path.stem}',
            args=(path_key,),
            daemon=True,
        ).start()

    @classmethod
    def has_reason(cls, reason_key: str) -> bool:
        """Return `True` if any tracked process has an active reason with this exact key."""
        with cls._lock:
            return any(reason_key in state.reasons for state in cls._states.values())

    @staticmethod
    def is_process_suspended(process_path: Path) -> bool:
        """Return `True` when the running process at *process_path* is currently suspended.

        This queries the live process status from psutil so UI code can use the
        actual runtime state as the source of truth.
        """
        pid = get_pid_by_path(process_path)
        if pid is None:
            return False
        try:
            return psutil.Process(pid).status() == psutil.STATUS_STOPPED
        except psutil.NoSuchProcess:
            return False
        except psutil.AccessDenied:
            logger.warning('Cannot read suspend status for PID %d: access denied', pid)
            return False
        except psutil.Error:
            logger.exception('Unexpected error while reading suspend status for PID %d', pid)
            return False

    @classmethod
    def release_reason_global(cls, reason_key: str) -> None:
        """Remove *reason_key* from every tracked process.

        The monitor thread for each affected process will resume it once all
        remaining reasons are satisfied.
        """
        with cls._lock:
            for state in cls._states.values():
                state.reasons.pop(reason_key, None)

    @classmethod
    def shutdown(cls) -> None:
        """Resume every suspended process and stop all monitor threads.

        Safe to call more than once.
        """
        cls._shutdown_event.set()

        with cls._lock:
            for state in cls._states.values():
                if state.suspended:
                    cls._try_resume_pid(state.pid)
                    state.suspended = False
            cls._states.clear()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @classmethod
    def _try_suspend_pid(cls, pid: int, reason: str) -> bool:
        """Suspend *pid*, returning `True` on success."""
        try:
            psutil.Process(pid).suspend()
        except psutil.NoSuchProcess:
            logger.warning('Cannot suspend PID %d: process exited before suspend', pid)
            return False
        except psutil.AccessDenied:
            logger.warning('Cannot suspend PID %d: access denied — try running as administrator', pid)
            return False
        except psutil.Error:
            logger.exception('Unexpected error while suspending PID %d', pid)
            return False
        logger.info('Suspended process PID %d — %s', pid, reason)
        return True

    @classmethod
    def _try_resume_pid(cls, pid: int) -> bool:
        """Resume *pid*, returning `True` on success (or if process no longer exists)."""
        try:
            psutil.Process(pid).resume()
        except psutil.NoSuchProcess:
            logger.info('Process PID %d already exited — nothing to resume', pid)
            return True
        except psutil.AccessDenied:
            logger.warning('Cannot resume PID %d: access denied', pid)
            return False
        except psutil.Error:
            logger.exception('Unexpected error while resuming PID %d', pid)
            return False
        logger.info('Resumed process PID %d', pid)
        return True

    @classmethod
    def _reason_is_satisfied(cls, reason: _SuspendReason, now: float) -> bool:
        """Return `True` when a single reason allows permanent resume."""
        if reason.manual:
            return False
        if reason.require_left_event and not reason.left_event.is_set():
            return False
        return now - reason.added_at >= reason.min_duration

    @classmethod
    def _all_reasons_satisfied(cls, state: _ProcessState) -> bool:
        """Return `True` when every reason allows the process to resume permanently.

        Must be called while holding `_lock`.
        """
        now = time.monotonic()
        return all(cls._reason_is_satisfied(r, now) for r in state.reasons.values())

    @classmethod
    def _monitor(cls, path_key: str) -> None:
        """Poll reasons until all are satisfied, then resume the process."""
        while not cls._shutdown_event.is_set():
            cls._shutdown_event.wait(_MONITOR_POLL_INTERVAL)
            if cls._shutdown_event.is_set():
                break

            with cls._lock:
                state = cls._states.get(path_key)
                if state is None:
                    return

                # --- Permanent resume: all reasons satisfied ---
                if not state.reasons or cls._all_reasons_satisfied(state):
                    if state.suspended:
                        cls._try_resume_pid(state.pid)
                    state.suspended = False
                    cls._states.pop(path_key, None)
                    return

        # Shutdown was requested — the shutdown() method already resumes everything,
        # so the monitor simply exits.
