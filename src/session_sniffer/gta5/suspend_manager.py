"""Reason-based process suspension manager for the global GTA5 process.

This module provides a singleton manager that controls suspension and resumption
of the single, globally-resolved GTA5 process based on multiple concurrent
"reasons" (e.g. detections, player events, manual overrides). It ensures the
process is only suspended once and only resumed when all active reasons are resolved.
"""

import time
from dataclasses import dataclass, field
from threading import Condition, Event, Thread
from typing import ClassVar, Literal

import psutil

from session_sniffer.logging_setup import get_logger
from session_sniffer.rendering_core.types import CaptureState

logger = get_logger(__name__)


@dataclass(slots=True)
class _SuspendReason:
    left_event: Event
    min_duration: float
    added_at: float
    manual: bool


@dataclass(slots=True)
class _ProcessState:
    pid: int
    suspended: bool = False
    reasons: dict[str, _SuspendReason] = field(default_factory=dict[str, _SuspendReason])


@dataclass(frozen=True, slots=True)
class GTASuspendSnapshot:
    """Immutable, lock-free view of the manager state for GUI reads.

    Republished by the background suspend threads after every state change so the GUI
    thread can read the suspend/manual/solo flags through a single atomic reference
    read, never acquiring the manager lock.
    """

    is_suspended: bool = False
    manual_active: bool = False
    solo_active: bool = False


class GTASuspendManager:
    """Singleton suspend manager (thread-safe, reason-based)."""

    _state: ClassVar[_ProcessState | None] = None
    _condition: ClassVar[Condition] = Condition()
    _shutdown_event: ClassVar[Event] = Event()
    _monitor_thread: ClassVar[Thread | None] = None
    _snapshot: ClassVar[GTASuspendSnapshot] = GTASuspendSnapshot()

    # ------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------

    @classmethod
    def request_suspend(
        cls,
        reason_key: str,
        left_event: Event,
        duration: int | Literal['Auto', 'Manual'],
    ) -> None:
        """Register a suspend reason for the global GTA5 process.

        The process will be suspended on the first active reason and will remain
        suspended until all registered reasons are resolved.

        Args:
            reason_key: Unique identifier for this suspension reason.
            left_event: Event that indicates when a player has left.
            duration: Either:
                - "Auto": resume after conditions are met
                - "Manual": requires explicit removal
                - int: minimum suspension duration in seconds
        """
        if cls._shutdown_event.is_set():
            return

        manual = duration == 'Manual'
        min_dur = 0.0 if isinstance(duration, str) else max(0.0, float(duration))

        reason = _SuspendReason(
            left_event=left_event,
            min_duration=min_dur,
            added_at=time.monotonic(),
            manual=manual,
        )

        with cls._condition:
            # -------------------------
            # existing state
            # -------------------------
            if cls._state is not None:
                if reason_key in cls._state.reasons:
                    logger.warning('Overwriting suspend reason: %s', reason_key)

                cls._state.reasons[reason_key] = reason

                if not cls._state.suspended:
                    cls._try_suspend_pid(cls._state.pid, f'reason added: {reason_key}')
                    cls._state.suspended = True

                cls._publish_snapshot_locked()
                cls._condition.notify_all()

                cls._ensure_monitor_running_locked()
                return

            # -------------------------
            # first suspend
            # -------------------------
            # Reuse the PID cached by the GTA5 process monitor instead of rescanning
            # every process; path and PID come from the same validated snapshot.
            pid = CaptureState.gta5_pid
            if pid is None:
                logger.debug('GTA5 process not running; suspend request ignored for reason: %s', reason_key)
                return

            if not cls._try_suspend_pid(pid, f'first reason: {reason_key}'):
                return

            cls._state = _ProcessState(pid=pid, suspended=True)
            cls._state.reasons[reason_key] = reason

            cls._publish_snapshot_locked()
            cls._ensure_monitor_running_locked()
            cls._condition.notify_all()

    @classmethod
    def release_reason_global(cls, reason_key: str) -> None:
        """Remove a suspend reason from the active process.

        If the given reason key exists, it will be removed from the internal
        reason registry. The monitor thread will automatically resume the process
        once no active reasons remain.

        Args:
            reason_key: Unique identifier of the suspend reason to remove.
        """
        with cls._condition:
            if cls._state:
                cls._state.reasons.pop(reason_key, None)
            cls._publish_snapshot_locked()
            cls._condition.notify_all()

    @classmethod
    def release_reasons_for_ip(cls, ip: str) -> None:
        """Remove every suspend reason associated with the given player IP.

        Reason keys created for player-driven suspensions embed the player IP as
        their final `:`-delimited segment (e.g. `userip:1.2.3.4`). All matching
        reasons are removed; the monitor thread resumes the process automatically
        once no active reasons remain.

        Args:
            ip: The player IP whose suspend reasons should be released.
        """
        suffix = f':{ip}'
        with cls._condition:
            if cls._state:
                for reason_key in [key for key in cls._state.reasons if key.endswith(suffix)]:
                    del cls._state.reasons[reason_key]
            cls._publish_snapshot_locked()
            cls._condition.notify_all()

    @classmethod
    def shutdown(cls) -> None:
        """Shutdown the suspend manager and restore process state.

        This method signals the monitor thread to exit, resumes the target process
        if it is currently suspended, and clears all internal state. It is safe to
        call multiple times and is typically used during application shutdown.

        The monitor thread will be joined briefly to ensure clean termination.

        Returns:
            None
        """
        cls._shutdown_event.set()

        with cls._condition:
            if cls._state and cls._state.suspended:
                cls._try_resume_pid(cls._state.pid)

            cls._state = None
            cls._publish_snapshot_locked()
            cls._condition.notify_all()

        thread = cls._monitor_thread
        if thread:
            thread.join(timeout=2.0)

        cls._monitor_thread = None

    @classmethod
    def is_suspended(cls) -> bool:
        """Return whether the global GTA5 process is currently suspended by this manager."""
        with cls._condition:
            return cls._state is not None and cls._state.suspended

    @classmethod
    def has_reason(cls, reason_key: str) -> bool:
        """Check if a suspend reason is currently active."""
        with cls._condition:
            return cls._state is not None and reason_key in cls._state.reasons

    @classmethod
    def snapshot(cls) -> GTASuspendSnapshot:
        """Return the latest published state snapshot without acquiring the lock.

        Reads a single immutable reference (atomic under the GIL), letting the GUI
        thread refresh its GTA5 menu flags with zero lock contention against the
        background suspend and monitor threads.
        """
        return cls._snapshot

    @classmethod
    def wake(cls) -> None:
        """Wake the suspend monitor so it re-evaluates its reasons immediately.

        Notifies the monitor thread to re-check every reason without waiting for the
        next poll cycle — useful right after a player's `left_event` is set so the
        process resumes with zero added latency. This is a pure nudge: it never sets
        any event nor mutates state, keeping callers fully decoupled from this manager.
        """
        with cls._condition:
            cls._condition.notify_all()

    @classmethod
    def resume_os_suspended(cls) -> bool:
        """Resume the live GTA5 process when it was suspended outside this manager.

        Recovers a process left stopped outside this manager's control (for example, by
        a previously-crashed session) by issuing a single resume on the PID cached by the
        GTA5 process monitor, so the OS thread suspend counts are not left unbalanced.
        Does nothing and returns `False` when this manager owns an active suspend state,
        since the monitor thread is responsible for resuming in that case.
        """
        with cls._condition:
            if cls._state is not None:
                return False
            pid = CaptureState.gta5_pid
            if pid is None:
                return False
            return cls._try_resume_pid(pid)

    # ------------------------------------------------------------
    # Monitor lifecycle
    # ------------------------------------------------------------

    @classmethod
    def _ensure_monitor_running_locked(cls) -> None:
        """Start monitor thread if not alive."""
        thread = cls._monitor_thread

        if thread is None or not thread.is_alive():
            cls._monitor_thread = Thread(
                target=cls._monitor,
                name='SuspendMonitor-GTA5',
                daemon=True,
            )
            cls._monitor_thread.start()

    @classmethod
    def _monitor(cls) -> None:
        try:
            while True:
                with cls._condition:
                    if cls._shutdown_event.is_set() or cls._state is None:
                        return

                    state = cls._state

                    # Stale-PID check (process exited -> None, or restarted -> new PID).
                    # Reads the PID cached by the GTA5 process monitor to avoid a full
                    # `process_iter` scan on every monitor iteration while holding the lock.
                    pid = CaptureState.gta5_pid
                    if pid != state.pid:
                        logger.warning('GTA5 PID changed (%s -> %s); clearing suspend state', state.pid, pid)
                        cls._state = None
                        cls._publish_snapshot_locked()
                        return

                    # all reasons satisfied
                    now = time.monotonic()
                    if all(cls._reason_ok(reason, now) for reason in state.reasons.values()):
                        pid_to_resume = state.pid
                        cls._state = None
                        cls._publish_snapshot_locked()
                    else:
                        timeout = cls._next_timeout(state, now)
                        cls._condition.wait(timeout=timeout)
                        continue

                cls._try_resume_pid(pid_to_resume)
                return

        finally:
            # IMPORTANT: lifecycle reset
            cls._monitor_thread = None

    # ------------------------------------------------------------
    # Logic helpers
    # ------------------------------------------------------------

    @classmethod
    def _publish_snapshot_locked(cls) -> None:
        """Rebuild the lock-free GUI snapshot from the current state.

        Must be called while holding `_condition`. Rebinds `_snapshot` to a fresh
        immutable object so lock-free GUI readers always observe a consistent view.
        """
        state = cls._state
        if state is None:
            cls._snapshot = GTASuspendSnapshot()
            return
        cls._snapshot = GTASuspendSnapshot(
            is_suspended=state.suspended,
            manual_active='manual:toolbar' in state.reasons,
            solo_active='solo:toolbar' in state.reasons,
        )

    @staticmethod
    def _reason_ok(reason: _SuspendReason, now: float) -> bool:
        if reason.manual:
            return False
        return reason.left_event.is_set() and (now - reason.added_at) >= reason.min_duration

    @staticmethod
    def _next_timeout(state: _ProcessState, now: float) -> float:
        earliest = None

        for reason in state.reasons.values():
            if reason.manual:
                continue
            remaining = reason.min_duration - (now - reason.added_at)
            if remaining > 0:
                earliest = remaining if earliest is None else min(earliest, remaining)

        return max(0.01, earliest) if earliest is not None else 0.2

    # ------------------------------------------------------------
    # psutil wrappers
    # ------------------------------------------------------------

    @staticmethod
    def _try_suspend_pid(pid: int, reason: str) -> bool:
        try:
            psutil.Process(pid).suspend()

        except psutil.NoSuchProcess:
            logger.warning('Suspend failed PID %d: process no longer exists', pid)
            return False

        except psutil.AccessDenied:
            logger.warning('Suspend failed PID %d: access denied', pid)
            return False

        except psutil.Error as e:
            logger.warning('Suspend failed PID %d: psutil error: %s', pid, e)
            return False

        logger.info('Suspended PID %d (%s)', pid, reason)
        return True

    @staticmethod
    def _try_resume_pid(pid: int) -> bool:
        try:
            psutil.Process(pid).resume()

        except psutil.NoSuchProcess:
            logger.info('Resume skipped PID %d: process already exited', pid)
            return True

        except psutil.AccessDenied:
            logger.warning('Resume failed PID %d: access denied', pid)
            return False

        except psutil.Error as e:
            logger.warning('Resume failed PID %d: psutil error: %s', pid, e)
            return False

        logger.info('Resumed PID %d', pid)
        return True
