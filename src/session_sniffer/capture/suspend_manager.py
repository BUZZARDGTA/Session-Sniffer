"""Reason-based process suspension manager base."""

import logging
import time
from dataclasses import dataclass, field
from threading import Condition, Event, Thread
from typing import ClassVar, Literal

from session_sniffer.capture.process import resume_process, suspend_process

logger = logging.getLogger(__name__)


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
class SuspendSnapshot:
    """Immutable, lock-free view of the manager state for GUI reads.

    Republished by the background suspend threads after every state change so the GUI
    thread can read the suspend/manual/solo flags through a single atomic reference
    read, never acquiring the manager lock.
    """

    is_suspended: bool = False
    manual_active: bool = False
    solo_active: bool = False


class BaseSuspendManager:
    """Singleton suspend manager base (thread-safe, reason-based)."""

    _game_name: ClassVar[str]
    _state: ClassVar[_ProcessState | None]
    _condition: ClassVar[Condition]
    _shutdown_event: ClassVar[Event]
    _monitor_thread: ClassVar[Thread | None]
    _snapshot: ClassVar[SuspendSnapshot]

    def __init_subclass__(cls, **kwargs: object) -> None:
        """Initialize independent state and synchronization primitives for each subclass."""
        super().__init_subclass__(**kwargs)
        cls._state = None
        cls._condition = Condition()
        cls._shutdown_event = Event()
        cls._monitor_thread = None
        cls._snapshot = SuspendSnapshot()

    @classmethod
    def _get_target_pid(cls) -> int | None:
        raise NotImplementedError

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
        """Register a suspend reason for the global target process.

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
        min_duration = 0.0 if isinstance(duration, str) else max(0.0, float(duration))

        reason = _SuspendReason(
            left_event=left_event,
            min_duration=min_duration,
            added_at=time.monotonic(),
            manual=manual,
        )

        with cls._condition:
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

            target_process_id = cls._get_target_pid()
            if target_process_id is None:
                logger.debug('%s process not running; suspend request ignored for reason: %s', cls._game_name, reason_key)
                return

            if not cls._try_suspend_pid(target_process_id, f'first reason: {reason_key}'):
                return

            cls._state = _ProcessState(pid=target_process_id, suspended=True)
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
        """
        cls._shutdown_event.set()

        with cls._condition:
            if cls._state and cls._state.suspended:
                cls._try_resume_pid(cls._state.pid)

            cls._state = None
            cls._publish_snapshot_locked()
            cls._condition.notify_all()

        if cls._monitor_thread is not None:
            cls._monitor_thread.join(timeout=2.0)
            cls._monitor_thread = None

    @classmethod
    def is_suspended(cls) -> bool:
        """Return whether the target process is currently suspended by this manager."""
        with cls._condition:
            return cls._state is not None and cls._state.suspended

    @classmethod
    def has_reason(cls, reason_key: str) -> bool:
        """Check if a suspend reason is currently active."""
        with cls._condition:
            return cls._state is not None and reason_key in cls._state.reasons

    @classmethod
    def snapshot(cls) -> SuspendSnapshot:
        """Return the latest published state snapshot without acquiring the lock.

        Reads a single immutable reference (atomic under the GIL), letting the GUI
        thread refresh its menu flags with zero lock contention against the
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
    def resume_os_suspended(cls) -> None:
        """Resume the live target process when it was suspended outside this manager.

        Recovers a process left stopped outside this manager's control (for example, by
        a previously-crashed session) by issuing a single resume on the PID cached by the
        process monitor, so the OS thread suspend counts are not left unbalanced.
        Does nothing when this manager owns an active suspend state, since the monitor
        thread is responsible for resuming in that case.
        """
        with cls._condition:
            if cls._state is not None:
                return
            target_process_id = cls._get_target_pid()
            if target_process_id is None:
                return
            cls._try_resume_pid(target_process_id)

    # ------------------------------------------------------------
    # Monitor lifecycle
    # ------------------------------------------------------------

    @classmethod
    def _ensure_monitor_running_locked(cls) -> None:
        """Start monitor thread if not alive."""
        if cls._monitor_thread is None or not cls._monitor_thread.is_alive():
            cls._monitor_thread = Thread(
                target=cls._monitor,
                name=f'SuspendMonitor-{cls._game_name}',
                daemon=True,
            )
            cls._monitor_thread.start()

    @classmethod
    def _monitor(cls) -> None:
        while True:
            with cls._condition:
                if cls._shutdown_event.is_set() or cls._state is None:
                    cls._monitor_thread = None
                    return

                # Stale-PID check (process exited -> None, or restarted -> new PID).
                current_process_id = cls._get_target_pid()
                if current_process_id != cls._state.pid:
                    logger.warning('%s PID changed (%s -> %s); clearing suspend state', cls._game_name, cls._state.pid, current_process_id)
                    cls._state = None
                    cls._publish_snapshot_locked()
                    cls._monitor_thread = None
                    return

                # all reasons satisfied
                now = time.monotonic()
                if all(cls._reason_ok(reason, now) for reason in cls._state.reasons.values()):
                    process_id_to_resume = cls._state.pid
                    cls._state = None
                    cls._publish_snapshot_locked()
                    cls._monitor_thread = None
                else:
                    process_id_to_resume = None
                    timeout = cls._next_timeout(cls._state, now)
                    cls._condition.wait(timeout=timeout)

            if process_id_to_resume is not None:
                cls._try_resume_pid(process_id_to_resume)
                return

    # ------------------------------------------------------------
    # Logic helpers
    # ------------------------------------------------------------

    @classmethod
    def _publish_snapshot_locked(cls) -> None:
        """Rebuild the lock-free GUI snapshot from the current state.

        Must be called while holding `_condition`. Rebinds `_snapshot` to a fresh
        immutable object so lock-free GUI readers always observe a consistent view.
        """
        if cls._state is None:
            cls._snapshot = SuspendSnapshot()
            return
        cls._snapshot = SuspendSnapshot(
            is_suspended=cls._state.suspended,
            manual_active='manual:toolbar' in cls._state.reasons,
            solo_active='solo:toolbar' in cls._state.reasons,
        )

    @staticmethod
    def _reason_ok(reason: _SuspendReason, now: float) -> bool:
        if reason.manual:
            return False
        if reason.min_duration > 0:
            return (now - reason.added_at) >= reason.min_duration
        return reason.left_event.is_set()

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
    # Process suspension wrappers
    # ------------------------------------------------------------

    @classmethod
    def _try_suspend_pid(cls, pid: int, reason: str) -> bool:
        try:
            suspend_process(pid)

        except ProcessLookupError:
            logger.warning('%s suspend failed PID %d: process no longer exists', cls._game_name, pid)
            return False

        except PermissionError:
            logger.warning('%s suspend failed PID %d: access denied', cls._game_name, pid)
            return False

        except OSError as e:
            logger.warning('%s suspend failed PID %d: error: %s', cls._game_name, pid, e)
            return False

        logger.info('Suspended %s PID %d (%s)', cls._game_name, pid, reason)
        return True

    @classmethod
    def _try_resume_pid(cls, pid: int) -> bool:
        try:
            resume_process(pid)

        except ProcessLookupError:
            logger.info('%s resume skipped PID %d: process already exited', cls._game_name, pid)
            return True

        except PermissionError:
            logger.warning('%s resume failed PID %d: access denied', cls._game_name, pid)
            return False

        except OSError as e:
            logger.warning('%s resume failed PID %d: error: %s', cls._game_name, pid, e)
            return False

        logger.info('Resumed %s PID %d', cls._game_name, pid)
        return True
