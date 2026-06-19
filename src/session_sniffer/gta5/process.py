"""GTA5 process detection and immutable state snapshot.

Detects the currently running GTA V process (Legacy `GTA5.exe` or Enhanced
`GTA5_Enhanced.exe`), verifies its Authenticode signature to reject impostor
executables that merely reuse the process name, and exposes the result as an
immutable `GTA5Status` snapshot.
"""

from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path

import psutil

from session_sniffer.ctypes_wintrust import has_valid_authenticode_signature
from session_sniffer.logging_setup import get_logger

logger = get_logger(__name__)

_GTA5_PROCESS_NAMES: frozenset[str] = frozenset(
    {
        'gta5.exe',
        'gta5_enhanced.exe',
    },
)


@dataclass(frozen=True, slots=True)
class GTA5Status:
    """Immutable snapshot of the running GTA5 process state.

    Attributes:
        path: Resolved path to the running GTA5 executable, or `None` if not running.
        pid: PID of the running GTA5 process, or `None` if not running.
        is_suspended: `True` if the running GTA5 process is currently suspended at the
            OS level (its threads are stopped), regardless of what suspended it.
        is_running: `True` if a GTA5 process was detected.
        is_enhanced: `True` if the running version is GTA V Enhanced (`GTA5_Enhanced.exe`).
        is_legacy: `True` if the running version is GTA V Legacy (`GTA5.exe`).
    """

    path: Path | None
    pid: int | None = None
    is_suspended: bool = False
    is_running: bool = field(init=False)
    is_enhanced: bool = field(init=False)
    is_legacy: bool = field(init=False)

    def __post_init__(self) -> None:
        """Derive `is_running`, `is_enhanced`, and `is_legacy` from `path`."""
        stem = self.path.stem.lower() if self.path is not None else ''

        object.__setattr__(self, 'is_running', self.path is not None)
        object.__setattr__(self, 'is_enhanced', stem == 'gta5_enhanced')
        object.__setattr__(self, 'is_legacy', stem == 'gta5')


def find_running_gta5_path(
    cached_proc: psutil.Process | None = None,
    cached_status: GTA5Status | None = None,
) -> tuple[GTA5Status, psutil.Process | None]:
    """Return a `GTA5Status` snapshot for the currently running GTA5 process plus its process handle.

    Scans all running processes for `GTA5.exe` or `GTA5_Enhanced.exe`
    (legacy retail and enhanced PC versions respectively) using a
    case-insensitive filename stem match, then verifies the binary carries
    a valid Authenticode signature to reject any impostor executable that
    merely reuses the GTA5 process name.

    The full scan is the expensive part: resolving each process `exe` opens a handle to
    every running process. So when `cached_proc`/`cached_status` describe a process a
    previous call already validated, the fast path re-queries only that single PID:
    `is_running()` confirms it is still the same process (it compares the OS creation
    time, so a dead PID or a PID reused by another process both fail), and a single
    `status()` read refreshes the suspended flag. Because a live PID maps to one
    immutable executable image for its whole lifetime, the already-validated signature
    still holds, so the full scan and Authenticode check are skipped entirely. Any
    change (process gone or PID reused) fails `is_running()` and falls through to a
    fresh scan + signature check, preserving impostor rejection.

    Args:
        cached_proc: The `psutil.Process` returned by the previous call, re-queried
            directly to avoid a full scan. Pass `None` to force a full scan.
        cached_status: The `GTA5Status` returned by the previous call, supplying the
            already-resolved executable path reused on the fast path.

    Returns:
        A `(GTA5Status, psutil.Process | None)` tuple. `GTA5Status.path` is set to the
        resolved executable path when found, or `None` (with all boolean flags `False`)
        when neither version is running. The returned process handle should be passed
        back as `cached_proc` on the next call, or is `None` when nothing was found.
    """
    # Fast path: re-query only the previously validated PID.
    if cached_proc is not None and cached_status is not None and cached_status.path is not None:
        with suppress(psutil.NoSuchProcess, psutil.AccessDenied):
            if cached_proc.is_running():
                return (
                    GTA5Status(
                        path=cached_status.path,
                        pid=cached_proc.pid,
                        is_suspended=cached_proc.status() == psutil.STATUS_STOPPED,
                    ),
                    cached_proc,
                )

    # Slow path: cheap scan by process name only.
    for process in psutil.process_iter(['name']):
        process_name: str | None = process.info.get('name')

        if not process_name or process_name.lower() not in _GTA5_PROCESS_NAMES:
            continue

        try:
            process_path = Path(process.exe())
        except psutil.NoSuchProcess, psutil.AccessDenied:
            continue

        if not has_valid_authenticode_signature(process_path):
            logger.debug('[GTA5Monitor] Authenticode signature invalid, ignoring impostor: "%s" (PID: %s)', process_path, process.pid)
            continue

        resolved_path = process_path.resolve()

        logger.debug('[GTA5Monitor] Authenticode signature verified: "%s" (PID: %s)', resolved_path, process.pid)

        with suppress(psutil.NoSuchProcess, psutil.AccessDenied):
            return (
                GTA5Status(
                    path=resolved_path,
                    pid=process.pid,
                    is_suspended=process.status() == psutil.STATUS_STOPPED,
                ),
                process,
            )

    return (
        GTA5Status(path=None),
        None,
    )
