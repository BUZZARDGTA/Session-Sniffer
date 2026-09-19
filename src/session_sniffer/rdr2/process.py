"""RDR2 process detection and immutable state snapshot.

Detects the currently running Red Dead Redemption 2 process (`RDR2.exe`),
verifies its Authenticode signature to reject impostor executables that merely
reuse the process name, and exposes the result as an immutable `RDR2Status` snapshot.
"""

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from session_sniffer.capture.process import (
    ProcessInfo,
    get_process_creation_time,
    get_process_image_path,
    get_process_udp_ports,
    is_process_running,
    is_process_suspended,
    iter_running_processes,
)
from session_sniffer.ctypes_wintrust import has_valid_authenticode_signature

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)

# pylint: disable=duplicate-code

_RDR2_PROCESS_NAMES: frozenset[str] = frozenset(
    {
        'rdr2.exe',
    },
)


@dataclass(frozen=True, slots=True)
class RDR2Status:
    """Immutable snapshot of the running RDR2 process state.

    Attributes:
        path: Resolved path to the running RDR2 executable, or `None` if not running.
        pid: PID of the running RDR2 process, or `None` if not running.
        is_suspended: `True` if the running RDR2 process is currently suspended at the
            OS level (its threads are stopped), regardless of what suspended it.
        udp_ports: Set of local UDP socket ports currently bound by the RDR2 process.
        is_running: `True` if an RDR2 process was detected.
    """

    path: Path | None
    pid: int | None = None
    is_suspended: bool = False
    udp_ports: frozenset[int] = frozenset()
    is_running: bool = field(init=False)

    def __post_init__(self) -> None:
        """Derive `is_running` from `path`."""
        object.__setattr__(self, 'is_running', self.path is not None)


def find_running_rdr2_path(
    cached_proc: ProcessInfo | None = None,
    cached_status: RDR2Status | None = None,
) -> tuple[RDR2Status, ProcessInfo | None]:
    """Return an `RDR2Status` snapshot for the currently running RDR2 process plus its process handle.

    Scans all running processes for `RDR2.exe` using a case-insensitive filename stem match,
    then verifies the binary carries a valid Authenticode signature to reject any impostor
    executable that merely reuses the RDR2 process name.

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
        cached_proc: The `ProcessInfo` returned by the previous call, re-queried
            directly to avoid a full scan. Pass `None` to force a full scan.
        cached_status: The `RDR2Status` returned by the previous call, supplying the
            already-resolved executable path reused on the fast path.

    Returns:
        A `(RDR2Status, ProcessInfo | None)` tuple. `RDR2Status.path` is set to the
        resolved executable path when found, or `None` (with all boolean flags `False`)
        when not running. The returned process handle should be passed
        back as `cached_proc` on the next call, or is `None` when nothing was found.
    """
    # Fast path: re-query only the previously validated PID.
    if cached_proc is not None and cached_status is not None and cached_status.path is not None and is_process_running(cached_proc):
        return (
            RDR2Status(
                path=cached_status.path,
                pid=cached_proc.pid,
                is_suspended=is_process_suspended(cached_proc.pid),
                udp_ports=get_process_udp_ports(cached_proc.pid),
            ),
            cached_proc,
        )

    # Slow path: cheap scan by process name only.
    for pid, process_name in iter_running_processes():
        if not process_name or process_name.lower() not in _RDR2_PROCESS_NAMES:
            continue

        process_path = get_process_image_path(pid)
        if process_path is None:
            continue

        if not has_valid_authenticode_signature(process_path):
            logger.debug('[RDR2Monitor] Authenticode signature invalid, ignoring impostor: "%s" (PID: %s)', process_path, pid)
            continue

        resolved_path = process_path.resolve()

        logger.debug('[RDR2Monitor] Authenticode signature verified: "%s" (PID: %s)', resolved_path, pid)

        creation_time = get_process_creation_time(pid)
        cached_info = ProcessInfo(pid=pid, creation_time=creation_time) if creation_time is not None else None

        return (
            RDR2Status(
                path=resolved_path,
                pid=pid,
                is_suspended=is_process_suspended(pid),
                udp_ports=get_process_udp_ports(pid),
            ),
            cached_info,
        )

    return (
        RDR2Status(path=None),
        None,
    )
