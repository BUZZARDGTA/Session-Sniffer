"""GTA5 process detection and immutable state snapshot.

Detects the currently running GTA V process (Legacy `GTA5.exe` or Enhanced
`GTA5_Enhanced.exe`), verifies its Authenticode signature to reject impostor
executables that merely reuse the process name, and exposes the result as an
immutable `GTA5Status` snapshot.
"""

from dataclasses import dataclass, field

from session_sniffer.capture.process import (
    GTA5_PROCESS_NAMES,
    GameProcessStatus,
    ProcessInfo,
    find_running_game_process,
)


@dataclass(frozen=True, slots=True)
class GTA5Status(GameProcessStatus):
    """Immutable snapshot of the running GTA5 process state.

    Attributes:
        path: Resolved path to the running GTA5 executable, or `None` if not running.
        pid: PID of the running GTA5 process, or `None` if not running.
        is_suspended: `True` if the running GTA5 process is currently suspended at the
            OS level (its threads are stopped), regardless of what suspended it.
        udp_ports: Set of local UDP socket ports currently bound by the GTA5 process.
        is_running: `True` if a GTA5 process was detected.
        is_enhanced: `True` if the running version is GTA V Enhanced (`GTA5_Enhanced.exe`).
        is_legacy: `True` if the running version is GTA V Legacy (`GTA5.exe`).
    """

    is_enhanced: bool = field(init=False)
    is_legacy: bool = field(init=False)

    def __post_init__(self) -> None:
        """Derive `is_running`, `is_enhanced`, and `is_legacy` from `path`."""
        super().__post_init__()
        stem = self.path.stem.lower() if self.path is not None else ''

        object.__setattr__(self, 'is_enhanced', stem == 'gta5_enhanced')
        object.__setattr__(self, 'is_legacy', stem == 'gta5')


def find_running_gta5_path(
    cached_proc: ProcessInfo | None = None,
    cached_status: GTA5Status | None = None,
) -> tuple[GTA5Status, ProcessInfo | None]:
    """Return a `GTA5Status` snapshot for the currently running GTA5 process plus its process handle."""
    return find_running_game_process(
        GTA5_PROCESS_NAMES,
        'GTA5',
        GTA5Status,
        cached_proc=cached_proc,
        cached_status=cached_status,
    )
