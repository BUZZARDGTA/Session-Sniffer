"""Target process inspection and UDP port resolution via Win32 IP Helper and Windows APIs on Windows, procfs on Linux, or libproc and lsof on macOS."""

import logging
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from session_sniffer.capture.ctypes_process import (
    get_current_process_cpu_time_win32,
    get_current_process_io_bytes_win32,
    get_current_process_memory_darwin,
    get_current_process_memory_win32,
    get_process_creation_time_darwin,
    get_process_creation_time_win32,
    get_process_image_path_darwin,
    get_process_image_path_win32,
    get_process_udp_ports_win32,
    is_process_running_win32,
    is_process_suspended_darwin,
    is_process_suspended_win32,
    iter_running_processes_darwin,
    iter_running_processes_win32,
    set_process_suspended_win32,
)
from session_sniffer.ctypes_wintrust import has_valid_authenticode_signature

if sys.platform != 'win32':
    import signal

logger = logging.getLogger(__name__)

_CREATION_TIME_TOLERANCE_SECONDS = 0.05
_PROC_NET_UDP_MIN_FIELDS = 10
_MIN_LSOF_UDP_FIELDS = 9
_DARWIN_LSOF_EXECUTABLE = '/usr/sbin/lsof'


@dataclass(frozen=True, slots=True)
class ProcessInfo:
    """Snapshot of a process identity for tracking and cache validation."""

    pid: int
    creation_time: float


@dataclass(frozen=True, slots=True)
class TargetProcessStatus:
    """Immutable snapshot of the monitored target process state.

    Attributes:
        pid: PID of the monitored process, or `None` if not monitored or not running.
        name: Name of the process executable, or `None` if not running.
        path: Resolved path to the running executable, or `None` if not running.
        udp_ports: Set of local UDP socket ports currently bound by the process.
        is_running: `True` if the process was detected and is running.
    """

    pid: int | None = None
    name: str | None = None
    path: Path | None = None
    udp_ports: frozenset[int] = frozenset()
    is_running: bool = False


@dataclass(frozen=True, slots=True)
class GameProcessStatus:
    """Base immutable snapshot of a running game process state.

    Attributes:
        path: Resolved path to the running game executable, or `None` if not running.
        pid: PID of the running game process, or `None` if not running.
        is_suspended: `True` if the running game process is currently suspended at the
            OS level (its threads are stopped), regardless of what suspended it.
        udp_ports: Set of local UDP socket ports currently bound by the game process.
        is_running: `True` if a game process was detected.
    """

    path: Path | None
    pid: int | None = None
    is_suspended: bool = False
    udp_ports: frozenset[int] = frozenset()
    is_running: bool = field(init=False)

    def __post_init__(self) -> None:
        """Derive `is_running` from `path`."""
        object.__setattr__(self, 'is_running', self.path is not None)


def _is_process_running_darwin(pid: int, creation_time: float | None) -> bool:
    """Check if process is running on macOS."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        pass
    if creation_time is not None:
        actual_creation_time = get_process_creation_time(pid)
        return not (actual_creation_time is None or abs(actual_creation_time - creation_time) > _CREATION_TIME_TOLERANCE_SECONDS)
    return True


def _get_process_udp_ports_darwin(target_pid: int) -> frozenset[int]:
    """Return the set of local UDP ports currently bound by target PID on macOS via lsof."""
    try:
        lsof_executable = shutil.which('lsof') or _DARWIN_LSOF_EXECUTABLE
        process = subprocess.run(
            [lsof_executable, '-nP', '-iUDP', '-a', '-p', str(target_pid)],
            capture_output=True,
            text=True,
            check=False,
            timeout=3.0,
        )
    except (OSError, subprocess.TimeoutExpired):
        return frozenset[int]()

    ports: set[int] = set()
    for line in process.stdout.splitlines()[1:]:
        tokens = line.strip().split()
        if len(tokens) >= _MIN_LSOF_UDP_FIELDS:
            endpoint = tokens[-1]
            port_string = endpoint.rsplit(':', 1)[-1]
            if port_string.isdigit():
                ports.add(int(port_string))
    return frozenset(ports)


def get_process_creation_time(pid: int) -> float | None:
    """Return the creation time of the process in seconds since Unix epoch, or None if unavailable."""
    if pid <= 0:
        return None
    if sys.platform == 'darwin':
        return get_process_creation_time_darwin(pid)
    if sys.platform != 'win32':
        try:
            return Path(f'/proc/{pid}').stat().st_ctime
        except OSError:
            return None
    return get_process_creation_time_win32(pid)


def _is_process_running_linux(pid: int, creation_time: float | None) -> bool:
    """Check if process is running on Linux."""
    if not Path(f'/proc/{pid}').exists():
        return False
    if creation_time is not None:
        actual_creation_time = get_process_creation_time(pid)
        return not (actual_creation_time is None or abs(actual_creation_time - creation_time) > _CREATION_TIME_TOLERANCE_SECONDS)
    return True


def is_process_running(target: int | ProcessInfo) -> bool:
    """Return `True` if the process is currently active and matches creation time if specified."""
    if isinstance(target, ProcessInfo):
        pid = target.pid
        creation_time = target.creation_time
    else:
        pid = target
        creation_time = None

    if pid <= 0:
        return False
    if sys.platform == 'darwin':
        return _is_process_running_darwin(pid, creation_time)
    if sys.platform != 'win32':
        return _is_process_running_linux(pid, creation_time)
    return is_process_running_win32(pid, creation_time, _CREATION_TIME_TOLERANCE_SECONDS)


def _get_process_image_path_linux(pid: int) -> Path | None:
    try:
        return Path(f'/proc/{pid}/exe').resolve()
    except OSError:
        return None


def get_process_image_path(pid: int) -> Path | None:
    """Return the resolved executable file path for the given PID, or `None` if inaccessible."""
    if pid <= 0:
        return None
    if sys.platform == 'darwin':
        return get_process_image_path_darwin(pid)
    if sys.platform != 'win32':
        return _get_process_image_path_linux(pid)
    return get_process_image_path_win32(pid)


def iter_running_processes() -> list[tuple[int, str]]:
    """Return a snapshot list of `(pid, name)` for all running processes."""
    if sys.platform == 'darwin':
        return iter_running_processes_darwin()
    if sys.platform != 'win32':
        processes: list[tuple[int, str]] = []
        proc_dir = Path('/proc')
        try:
            for entry in proc_dir.iterdir():
                if entry.name.isdigit():
                    pid = int(entry.name)
                    comm_file = entry / 'comm'
                    try:
                        name = comm_file.read_text(encoding='utf-8', errors='replace').strip()
                    except OSError:
                        name = ''
                    processes.append((pid, name))
        except OSError:
            pass
        return processes
    return iter_running_processes_win32()


def _set_process_suspended(pid: int, *, suspend: bool) -> None:
    """Suspend or resume execution of the process with the given PID."""
    if pid <= 0:
        error_message = f'Invalid process ID: {pid}'
        raise ProcessLookupError(error_message)
    if sys.platform != 'win32':
        os.kill(pid, signal.SIGSTOP if suspend else signal.SIGCONT)
        return
    set_process_suspended_win32(pid, suspend=suspend)


def suspend_process(pid: int) -> None:
    """Suspend execution of the process with the given PID."""
    _set_process_suspended(pid, suspend=True)


def resume_process(pid: int) -> None:
    """Resume execution of the process with the given PID."""
    _set_process_suspended(pid, suspend=False)


def _is_process_suspended_linux(pid: int) -> bool:
    """Check if process is suspended on Linux."""
    try:
        with Path(f'/proc/{pid}/status').open(encoding='ascii') as status_file:
            for line in status_file:
                if line.startswith('State:'):
                    return 'T (stopped)' in line or 'T (tracing stop)' in line
    except OSError:
        pass
    return False


def is_process_suspended(pid: int) -> bool:
    """Check whether the target process is in a suspended/stopped state."""
    if pid <= 0:
        return False
    if sys.platform == 'darwin':
        return is_process_suspended_darwin(pid)
    if sys.platform != 'win32':
        return _is_process_suspended_linux(pid)
    return is_process_suspended_win32(pid)


def _get_current_process_memory_linux() -> float:
    try:
        with Path('/proc/self/status').open(encoding='ascii') as status_file:
            for line in status_file:
                if line.startswith('VmRSS:'):
                    fields = line.split()
                    return float(fields[1]) / 1024.0
    except OSError:
        pass
    return 0.0


def get_current_process_memory_mb() -> float:
    """Return the RSS memory usage of the current process in megabytes."""
    if sys.platform == 'darwin':
        return get_current_process_memory_darwin()
    if sys.platform != 'win32':
        return _get_current_process_memory_linux()
    return get_current_process_memory_win32()


def get_current_process_io_bytes() -> tuple[int, int]:
    """Return `(read_bytes, write_bytes)` for the current process."""
    if sys.platform == 'darwin':
        return (0, 0)
    if sys.platform != 'win32':
        read_bytes = 0
        write_bytes = 0
        try:
            with Path('/proc/self/io').open(encoding='ascii') as io_file:
                for line in io_file:
                    if line.startswith('read_bytes:'):
                        read_bytes = int(line.split()[1])
                    elif line.startswith('write_bytes:'):
                        write_bytes = int(line.split()[1])
        except OSError:
            pass
        return (read_bytes, write_bytes)
    return get_current_process_io_bytes_win32()


def get_current_process_cpu_time() -> float:
    """Return total CPU time (kernel + user) in seconds for the current process."""
    if sys.platform != 'win32':
        return time.process_time()
    return get_current_process_cpu_time_win32()


def get_process_udp_ports(target_pid: int) -> frozenset[int]:
    """Return the set of local UDP ports currently bound by the target PID via Win32 IP Helper API."""
    if sys.platform == 'darwin':
        return _get_process_udp_ports_darwin(target_pid)
    if sys.platform != 'win32':
        inode_to_port: dict[str, int] = {}
        for udp_table_path in ('/proc/net/udp', '/proc/net/udp6'):
            try:
                with Path(udp_table_path).open(encoding='ascii') as udp_file:
                    for line in udp_file.readlines()[1:]:
                        fields = line.strip().split()
                        if len(fields) >= _PROC_NET_UDP_MIN_FIELDS:
                            port_hex = fields[1].split(':')[1]
                            port = int(port_hex, 16)
                            inode = fields[9]
                            inode_to_port[inode] = port
            except OSError:
                pass

        ports: set[int] = set()
        fd_dir = Path(f'/proc/{target_pid}/fd')
        try:
            for entry in fd_dir.iterdir():
                try:
                    target = str(entry.readlink())
                    if target.startswith('socket:[') and target.endswith(']'):
                        inode = target[8:-1]
                        if inode in inode_to_port:
                            ports.add(inode_to_port[inode])
                except OSError:
                    pass
        except OSError:
            pass
        return frozenset(ports)
    return get_process_udp_ports_win32(target_pid)


def inspect_target_process(
    target_pid: int,
    cached_process: ProcessInfo | None = None,
) -> tuple[TargetProcessStatus, ProcessInfo | None]:
    """Return a `TargetProcessStatus` snapshot for the specified PID plus its process cache token.

    Args:
        target_pid: The Process ID (PID) to inspect.
        cached_process: The `ProcessInfo` returned by a previous call, re-queried directly
            to avoid resolving a new handle. Pass `None` to force a new handle resolution.

    Returns:
        A `(TargetProcessStatus, ProcessInfo | None)` tuple.
    """
    if target_pid <= 0:
        return (TargetProcessStatus(), None)

    # Fast path: re-query existing cached process handle if PID matches.
    if cached_process is not None and cached_process.pid == target_pid and is_process_running(cached_process):
        process_path = get_process_image_path(target_pid)
        process_name = process_path.name if process_path is not None else None
        return (
            TargetProcessStatus(
                pid=target_pid,
                name=process_name,
                path=process_path,
                udp_ports=get_process_udp_ports(target_pid),
                is_running=True,
            ),
            cached_process,
        )

    # Slow path: resolve process information for target_pid
    if is_process_running(target_pid):
        creation_time = get_process_creation_time(target_pid)
        process_path = get_process_image_path(target_pid)
        process_name = process_path.name if process_path is not None else None
        cached_info = ProcessInfo(pid=target_pid, creation_time=creation_time) if creation_time is not None else None
        return (
            TargetProcessStatus(
                pid=target_pid,
                name=process_name,
                path=process_path,
                udp_ports=get_process_udp_ports(target_pid),
                is_running=True,
            ),
            cached_info,
        )

    return (TargetProcessStatus(pid=target_pid, is_running=False), None)


GTA5_PROCESS_NAMES: frozenset[str] = frozenset(
    {
        'gta5.exe',
        'gta5_enhanced.exe',
    },
)


def find_running_target_process(
    target_name: str,
    target_pid: int = 0,
    *,
    cached_process: ProcessInfo | None = None,
) -> tuple[TargetProcessStatus, ProcessInfo | None]:
    """Inspect and resolve a running target process by executable name and/or PID.

    If the target process matches a known GTA V executable (`gta5.exe` or `gta5_enhanced.exe`),
    both editions are searched interchangeably and verified with Authenticode signatures.
    """
    normalized_target = target_name.strip().lower()
    is_gta5 = normalized_target in GTA5_PROCESS_NAMES
    candidate_names = GTA5_PROCESS_NAMES if is_gta5 else frozenset({normalized_target})

    # Fast path: re-query existing cached process handle if still running.
    if cached_process is not None and is_process_running(cached_process):
        process_path = get_process_image_path(cached_process.pid)
        if process_path is not None and process_path.name.lower() in candidate_names:
            return (
                TargetProcessStatus(
                    pid=cached_process.pid,
                    name=process_path.name,
                    path=process_path,
                    udp_ports=get_process_udp_ports(cached_process.pid),
                    is_running=True,
                ),
                cached_process,
            )

    # Secondary fast path: verify target_pid if provided and running.
    if target_pid > 0 and is_process_running(target_pid):
        process_path = get_process_image_path(target_pid)
        if (
            process_path is not None
            and process_path.name.lower() in candidate_names
            and (not is_gta5 or has_valid_authenticode_signature(process_path))
        ):
            creation_time = get_process_creation_time(target_pid)
            cached_info = ProcessInfo(pid=target_pid, creation_time=creation_time) if creation_time is not None else None
            return (
                TargetProcessStatus(
                    pid=target_pid,
                    name=process_path.name,
                    path=process_path.resolve(),
                    udp_ports=get_process_udp_ports(target_pid),
                    is_running=True,
                ),
                cached_info,
            )

    # Slow path: iterate running processes to find candidate executable.
    for pid, process_name in iter_running_processes():
        if not process_name or process_name.lower() not in candidate_names:
            continue

        process_path = get_process_image_path(pid)
        if process_path is None:
            continue

        if is_gta5 and not has_valid_authenticode_signature(process_path):
            logger.debug('[TargetProcess] Authenticode signature invalid for GTA5, ignoring: "%s" (PID: %s)', process_path, pid)
            continue

        resolved_path = process_path.resolve()
        creation_time = get_process_creation_time(pid)
        cached_info = ProcessInfo(pid=pid, creation_time=creation_time) if creation_time is not None else None
        return (
            TargetProcessStatus(
                pid=pid,
                name=process_path.name,
                path=resolved_path,
                udp_ports=get_process_udp_ports(pid),
                is_running=True,
            ),
            cached_info,
        )

    return (TargetProcessStatus(name=target_name, is_running=False), None)


_SYSTEM_PROCESS_NAMES: frozenset[str] = frozenset(
    {
        'conhost.exe', 'csrss.exe', 'dwm.exe', 'fontdrvhost.exe', 'lsass.exe', 'registry',
        'runtimebroker.exe', 'services.exe', 'sihost.exe', 'smss.exe', 'spoolsv.exe',
        'system', 'taskhostw.exe', 'wininit.exe', 'winlogon.exe',
    },
)


def get_running_applications(*, user_apps_only: bool = True) -> list[tuple[int, str, str]]:
    """Return a sorted list of `(pid, name, exe_path)` for running processes."""
    processes: list[tuple[int, str, str]] = []

    for pid, name in iter_running_processes():
        if pid <= 0:
            continue
        if not name:
            continue

        if user_apps_only and name.lower() in _SYSTEM_PROCESS_NAMES:
            continue

        process_path = get_process_image_path(pid)
        exe_path = str(process_path) if process_path is not None else ''

        if user_apps_only and exe_path:
            normalized_exe_path = exe_path.lower()
            if '\\windows\\system32\\' in normalized_exe_path or '\\windows\\systemapps\\' in normalized_exe_path:
                continue

        processes.append((pid, name, exe_path))

    processes.sort(key=lambda item: item[1].lower())
    return processes


def find_running_game_process[T: GameProcessStatus](
    target_process_names: frozenset[str],
    game_tag: str,
    status_class: type[T],
    *,
    cached_proc: ProcessInfo | None = None,
    cached_status: T | None = None,
) -> tuple[T, ProcessInfo | None]:
    """Inspect and resolve a running game process by its executable names and Authenticode signature.

    Args:
        target_process_names: Set of lowercased target process executable names.
        game_tag: Prefix name used in debug log messages (e.g. 'GTA5' or 'RDR2').
        status_class: Concrete `GameProcessStatus` subclass or class to instantiate.
        cached_proc: The `ProcessInfo` returned by the previous call. Pass `None` to force a full scan.
        cached_status: The status returned by the previous call.

    Returns:
        A `(status, cached_info)` tuple.
    """
    cached_path = cached_status.path if cached_status is not None else None
    # Fast path: re-query only the previously validated PID.
    if cached_proc is not None and cached_path is not None and is_process_running(cached_proc):
        return (
            status_class(
                path=cached_path,
                pid=cached_proc.pid,
                is_suspended=is_process_suspended(cached_proc.pid),
                udp_ports=get_process_udp_ports(cached_proc.pid),
            ),
            cached_proc,
        )

    # Slow path: cheap scan by process name only.
    for pid, process_name in iter_running_processes():
        if not process_name or process_name.lower() not in target_process_names:
            continue

        process_path = get_process_image_path(pid)
        if process_path is None:
            continue

        if not has_valid_authenticode_signature(process_path):
            logger.debug('[%sMonitor] Authenticode signature invalid, ignoring impostor: "%s" (PID: %s)', game_tag, process_path, pid)
            continue

        resolved_path = process_path.resolve()
        logger.debug('[%sMonitor] Authenticode signature verified: "%s" (PID: %s)', game_tag, resolved_path, pid)

        creation_time = get_process_creation_time(pid)
        cached_info = ProcessInfo(pid=pid, creation_time=creation_time) if creation_time is not None else None

        return (
            status_class(
                path=resolved_path,
                pid=pid,
                is_suspended=is_process_suspended(pid),
                udp_ports=get_process_udp_ports(pid),
            ),
            cached_info,
        )

    return (
        status_class(path=None),
        None,
    )
