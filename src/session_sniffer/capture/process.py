"""Target process inspection and UDP port resolution via Win32 IP Helper API."""

import ctypes
import socket
from contextlib import suppress
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path

import psutil

from session_sniffer.logging_setup import get_logger

logger = get_logger(__name__)


class _MIB_UDPROW_OWNER_PID(ctypes.Structure):
    """ctypes definition for MIB_UDPROW_OWNER_PID structure."""

    _fields_ = [
        ('dwLocalAddr', wintypes.DWORD),
        ('dwLocalPort', wintypes.DWORD),
        ('dwOwningPid', wintypes.DWORD),
    ]


_AF_INET = 2
_UDP_TABLE_OWNER_PID = 1
_ERROR_INSUFFICIENT_BUFFER = 122
_ERROR_SUCCESS = 0

_GetExtendedUdpTable = ctypes.windll.iphlpapi.GetExtendedUdpTable
_GetExtendedUdpTable.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(wintypes.DWORD),
    wintypes.BOOL,
    wintypes.ULONG,
    ctypes.c_int,
    wintypes.ULONG,
]
_GetExtendedUdpTable.restype = wintypes.DWORD


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


def get_process_udp_ports(target_pid: int) -> frozenset[int]:
    """Return the set of local UDP ports currently bound by the target PID via Win32 IP Helper API."""
    buffer_size = wintypes.DWORD(0)
    result = _GetExtendedUdpTable(None, ctypes.byref(buffer_size), 0, _AF_INET, _UDP_TABLE_OWNER_PID, 0)

    for _attempt in range(3):
        if result != _ERROR_INSUFFICIENT_BUFFER:
            break
        buffer = ctypes.create_string_buffer(buffer_size.value)
        result = _GetExtendedUdpTable(buffer, ctypes.byref(buffer_size), 0, _AF_INET, _UDP_TABLE_OWNER_PID, 0)
        if result == _ERROR_SUCCESS:
            number_of_entries = ctypes.cast(buffer, ctypes.POINTER(wintypes.DWORD)).contents.value
            if not number_of_entries:
                return frozenset[int]()
            table_offset = ctypes.sizeof(wintypes.DWORD)
            row_array = (_MIB_UDPROW_OWNER_PID * number_of_entries).from_buffer(buffer, table_offset)
            return frozenset(
                socket.ntohs(row.dwLocalPort)
                for row in row_array
                if row.dwOwningPid == target_pid
            )

    return frozenset[int]()


def inspect_target_process(
    target_pid: int,
    cached_process: psutil.Process | None = None,
) -> tuple[TargetProcessStatus, psutil.Process | None]:
    """Return a `TargetProcessStatus` snapshot for the specified PID plus its process handle.

    Args:
        target_pid: The Process ID (PID) to inspect.
        cached_process: The `psutil.Process` returned by a previous call, re-queried directly
            to avoid resolving a new handle. Pass `None` to force a new handle resolution.

    Returns:
        A `(TargetProcessStatus, psutil.Process | None)` tuple.
    """
    if target_pid <= 0:
        return (TargetProcessStatus(), None)

    # Fast path: re-query existing cached process handle if PID matches.
    if cached_process is not None and cached_process.pid == target_pid:
        with suppress(psutil.NoSuchProcess, psutil.AccessDenied):
            if cached_process.is_running():
                process_name: str | None = None
                with suppress(psutil.AccessDenied):
                    process_name = cached_process.name()

                process_path: Path | None = None
                with suppress(psutil.AccessDenied):
                    process_path = Path(cached_process.exe()).resolve()

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

    # Slow path: resolve new psutil.Process for target_pid
    with suppress(psutil.NoSuchProcess, psutil.AccessDenied):
        process = psutil.Process(target_pid)
        if process.is_running():
            process_name = None
            with suppress(psutil.AccessDenied):
                process_name = process.name()

            process_path = None
            with suppress(psutil.AccessDenied):
                process_path = Path(process.exe()).resolve()

            return (
                TargetProcessStatus(
                    pid=target_pid,
                    name=process_name,
                    path=process_path,
                    udp_ports=get_process_udp_ports(target_pid),
                    is_running=True,
                ),
                process,
            )

    return (TargetProcessStatus(pid=target_pid, is_running=False), None)


_SYSTEM_PROCESS_NAMES: frozenset[str] = frozenset(
    {
        'conhost.exe',
        'csrss.exe',
        'dwm.exe',
        'fontdrvhost.exe',
        'lsass.exe',
        'registry',
        'runtimebroker.exe',
        'services.exe',
        'sihost.exe',
        'smss.exe',
        'spoolsv.exe',
        'system',
        'taskhostw.exe',
        'wininit.exe',
        'winlogon.exe',
    },
)


def get_running_applications(*, user_apps_only: bool = True) -> list[tuple[int, str, str]]:
    """Return a sorted list of `(pid, name, exe_path)` for running processes."""
    processes: list[tuple[int, str, str]] = []

    for process in psutil.process_iter(['pid', 'name']):
        try:
            pid = process.pid
            if pid <= 0:
                continue
            name = process.name()
            if not name:
                continue

            if user_apps_only and name.lower() in _SYSTEM_PROCESS_NAMES:
                continue

            exe_path = ''
            with suppress(psutil.NoSuchProcess, psutil.AccessDenied):
                exe = process.exe()
                if exe:
                    exe_path = str(Path(exe).resolve())

            if user_apps_only and exe_path:
                normalized_exe_path = exe_path.lower()
                if '\\windows\\system32\\' in normalized_exe_path or '\\windows\\systemapps\\' in normalized_exe_path:
                    continue

            processes.append((pid, name, exe_path))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    processes.sort(key=lambda item: item[1].lower())
    return processes
