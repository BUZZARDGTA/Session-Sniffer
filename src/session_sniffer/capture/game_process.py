"""Active game process detection and UDP port resolution across all supported PC games."""

import ctypes
import socket
from contextlib import suppress
from ctypes import wintypes
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

import psutil

from session_sniffer.capture.games_catalog import ALL_SUPPORTED_EXECUTABLE_NAMES, GAME_BY_EXECUTABLE_NAME
from session_sniffer.ctypes_wintrust import has_valid_authenticode_signature
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
class ActiveGameStatus:
    """Immutable snapshot of the running supported game process state.

    Attributes:
        game_name: The official display name of the detected game, or `None` if no game is running.
        path: Resolved path to the running game executable, or `None` if not running.
        pid: PID of the running game process, or `None` if not running.
        udp_ports: Set of local UDP socket ports currently bound by the game process.
        is_running: `True` if a supported game process was detected.
    """

    game_name: str | None
    path: Path | None
    pid: int | None = None
    udp_ports: frozenset[int] = frozenset()
    is_running: bool = field(init=False)

    def __post_init__(self) -> None:
        """Derive `is_running` from `path`."""
        object.__setattr__(self, 'is_running', self.path is not None)


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


def find_running_game_process(
    cached_process: psutil.Process | None = None,
    cached_status: ActiveGameStatus | None = None,
    target_game_name: str | None = None,
) -> tuple[ActiveGameStatus, psutil.Process | None]:
    """Return an `ActiveGameStatus` snapshot for a running supported PC game plus its process handle.

    Scans running processes for any matching executable from `SUPPORTED_PC_GAMES`. If
    `target_game_name` is provided, only executables matching that specific game name
    will be matched.

    Args:
        cached_process: The `psutil.Process` returned by a previous call, re-queried directly
            to avoid a full scan. Pass `None` to force a full scan.
        cached_status: The `ActiveGameStatus` returned by a previous call.
        target_game_name: Optional game name to restrict detection to.

    Returns:
        A `(ActiveGameStatus, psutil.Process | None)` tuple.
    """
    # Fast path: re-query only the previously validated PID.
    if cached_process is not None and cached_status is not None and cached_status.path is not None:
        with suppress(psutil.NoSuchProcess, psutil.AccessDenied):
            if cached_process.is_running() and (target_game_name is None or cached_status.game_name == target_game_name):
                return (
                    ActiveGameStatus(
                        game_name=cached_status.game_name,
                        path=cached_status.path,
                        pid=cached_process.pid,
                        udp_ports=get_process_udp_ports(cached_process.pid),
                    ),
                    cached_process,
                )

    # Slow path: scan running processes.
    for process in psutil.process_iter(['name']):
        process_name = cast('str | None', process.info.get('name'))
        if not process_name:
            continue

        normalized_process_name = process_name.lower()
        if normalized_process_name not in ALL_SUPPORTED_EXECUTABLE_NAMES:
            continue

        game = GAME_BY_EXECUTABLE_NAME[normalized_process_name]
        if target_game_name is not None and game.name != target_game_name:
            continue

        try:
            process_path = Path(process.exe())
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

        if game.verify_authenticode and not has_valid_authenticode_signature(process_path):
            logger.debug('[GameProcess] Authenticode signature invalid, ignoring impostor: "%s" (PID: %s)', process_path, process.pid)
            continue

        resolved_path = process_path.resolve()

        with suppress(psutil.NoSuchProcess, psutil.AccessDenied):
            return (
                ActiveGameStatus(
                    game_name=game.name,
                    path=resolved_path,
                    pid=process.pid,
                    udp_ports=get_process_udp_ports(process.pid),
                ),
                process,
            )

    return (
        ActiveGameStatus(game_name=None, path=None),
        None,
    )
