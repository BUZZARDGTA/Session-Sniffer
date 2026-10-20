"""Low-level Win32 and macOS libproc ctypes bindings for process inspection and control."""

import ctypes
import os
import socket
import sys
from ctypes import wintypes
from pathlib import Path

from session_sniffer.ctypes_windows import iter_win32_toolhelp_processes

_PROCESS_SUSPEND_RESUME = 0x0800
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_STILL_ACTIVE = 259
_SYSTEM_PROCESS_INFORMATION_CLASS = 5
_STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
_THREAD_STATE_WAITING = 5
_WAIT_REASON_SUSPENDED = 5
_WINDOWS_EPOCH_DELTA_100NS = 116444736000000000
_BYTES_PER_MB = 1024**2
_ERROR_ACCESS_DENIED = 5
_AF_INET = 2
_UDP_TABLE_OWNER_PID = 1
_ERROR_INSUFFICIENT_BUFFER = 122
_ERROR_SUCCESS = 0
_SYSTEM_PROCESS_INFORMATION_MIN_SIZE = 256
_SYSTEM_THREAD_INFORMATION_SIZE = 80
_PORT_MASK = 0xFFFF

_DARWIN_PROC_ALL_PIDS = 1
_DARWIN_PROC_PIDTBSDINFO = 3
_DARWIN_PROC_PIDTASKINFO = 4
_DARWIN_SSTOP = 4


class _MibUdpRowOwnerPid(ctypes.Structure):
    """ctypes definition for MIB_UDPROW_OWNER_PID structure."""

    _fields_ = [
        ('dwLocalAddr', wintypes.DWORD),
        ('dwLocalPort', wintypes.DWORD),
        ('dwOwningPid', wintypes.DWORD),
    ]


class _IOCounters(ctypes.Structure):
    """ctypes definition for IO_COUNTERS structure."""

    _fields_ = [
        ('ReadOperationCount', ctypes.c_uint64),
        ('WriteOperationCount', ctypes.c_uint64),
        ('OtherOperationCount', ctypes.c_uint64),
        ('ReadTransferCount', ctypes.c_uint64),
        ('WriteTransferCount', ctypes.c_uint64),
        ('OtherTransferCount', ctypes.c_uint64),
    ]


class _ProcessMemoryCounters(ctypes.Structure):
    """ctypes definition for PROCESS_MEMORY_COUNTERS structure."""

    _fields_ = [
        ('cb', wintypes.DWORD),
        ('PageFaultCount', wintypes.DWORD),
        ('PeakWorkingSetSize', ctypes.c_size_t),
        ('WorkingSetSize', ctypes.c_size_t),
        ('QuotaPeakPagedPoolUsage', ctypes.c_size_t),
        ('QuotaPagedPoolUsage', ctypes.c_size_t),
        ('QuotaPeakNonPagedPoolUsage', ctypes.c_size_t),
        ('QuotaNonPagedPoolUsage', ctypes.c_size_t),
        ('PagefileUsage', ctypes.c_size_t),
        ('PeakPagefileUsage', ctypes.c_size_t),
    ]

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self.cb = ctypes.sizeof(self)


class _DarwinProcBsdInfo(ctypes.Structure):
    """ctypes definition for macOS proc_bsdinfo structure."""

    _fields_ = [
        ('pbi_flags', ctypes.c_uint32),
        ('pbi_status', ctypes.c_uint32),
        ('pbi_xstatus', ctypes.c_uint32),
        ('pbi_pid', ctypes.c_uint32),
        ('pbi_ppid', ctypes.c_uint32),
        ('pbi_uid', ctypes.c_uint32),
        ('pbi_gid', ctypes.c_uint32),
        ('pbi_ruid', ctypes.c_uint32),
        ('pbi_rgid', ctypes.c_uint32),
        ('pbi_svuid', ctypes.c_uint32),
        ('pbi_svgid', ctypes.c_uint32),
        ('rfu_1', ctypes.c_uint32),
        ('pbi_comm', ctypes.c_char * 16),
        ('pbi_name', ctypes.c_char * 32),
        ('pbi_nfiles', ctypes.c_uint32),
        ('pbi_pgid', ctypes.c_uint32),
        ('pbi_pjobc', ctypes.c_uint32),
        ('e_tdev', ctypes.c_uint32),
        ('e_tpgid', ctypes.c_uint32),
        ('pbi_nice', ctypes.c_int32),
        ('pbi_start_tvsec', ctypes.c_uint64),
        ('pbi_start_tvusec', ctypes.c_uint64),
    ]


class _DarwinProcTaskInfo(ctypes.Structure):
    """ctypes definition for macOS proc_taskinfo structure."""

    _fields_ = [
        ('pti_virtual_size', ctypes.c_uint64),
        ('pti_resident_size', ctypes.c_uint64),
        ('pti_total_user', ctypes.c_uint64),
        ('pti_total_system', ctypes.c_uint64),
        ('pti_threads_user', ctypes.c_uint64),
        ('pti_threads_system', ctypes.c_uint64),
        ('pti_policy', ctypes.c_int32),
        ('pti_faults', ctypes.c_int32),
        ('pti_pageins', ctypes.c_int32),
        ('pti_cow_faults', ctypes.c_int32),
        ('pti_messages_sent', ctypes.c_int32),
        ('pti_messages_received', ctypes.c_int32),
        ('pti_syscalls_mach', ctypes.c_int32),
        ('pti_syscalls_unix', ctypes.c_int32),
        ('pti_csw', ctypes.c_int32),
        ('pti_threadnum', ctypes.c_int32),
        ('pti_numrunning', ctypes.c_int32),
        ('pti_priority', ctypes.c_int32),
    ]


if sys.platform == 'win32':
    _kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    _ntdll = ctypes.windll.ntdll
    _psapi = ctypes.windll.psapi
    _iphlpapi = ctypes.windll.iphlpapi

    _kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _kernel32.OpenProcess.restype = wintypes.HANDLE
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL
    _kernel32.GetCurrentProcess.argtypes = []
    _kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    _kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    _kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    _kernel32.GetProcessTimes.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
    ]
    _kernel32.GetProcessTimes.restype = wintypes.BOOL
    _kernel32.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    _kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    _kernel32.GetProcessIoCounters.argtypes = [wintypes.HANDLE, ctypes.POINTER(_IOCounters)]
    _kernel32.GetProcessIoCounters.restype = wintypes.BOOL
    _psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ProcessMemoryCounters), wintypes.DWORD]
    _psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
    _ntdll.NtSuspendProcess.argtypes = [wintypes.HANDLE]
    _ntdll.NtSuspendProcess.restype = wintypes.LONG
    _ntdll.NtResumeProcess.argtypes = [wintypes.HANDLE]
    _ntdll.NtResumeProcess.restype = wintypes.LONG
    _ntdll.NtQuerySystemInformation.argtypes = [wintypes.ULONG, ctypes.c_void_p, wintypes.ULONG, ctypes.POINTER(wintypes.ULONG)]
    _ntdll.NtQuerySystemInformation.restype = wintypes.LONG
    _GetExtendedUdpTable = _iphlpapi.GetExtendedUdpTable
    _GetExtendedUdpTable.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), wintypes.BOOL, wintypes.ULONG, ctypes.c_int, wintypes.ULONG]
    _GetExtendedUdpTable.restype = wintypes.DWORD


def _get_creation_time_from_handle(handle: wintypes.HANDLE) -> float | None:
    creation_time = wintypes.FILETIME()
    exit_time = wintypes.FILETIME()
    kernel_time = wintypes.FILETIME()
    user_time = wintypes.FILETIME()
    if not _kernel32.GetProcessTimes(handle, ctypes.byref(creation_time), ctypes.byref(exit_time), ctypes.byref(kernel_time), ctypes.byref(user_time)):
        return None
    time_100ns = (creation_time.dwHighDateTime << 32) + creation_time.dwLowDateTime
    return (time_100ns - _WINDOWS_EPOCH_DELTA_100NS) / 10000000.0


def get_process_creation_time_darwin(pid: int) -> float | None:
    """Return creation time of the process on macOS using libproc."""
    try:
        libc = ctypes.CDLL(None)
        bsdinfo = _DarwinProcBsdInfo()
        return_bytes = libc.proc_pidinfo(pid, _DARWIN_PROC_PIDTBSDINFO, 0, ctypes.byref(bsdinfo), ctypes.sizeof(bsdinfo))
        if return_bytes == ctypes.sizeof(bsdinfo):
            return float(bsdinfo.pbi_start_tvsec) + (float(bsdinfo.pbi_start_tvusec) / 1_000_000.0)
    except (OSError, AttributeError):
        pass
    return None


def get_process_creation_time_win32(pid: int) -> float | None:
    """Return creation time of the process on Windows via GetProcessTimes."""
    if sys.platform != 'win32':
        return None
    handle = _kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, 0, pid)
    if not handle:
        return None
    try:
        return _get_creation_time_from_handle(handle)
    finally:
        _kernel32.CloseHandle(handle)


def is_process_running_win32(pid: int, creation_time: float | None, tolerance_seconds: float) -> bool:
    """Check if process is running on Windows and matches *creation_time* within *tolerance_seconds*."""
    if sys.platform != 'win32':
        return False
    handle = _kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, 0, pid)
    if not handle:
        return False
    try:
        exit_code = wintypes.DWORD()
        if not _kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)) or exit_code.value != _STILL_ACTIVE:
            return False
        if creation_time is not None:
            actual_creation_time = _get_creation_time_from_handle(handle)
            return not (actual_creation_time is None or abs(actual_creation_time - creation_time) > tolerance_seconds)
        return True
    finally:
        _kernel32.CloseHandle(handle)


def get_process_image_path_darwin(pid: int) -> Path | None:
    """Return the resolved executable file path for the given PID on macOS via proc_pidpath."""
    try:
        libc = ctypes.CDLL(None)
        path_buffer = ctypes.create_string_buffer(4096)
        return_length = libc.proc_pidpath(pid, path_buffer, ctypes.sizeof(path_buffer))
        if return_length > 0:
            path_string = path_buffer.value.decode('utf-8', errors='replace')
            if path_string:
                return Path(path_string).resolve()
    except (OSError, AttributeError):
        pass
    return None


def get_process_image_path_win32(pid: int) -> Path | None:
    """Return the resolved executable file path for the given PID on Windows via QueryFullProcessImageNameW."""
    if sys.platform != 'win32':
        return None
    handle = _kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, 0, pid)
    if not handle:
        return None
    try:
        buffer_size = wintypes.DWORD(1024)
        image_path_buffer = ctypes.create_unicode_buffer(buffer_size.value)
        if not _kernel32.QueryFullProcessImageNameW(handle, 0, image_path_buffer, ctypes.byref(buffer_size)):
            return None
        return Path(image_path_buffer.value).resolve()
    finally:
        _kernel32.CloseHandle(handle)


def iter_running_processes_darwin() -> list[tuple[int, str]]:
    """Return a snapshot list of (pid, name) for all running processes on macOS via libproc."""
    try:
        libc = ctypes.CDLL(None)
        bytes_needed = libc.proc_listpids(_DARWIN_PROC_ALL_PIDS, 0, None, 0)
        if bytes_needed <= 0:
            return []
        buffer = ctypes.create_string_buffer(bytes_needed)
        actual_bytes = libc.proc_listpids(_DARWIN_PROC_ALL_PIDS, 0, buffer, bytes_needed)
        if actual_bytes <= 0:
            return []
        pid_count = actual_bytes // ctypes.sizeof(ctypes.c_int32)
        pids = (ctypes.c_int32 * pid_count).from_buffer(buffer)
        processes: list[tuple[int, str]] = []
        name_buffer = ctypes.create_string_buffer(256)
        for pid in pids:
            if pid <= 0:
                continue
            name_length = libc.proc_name(pid, name_buffer, ctypes.sizeof(name_buffer))
            name = name_buffer.value.decode('utf-8', errors='replace') if name_length > 0 else ''
            processes.append((int(pid), name))
    except (OSError, AttributeError):
        return []
    return processes


def iter_running_processes_win32() -> list[tuple[int, str]]:
    """Return a snapshot list of (pid, name) for all running processes on Windows via Toolhelp32."""
    return [(pid, name) for pid, _ppid, name in iter_win32_toolhelp_processes()]


def set_process_suspended_win32(pid: int, *, suspend: bool) -> None:
    """Suspend or resume execution of *pid* on Windows via NtSuspendProcess / NtResumeProcess."""
    if sys.platform != 'win32':
        return
    handle = _kernel32.OpenProcess(_PROCESS_SUSPEND_RESUME | _PROCESS_QUERY_LIMITED_INFORMATION, 0, pid)
    if not handle:
        last_error = ctypes.get_last_error()
        if last_error in (2, 87, 1168):
            error_message = f'Process {pid} does not exist'
            raise ProcessLookupError(error_message)
        if last_error == _ERROR_ACCESS_DENIED:
            action = 'suspend' if suspend else 'resume'
            error_message = f'Access denied to {action} process {pid}'
            raise PermissionError(error_message)
        error_message = f'Failed to open process {pid}: Win32 error {last_error}'
        raise OSError(error_message)
    try:
        nt_fn, fn_name = (_ntdll.NtSuspendProcess, 'NtSuspendProcess') if suspend else (_ntdll.NtResumeProcess, 'NtResumeProcess')
        ntstatus = nt_fn(handle)
        if ntstatus:
            error_message = f'{fn_name} failed for PID {pid} with NTSTATUS {ntstatus & 0xFFFFFFFF:#x}'
            raise OSError(error_message)
    finally:
        _kernel32.CloseHandle(handle)


def is_process_suspended_darwin(pid: int) -> bool:
    """Check if process is suspended on macOS via proc_pidinfo."""
    try:
        libc = ctypes.CDLL(None)
        bsdinfo = _DarwinProcBsdInfo()
        return_bytes = libc.proc_pidinfo(pid, _DARWIN_PROC_PIDTBSDINFO, 0, ctypes.byref(bsdinfo), ctypes.sizeof(bsdinfo))
        if return_bytes == ctypes.sizeof(bsdinfo):
            return bool(bsdinfo.pbi_status == _DARWIN_SSTOP)
    except (OSError, AttributeError):
        pass
    return False


def is_process_suspended_win32(pid: int) -> bool:
    """Check whether the target process is suspended on Windows via NtQuerySystemInformation."""
    if sys.platform != 'win32':
        return False
    buffer_size = wintypes.ULONG(0x100000)
    return_length = wintypes.ULONG(0)
    process_info_buffer: ctypes.Array[ctypes.c_char] | None = None
    for _ in range(10):
        current_buffer = ctypes.create_string_buffer(buffer_size.value)
        status = _ntdll.NtQuerySystemInformation(
            _SYSTEM_PROCESS_INFORMATION_CLASS,
            current_buffer,
            buffer_size,
            ctypes.byref(return_length),
        ) & 0xFFFFFFFF
        if not status:
            process_info_buffer = current_buffer
            break
        if status == _STATUS_INFO_LENGTH_MISMATCH:
            buffer_size = wintypes.ULONG(max(buffer_size.value * 2, return_length.value + 4096))
            continue
        return False

    if process_info_buffer is None:
        return False

    buffer_len = len(process_info_buffer)
    buffer_start = ctypes.addressof(process_info_buffer)
    buffer_end = buffer_start + min(buffer_len, return_length.value)
    current_address = buffer_start

    while current_address + _SYSTEM_PROCESS_INFORMATION_MIN_SIZE <= buffer_end:
        next_entry_offset = wintypes.ULONG.from_address(current_address).value
        number_of_threads = wintypes.ULONG.from_address(current_address + 4).value
        process_id = ctypes.c_void_p.from_address(current_address + 80).value or 0

        if process_id == pid:
            threads_base_address = current_address + _SYSTEM_PROCESS_INFORMATION_MIN_SIZE
            threads_end_address = threads_base_address + number_of_threads * _SYSTEM_THREAD_INFORMATION_SIZE
            if not number_of_threads or threads_end_address > buffer_end:
                return False
            return all(
                wintypes.ULONG.from_address(threads_base_address + i * _SYSTEM_THREAD_INFORMATION_SIZE + 68).value == _THREAD_STATE_WAITING
                and wintypes.ULONG.from_address(threads_base_address + i * _SYSTEM_THREAD_INFORMATION_SIZE + 72).value == _WAIT_REASON_SUSPENDED
                for i in range(number_of_threads)
            )

        if not next_entry_offset:
            break
        if (
            next_entry_offset < _SYSTEM_PROCESS_INFORMATION_MIN_SIZE
            or next_entry_offset % 8
            or current_address + next_entry_offset >= buffer_end
        ):
            break
        current_address += next_entry_offset

    return False


def get_current_process_memory_darwin() -> float:
    """Return RSS memory usage of the current process in megabytes on macOS via proc_pidinfo."""
    try:
        libc = ctypes.CDLL(None)
        taskinfo = _DarwinProcTaskInfo()
        return_bytes = libc.proc_pidinfo(os.getpid(), _DARWIN_PROC_PIDTASKINFO, 0, ctypes.byref(taskinfo), ctypes.sizeof(taskinfo))
        if return_bytes == ctypes.sizeof(taskinfo):
            return float(taskinfo.pti_resident_size) / _BYTES_PER_MB
    except (OSError, AttributeError):
        pass
    return 0.0


def get_current_process_memory_win32() -> float:
    """Return working-set memory usage of the current process in megabytes on Windows via GetProcessMemoryInfo."""
    if sys.platform != 'win32':
        return 0.0
    memory_counters = _ProcessMemoryCounters()
    if not _psapi.GetProcessMemoryInfo(_kernel32.GetCurrentProcess(), ctypes.byref(memory_counters), ctypes.sizeof(memory_counters)):
        return 0.0
    return float(memory_counters.WorkingSetSize) / _BYTES_PER_MB


def get_current_process_io_bytes_win32() -> tuple[int, int]:
    """Return (read_bytes, write_bytes) for the current process on Windows via GetProcessIoCounters."""
    if sys.platform != 'win32':
        return (0, 0)
    io_counters = _IOCounters()
    if not _kernel32.GetProcessIoCounters(_kernel32.GetCurrentProcess(), ctypes.byref(io_counters)):
        return (0, 0)
    return (int(io_counters.ReadTransferCount), int(io_counters.WriteTransferCount))


def get_current_process_cpu_time_win32() -> float:
    """Return total CPU time (kernel + user) in seconds for the current process on Windows via GetProcessTimes."""
    if sys.platform != 'win32':
        return 0.0
    creation_time = wintypes.FILETIME()
    exit_time = wintypes.FILETIME()
    kernel_time = wintypes.FILETIME()
    user_time = wintypes.FILETIME()
    if not _kernel32.GetProcessTimes(
        _kernel32.GetCurrentProcess(),
        ctypes.byref(creation_time),
        ctypes.byref(exit_time),
        ctypes.byref(kernel_time),
        ctypes.byref(user_time),
    ):
        return 0.0
    kernel_100ns = (kernel_time.dwHighDateTime << 32) + kernel_time.dwLowDateTime
    user_100ns = (user_time.dwHighDateTime << 32) + user_time.dwLowDateTime
    return (kernel_100ns + user_100ns) / 10000000.0


def get_process_udp_ports_win32(target_pid: int) -> frozenset[int]:
    """Return the set of local UDP ports currently bound by *target_pid* on Windows via GetExtendedUdpTable."""
    if sys.platform != 'win32':
        return frozenset[int]()
    buffer_size = wintypes.DWORD(0)
    result = _GetExtendedUdpTable(None, ctypes.byref(buffer_size), 0, _AF_INET, _UDP_TABLE_OWNER_PID, 0)

    for _attempt in range(3):
        if result != _ERROR_INSUFFICIENT_BUFFER:
            break
        allocated_size = buffer_size.value + 4096
        buffer = ctypes.create_string_buffer(allocated_size)
        actual_size = wintypes.DWORD(allocated_size)
        result = _GetExtendedUdpTable(buffer, ctypes.byref(actual_size), 0, _AF_INET, _UDP_TABLE_OWNER_PID, 0)
        if result == _ERROR_SUCCESS:
            number_of_entries = ctypes.cast(buffer, ctypes.POINTER(wintypes.DWORD)).contents.value
            if not number_of_entries:
                return frozenset[int]()
            table_offset = ctypes.sizeof(wintypes.DWORD)
            required_size = table_offset + ctypes.sizeof(_MibUdpRowOwnerPid) * number_of_entries
            if required_size > len(buffer):
                return frozenset[int]()
            row_array = (_MibUdpRowOwnerPid * number_of_entries).from_buffer(buffer, table_offset)
            return frozenset(
                socket.ntohs(row.dwLocalPort & _PORT_MASK)
                for row in row_array
                if row.dwOwningPid == target_pid
            )
        buffer_size = actual_size

    return frozenset[int]()
