"""Utility Module.

This module contains a variety of helper functions and custom exceptions used across the project.
"""

import ctypes
import logging
import os
import shutil
import signal
import subprocess
import sys
from ctypes import wintypes
from datetime import UTC, datetime, tzinfo
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from pydantic import ValidationError

from session_sniffer.constants.standalone import TITLE
from session_sniffer.constants.standard import CMD_EXE
from session_sniffer.error_messages import format_type_error
from session_sniffer.models import SessionLogFile
from session_sniffer.utils_exceptions import (
    InvalidBooleanValueError,
    InvalidFileError,
    InvalidNoneTypeValueError,
    MismatchedBooleanValueError,
    NoMatchFoundError,
    ParenthesisMismatchError,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

    from packaging.version import Version

logger = logging.getLogger(__name__)

USER_SHELL_FOLDERS__REG_KEY = R'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders'


def get_repo_root_from_package_path() -> Path:
    """Return the repository root (parent of the src/ directory)."""
    return Path(__file__).resolve().parent.parent.parent


def is_pyinstaller_compiled() -> bool:
    """Check if the script is running as a PyInstaller compiled executable."""
    return bool(getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'))  # https://pyinstaller.org/en/stable/runtime-information.html


def get_working_directory_to_script_location() -> Path:
    """Get the working directory to the script or executable location."""
    if is_pyinstaller_compiled():
        return Path(sys.executable).parent
    return get_repo_root_from_package_path()


def resource_path(relative_path: Path) -> Path:
    """Get absolute path to resource, works for dev and for PyInstaller."""
    base_path = getattr(sys, '_MEIPASS', get_repo_root_from_package_path())
    return Path(base_path) / relative_path


def get_documents_dir() -> Path:
    """Retrieve the Path object to the current user's "Documents" directory.

    On Windows, this queries the Windows registry shell folders key.
    On non-Windows platforms, this defaults to `Path.home() / 'Documents'`.

    Returns:
        A `Path` object pointing to the user's "Documents" folder.

    Raises:
        TypeError: If the retrieved path is not a string.
    """
    if sys.platform == 'win32':
        import winreg  # noqa: PLC0415  # pylint: disable=import-outside-toplevel
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, USER_SHELL_FOLDERS__REG_KEY) as key:
            documents_path, _ = winreg.QueryValueEx(key, 'Personal')
            if not isinstance(documents_path, str):
                raise TypeError(format_type_error(documents_path, str))
        return Path(documents_path)

    return Path.home() / 'Documents'


def get_app_dir(*, scope: Literal['roaming', 'local']) -> Path:
    """Return the per-user application data directory.

    Use `scope='roaming'` for user-owned, syncable data that should follow the user profile
    between machines (when applicable), such as:
    - Configuration (e.g., `Settings.ini`)
    - User-managed databases/tags (e.g., UserIP databases)
    - User scripts

    Use `scope='local'` for machine-specific and/or potentially large, non-syncable data,
    such as:
    - Logs (e.g., `warnings.log`, `errors.log`, session logs)
    - Large databases/caches (e.g., GeoLite2 databases)

    On Windows, this uses `APPDATA` and `LOCALAPPDATA`.
    On Linux, this adheres to the XDG Base Directory Specification:
    `XDG_CONFIG_HOME` for roaming (defaults to `~/.config`) and `XDG_DATA_HOME` for local
    (defaults to `~/.local/share`).

    Args:
        scope: Which application directory base to use: `roaming` or `local`.
    """
    if sys.platform == 'win32':
        if scope == 'roaming':
            base = Path(os.getenv('APPDATA', str(Path.home() / 'AppData' / 'Roaming')))
        else:
            base = Path(os.getenv('LOCALAPPDATA', str(Path.home() / 'AppData' / 'Local')))
    elif scope == 'roaming':
        base = Path(os.getenv('XDG_CONFIG_HOME', str(Path.home() / '.config')))
    else:
        base = Path(os.getenv('XDG_DATA_HOME', str(Path.home() / '.local' / 'share')))

    app_dir = base / TITLE
    app_dir.mkdir(parents=True, exist_ok=True)
    return app_dir


def get_session_log_path(base_dir: Path, tz: tzinfo) -> Path:
    """Generate a timestamped session log path in a year/month/day folder structure.

    Args:
        base_dir: Root directory for session logs.
        tz: Timezone to use for timestamps.

    Returns:
        Full path to the timestamped log file.
    """
    now = datetime.now(tz=tz)
    date_dir = base_dir / now.strftime('%Y') / now.strftime('%m') / now.strftime('%d')
    date_dir.mkdir(parents=True, exist_ok=True)
    return date_dir / f'{now.strftime("%Y-%m-%d_%H-%M-%S")}.log'


def validate_file(file_path: Path) -> Path:
    """Validate if the given file path exists and is a file.

    Raises:
        FileNotFoundError: If the file does not exist.
        InvalidFileError: If the path is not a file.

    Returns:
        The validated file path.
    """
    if not file_path.exists():
        message = f'File not found: {file_path.absolute()}'
        raise FileNotFoundError(message)
    if not file_path.is_file():
        raise InvalidFileError(file_path)

    return file_path


def format_project_version(version: Version) -> str:
    """Format the project version for display."""
    if version.local:
        date_time = datetime.strptime(version.local, '%Y%m%d.%H%M').replace(tzinfo=UTC).strftime('%Y/%m/%d (%H:%M)')
        return f'v{version.public} - {date_time}'

    return f'v{version.public}'


def dedup_preserve_order[T](*iterables: Iterable[T]) -> list[T]:
    """Concatenate one or more iterables while removing duplicates and preserving order."""
    seen: set[T] = set()
    unique: list[T] = []

    for iterable in iterables:
        for item in iterable:
            if item not in seen:
                seen.add(item)
                unique.append(item)

    return unique


def is_file_need_newline_ending(file: Path) -> bool:
    """Return whether the file exists and is missing a trailing newline."""
    if not file.exists() or not file.stat().st_size:
        return False

    with file.open('rb') as opened_file:
        opened_file.seek(-1, os.SEEK_END)
        return opened_file.read(1) != b'\n'


def write_lines_to_file(file: Path, mode: Literal['w', 'x', 'a'], lines: list[str]) -> None:
    """Writes or appends a list of lines to a file, ensuring proper newline handling.

    Args:
        file: The path to the file.
        mode: The file mode ('w', 'x' or 'a').
        lines: A list of lines to write to the file.
    """
    # If the content list is empty, exit early without writing to the file
    if not lines:
        return

    # Copy the input lines to avoid modifying the original list only when mutation is needed
    need_leading_newline = mode == 'a' and is_file_need_newline_ending(file)
    need_trailing_newline = not lines[-1].endswith('\n')

    if need_leading_newline or need_trailing_newline:
        content = lines[:]
        if need_leading_newline:
            content.insert(0, '')
        if need_trailing_newline:
            content[-1] += '\n'
    else:
        content = lines

    # Write content to the file
    with file.open(mode, encoding='utf-8') as opened_file:
        opened_file.writelines(content)


class ProcessEntry32W(ctypes.Structure):
    """ctypes definition for PROCESSENTRY32W structure."""

    _fields_ = [
        ('dwSize', wintypes.DWORD),
        ('cntUsage', wintypes.DWORD),
        ('th32ProcessID', wintypes.DWORD),
        ('th32DefaultHeapID', ctypes.c_size_t),
        ('th32ModuleID', wintypes.DWORD),
        ('cntThreads', wintypes.DWORD),
        ('th32ParentProcessID', wintypes.DWORD),
        ('pcPriClassBase', wintypes.LONG),
        ('dwFlags', wintypes.DWORD),
        ('szExeFile', wintypes.WCHAR * 260),
    ]

    def __init__(self, *args: object, **kwargs: object) -> None:
        """Initialize the PROCESSENTRY32W structure with its byte size."""
        super().__init__(*args, **kwargs)
        self.dwSize = ctypes.sizeof(self)


def terminate_process_tree(pid: int | None = None) -> None:
    """Terminates the process with the given PID and all its child processes.

    Defaults to the current process if no PID is specified.
    """
    target_pid = pid if pid is not None else os.getpid()
    if target_pid <= 0:
        return

    if sys.platform != 'win32':
        children_by_parent: dict[int, list[int]] = {}
        proc_path = Path('/proc')
        if proc_path.is_dir():
            for proc_entry in proc_path.iterdir():
                if proc_entry.name.isdigit():
                    try:
                        stat_content = (proc_entry / 'stat').read_text().split()
                        parent_process_id = int(stat_content[3])
                        child_pid = int(proc_entry.name)
                        children_by_parent.setdefault(parent_process_id, []).append(child_pid)
                    except (OSError, ValueError, IndexError):
                        continue

        descendant_pids: list[int] = []
        queue: list[int] = [target_pid]
        while queue:
            parent_pid = queue.pop(0)
            for child_pid in children_by_parent.get(parent_pid, []):
                descendant_pids.append(child_pid)
                queue.append(child_pid)

        for child_pid in reversed(descendant_pids):
            try:
                os.kill(child_pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError) as e:
                logger.debug('Failed to kill child PID %d: %s', child_pid, e)

        try:
            os.kill(target_pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError) as e:
            logger.debug('Failed to kill process %d: %s', target_pid, e)
        return

    kernel32 = ctypes.windll.kernel32
    snapshot_handle = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
    if snapshot_handle and snapshot_handle != wintypes.HANDLE(-1).value:
        try:
            entry = ProcessEntry32W()
            if kernel32.Process32FirstW(snapshot_handle, ctypes.byref(entry)):
                children_by_parent: dict[int, list[int]] = {}
                while True:
                    children_by_parent.setdefault(entry.th32ParentProcessID, []).append(entry.th32ProcessID)
                    if not kernel32.Process32NextW(snapshot_handle, ctypes.byref(entry)):
                        break

                descendant_pids: list[int] = []
                queue: list[int] = [target_pid]
                while queue:
                    parent_pid = queue.pop(0)
                    for child_pid in children_by_parent.get(parent_pid, []):
                        descendant_pids.append(child_pid)
                        queue.append(child_pid)

                for child_pid in reversed(descendant_pids):
                    child_handle = kernel32.OpenProcess(0x0001, False, child_pid)  # noqa: FBT003
                    if child_handle:
                        kernel32.TerminateProcess(child_handle, 1)
                        kernel32.CloseHandle(child_handle)
        finally:
            kernel32.CloseHandle(snapshot_handle)

    target_handle = kernel32.OpenProcess(0x0001, False, target_pid)  # noqa: FBT003
    if target_handle:
        kernel32.TerminateProcess(target_handle, 1)
        kernel32.CloseHandle(target_handle)


def check_case_insensitive_and_exact_match(input_value: str, custom_values_tuple: tuple[str, ...]) -> tuple[bool, str]:
    """Check if the input value matches any string in the tuple case-insensitively, and whether it also matches exactly (case-sensitive).

    It also returns the correctly capitalized version of the matched value from the tuple if a case-insensitive match is found.
    If no match is found, raises a NoMatchFoundError.

    Returns a tuple of two values:
    - The first boolean is True if the exact case-sensitive match is found.
    - The second value is the correctly capitalized version of the matched string, never None.
    """
    case_sensitive_match = False
    normalized_match = None

    lowered_input_value = input_value.lower()
    for value in custom_values_tuple:
        if value.lower() == lowered_input_value:
            normalized_match = value
            if normalized_match == input_value:
                case_sensitive_match = True

            return case_sensitive_match, normalized_match

    raise NoMatchFoundError(input_value)


def custom_str_to_bool(string: str, *, only_match_against: bool | None = None) -> tuple[bool, bool]:
    """Return the boolean value represented by the string, regardless of case.

    Raise:
        InvalidBooleanValueError: if the string does not match a boolean value.
        MismatchedBooleanValueError: If the resolved value does not match the expected boolean value.

    Args:
        string: The boolean string to be checked.
        only_match_against: If provided, the only boolean value to match against.
    """
    need_rewrite_current_setting = False
    resolved_value = None

    string_lower = string.lower()

    if string_lower == 'true':
        resolved_value = True
    elif string_lower == 'false':
        resolved_value = False

    if resolved_value is None:
        raise InvalidBooleanValueError

    if only_match_against is not None and only_match_against is not resolved_value:
        raise MismatchedBooleanValueError

    if string != str(resolved_value):
        need_rewrite_current_setting = True

    return resolved_value, need_rewrite_current_setting


def custom_str_to_nonetype(string: str) -> tuple[None, bool]:
    """Return the NoneType value represented by the string for lowercase or any case variation.

    Raise:
        InvalidNoneTypeValueError: If the string is not a valid NoneType value.

    Args:
        string: The NoneType string to be checked.

    Returns:
        A tuple containing the resolved NoneType value and a boolean indicating if the string was exactly matching "None".
    """
    if not string.lower() == 'none':
        raise InvalidNoneTypeValueError

    need_rewrite_current_setting = string != 'None'
    return None, need_rewrite_current_setting


def validate_and_strip_balanced_outer_parens(expr: str) -> str:
    """Validate and strip balanced outer parentheses from a string.

    This function checks for balanced parentheses in the input string and removes
    the outermost parentheses if they are balanced.<br>
    If the parentheses are not  balanced, it raises a `ParenthesisMismatchError`
    with the positions of the unmatched parentheses.
    """

    def strip_n_times(string: str, *, times: int) -> str:
        """Strip outer parentheses from a string n times."""
        for _ in range(times):
            string = string.removeprefix('(').removesuffix(')')
        return string

    if not (expr := expr.strip()):
        return ''

    unmatched_opening: list[int] = []
    unmatched_closing: list[int] = []
    strip_outer_depth = 0

    for i, char in enumerate(expr):
        if char == '(':
            unmatched_opening.append(i)
        elif char == ')':
            if unmatched_opening:
                opening_index = unmatched_opening.pop()

                before_opening = expr[:opening_index]
                remaining_expr = expr[i + 1 :]

                if all(char == '(' for char in before_opening) and all(char == ')' for char in remaining_expr):
                    strip_outer_depth += 1

            else:
                unmatched_closing.append(i)

    if unmatched_opening or unmatched_closing:
        raise ParenthesisMismatchError(expr, unmatched_opening, unmatched_closing)

    if strip_outer_depth:
        expr = strip_n_times(expr, times=strip_outer_depth)

    return expr


# pylint: disable=duplicate-code
class _Guid(ctypes.Structure):
    """ctypes definition for GUID structure."""

    _fields_ = [
        ('Data1', wintypes.DWORD),
        ('Data2', wintypes.WORD),
        ('Data3', wintypes.WORD),
        ('Data4', ctypes.c_ubyte * 8),
    ]
# pylint: enable=duplicate-code


_CLSID_SHELL_LINK = _Guid(0x00021401, 0x0000, 0x0000, (ctypes.c_ubyte * 8)(0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46))
_IID_ISHELL_LINK_W = _Guid(0x000214F9, 0x0000, 0x0000, (ctypes.c_ubyte * 8)(0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46))
_IID_IPERSIST_FILE = _Guid(0x0000010B, 0x0000, 0x0000, (ctypes.c_ubyte * 8)(0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46))


def _release_com_interface(pointer: wintypes.LPVOID) -> None:
    """Releases a COM interface pointer via its IUnknown vtable."""
    if pointer:
        vtable = ctypes.cast(pointer, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
        release_function = ctypes.WINFUNCTYPE(wintypes.ULONG, wintypes.LPVOID)(vtable[2])
        release_function(pointer)


def resolve_lnk(shortcut_path: Path) -> Path:
    """Resolves a Windows shortcut (.lnk) to its target path."""
    if sys.platform != 'win32':
        return shortcut_path

    ole32 = ctypes.windll.ole32
    hr_init = ole32.CoInitializeEx(None, 2)
    need_uninit = hr_init in (0, 1)

    shell_link_ptr = wintypes.LPVOID()
    hr_create = ole32.CoCreateInstance(
        ctypes.byref(_CLSID_SHELL_LINK),
        None,
        1,
        ctypes.byref(_IID_ISHELL_LINK_W),
        ctypes.byref(shell_link_ptr),
    )
    if hr_create or not shell_link_ptr:
        if need_uninit:
            ole32.CoUninitialize()
        return shortcut_path

    try:
        link_vtable = ctypes.cast(shell_link_ptr, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
        query_interface = ctypes.WINFUNCTYPE(wintypes.HRESULT, wintypes.LPVOID, ctypes.POINTER(_Guid), ctypes.POINTER(wintypes.LPVOID))(link_vtable[0])
        get_path = ctypes.WINFUNCTYPE(wintypes.HRESULT, wintypes.LPVOID, wintypes.LPWSTR, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD)(link_vtable[3])

        persist_file_ptr = wintypes.LPVOID()
        if not query_interface(shell_link_ptr, ctypes.byref(_IID_IPERSIST_FILE), ctypes.byref(persist_file_ptr)) and persist_file_ptr:
            try:
                persist_vtable = ctypes.cast(persist_file_ptr, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
                load = ctypes.WINFUNCTYPE(wintypes.HRESULT, wintypes.LPVOID, wintypes.LPCWSTR, wintypes.DWORD)(persist_vtable[5])

                if not load(persist_file_ptr, str(shortcut_path), 0):
                    path_buffer = ctypes.create_unicode_buffer(1024)
                    if not get_path(shell_link_ptr, path_buffer, 1024, None, 0) and path_buffer.value:
                        return Path(path_buffer.value)
            finally:
                _release_com_interface(persist_file_ptr)
    finally:
        _release_com_interface(shell_link_ptr)
        if need_uninit:
            ole32.CoUninitialize()

    return shortcut_path


def run_cmd_script(script: Path, args: list[str] | None = None) -> None:
    """Executes a script with the given arguments in a new terminal window."""
    if script.suffix.casefold() == '.lnk':
        script = resolve_lnk(script)

    if sys.platform != 'win32':
        command = [sys.executable, str(script)] if script.suffix.casefold() == '.py' else [str(script)]
        if args is not None:
            command.extend(args)
        terminal_emulator = shutil.which('x-terminal-emulator') or shutil.which('gnome-terminal') or shutil.which('xterm')
        if terminal_emulator:
            subprocess.run([terminal_emulator, '-e', *command], check=False)
        else:
            subprocess.Popen(command)
        return

    full_command = [str(CMD_EXE), '/K']

    if script.suffix.casefold() == '.py':
        full_command.append('py')
    full_command.append(str(script))

    if args is not None:
        full_command.extend(args)

    subprocess.run([str(CMD_EXE), '/c', 'start', '', *full_command], check=False)


def is_session_file_empty(file_path: Path) -> bool:
    """Check if the given session log file has no players found or is invalid.

    Args:
        file_path: Absolute path to the session JSON file.

    Returns:
        True if the file has no players (empty 'connected' and 'disconnected' sections) or is unreadable.
    """
    try:
        session_log = SessionLogFile.model_validate_json(file_path.read_text(encoding='utf-8', errors='replace'))
    except (OSError, ValidationError) as e:
        logger.warning('Failed to read or parse session log file %s: %s', file_path, e)
        return True

    return not (session_log.connected or session_log.disconnected)


def cleanup_session_logs(
    sessions_dir: Path,
    *,
    delete_empty_files: bool,
    delete_empty_folders: bool,
    gui_sessions_logging: bool,
    active_session_path: Path | None = None,
) -> tuple[int, int]:
    """Automatically clean up empty session log files and empty directories in the sessions directory.

    Args:
        sessions_dir: Root directory for session log files.
        delete_empty_files: If True, delete session files that have no players found.
        delete_empty_folders: If True, delete empty year, month, or day folders.
        gui_sessions_logging: If True, prevent scanning the currently running session file.
        active_session_path: Path to the active session file.

    Returns:
        A tuple of (files_deleted_count, folders_deleted_count).
    """
    files_deleted_count = 0
    deleted_folders_set: set[Path] = set()

    if not delete_empty_files and not delete_empty_folders:
        return files_deleted_count, len(deleted_folders_set)

    if not sessions_dir.exists():
        return files_deleted_count, len(deleted_folders_set)

    json_files = sorted(sessions_dir.rglob('*.json'))
    if not json_files:
        if delete_empty_folders:
            _delete_all_empty_folders(sessions_dir, deleted_folders_set)
        return files_deleted_count, len(deleted_folders_set)

    files_to_scan = json_files
    if gui_sessions_logging:
        if files_to_scan:
            files_to_scan = files_to_scan[:-1]
        if active_session_path:
            try:
                active_session_path_resolved = active_session_path.resolve()
                files_to_scan = [file_path for file_path in files_to_scan if file_path.resolve() != active_session_path_resolved]
            except OSError as e:
                logger.debug('Failed to resolve active session path %s: %s', active_session_path, e)
                files_to_scan = [file_path for file_path in files_to_scan if file_path != active_session_path]

    deleted_parents: set[Path] = set()

    if delete_empty_files:
        for file_path in files_to_scan:
            if is_session_file_empty(file_path):
                try:
                    file_path.unlink()
                    files_deleted_count += 1
                    deleted_parents.add(file_path.parent)
                except OSError as e:
                    logger.warning('Failed to delete empty session file %s: %s', file_path, e)

        for folder in deleted_parents:
            _clean_upwards_if_empty(folder, sessions_dir, deleted_folders_set)

    if delete_empty_folders:
        _delete_all_empty_folders(sessions_dir, deleted_folders_set)

    return files_deleted_count, len(deleted_folders_set)


def _clean_upwards_if_empty(folder: Path, base_dir: Path, deleted_folders: set[Path]) -> None:
    """Clean empty directories bottom-up from folder to base_dir, not deleting base_dir itself.

    Args:
        folder: Subdirectory to start cleaning from.
        base_dir: Root directory to stop at.
        deleted_folders: Set to collect deleted folder paths.
    """
    current = folder
    try:
        base_dir_resolved = base_dir.resolve()
    except OSError as e:
        logger.debug('Failed to resolve base directory %s: %s', base_dir, e)
        base_dir_resolved = base_dir

    while True:
        try:
            current_resolved = current.resolve()
        except OSError as e:
            logger.debug('Failed to resolve directory %s: %s', current, e)
            current_resolved = current

        if current_resolved == base_dir_resolved or not current.is_relative_to(base_dir):
            break

        if not current.exists():
            current = current.parent
            continue

        try:
            if not any(current.iterdir()):
                current.rmdir()
                deleted_folders.add(current)
            else:
                break
        except OSError as e:
            logger.warning('Failed to remove empty folder %s: %s', current, e)
            break
        current = current.parent


def _delete_all_empty_folders(base_dir: Path, deleted_folders: set[Path]) -> None:
    """Recursively delete all empty folders under base_dir bottom-up.

    Args:
        base_dir: Root directory.
        deleted_folders: Set to collect deleted folder paths.
    """
    for root, dirs, _ in os.walk(base_dir, topdown=False):
        for dir_name in dirs:
            dir_path = Path(root) / dir_name
            try:
                dir_path_resolved = dir_path.resolve()
                base_dir_resolved = base_dir.resolve()
                if dir_path_resolved == base_dir_resolved:
                    continue
            except OSError as e:
                logger.warning('Failed to resolve directory path %s: %s', dir_path, e)
            try:
                if not any(dir_path.iterdir()):
                    dir_path.rmdir()
                    deleted_folders.add(dir_path)
            except OSError as e:
                logger.warning('Failed to remove empty folder %s: %s', dir_path, e)
