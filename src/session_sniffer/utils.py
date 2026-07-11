"""Utility Module.

This module contains a variety of helper functions and custom exceptions used across the project.
"""

import json
import os
import subprocess
import sys
import winreg
from contextlib import suppress
from datetime import UTC, datetime, tzinfo
from pathlib import Path
from typing import TYPE_CHECKING, Literal, cast

import psutil
from win32com.client import Dispatch

from session_sniffer.constants.standalone import TITLE
from session_sniffer.constants.standard import CMD_EXE
from session_sniffer.error_messages import format_type_error
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
    from typing import Any

    from packaging.version import Version

USER_SHELL_FOLDERS__REG_KEY = R'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders'


def get_repo_root_from_package_path() -> Path:
    """Return the repository root (parent of the src/ directory)."""
    return Path(__file__).resolve().parent.parent.parent


def is_pyinstaller_compiled() -> bool:
    """Check if the script is running as a PyInstaller compiled executable."""
    return getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS')  # https://pyinstaller.org/en/stable/runtime-information.html


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
    """Retrieve the Path object to the current user's "Documents" directory by querying the Windows registry.

    Returns:
        A `Path` object pointing to the user's "Documents" folder.

    Raises:
        TypeError: If the retrieved path is not a string.
    """
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, USER_SHELL_FOLDERS__REG_KEY) as key:
        documents_path, _ = winreg.QueryValueEx(key, 'Personal')
        if not isinstance(documents_path, str):
            raise TypeError(format_type_error(documents_path, str))

    return Path(documents_path)


def get_app_dir(*, scope: Literal['roaming', 'local']) -> Path:
    """Return the per-user application data directory.

    Session Sniffer is Windows-only.

    Use `scope='roaming'` for user-owned, syncable data that should follow the user profile
    between machines (when applicable), such as:
    - Configuration (e.g., `Settings.ini`)
    - User-managed databases/tags (e.g., UserIP databases)
    - User scripts

    Use `scope='local'` for machine-specific and/or potentially large, non-syncable data,
    such as:
    - Logs (e.g., `warnings.log`, `errors.log`, session logs)
    - Large databases/caches (e.g., GeoLite2 databases)

    This function prefers the Windows environment variables (`APPDATA` and `LOCALAPPDATA`)
    to support redirected profiles (common in corporate environments). If the variables are
    missing, it falls back to the default `Path.home() / 'AppData' / ...` layout.

    Args:
        scope: Which AppData base to use: `roaming` or `local`.
    """
    if scope == 'roaming':
        base = Path(os.getenv('APPDATA', str(Path.home() / 'AppData' / 'Roaming')))
    else:
        base = Path(os.getenv('LOCALAPPDATA', str(Path.home() / 'AppData' / 'Local')))

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

    with file.open('rb') as f:
        f.seek(-1, os.SEEK_END)
        return f.read(1) != b'\n'


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
    with file.open(mode, encoding='utf-8') as f:
        f.writelines(content)


def terminate_process_tree(pid: int | None = None) -> None:
    """Terminates the process with the given PID and all its child processes.

    Defaults to the current process if no PID is specified.
    """
    try:
        parent = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return  # Process already terminated

    try:
        children = parent.children(recursive=True)
    except psutil.NoSuchProcess:
        return

    for child in children:
        with suppress(psutil.NoSuchProcess, psutil.AccessDenied):
            child.terminate()

    with suppress(psutil.NoSuchProcess, psutil.AccessDenied):
        psutil.wait_procs(children, timeout=3)

    with suppress(psutil.NoSuchProcess, psutil.AccessDenied):
        parent.terminate()

    with suppress(psutil.NoSuchProcess, psutil.AccessDenied):
        parent.wait(3)


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


def resolve_lnk(shortcut_path: Path) -> Path:
    """Resolves a Windows shortcut (.lnk) to its target path."""
    winshell = Dispatch('WScript.Shell')
    shortcut = winshell.CreateShortcut(str(shortcut_path))
    return Path(shortcut.Targetpath)


def run_cmd_script(script: Path, args: list[str] | None = None) -> None:
    """Executes a script with the given arguments in a new CMD terminal window."""
    full_command = [str(CMD_EXE), '/K']

    if script.suffix.casefold() == '.lnk':
        script = resolve_lnk(script)

    if script.suffix.casefold() == '.py':
        full_command.append('py')
    full_command.append(str(script))

    if args is not None:
        full_command.extend(args)

    subprocess.run([str(CMD_EXE), '/c', 'start', '', *full_command], check=False)


def run_cmd_command(command: str, args: list[str] | None = None) -> None:
    """Executes a command with the given arguments in a new CMD terminal window."""
    full_command = [str(CMD_EXE), '/K', command]

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
        content = file_path.read_text(encoding='utf-8')
        if not content.strip():
            return True
        parsed_data = json.loads(content)
    except OSError, json.JSONDecodeError:
        return True

    if not isinstance(parsed_data, dict):
        return True

    data = cast('Any', parsed_data)
    connected = data.get('connected')
    disconnected = data.get('disconnected')

    has_connected = isinstance(connected, dict) and len(cast('Any', connected)) > 0
    has_disconnected = isinstance(disconnected, dict) and len(cast('Any', disconnected)) > 0

    return not (has_connected or has_disconnected)


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
            except OSError:
                files_to_scan = [file_path for file_path in files_to_scan if file_path != active_session_path]

    deleted_parents: set[Path] = set()

    if delete_empty_files:
        for file_path in files_to_scan:
            if is_session_file_empty(file_path):
                parent_dir = file_path.parent
                try:
                    file_path.unlink()
                    files_deleted_count += 1
                    deleted_parents.add(parent_dir)
                except OSError:
                    pass

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
    except OSError:
        base_dir_resolved = base_dir

    while True:
        try:
            current_resolved = current.resolve()
        except OSError:
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
        except OSError:
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
            except OSError:
                pass
            try:
                if not any(dir_path.iterdir()):
                    dir_path.rmdir()
                    deleted_folders.add(dir_path)
            except OSError:
                pass
