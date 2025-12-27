"""Utility Module.

This module contains a variety of helper functions and custom exceptions used across the project.
"""
import os
import subprocess
import sys
import winreg
from contextlib import suppress
from datetime import UTC, datetime, tzinfo
from pathlib import Path
from typing import TYPE_CHECKING, Literal

import psutil
from win32com.client import Dispatch

from modules.constants.standalone import TITLE
from modules.constants.standard import CMD_EXE
from modules.error_messages import format_type_error
from modules.utils_exceptions import (
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

USER_SHELL_FOLDERS__REG_KEY = R'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders'


def is_pyinstaller_compiled() -> bool:
    """Check if the script is running as a PyInstaller compiled executable."""
    return getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS')  # https://pyinstaller.org/en/stable/runtime-information.html


def get_working_directory_to_script_location() -> Path:
    """Get the working directory to the script or executable location."""
    if is_pyinstaller_compiled():
        return Path(sys.executable).parent
    return Path(__file__).resolve().parents[1]


def set_working_directory_to_script_location() -> None:
    """Set the current working directory to the script or executable location."""
    os.chdir(get_working_directory_to_script_location())


def resource_path(relative_path: Path) -> Path:
    """Get absolute path to resource, works for dev and for PyInstaller."""
    base_path = getattr(sys, '_MEIPASS', Path(__file__).resolve().parents[1])
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
    - Logs (e.g., `error.log`, session logs)
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
    return date_dir / f"{now.strftime('%Y-%m-%d_%H-%M-%S')}.log"


def set_window_title(title: str) -> None:
    """Set the terminal window title (best-effort)."""
    print(f'\033]0;{title}\007', end='')  # noqa: T201


def clear_screen() -> None:
    """Clear the terminal screen (best-effort)."""
    print('\033c', end='')  # noqa: T201


def validate_file(file_path: Path) -> Path:
    """Validate if the given file path exists and is a file.

    Raises:
        FileNotFoundError: If the file does not exist.
        InvalidFileError: If the path is not a file.

    Returns:
        The validated file path.
    """
    if not file_path.exists():
        error_msg = f'File not found: {file_path.absolute()}'
        raise FileNotFoundError(error_msg)
    if not file_path.is_file():
        raise InvalidFileError(file_path)

    return file_path


def format_project_version(version: Version) -> str:
    """Format the project version for display."""
    if version.local:
        date_time = datetime.strptime(version.local, '%Y%m%d.%H%M').replace(tzinfo=UTC).strftime('%Y/%m/%d (%H:%M)')
        return f'v{version.public} - {date_time}'

    return f'v{version.public}'


def take[T](n: int, iterable: Iterable[T]) -> list[T]:
    """Return the first n items from the given iterable."""
    return list(iterable)[:n]


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
    # Copy the input lines to avoid modifying the original list
    content = lines[:]

    # If the content list is empty, exit early without writing to the file
    if not content:
        return

    # If appending to a file, ensure a leading newline is added if the file exists, otherwise creates it.
    if mode == 'a' and is_file_need_newline_ending(file):
        content.insert(0, '')

    # Ensure the last line ends with a newline character
    if not content[-1].endswith('\n'):
        content[-1] += '\n'

    # Write content to the file
    with file.open(mode, encoding='utf-8') as f:
        f.writelines(content)


def get_pid_by_path(filepath: Path, /) -> int | None:
    """Get the process ID (PID) of a running process by its executable path."""
    target_path = filepath.resolve()

    for process in psutil.process_iter(['exe', 'pid']):  # pyright: ignore[reportUnknownMemberType]
        process_exe: str | None = process.info.get('exe')
        if process_exe is None:
            continue

        process_path = Path(process_exe).resolve()

        if str(process_path).lower() != str(target_path).lower():
            continue

        process_pid: int | None = process.info.get('pid')
        if process_pid is None:
            continue

        return process_pid

    return None


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

    with suppress(psutil.NoSuchProcess):
        psutil.wait_procs(children, timeout=3)

    with suppress(psutil.NoSuchProcess, psutil.AccessDenied):
        parent.terminate()

    with suppress(psutil.NoSuchProcess):
        parent.wait(3)


def check_case_insensitive_and_exact_match(input_value: str, custom_values_tuple: tuple[str, ...]) -> tuple[bool, str]:
    """Check if the input value matches any string in the tuple case-insensitively, and whether it also matches exactly (case-sensitive).

    It also returns the correctly capitalized version of the matched value from the tuple if a case-insensitive match is found.
    If no match is found, raises a NoMatchFoundError.

    Returns a tuple of three values:
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

    if (
        only_match_against is not None
        and only_match_against is not resolved_value
    ):
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

    def strip_n_times(s: str, *, times: int) -> str:
        """Strip outer parentheses from a string n times."""
        for _ in range(times):
            s = s.removeprefix('(').removesuffix(')')
        return s

    expr = expr.strip()
    if not expr:
        return ''

    unmatched_opening: list[int] = []
    unmatched_closing: list[int] = []
    strip_outer_depth = 0

    for idx, char in enumerate(expr):
        if char == '(':
            unmatched_opening.append(idx)
        elif char == ')':
            if unmatched_opening:
                opening_index = unmatched_opening.pop()

                before_opening = expr[:opening_index]
                remaining_expr = expr[idx + 1:]

                if (
                    all(c == '(' for c in before_opening)
                    and all(c == ')' for c in remaining_expr)
                ):
                    strip_outer_depth += 1

            else:
                unmatched_closing.append(idx)

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
    # Build the base command
    full_command = [str(CMD_EXE), '/K']

    # Check if the script is a Windows shortcut
    if script.suffix.casefold() == '.lnk':
        script = resolve_lnk(script)

    # Add the script to the command
    if script.suffix.casefold() == '.py':
        full_command.append('py')
    full_command.append(str(script))

    # Add the rest of the arguments
    if args is not None:
        full_command.extend(args)

    subprocess.Popen(full_command, creationflags=subprocess.CREATE_NEW_CONSOLE)  # pylint: disable=consider-using-with


def run_cmd_command(command: str, args: list[str] | None = None) -> None:
    """Executes a command with the given arguments in a new CMD terminal window."""
    # Build the base command
    full_command = [str(CMD_EXE), '/K', command]

    # Add the rest of the arguments
    if args is not None:
        full_command.extend(args)

    subprocess.Popen(full_command, creationflags=subprocess.CREATE_NEW_CONSOLE)  # pylint: disable=consider-using-with
