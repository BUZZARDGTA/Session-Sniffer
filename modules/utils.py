"""Utility Module.

This module contains a variety of helper functions and custom exceptions used across the project.
"""
import os
import subprocess
import sys
import textwrap
import winreg
from collections.abc import Iterable
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import psutil
from packaging.version import Version
from win32com.client import Dispatch

from modules.utils_exceptions import (
    InvalidBooleanValueError,
    InvalidFileError,
    InvalidNoneTypeValueError,
    MismatchedBooleanValueError,
    NoMatchFoundError,
    ParenthesisMismatchError,
)


def format_attribute_error(cls: type, name: str) -> str:
    """Format an attribute error message.

    Args:
        cls (type): The class of the object.
        name (str): The name of the missing attribute.

    Returns:
        str: The formatted error message.
    """
    return f"'{cls.__name__}' object has no attribute '{name}'"


def format_type_error(
    obj: object,
    expected_types: type[Any] | tuple[type[Any], ...],
    suffix: str = '',
) -> str:
    """Generate a formatted error message for a type mismatch.

    Args:
        obj (object): The object whose type is being checked.
        expected_types (type[Any] | tuple[type[Any], ...]): The expected type(s) for the object.
        suffix (str): An optional suffix to append to the error message.

    Returns:
        str: The formatted error message. (e.g., for deeper debugging purposes)
    """
    # Determine the actual type of the object
    actual_type = type(obj).__name__

    # Handle expected types, which could be a single type or a tuple of types
    if isinstance(expected_types, tuple):
        expected_types_names = ' | '.join(t.__name__ for t in expected_types)
        expected_type_count = len(expected_types)
    else:
        expected_types_names = expected_types.__name__
        expected_type_count = 1

    # Format the error message
    return f'Expected type{pluralize(expected_type_count)} {expected_types_names}, got {actual_type} instead.{suffix}'


def format_file_not_found_error(file_path: Path) -> str:
    """Format the file not found error message.

    Args:
        file_path (Path): The path to the file that was not found.
    """
    return f'File not found: {file_path.absolute()}'


def is_pyinstaller_compiled() -> bool:
    """Check if the script is running as a PyInstaller compiled executable."""
    return getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS')  # https://pyinstaller.org/en/stable/runtime-information.html


def get_working_directory_to_script_location() -> Path:
    """Get the working directory to the script or executable location."""
    if is_pyinstaller_compiled():
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent.parent


def set_working_directory_to_script_location() -> None:
    """Set the current working directory to the script or executable location."""
    os.chdir(get_working_directory_to_script_location())


def resource_path(relative_path: Path) -> Path:
    """Get absolute path to resource, works for dev and for PyInstaller."""
    base_path = getattr(sys, '_MEIPASS', Path(__file__).resolve().parent.parent)  # .parent twice because of modularizing bruh
    if isinstance(base_path, str):
        return Path(base_path) / relative_path
    if isinstance(base_path, Path):
        return base_path / relative_path
    raise TypeError(format_type_error(base_path, (str, Path)))


def get_documents_folder() -> Path:
    """Retrieve the Path object to the current user's "Documents" folder by querying the Windows registry.

    Returns:
        Path: A `Path` object pointing to the user's "Documents" folder.

    Raises:
        TypeError: If the retrieved path is not a string.
    """
    from modules.constants.standalone import USER_SHELL_FOLDERS__REG_KEY

    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, USER_SHELL_FOLDERS__REG_KEY) as key:
        documents_path, _ = winreg.QueryValueEx(key, 'Personal')
        if not isinstance(documents_path, str):
            raise TypeError(format_type_error(documents_path, str))

    return Path(documents_path)


def set_window_title(title: str) -> None:
    print(f'\033]0;{title}\007', end='')


def clear_screen() -> None:
    print('\033c', end='')


def pluralize(count: int, singular: str = '', plural: str = 's') -> str:
    return singular if count == 1 else plural


def validate_file(file_path: Path) -> Path:
    """Validate if the given file path exists and is a file.

    Raises:
        FileNotFoundError: If the file does not exist.
        InvalidFileError: If the path is not a file.

    Returns:
        Path: The validated file path.
    """
    if not file_path.exists():
        raise FileNotFoundError(format_file_not_found_error(file_path))
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
    if not file.exists() or not file.stat().st_size:
        return False

    return not file.read_bytes().endswith(b'\n')


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


def format_triple_quoted_text(
    text: str,
    /,
    *,
    add_leading_newline: bool = False,
    add_trailing_newline: bool = False,
):
    """Format a triple-quoted string by removing leading whitespace and optionally adding newlines.

    Args:
        text (str): The text to format.
        add_leading_newline (bool): Whether to add a leading newline. Defaults to False.
        add_trailing_newline (bool): Whether to add a trailing newline. Defaults to False.

    Returns:
        str: The formatted text.
    """
    formatted_text = textwrap.dedent(text).strip()

    if add_leading_newline:
        formatted_text = '\n' + formatted_text
    if add_trailing_newline:
        formatted_text += '\n'

    return formatted_text


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
        only_match_against (optional): If provided, the only boolean value to match against.
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
        tuple: A tuple containing the resolved NoneType value and a boolean indicating if the string was exactly matching "None".
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
    from modules.constants.standard import CMD_EXE

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
    from modules.constants.standard import CMD_EXE

    # Build the base command
    full_command = [str(CMD_EXE), '/K', command]

    # Add the rest of the arguments
    if args is not None:
        full_command.extend(args)

    subprocess.Popen(full_command, creationflags=subprocess.CREATE_NEW_CONSOLE)  # pylint: disable=consider-using-with
