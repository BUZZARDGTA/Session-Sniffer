"""Logging setup using Rich with console + file handlers.

Console shows all messages with source file information.
File logs only WARNING and ERROR messages with full context.
Supports rotating log files, Rich formatting, and safe flushing.
"""
import atexit
import logging
from logging.handlers import RotatingFileHandler
from typing import TYPE_CHECKING

from rich.console import Console
from rich.logging import RichHandler

from modules.constants.local import ERROR_LOG_PATH

if TYPE_CHECKING:
    from pathlib import Path

__all__ = ['console', 'get_logger', 'setup_logging']

# --- Shared Rich console instance ---
console: Console = Console()

# --- Handler names for idempotency ---
_CONSOLE_HANDLER = 'rich_console_handler'
_FILE_HANDLER = 'file_handler'


# --- Default levels ---
DEFAULT_CONSOLE_LEVEL = logging.INFO
DEFAULT_FILE_LEVEL = logging.WARNING

# --- Module-level flag to register atexit only once ---
_atexit_registered = False  # pylint: disable=invalid-name


def setup_logging(  # pylint: disable=too-many-arguments  # noqa: PLR0913
    console_level: int = DEFAULT_CONSOLE_LEVEL,
    file_level: int = DEFAULT_FILE_LEVEL,
    log_file: Path | str = ERROR_LOG_PATH,
    max_bytes: int = 10_000_000,  # 10 MB
    backup_count: int = 5,
    *,
    rich_tracebacks: bool = True,
    show_path: bool = True,
    show_time: bool = True,
) -> None:
    """Configure root logging with Rich console + rotating file handler (idempotent).

    Parameters:
        console_level (int): log level for console (DEBUG+ recommended)
        file_level (int): log level for file (WARNING+ recommended)
        log_file (Path | str): path to log file
        max_bytes (int): max file size before rotation
        backup_count (int): number of rotated files to keep
        rich_tracebacks (bool): enable/disable rich tracebacks on console
        show_path (bool): show file path in `RichHandler` output
        show_time (bool): show timestamps in `RichHandler output
    """
    global _atexit_registered  # pylint: disable=global-statement  # noqa: PLW0603

    root = logging.getLogger()

    # --- Console handler (Rich) ---
    if not any(h.name == _CONSOLE_HANDLER for h in root.handlers):
        console_handler = RichHandler(
            console=console,
            show_time=show_time,
            show_path=show_path,
            markup=False,
            rich_tracebacks=rich_tracebacks,
        )
        console_handler.name = _CONSOLE_HANDLER
        console_handler.setLevel(console_level)
        root.addHandler(console_handler)

    # --- Rotating file handler (WARNING+) ---
    if not any(h.name == _FILE_HANDLER for h in root.handlers):
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding='utf-8',
        )
        file_handler.name = _FILE_HANDLER
        file_handler.setLevel(file_level)

        file_handler.setFormatter(
            logging.Formatter(
                '%(asctime)s - %(levelname)s - %(pathname)s:%(lineno)d - %(name)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M',
            ),
        )
        root.addHandler(file_handler)

    # --- Root logger must be permissive ---
    root.setLevel(min(console_level, file_level, logging.DEBUG))

    # --- Redirect Python warnings to logging ---
    logging.captureWarnings(capture=True)

    # --- Ensure logs flush on exit ---
    if not _atexit_registered:
        atexit.register(logging.shutdown)
        _atexit_registered = True


def get_logger(name: str | None = None) -> logging.Logger:
    """Return a logger, ensuring logging is configured (idempotent).

    Parameters:
        name (str | None): the logger name (default: root logger)

    Returns:
        logging.Logger: the configured logger
    """
    setup_logging()
    return logging.getLogger(name)
