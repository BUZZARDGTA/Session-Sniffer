"""UserIP settings, database loading, and IP-to-user resolution."""

from pathlib import Path  # noqa: TC003
from threading import Lock, Thread
from typing import ClassVar, Literal, NamedTuple

from pydantic.dataclasses import dataclass as pydantic_dataclass
from PyQt6.QtGui import QColor  # noqa: TC002

from session_sniffer import msgbox
from session_sniffer.constants.local import USERIP_DATABASES_DIR_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.error_messages import format_userip_ip_conflict_message
from session_sniffer.player.registry import PlayersRegistry
from session_sniffer.text_utils import format_triple_quoted_text


@pydantic_dataclass(frozen=True, config={'arbitrary_types_allowed': True}, slots=True)
class UserIPSettings:
    """Class to represent settings with attributes for each setting key."""
    ENABLED: bool
    COLOR: QColor
    LOG: bool
    NOTIFICATIONS: bool
    VOICE_NOTIFICATIONS: Literal['Male', 'Female', False]
    PROTECTION: Literal['Suspend_Process', 'Exit_Process', 'Restart_Process', 'Shutdown_PC', 'Restart_PC', False]
    PROTECTION_PROCESS_PATH: Path | None
    PROTECTION_RESTART_PROCESS_PATH: Path | None
    PROTECTION_SUSPEND_PROCESS_MODE: int | float | Literal['Auto', 'Manual']


class UserIP(NamedTuple):
    """Class representing information associated with a specific IP, including settings and usernames."""
    ip: str
    database_path: Path
    settings: UserIPSettings
    usernames: list[str]


class UserIPDatabases:
    """Load and cache enabled UserIP databases and resolve IP-to-user mappings."""

    _update_userip_database_lock: ClassVar = Lock()

    userip_databases: ClassVar[list[tuple[Path, UserIPSettings, dict[str, list[str]]]]] = []
    ips_set: ClassVar[set[str]] = set()
    notified_settings_corrupted: ClassVar[set[Path]] = set()
    notified_ip_invalid: ClassVar[set[str]] = set()
    notified_ip_conflicts: ClassVar[set[str]] = set()

    @staticmethod
    def _notify_ip_conflict(
        *,
        existing_userip: UserIP,
        conflicting_database_path: Path,
        conflicting_username: str,
    ) -> None:
        Thread(
            target=msgbox.show,
            name=f'UserIPConflictError-{existing_userip.ip}',
            kwargs={
                'title': TITLE,
                'text': format_triple_quoted_text(format_userip_ip_conflict_message(
                    existing_userip=existing_userip,
                    conflicting_database_path=conflicting_database_path,
                    conflicting_username=conflicting_username,
                    userip_databases_dir=USERIP_DATABASES_DIR_PATH,
                )),
                'style': msgbox.Style.MB_OK | msgbox.Style.MB_ICONEXCLAMATION | msgbox.Style.MB_SYSTEMMODAL,
            },
            daemon=True,
        ).start()

    @classmethod
    def populate(cls, database_entries: list[tuple[Path, UserIPSettings, dict[str, list[str]]]]) -> None:
        """Replace `cls.userip_databases` with a new set of databases.

        Args:
            database_entries: A list of tuples containing database_path, settings, and user_ips.
        """
        with cls._update_userip_database_lock:
            cls.userip_databases = [
                (database_path, settings, user_ips)
                for database_path, settings, user_ips in database_entries
                if settings.ENABLED
            ]

    @classmethod
    def build(cls) -> None:
        """Rebuild the `ips_set` cache dynamically from the current databases.

        This method refreshes the cached data without clearing entire structures and avoids duplicates.
        """
        with cls._update_userip_database_lock:
            ips_set: set[str] = set()
            ip_to_userip: dict[str, UserIP] = {}
            unresolved_conflicts: set[str] = set()

            for database_path, settings, user_ips in cls.userip_databases:
                for username, ips in user_ips.items():
                    for ip in ips:
                        # If the IP is already assigned to a different database, it's a conflict.
                        if ip in ip_to_userip and ip_to_userip[ip].database_path != database_path:
                            if ip not in cls.notified_ip_conflicts:
                                cls._notify_ip_conflict(
                                    existing_userip=ip_to_userip[ip],
                                    conflicting_database_path=database_path,
                                    conflicting_username=username,
                                )
                                cls.notified_ip_conflicts.add(ip)
                            unresolved_conflicts.add(ip)
                            continue

                        ips_set.add(ip)

                        # If it's a new entry, add it
                        if ip not in ip_to_userip:
                            ip_to_userip[ip] = UserIP(
                                ip=ip,
                                database_path=database_path,
                                settings=settings,
                                usernames=[username],
                            )
                        elif username not in ip_to_userip[ip].usernames:  # Append username if it doesn't already exist
                            ip_to_userip[ip].usernames.append(username)

                        # Assign the UserIP object to the PlayerRegistry if applicable
                        if matched_player := PlayersRegistry.get_player_by_ip(ip):
                            matched_player.userip = ip_to_userip[ip]

            # Remove resolved conflicts
            resolved_conflicts = cls.notified_ip_conflicts - unresolved_conflicts
            for resolved_ip in resolved_conflicts:
                cls.notified_ip_conflicts.remove(resolved_ip)

            cls.ips_set = ips_set

    @classmethod
    def get_userip_database_filepaths(cls) -> list[Path]:
        """Return all enabled UserIP database file paths."""
        with cls._update_userip_database_lock:
            return [database_path for database_path, _, _ in cls.userip_databases]
