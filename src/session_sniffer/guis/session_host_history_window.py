"""Session Host History submenu population for the Session Host menu."""

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

from PySide6.QtGui import QAction, QIcon

from session_sniffer.constants.local import RESOURCES_DIR_PATH
from session_sniffer.constants.standard import LOCAL_TZ
from session_sniffer.guis.utils import load_country_flag_icon
from session_sniffer.player.registry import HostHistoryEntry, PlayersRegistry, SessionHost
from session_sniffer.text_utils import format_elapsed_time

if TYPE_CHECKING:
    from collections.abc import Callable

    from PySide6.QtWidgets import QMenu


@dataclass(slots=True)
class SessionHostActionCallbacks:
    """Callback bundle for configuring session host actions and history."""

    clear_host: Callable[[], None]
    redetect_host: Callable[[], None]
    show_diagnostics: Callable[[], None]
    select_ips: Callable[[list[str]], None]
    open_history_diagnostics: Callable[[HostHistoryEntry], None]


def populate_host_history_submenu(
    menu: QMenu,
    select_ips_callback: Callable[[list[str]], None],
    open_history_diagnostics_callback: Callable[[HostHistoryEntry], None],
) -> None:
    """Clear and rebuild `menu` with the current session host detection history."""
    menu.clear()
    history = SessionHost.get_history()
    if not history:
        empty_action = QAction('(no hosts recorded yet)', menu)
        empty_action.setEnabled(False)
        menu.addAction(empty_action)
        return

    def _create_entry_triggered_handler(target_entry: HostHistoryEntry) -> Callable[[], None]:
        def _handler() -> None:
            select_ips_callback([target_entry.ip])
            open_history_diagnostics_callback(target_entry)

        return _handler

    now = datetime.now(tz=LOCAL_TZ)
    for entry in reversed(history):
        matched_player = PlayersRegistry.get_player_by_ip(entry.ip)
        usernames = ', '.join(matched_player.usernames) if matched_player is not None and matched_player.usernames else '—'
        elapsed_time_string = format_elapsed_time(now - entry.detected_at)
        action_label = f'{entry.ip}  |  {usernames}  |  {entry.detected_at.strftime("%H:%M:%S")} ({elapsed_time_string} ago)'
        action = QAction(action_label, menu)
        action.setToolTip('Select this player in the table and open their host detection diagnostics.')
        action.triggered.connect(_create_entry_triggered_handler(entry))
        flag_icon = load_country_flag_icon(entry.country_code)
        if flag_icon is not None:
            action.setIcon(flag_icon)
        menu.addAction(action)


def setup_session_host_actions(
    session_host_submenu: QMenu,
    callbacks: SessionHostActionCallbacks,
) -> None:
    """Populate common session host control actions and the Host History submenu."""
    session_host_submenu.addSeparator()

    clear_host_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'close.svg')), 'Clear Session Host', session_host_submenu)
    clear_host_action.setToolTip('Manually clear the currently detected session host')
    clear_host_action.triggered.connect(callbacks.clear_host)
    session_host_submenu.addAction(clear_host_action)

    redetect_host_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'refresh.svg')), 'Re-detect Host', session_host_submenu)
    redetect_host_action.setToolTip('Clear the current host and immediately re-trigger host detection')
    redetect_host_action.triggered.connect(callbacks.redetect_host)
    session_host_submenu.addAction(redetect_host_action)

    diagnostics_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'bug.svg')), 'Host Diagnostics…', session_host_submenu)
    diagnostics_action.setToolTip('Show detailed diagnostics and debug information from the last session host detection')
    diagnostics_action.triggered.connect(callbacks.show_diagnostics)
    session_host_submenu.addAction(diagnostics_action)

    session_host_submenu.addSeparator()
    host_history_submenu = session_host_submenu.addMenu(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'history.svg')), 'Host History')
    if not host_history_submenu:
        message = 'Failed to create Host History submenu'
        raise RuntimeError(message)
    host_history_submenu.setToolTipsVisible(True)
    host_history_submenu.aboutToShow.connect(
        lambda: populate_host_history_submenu(
            host_history_submenu,
            callbacks.select_ips,
            callbacks.open_history_diagnostics,
        ),
    )
