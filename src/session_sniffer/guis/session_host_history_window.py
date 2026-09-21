"""Session Host History submenu population for the Session Host menu."""

from datetime import datetime
from typing import TYPE_CHECKING

from PySide6.QtGui import QAction, QIcon

from session_sniffer.constants.local import RESOURCES_DIR_PATH
from session_sniffer.constants.standard import LOCAL_TZ
from session_sniffer.guis.utils import load_country_flag_icon
from session_sniffer.player.registry import PlayersRegistry, SessionHost
from session_sniffer.text_utils import format_elapsed_time

if TYPE_CHECKING:
    from collections.abc import Callable

    from PySide6.QtWidgets import QMenu


def populate_host_history_submenu(menu: QMenu, select_ip_callback: Callable[[list[str]], None]) -> None:
    """Clear and rebuild `menu` with the current session host detection history."""
    menu.clear()
    history = SessionHost.get_history()
    if not history:
        act = QAction('(no hosts recorded yet)', menu)
        act.setEnabled(False)
        menu.addAction(act)
        return

    now = datetime.now(tz=LOCAL_TZ)
    for entry in reversed(history):
        matched_player = PlayersRegistry.get_player_by_ip(entry.ip)
        usernames = ', '.join(matched_player.usernames) if matched_player is not None and matched_player.usernames else '—'
        elapsed_time_str = format_elapsed_time(now - entry.detected_at)
        act = QAction(f'{entry.ip}  |  {usernames}  |  {entry.detected_at.strftime("%H:%M:%S")} ({elapsed_time_str} ago)', menu)
        target_ip = entry.ip
        act.triggered.connect(lambda _checked=False, ip=target_ip: select_ip_callback([ip]))
        flag_icon = load_country_flag_icon(entry.country_code)
        if flag_icon is not None:
            act.setIcon(flag_icon)
        menu.addAction(act)


def setup_session_host_actions(
    session_host_submenu: QMenu,
    clear_host_callback: Callable[[], None],
    redetect_host_callback: Callable[[], None],
    select_ips_callback: Callable[[list[str]], None],
    *,
    error_label: str = 'Host History',
) -> None:
    """Populate common session host control actions and the Host History submenu."""
    session_host_submenu.addSeparator()

    clear_host_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'close.svg')), 'Clear Session Host', session_host_submenu)
    clear_host_action.setToolTip('Manually clear the currently detected session host')
    clear_host_action.triggered.connect(clear_host_callback)
    session_host_submenu.addAction(clear_host_action)

    redetect_host_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'refresh.svg')), 'Re-detect Host', session_host_submenu)
    redetect_host_action.setToolTip('Clear the current host and immediately re-trigger host detection')
    redetect_host_action.triggered.connect(redetect_host_callback)
    session_host_submenu.addAction(redetect_host_action)

    session_host_submenu.addSeparator()
    host_history_submenu = session_host_submenu.addMenu(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'history.svg')), 'Host History')
    if not host_history_submenu:
        message = f'Failed to create {error_label} submenu'
        raise RuntimeError(message)
    host_history_submenu.setToolTipsVisible(True)
    host_history_submenu.aboutToShow.connect(lambda: populate_host_history_submenu(host_history_submenu, select_ips_callback))
