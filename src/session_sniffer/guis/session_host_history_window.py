"""Session Host History submenu population for the GTA5 Session Host menu."""

from datetime import datetime
from typing import TYPE_CHECKING

from PyQt6.QtGui import QAction, QIcon, QPixmap

from session_sniffer.constants.external import LOCAL_TZ
from session_sniffer.guis._combo_rule_editor import AVAILABLE_FLAG_CODES, COUNTRY_FLAGS_DIR
from session_sniffer.player.registry import PlayersRegistry, SessionHost
from session_sniffer.rendering_core.session_table_renderer import format_elapsed_time

if TYPE_CHECKING:
    from collections.abc import Callable

    from PyQt6.QtWidgets import QMenu


def populate_host_history_submenu(menu: QMenu, highlight_ip_callback: Callable[[list[str]], None]) -> None:
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
        usernames = ', '.join(matched_player.usernames) if matched_player and matched_player.usernames else '—'
        elapsed_time_str = format_elapsed_time(now - entry.detected_at)
        act = QAction(f'{entry.ip}  |  {usernames}  |  {entry.detected_at.strftime("%H:%M:%S")} ({elapsed_time_str} ago)', menu)
        ip = entry.ip
        act.triggered.connect(lambda _checked=False, _ip=ip: highlight_ip_callback([_ip]))
        country_code = entry.country_code.strip().upper()
        if country_code and country_code in AVAILABLE_FLAG_CODES:
            act.setIcon(QIcon(QPixmap(str(COUNTRY_FLAGS_DIR / f'{country_code}.png'))))
        menu.addAction(act)
