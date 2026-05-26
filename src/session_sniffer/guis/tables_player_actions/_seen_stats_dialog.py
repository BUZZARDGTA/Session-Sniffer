"""SeenStatsDialog and show_seen_stats helper."""

from typing import TYPE_CHECKING

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.local import SESSIONS_LOGGING_DIR_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis.tables_player_actions._player_info_dialog_mixin import PlayerInfoDialogMixin
from session_sniffer.guis.utils import format_player_display, get_screen_size, resize_window_for_screen, set_dialog_window_flags
from session_sniffer.player.seen_stats import SEEN_STATS_LABELS, SeenStats, analyze_sessions_logging

if TYPE_CHECKING:
    from session_sniffer.models.player import Player


class SeenStatsDialog(PlayerInfoDialogMixin):
    """A dialog showing historical encounter statistics for a player IP."""

    def __init__(self, parent: QWidget, player: Player) -> None:
        """Compute seen stats and build the dialog UI."""
        super().__init__(parent)
        set_dialog_window_flags(self)
        stats = analyze_sessions_logging(SESSIONS_LOGGING_DIR_PATH, player.ip)

        self.setWindowTitle(f'{TITLE} - Seen Stats ({format_player_display(player.ip, player.usernames)})')
        self.setMinimumSize(400, 300)

        screen_size = get_screen_size()

        if screen_size >= (1920, 1080):
            self.resize(500, 360)
        elif screen_size >= (1280, 720):
            self.resize(460, 340)
        else:
            resize_window_for_screen(self, screen_size)
            self.resize(min(self.width(), max(400, screen_size[0] - 80)), min(self.height(), max(300, screen_size[1] - 80)))

        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(10, 10, 10, 10)
        outer_layout.setSpacing(8)

        self._add_header_label(outer_layout, f'\U0001f4c5  Seen Stats \u2014 {format_player_display(player.ip, player.usernames)}', '#6b46c1', '#9f7aea')

        scroll_layout = self._init_scroll_area(outer_layout)

        self._build_encounter_group(scroll_layout, stats)
        scroll_layout.addStretch(1)

        self._add_close_button_box(outer_layout)

    def _build_encounter_group(self, parent_layout: QVBoxLayout, stats: SeenStats) -> None:
        """Add the 'Session Encounters' section to the scroll layout."""
        group, form = self._make_group('\U0001f4c5  Session Encounters', accent='#6b46c1')
        for key, label in SEEN_STATS_LABELS.items():
            self._add_row(form, label, str(getattr(stats, key)))
        parent_layout.addWidget(group)


def show_seen_stats(parent: QWidget, player: Player) -> None:
    """Open the Seen Stats dialog for *player*."""
    dialog = SeenStatsDialog(parent, player)
    dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
    dialog.show()
