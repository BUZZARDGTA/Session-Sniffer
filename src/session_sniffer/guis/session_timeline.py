"""Session timeline window — sortable table view of per-player presence."""

from datetime import datetime
from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QTableWidget, QTableWidgetItem

from session_sniffer.constants.tables import SESSION_TIMELINE_TABLE_MIN_COLUMN_WIDTHS
from session_sniffer.exceptions import PlayerDateTimeCorruptionError
from session_sniffer.guis.live_language import register_language_refresh, set_table_headers
from session_sniffer.guis.table_context_menu import StatTableWindowMixin, skip_if_menu_open
from session_sniffer.guis.theming import register_theme_change_callback, themed_text_qcolor
from session_sniffer.guis.utils import (
    NumericTableWidgetItem,
    format_duration,
    format_player_display,
    scale_by_ui,
    setup_stat_table,
)
from session_sniffer.i18n import tr
from session_sniffer.player.registry import PlayersRegistry

if TYPE_CHECKING:
    from session_sniffer.models.player import Player


_COLUMN_PLAYER = 0
_COLUMN_STATUS = 1
_COLUMN_FIRST_SEEN = 2
_COLUMN_LAST_REJOIN = 3
_COLUMN_LAST_SEEN = 4
_COLUMN_SESSION_TIME = 5
_COLUMN_TOTAL_TIME = 6
_COLUMN_REJOINS = 7

_HEADERS = ['Player', 'Status', 'First Seen', 'Last Rejoin', 'Last Seen', 'Session Time', 'Total Time', 'Rejoins']

_COLOR_CONNECTED = themed_text_qcolor('#50c850', '#1e1e1e')
_COLOR_DISCONNECTED = themed_text_qcolor('#dc503c', '#1e1e1e')


def _refresh_timeline_colors() -> None:
    _COLOR_CONNECTED.setRgba(themed_text_qcolor('#50c850', '#1e1e1e').rgba())
    _COLOR_DISCONNECTED.setRgba(themed_text_qcolor('#dc503c', '#1e1e1e').rgba())


register_theme_change_callback(_refresh_timeline_colors)


def _calculate_player_session_times(player: Player, now: datetime) -> tuple[float, float]:
    """Calculate the player session time and total session time in seconds."""
    try:
        session_seconds = player.datetime.get_session_time().total_seconds()
    except PlayerDateTimeCorruptionError:
        session_seconds = (now - player.datetime.last_rejoin).total_seconds()
    try:
        total_seconds = player.datetime.get_total_session_time().total_seconds()
    except PlayerDateTimeCorruptionError:
        total_seconds = session_seconds
    return session_seconds, total_seconds


class SessionTimelineWindow(StatTableWindowMixin):
    """Sortable table showing every player's join/leave timestamps and session durations."""

    LAYOUT_KEY = 'session_timeline'

    def __init__(self, *, always_on_top: bool = True) -> None:
        """Initialize the session timeline window."""
        super().__init__()

        self.resize(scale_by_ui(1000), scale_by_ui(500))
        layout = self.setup_window_layout(always_on_top=always_on_top, spacing=4)

        self._table = QTableWidget(0, len(_HEADERS))
        set_table_headers(self._table, _HEADERS)
        setup_stat_table(self._table, layout, sorting=True)

        self.setup_stat_table_controls(layout, always_on_top=always_on_top, min_column_widths=SESSION_TIMELINE_TABLE_MIN_COLUMN_WIDTHS)
        self._setup_column_resizing()
        self._apply_default_or_saved_sort(_COLUMN_FIRST_SEEN, Qt.SortOrder.AscendingOrder)

        self._apply_translations()
        register_language_refresh(self, self._apply_translations)

    def _apply_translations(self) -> None:
        """Apply translated text to the window title and existing table cells."""
        self.setWindowTitle(tr('Session Timeline'))
        for row in range(self._table.rowCount()):
            status_cell = self._table.item(row, _COLUMN_STATUS)
            if status_cell is not None:
                is_connected = bool(status_cell.data(Qt.ItemDataRole.UserRole))
                status_cell.setText(tr('Connected') if is_connected else tr('Disconnected'))
            for column in (_COLUMN_SESSION_TIME, _COLUMN_TOTAL_TIME):
                time_cell = self._table.item(row, column)
                if time_cell is not None:
                    seconds = time_cell.data(Qt.ItemDataRole.UserRole)
                    if isinstance(seconds, int | float):
                        time_cell.setText(format_duration(seconds))

    @skip_if_menu_open
    def refresh(self) -> None:
        """Update the table with current player presence data."""
        num_players = PlayersRegistry.get_total_count()
        if not num_players:
            if self._table.rowCount() > 0:
                self._table.setRowCount(0)
            return

        all_players = PlayersRegistry.get_all_players()
        now = datetime.now(tz=all_players[0].datetime.first_seen.tzinfo)
        current_ips_set = {player.ip for player in all_players}

        table_ip_to_row: dict[str, int] = {}
        for row in range(self._table.rowCount()):
            item = self._table.item(row, _COLUMN_PLAYER)
            if item is not None:
                ip = item.data(Qt.ItemDataRole.UserRole)
                if isinstance(ip, str):
                    table_ip_to_row[ip] = row

        players_changed = current_ips_set != set(table_ip_to_row.keys())

        if players_changed:
            # Full repopulate: disable sorting so setItem doesn't trigger a sort after
            # every single cell write, then re-enable once at the end.
            self._table.setSortingEnabled(False)
            self._table.setRowCount(num_players)

            for row, player in enumerate(all_players):
                is_connected = PlayersRegistry.is_player_connected(player)
                color = _COLOR_CONNECTED if is_connected else _COLOR_DISCONNECTED

                session_seconds, total_seconds = _calculate_player_session_times(player, now)

                player_item = QTableWidgetItem(format_player_display(player.ip, player.usernames))
                player_item.setData(Qt.ItemDataRole.UserRole, player.ip)
                status_item = QTableWidgetItem(tr('Connected') if is_connected else tr('Disconnected'))
                status_item.setData(Qt.ItemDataRole.UserRole, is_connected)

                first_item = NumericTableWidgetItem(player.datetime.first_seen.strftime('%H:%M:%S'), sort_value=player.datetime.first_seen.timestamp())
                rejoin_item = NumericTableWidgetItem(player.datetime.last_rejoin.strftime('%H:%M:%S'), sort_value=player.datetime.last_rejoin.timestamp())
                seen_item = NumericTableWidgetItem(player.datetime.last_seen.strftime('%H:%M:%S'), sort_value=player.datetime.last_seen.timestamp())
                session_item = NumericTableWidgetItem(format_duration(session_seconds), sort_value=session_seconds)
                total_item = NumericTableWidgetItem(format_duration(total_seconds), sort_value=total_seconds)
                rejoins_item = NumericTableWidgetItem(player.rejoins)

                for column, item in enumerate((player_item, status_item, first_item, rejoin_item, seen_item, session_item, total_item, rejoins_item)):
                    item.setForeground(color)
                    item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                    self._table.setItem(row, column, item)

            self._apply_initial_column_resizing()
            # Re-enable sorting once — triggers a single sort, acceptable after a structural change.
            self._table.setSortingEnabled(True)

        else:
            # Incremental update: update each player at their exact sorted row.
            self._table.setSortingEnabled(False)
            for player in all_players:
                target_row = table_ip_to_row.get(player.ip)
                if target_row is None:
                    continue

                is_connected = PlayersRegistry.is_player_connected(player)
                color = _COLOR_CONNECTED if is_connected else _COLOR_DISCONNECTED

                session_seconds, total_seconds = _calculate_player_session_times(player, now)

                status_cell = self._table.item(target_row, _COLUMN_STATUS)
                status_text = tr('Connected') if is_connected else tr('Disconnected')
                if status_cell is not None and (status_cell.data(Qt.ItemDataRole.UserRole) != is_connected or status_cell.text() != status_text):
                    status_cell.setData(Qt.ItemDataRole.UserRole, is_connected)
                    status_cell.setText(status_text)
                    for column in range(len(_HEADERS)):
                        cell = self._table.item(target_row, column)
                        if cell is not None:
                            cell.setForeground(color)

                cell_updates: tuple[tuple[int, str, float | None], ...] = (
                    (_COLUMN_PLAYER, format_player_display(player.ip, player.usernames), None),
                    (_COLUMN_LAST_REJOIN, player.datetime.last_rejoin.strftime('%H:%M:%S'), player.datetime.last_rejoin.timestamp()),
                    (_COLUMN_LAST_SEEN, player.datetime.last_seen.strftime('%H:%M:%S'), player.datetime.last_seen.timestamp()),
                    (_COLUMN_SESSION_TIME, format_duration(session_seconds), session_seconds),
                    (_COLUMN_TOTAL_TIME, format_duration(total_seconds), total_seconds),
                    (_COLUMN_REJOINS, str(player.rejoins), player.rejoins),
                )
                for column, text, sort_value in cell_updates:
                    cell = self._table.item(target_row, column)
                    if cell is not None:
                        if sort_value is not None:
                            cell.setData(Qt.ItemDataRole.UserRole, sort_value)
                        if cell.text() != text:
                            cell.setText(text)
                            cell.setForeground(color)
            self._table.setSortingEnabled(True)
