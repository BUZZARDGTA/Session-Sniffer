"""Session timeline window — sortable table view of per-player presence."""

from datetime import datetime
from typing import override

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QHeaderView, QTableWidget, QTableWidgetItem

from session_sniffer.exceptions import PlayerDateTimeCorruptionError
from session_sniffer.guis.table_context_menu import StatTableWindowMixin, skip_if_menu_open
from session_sniffer.guis.utils import (
    NumericTableWidgetItem,
    format_duration,
    format_player_display,
    setup_stat_table,
)
from session_sniffer.player.registry import PlayersRegistry

_COLUMN_PLAYER = 0
_COLUMN_STATUS = 1
_COLUMN_FIRST_SEEN = 2
_COLUMN_LAST_REJOIN = 3
_COLUMN_LAST_SEEN = 4
_COLUMN_SESSION_TIME = 5
_COLUMN_TOTAL_TIME = 6
_COLUMN_REJOINS = 7

_HEADERS = ['Player', 'Status', 'First Seen', 'Last Rejoin', 'Last Seen', 'Session Time', 'Total Time', 'Rejoins']

_COLOR_CONNECTED = QColor(80, 200, 80)
_COLOR_DISCONNECTED = QColor(220, 80, 60)


class SessionTimelineWindow(StatTableWindowMixin):
    """Sortable table showing every player's join/leave timestamps and session durations."""

    def __init__(self, *, always_on_top: bool = True) -> None:
        """Initialize the session timeline window."""
        super().__init__()

        self.setWindowTitle('Session Timeline')
        self.resize(1000, 500)
        layout = self.setup_window_layout(always_on_top=always_on_top, spacing=4)

        self._table = QTableWidget(0, len(_HEADERS))
        self._table.setHorizontalHeaderLabels(_HEADERS)
        setup_stat_table(self._table, layout, sorting=True)

        h_header = self._table.horizontalHeader()
        if not h_header:
            message = 'Failed to get horizontal header'
            raise RuntimeError(message)
        # Use Interactive so column widths are not recalculated on every cell update;
        # _reset_column_sizes() is called once after a full repopulate instead.
        for column in range(len(_HEADERS)):
            h_header.setSectionResizeMode(column, QHeaderView.ResizeMode.Interactive)
        h_header.setStretchLastSection(False)
        self._reset_column_sizes()

        self._table.sortByColumn(_COLUMN_FIRST_SEEN, Qt.SortOrder.AscendingOrder)

        self.setup_stat_table_controls(layout, always_on_top=always_on_top)

    @override
    def _reset_column_sizes(self) -> None:
        """Reset column widths back to their initial default layout."""
        for column in (_COLUMN_STATUS, _COLUMN_FIRST_SEEN, _COLUMN_LAST_REJOIN, _COLUMN_LAST_SEEN, _COLUMN_SESSION_TIME, _COLUMN_TOTAL_TIME, _COLUMN_REJOINS):
            self._table.resizeColumnToContents(column)
        other_widths = sum(self._table.columnWidth(column) for column in range(1, len(_HEADERS)))
        viewport = self._table.viewport()
        available_width = viewport.width() if viewport and viewport.width() > 0 else self._table.width()
        player_width = max(180, available_width - other_widths)
        self._table.setColumnWidth(_COLUMN_PLAYER, player_width)

    @skip_if_menu_open
    def refresh(self) -> None:
        """Update the table with current player presence data."""
        all_players = PlayersRegistry.get_all_players()
        num_players = len(all_players)

        if not num_players:
            if self._table.rowCount() > 0:
                self._table.setRowCount(0)
            return

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

                try:
                    session_seconds = player.datetime.get_session_time().total_seconds()
                except PlayerDateTimeCorruptionError:
                    session_seconds = (now - player.datetime.last_rejoin).total_seconds()
                try:
                    total_seconds = player.datetime.get_total_session_time().total_seconds()
                except PlayerDateTimeCorruptionError:
                    total_seconds = session_seconds

                player_item = QTableWidgetItem(format_player_display(player.ip, player.usernames))
                player_item.setData(Qt.ItemDataRole.UserRole, player.ip)
                status_item = QTableWidgetItem('Connected' if is_connected else 'Disconnected')

                first_item = NumericTableWidgetItem(player.datetime.first_seen.strftime('%H:%M:%S'))
                first_item.setData(Qt.ItemDataRole.UserRole, player.datetime.first_seen.timestamp())

                rejoin_item = NumericTableWidgetItem(player.datetime.last_rejoin.strftime('%H:%M:%S'))
                rejoin_item.setData(Qt.ItemDataRole.UserRole, player.datetime.last_rejoin.timestamp())

                seen_item = NumericTableWidgetItem(player.datetime.last_seen.strftime('%H:%M:%S'))
                seen_item.setData(Qt.ItemDataRole.UserRole, player.datetime.last_seen.timestamp())

                session_item = NumericTableWidgetItem(format_duration(session_seconds))
                session_item.setData(Qt.ItemDataRole.UserRole, session_seconds)

                total_item = NumericTableWidgetItem(format_duration(total_seconds))
                total_item.setData(Qt.ItemDataRole.UserRole, total_seconds)

                rejoins_item = NumericTableWidgetItem(player.rejoins)
                rejoins_item.setData(Qt.ItemDataRole.UserRole, player.rejoins)

                for column, item in enumerate((player_item, status_item, first_item, rejoin_item, seen_item, session_item, total_item, rejoins_item)):
                    item.setForeground(color)
                    item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                    self._table.setItem(row, column, item)

            self._reset_column_sizes()
            # Re-enable sorting once — triggers a single sort, acceptable after a structural change.
            self._table.setSortingEnabled(True)

        else:
            # Incremental update: update each player at their exact sorted row.
            # Block signals so setText/setData don't trigger auto-sort during the tick.
            self._table.blockSignals(True)  # noqa: FBT003

            for player in all_players:
                target_row = table_ip_to_row.get(player.ip)
                if target_row is None:
                    continue

                is_connected = PlayersRegistry.is_player_connected(player)
                color = _COLOR_CONNECTED if is_connected else _COLOR_DISCONNECTED

                try:
                    session_seconds = player.datetime.get_session_time().total_seconds()
                except PlayerDateTimeCorruptionError:
                    session_seconds = (now - player.datetime.last_rejoin).total_seconds()
                try:
                    total_seconds = player.datetime.get_total_session_time().total_seconds()
                except PlayerDateTimeCorruptionError:
                    total_seconds = session_seconds

                status_cell = self._table.item(target_row, _COLUMN_STATUS)
                status_text = 'Connected' if is_connected else 'Disconnected'
                if status_cell is not None and status_cell.text() != status_text:
                    status_cell.setText(status_text)
                    for column in range(len(_HEADERS)):
                        cell = self._table.item(target_row, column)
                        if cell is not None:
                            cell.setForeground(color)

                player_cell = self._table.item(target_row, _COLUMN_PLAYER)
                if player_cell is not None:
                    new_val = format_player_display(player.ip, player.usernames)
                    if player_cell.text() != new_val:
                        player_cell.setText(new_val)
                        player_cell.setForeground(color)

                rejoin_cell = self._table.item(target_row, _COLUMN_LAST_REJOIN)
                if rejoin_cell is not None:
                    new_val = player.datetime.last_rejoin.strftime('%H:%M:%S')
                    if rejoin_cell.text() != new_val:
                        rejoin_cell.setText(new_val)
                        rejoin_cell.setData(Qt.ItemDataRole.UserRole, player.datetime.last_rejoin.timestamp())
                        rejoin_cell.setForeground(color)

                seen_cell = self._table.item(target_row, _COLUMN_LAST_SEEN)
                if seen_cell is not None:
                    new_val = player.datetime.last_seen.strftime('%H:%M:%S')
                    if seen_cell.text() != new_val:
                        seen_cell.setText(new_val)
                        seen_cell.setData(Qt.ItemDataRole.UserRole, player.datetime.last_seen.timestamp())
                        seen_cell.setForeground(color)

                session_cell = self._table.item(target_row, _COLUMN_SESSION_TIME)
                if session_cell is not None:
                    new_val = format_duration(session_seconds)
                    if session_cell.text() != new_val:
                        session_cell.setText(new_val)
                        session_cell.setData(Qt.ItemDataRole.UserRole, session_seconds)
                        session_cell.setForeground(color)

                total_cell = self._table.item(target_row, _COLUMN_TOTAL_TIME)
                if total_cell is not None:
                    new_val = format_duration(total_seconds)
                    if total_cell.text() != new_val:
                        total_cell.setText(new_val)
                        total_cell.setData(Qt.ItemDataRole.UserRole, total_seconds)
                        total_cell.setForeground(color)

                rejoins_cell = self._table.item(target_row, _COLUMN_REJOINS)
                if rejoins_cell is not None:
                    new_val = str(player.rejoins)
                    if rejoins_cell.text() != new_val:
                        rejoins_cell.setText(new_val)
                        rejoins_cell.setData(Qt.ItemDataRole.UserRole, player.rejoins)
                        rejoins_cell.setForeground(color)

            self._table.blockSignals(False)  # noqa: FBT003
