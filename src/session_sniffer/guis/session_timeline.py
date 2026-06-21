"""Session timeline window — sortable table view of per-player presence."""

from datetime import datetime

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import QHeaderView, QTableWidget, QTableWidgetItem

from session_sniffer.exceptions import PlayerDateTimeCorruptionError
from session_sniffer.guis.utils import NumericTableWidgetItem, ToggleAlwaysOnTopMixin, format_duration, format_player_display, setup_stat_table
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


class SessionTimelineWindow(ToggleAlwaysOnTopMixin):
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
        if h_header is None:
            message = 'Failed to get horizontal header'
            raise RuntimeError(message)
        # Use Interactive so column widths are not recalculated on every cell update;
        # resizeSections() is called once after a full repopulate instead.
        h_header.setSectionResizeMode(_COLUMN_PLAYER, QHeaderView.ResizeMode.Stretch)
        for column in (_COLUMN_STATUS, _COLUMN_FIRST_SEEN, _COLUMN_LAST_REJOIN, _COLUMN_LAST_SEEN, _COLUMN_SESSION_TIME, _COLUMN_TOTAL_TIME, _COLUMN_REJOINS):
            h_header.setSectionResizeMode(column, QHeaderView.ResizeMode.Interactive)
        h_header.setStretchLastSection(False)

        self._table.sortByColumn(_COLUMN_FIRST_SEEN, Qt.SortOrder.AscendingOrder)

        self.add_always_on_top_checkbox(layout, always_on_top=always_on_top)

        # Tracks the ordered IP list from the last full repopulate to detect row set changes.
        self._last_player_ips: list[str] = []

    # Public API —————————————————————————————————————————————————————————————

    def refresh(self) -> None:
        """Update the table with current player presence data."""
        all_players = PlayersRegistry.get_all_players()
        num_players = len(all_players)

        if not num_players:
            if self._table.rowCount() > 0:
                self._table.setRowCount(0)
            self._last_player_ips = []
            return

        now = datetime.now(tz=all_players[0].datetime.first_seen.tzinfo)
        current_ips = [player.ip for player in all_players]
        players_changed = current_ips != self._last_player_ips

        if players_changed:
            # Full repopulate: disable sorting so setItem doesn't trigger a sort after
            # every single cell write, then re-enable once at the end.
            self._table.setSortingEnabled(False)
            self._table.setRowCount(num_players)

            for row, player in enumerate(all_players):
                is_connected = not player.left_event.is_set()
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
                status_item = QTableWidgetItem('🟢 Connected' if is_connected else '🔴 Disconnected')

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

            h_header = self._table.horizontalHeader()
            if h_header is not None:
                h_header.resizeSections(QHeaderView.ResizeMode.ResizeToContents)
            self._last_player_ips = current_ips
            # Re-enable sorting once — triggers a single sort, acceptable after a structural change.
            self._table.setSortingEnabled(True)

        else:
            # Incremental update: block signals so setText/setData don't trigger Qt's
            # auto-sort (which fires on every itemChanged when sorting is enabled).
            # setSortingEnabled is NOT toggled here, so header-click sorting still works.
            self._table.blockSignals(True)  # noqa: FBT003

            for row, player in enumerate(all_players):
                is_connected = not player.left_event.is_set()
                color = _COLOR_CONNECTED if is_connected else _COLOR_DISCONNECTED

                try:
                    session_seconds = player.datetime.get_session_time().total_seconds()
                except PlayerDateTimeCorruptionError:
                    session_seconds = (now - player.datetime.last_rejoin).total_seconds()
                try:
                    total_seconds = player.datetime.get_total_session_time().total_seconds()
                except PlayerDateTimeCorruptionError:
                    total_seconds = session_seconds

                cell = self._table.item(row, _COLUMN_PLAYER)
                if cell is not None:
                    new_val = format_player_display(player.ip, player.usernames)
                    if cell.text() != new_val:
                        cell.setText(new_val)
                        cell.setForeground(color)

                cell = self._table.item(row, _COLUMN_STATUS)
                if cell is not None:
                    new_val = '🟢 Connected' if is_connected else '🔴 Disconnected'
                    if cell.text() != new_val:
                        cell.setText(new_val)
                        cell.setForeground(color)

                cell = self._table.item(row, _COLUMN_LAST_REJOIN)
                if cell is not None:
                    new_val = player.datetime.last_rejoin.strftime('%H:%M:%S')
                    if cell.text() != new_val:
                        cell.setText(new_val)
                        cell.setData(Qt.ItemDataRole.UserRole, player.datetime.last_rejoin.timestamp())
                        cell.setForeground(color)

                cell = self._table.item(row, _COLUMN_LAST_SEEN)
                if cell is not None:
                    new_val = player.datetime.last_seen.strftime('%H:%M:%S')
                    if cell.text() != new_val:
                        cell.setText(new_val)
                        cell.setData(Qt.ItemDataRole.UserRole, player.datetime.last_seen.timestamp())
                        cell.setForeground(color)

                cell = self._table.item(row, _COLUMN_SESSION_TIME)
                if cell is not None:
                    new_val = format_duration(session_seconds)
                    if cell.text() != new_val:
                        cell.setText(new_val)
                        cell.setData(Qt.ItemDataRole.UserRole, session_seconds)
                        cell.setForeground(color)

                cell = self._table.item(row, _COLUMN_TOTAL_TIME)
                if cell is not None:
                    new_val = format_duration(total_seconds)
                    if cell.text() != new_val:
                        cell.setText(new_val)
                        cell.setData(Qt.ItemDataRole.UserRole, total_seconds)
                        cell.setForeground(color)

                cell = self._table.item(row, _COLUMN_REJOINS)
                if cell is not None:
                    new_val = str(player.rejoins)
                    if cell.text() != new_val:
                        cell.setText(new_val)
                        cell.setData(Qt.ItemDataRole.UserRole, player.rejoins)
                        cell.setForeground(color)

            self._table.blockSignals(False)  # noqa: FBT003
