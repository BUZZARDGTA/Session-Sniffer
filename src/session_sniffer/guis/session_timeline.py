"""Session timeline window — sortable table view of per-player presence."""

from datetime import datetime

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import QHeaderView, QTableWidget, QTableWidgetItem

from session_sniffer.exceptions import PlayerDateTimeCorruptionError
from session_sniffer.guis.utils import NumericTableWidgetItem, ToggleAlwaysOnTopMixin, format_player_display, setup_stat_table
from session_sniffer.player.registry import PlayersRegistry

_COL_PLAYER = 0
_COL_STATUS = 1
_COL_FIRST_SEEN = 2
_COL_LAST_REJOIN = 3
_COL_LAST_SEEN = 4
_COL_SESSION_TIME = 5
_COL_TOTAL_TIME = 6
_COL_REJOINS = 7

_HEADERS = ['Player', 'Status', 'First Seen', 'Last Rejoin', 'Last Seen', 'Session Time', 'Total Time', 'Rejoins']

_COLOR_CONNECTED = QColor(80, 200, 80)
_COLOR_DISCONNECTED = QColor(220, 80, 60)


def _fmt_duration(total_seconds: float) -> str:
    """Format a duration in seconds as a human-readable string."""
    s = int(total_seconds)
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    if h:
        return f'{h}h {m}m {sec:02d}s'
    if m:
        return f'{m}m {sec:02d}s'
    return f'{sec}s'


class SessionTimelineWindow(ToggleAlwaysOnTopMixin):
    """Sortable table showing every player's join/leave timestamps and session durations."""

    def __init__(self, *, always_on_top: bool = True) -> None:
        """Initialize the session timeline window."""
        super().__init__()

        self.setWindowTitle('Session Timeline')
        self.resize(1000, 500)
        layout = self._setup_window_layout(always_on_top=always_on_top, spacing=4)

        self._table = QTableWidget(0, len(_HEADERS))
        self._table.setHorizontalHeaderLabels(_HEADERS)
        setup_stat_table(self._table, layout, sorting=True)

        h_header = self._table.horizontalHeader()
        if h_header is None:
            msg = 'Failed to get horizontal header'
            raise RuntimeError(msg)
        # Use Interactive so column widths are not recalculated on every cell update;
        # resizeSections() is called once after a full repopulate instead.
        h_header.setSectionResizeMode(_COL_PLAYER, QHeaderView.ResizeMode.Stretch)
        for col in (_COL_STATUS, _COL_FIRST_SEEN, _COL_LAST_REJOIN, _COL_LAST_SEEN,
                    _COL_SESSION_TIME, _COL_TOTAL_TIME, _COL_REJOINS):
            h_header.setSectionResizeMode(col, QHeaderView.ResizeMode.Interactive)
        h_header.setStretchLastSection(False)

        self._table.sortByColumn(_COL_FIRST_SEEN, Qt.SortOrder.AscendingOrder)

        self._add_always_on_top_checkbox(layout, always_on_top=always_on_top)

        # Tracks the ordered IP list from the last full repopulate to detect row set changes.
        self._last_player_ips: list[str] = []

    # Public API —————————————————————————————————————————————————————————————

    def refresh(self) -> None:
        """Update the table with current player presence data."""
        all_players = PlayersRegistry.get_all_players()
        n = len(all_players)

        if not n:
            if self._table.rowCount() > 0:
                self._table.setRowCount(0)
            self._last_player_ips = []
            return

        now = datetime.now(tz=all_players[0].datetime.first_seen.tzinfo)
        current_ips = [p.ip for p in all_players]
        players_changed = current_ips != self._last_player_ips

        if players_changed:
            # Full repopulate: disable sorting so setItem doesn't trigger a sort after
            # every single cell write, then re-enable once at the end.
            self._table.setSortingEnabled(False)
            self._table.setRowCount(n)

            for row, player in enumerate(all_players):
                is_connected = not player.left_event.is_set()
                color = _COLOR_CONNECTED if is_connected else _COLOR_DISCONNECTED

                try:
                    session_secs = player.datetime.get_session_time().total_seconds()
                except PlayerDateTimeCorruptionError:
                    session_secs = (now - player.datetime.last_rejoin).total_seconds()
                try:
                    total_secs = player.datetime.get_total_session_time().total_seconds()
                except PlayerDateTimeCorruptionError:
                    total_secs = session_secs

                player_item = QTableWidgetItem(format_player_display(player.ip, player.usernames))
                status_item = QTableWidgetItem('🟢 Connected' if is_connected else '🔴 Disconnected')

                first_item = NumericTableWidgetItem(player.datetime.first_seen.strftime('%H:%M:%S'))
                first_item.setData(Qt.ItemDataRole.UserRole, player.datetime.first_seen.timestamp())

                rejoin_item = NumericTableWidgetItem(player.datetime.last_rejoin.strftime('%H:%M:%S'))
                rejoin_item.setData(Qt.ItemDataRole.UserRole, player.datetime.last_rejoin.timestamp())

                seen_item = NumericTableWidgetItem(player.datetime.last_seen.strftime('%H:%M:%S'))
                seen_item.setData(Qt.ItemDataRole.UserRole, player.datetime.last_seen.timestamp())

                session_item = NumericTableWidgetItem(_fmt_duration(session_secs))
                session_item.setData(Qt.ItemDataRole.UserRole, session_secs)

                total_item = NumericTableWidgetItem(_fmt_duration(total_secs))
                total_item.setData(Qt.ItemDataRole.UserRole, total_secs)

                rejoins_item = NumericTableWidgetItem(str(player.rejoins))
                rejoins_item.setData(Qt.ItemDataRole.UserRole, player.rejoins)

                for col, item in enumerate((player_item, status_item, first_item, rejoin_item,
                                            seen_item, session_item, total_item, rejoins_item)):
                    item.setForeground(color)
                    item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                    self._table.setItem(row, col, item)

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
                    session_secs = player.datetime.get_session_time().total_seconds()
                except PlayerDateTimeCorruptionError:
                    session_secs = (now - player.datetime.last_rejoin).total_seconds()
                try:
                    total_secs = player.datetime.get_total_session_time().total_seconds()
                except PlayerDateTimeCorruptionError:
                    total_secs = session_secs

                cell = self._table.item(row, _COL_PLAYER)
                if cell is not None:
                    new_val = format_player_display(player.ip, player.usernames)
                    if cell.text() != new_val:
                        cell.setText(new_val)
                        cell.setForeground(color)

                cell = self._table.item(row, _COL_STATUS)
                if cell is not None:
                    new_val = '🟢 Connected' if is_connected else '🔴 Disconnected'
                    if cell.text() != new_val:
                        cell.setText(new_val)
                        cell.setForeground(color)

                cell = self._table.item(row, _COL_LAST_REJOIN)
                if cell is not None:
                    new_val = player.datetime.last_rejoin.strftime('%H:%M:%S')
                    if cell.text() != new_val:
                        cell.setText(new_val)
                        cell.setData(Qt.ItemDataRole.UserRole, player.datetime.last_rejoin.timestamp())
                        cell.setForeground(color)

                cell = self._table.item(row, _COL_LAST_SEEN)
                if cell is not None:
                    new_val = player.datetime.last_seen.strftime('%H:%M:%S')
                    if cell.text() != new_val:
                        cell.setText(new_val)
                        cell.setData(Qt.ItemDataRole.UserRole, player.datetime.last_seen.timestamp())
                        cell.setForeground(color)

                cell = self._table.item(row, _COL_SESSION_TIME)
                if cell is not None:
                    new_val = _fmt_duration(session_secs)
                    if cell.text() != new_val:
                        cell.setText(new_val)
                        cell.setData(Qt.ItemDataRole.UserRole, session_secs)
                        cell.setForeground(color)

                cell = self._table.item(row, _COL_TOTAL_TIME)
                if cell is not None:
                    new_val = _fmt_duration(total_secs)
                    if cell.text() != new_val:
                        cell.setText(new_val)
                        cell.setData(Qt.ItemDataRole.UserRole, total_secs)
                        cell.setForeground(color)

                cell = self._table.item(row, _COL_REJOINS)
                if cell is not None:
                    new_val = str(player.rejoins)
                    if cell.text() != new_val:
                        cell.setText(new_val)
                        cell.setData(Qt.ItemDataRole.UserRole, player.rejoins)
                        cell.setForeground(color)

            self._table.blockSignals(False)  # noqa: FBT003
