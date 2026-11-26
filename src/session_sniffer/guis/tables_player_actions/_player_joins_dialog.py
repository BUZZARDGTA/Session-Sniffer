"""PlayerJoinsWindow and show_player_joins helper."""

from typing import TYPE_CHECKING, override

from PySide6.QtCore import QSignalBlocker, Qt, QTimer
from PySide6.QtGui import QCloseEvent, QIcon
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QWidget,
)

from session_sniffer.constants.standalone import TITLE
from session_sniffer.constants.tables import PLAYER_JOINS_TABLE_MIN_COLUMN_WIDTHS
from session_sniffer.guis.live_language import register_language_refresh, set_table_headers
from session_sniffer.guis.stylesheets import player_info_header_stylesheet
from session_sniffer.guis.table_context_menu import StatTableWindowMixin, skip_if_menu_open
from session_sniffer.guis.theming import ICONS_DIR_PATH, register_theme_change_callback, themed_qss, themed_text_qcolor
from session_sniffer.guis.utils import (
    ActiveDialogRegistry,
    NumericTableWidgetItem,
    apply_adaptive_window_size,
    format_duration,
    format_player_display,
    setup_stat_table,
)
from session_sniffer.guis.window_layout import cascade_window_if_overlapping
from session_sniffer.i18n import tr, tr_plural
from session_sniffer.models.player_traffic import PlayerBandwidth
from session_sniffer.player.registry import PlayersRegistry

if TYPE_CHECKING:
    from session_sniffer.models.player import Player
    from session_sniffer.models.player_traffic import PlayerJoin

_COLUMN_INDEX = 0
_COLUMN_STATUS = 1
_COLUMN_LAST_SEEN = 3
_COLUMN_SESSION_TIME = 4
_COLUMN_MIDDLE_PORTS = 6
_COLUMN_LAST_PORT = 7
_COLUMN_PORTS = 8
_COLUMN_PACKETS = 9
_COLUMN_PACKETS_RECEIVED = 10
_COLUMN_PACKETS_SENT = 11
_COLUMN_MIN_PACKET_LENGTH = 12
_COLUMN_AVG_PACKET_LENGTH = 13
_COLUMN_MAX_PACKET_LENGTH = 14
_COLUMN_BANDWIDTH = 15
_COLUMN_DOWNLOAD = 16
_COLUMN_UPLOAD = 17

_HEADERS: tuple[str, ...] = (
    '#',
    'Status',
    'Rejoin Time',
    'Last Seen',
    'Session Time',
    'First Port',
    'Middle Ports',
    'Last Port',
    'Ports',
    'Packets',
    'Packets Received',
    'Packets Sent',
    'Min Packet Length',
    'Avg Packet Length',
    'Max Packet Length',
    'Bandwidth',
    'Download',
    'Upload',
)

_HEADER_TOOLTIPS: dict[str, str] = {
    '#': 'Sequential join index (1 = initial join, 2+ = rejoins).',
    'Status': 'Whether this join session is currently active/connected or ended.',
    'Rejoin Time': 'Timestamp when this player joined or rejoined the session.',
    'Last Seen': 'Timestamp when this player was last active in this join session.',
    'Session Time': 'Duration of this join session.',
    'First Port': 'First port observed for this join session only.',
    'Middle Ports': 'Middle ports observed for this join session only.',
    'Last Port': 'Last port observed for this join session only.',
    'Ports': 'All ports observed during this join session only.',
    'Packets': 'Total packets exchanged during this join session only.',
    'Packets Received': 'Packets received during this join session only.',
    'Packets Sent': 'Packets sent during this join session only.',
    'Min Packet Length': 'Minimum packet length (bytes) in this join session only.',
    'Avg Packet Length': 'Average packet length (bytes) in this join session only.',
    'Max Packet Length': 'Maximum packet length (bytes) in this join session only.',
    'Bandwidth': 'Total bandwidth exchanged during this join session only.',
    'Download': 'Bandwidth downloaded during this join session only.',
    'Upload': 'Bandwidth uploaded during this join session only.',
}

_COLOR_CONNECTED = themed_text_qcolor('#50c850', '#1e1e1e')
_COLOR_DISCONNECTED = themed_text_qcolor('#dc503c', '#1e1e1e')


def _refresh_player_joins_colors() -> None:
    _COLOR_CONNECTED.setRgba(themed_text_qcolor('#50c850', '#1e1e1e').rgba())
    _COLOR_DISCONNECTED.setRgba(themed_text_qcolor('#dc503c', '#1e1e1e').rgba())


register_theme_change_callback(_refresh_player_joins_colors)


class PlayerJoinsWindow(StatTableWindowMixin):
    """Sortable table window showing detailed session times, timestamps, ports, and stats for each join of a player."""

    LAYOUT_KEY = 'player_joins'

    def __init__(self, parent: QWidget | None, player: Player) -> None:
        """Initialize the Player Joins window."""
        super().__init__(parent.window() if parent is not None else None)
        self._player: Player = player

        display = format_player_display(self._player.ip, self._player.usernames)
        self.setWindowTitle(f'{TITLE} - {tr("Player Joins")} ({display})')
        self.setWindowIcon(QIcon(str(ICONS_DIR_PATH / 'rotate-ccw-clock.svg')))

        layout = self.setup_window_layout(always_on_top=True, spacing=6)

        self._header_label = QLabel(f'{tr("Player Joins")} — {display}')
        self._header_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._header_label.setStyleSheet(player_info_header_stylesheet('#1e3a8a', '#3b82f6'))
        self._header_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse | Qt.TextInteractionFlag.TextSelectableByKeyboard)
        layout.addWidget(self._header_label)

        self._info_label = QLabel()
        self._info_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._info_label.setStyleSheet(themed_qss('color: #cbd5e0; font-size: 9pt; font-weight: 600; padding: 2px 4px;'))
        self._info_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse | Qt.TextInteractionFlag.TextSelectableByKeyboard)
        layout.addWidget(self._info_label)

        self._table = QTableWidget(0, len(_HEADERS))
        set_table_headers(self._table, _HEADERS, _HEADER_TOOLTIPS)

        setup_stat_table(self._table, layout, sorting=True)

        apply_adaptive_window_size(self, min_size=(800, 420), size_1080p=(1120, 560), size_720p=(920, 480))

        bottom_layout = QHBoxLayout()
        self.setup_stat_table_controls(bottom_layout, always_on_top=True, min_column_widths=PLAYER_JOINS_TABLE_MIN_COLUMN_WIDTHS)
        bottom_layout.addStretch(1)

        self._count_label = QLabel()
        self._count_label.setStyleSheet(themed_qss('color: #a0aec0; font-size: 9pt;'))
        bottom_layout.addWidget(self._count_label)
        bottom_layout.addSpacing(12)

        close_button = QPushButton(tr('Close'))
        close_button.setToolTip(tr('Close this window.'))
        close_button.clicked.connect(self.close)
        bottom_layout.addWidget(close_button)
        layout.addLayout(bottom_layout)

        self._setup_column_resizing()
        self._apply_default_or_saved_sort(_COLUMN_INDEX, Qt.SortOrder.AscendingOrder)

        self._timer = QTimer(self)
        self._timer.setInterval(1000)
        self._timer.timeout.connect(self.refresh)
        self._timer.start()

        register_language_refresh(self, self.refresh)
        self.refresh()

    @skip_if_menu_open
    def refresh(self) -> None:
        """Update the player joins table with current session data."""
        display = format_player_display(self._player.ip, self._player.usernames)
        new_title = f'{TITLE} - {tr("Player Joins")} ({display})'
        if self.windowTitle() != new_title:
            self.setWindowTitle(new_title)
        self._header_label.setText(f'{tr("Player Joins")} — {display}')

        is_connected = PlayersRegistry.is_player_connected(self._player)
        status_text = tr('Connected') if is_connected else tr('Disconnected')
        total_time_str = format_duration(self._player.datetime.get_total_session_time().total_seconds())
        country = self._player.iplookup.resolve_country()[0]
        isp = self._player.iplookup.ipapi.isp

        join_count = len(self._player.joins)
        info_parts = [
            tr('Status: {status}', status=status_text),
            tr_plural('Total Join: {count}', 'Total Joins: {count}', join_count),
            tr('Total Session Time: {duration}', duration=total_time_str),
        ]
        if country:
            info_parts.append(tr('Country: {country}', country=country))
        if isp:
            info_parts.append(tr('ISP: {isp}', isp=isp))
        self._info_label.setText('   |   '.join(info_parts))
        self._count_label.setText(tr_plural('Showing {count} join', 'Showing {count} joins', join_count))

        joins = self._player.joins
        num_joins = len(joins)

        if self._table.rowCount() != num_joins:
            self._table.setSortingEnabled(False)
            self._table.setRowCount(num_joins)
            for row, join in enumerate(joins):
                self._populate_row(row, join)
            self._apply_initial_column_resizing()
            self._table.setSortingEnabled(True)
        else:
            with QSignalBlocker(self._table):
                table_index_to_row: dict[int, int] = {}
                for row in range(self._table.rowCount()):
                    item = self._table.item(row, _COLUMN_INDEX)
                    if item is not None:
                        stored_index = item.data(Qt.ItemDataRole.UserRole)
                        if isinstance(stored_index, int):
                            table_index_to_row[stored_index] = row

                for join in joins:
                    target_row = table_index_to_row.get(join.join_index)
                    if target_row is not None:
                        self._update_row(target_row, join)

    def _populate_row(self, row: int, join: PlayerJoin) -> None:
        """Create and place all table widget items for a single join session row."""
        is_player_connected = PlayersRegistry.is_player_connected(self._player)
        is_join_connected = join.is_active and is_player_connected
        status_str = tr('Connected') if is_join_connected else tr('Disconnected')
        status_color = _COLOR_CONNECTED if is_join_connected else _COLOR_DISCONNECTED

        center = Qt.AlignmentFlag.AlignCenter
        index_item = NumericTableWidgetItem(join.join_index, align=center)

        status_item = QTableWidgetItem(status_str)
        status_item.setForeground(status_color)
        status_item.setTextAlignment(center)

        rejoin_item = NumericTableWidgetItem(join.joined_at.strftime('%Y-%m-%d %H:%M:%S'), sort_value=join.joined_at.timestamp(), align=center)
        seen_item = NumericTableWidgetItem(join.last_seen.strftime('%Y-%m-%d %H:%M:%S'), sort_value=join.last_seen.timestamp(), align=center)

        session_seconds = join.get_session_time().total_seconds()
        session_item = NumericTableWidgetItem(format_duration(session_seconds), sort_value=session_seconds, align=center)

        first_port_item = NumericTableWidgetItem(join.ports.first, align=center)

        middle_ports_str = ', '.join(map(str, reversed(join.ports.middle))) or '—'
        middle_item = QTableWidgetItem(middle_ports_str)
        middle_item.setTextAlignment(center)

        last_port_item = NumericTableWidgetItem(join.ports.last, align=center)
        ports_item = NumericTableWidgetItem(', '.join(map(str, join.ports.all)), sort_value=len(join.ports.all), align=center)
        packets_item = NumericTableWidgetItem(f'{join.packets.exchanged:,}', sort_value=join.packets.exchanged, align=center)
        recv_item = NumericTableWidgetItem(f'{join.packets.received:,}', sort_value=join.packets.received, align=center)
        sent_item = NumericTableWidgetItem(f'{join.packets.sent:,}', sort_value=join.packets.sent, align=center)
        min_len_item = NumericTableWidgetItem(f'{join.packets.min_len:,}', sort_value=join.packets.min_len, align=center)
        avg_len_item = NumericTableWidgetItem(f'{join.packets.avg_len:,.1f} B', sort_value=join.packets.avg_len, align=center)
        max_len_item = NumericTableWidgetItem(f'{join.packets.max_len:,}', sort_value=join.packets.max_len, align=center)
        bandwidth_item = NumericTableWidgetItem(PlayerBandwidth.format_bytes(join.bandwidth.exchanged), sort_value=join.bandwidth.exchanged, align=center)
        download_item = NumericTableWidgetItem(PlayerBandwidth.format_bytes(join.bandwidth.download), sort_value=join.bandwidth.download, align=center)
        upload_item = NumericTableWidgetItem(PlayerBandwidth.format_bytes(join.bandwidth.upload), sort_value=join.bandwidth.upload, align=center)

        items = (
            index_item,
            status_item,
            rejoin_item,
            seen_item,
            session_item,
            first_port_item,
            middle_item,
            last_port_item,
            ports_item,
            packets_item,
            recv_item,
            sent_item,
            min_len_item,
            avg_len_item,
            max_len_item,
            bandwidth_item,
            download_item,
            upload_item,
        )

        for column, item in enumerate(items):
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self._table.setItem(row, column, item)

    def _update_row(self, row: int, join: PlayerJoin) -> None:
        """Update live cell values in an existing row."""
        is_player_connected = PlayersRegistry.is_player_connected(self._player)
        is_join_connected = join.is_active and is_player_connected
        status_str = tr('Connected') if is_join_connected else tr('Disconnected')
        status_color = _COLOR_CONNECTED if is_join_connected else _COLOR_DISCONNECTED

        status_item = self._table.item(row, _COLUMN_STATUS)
        if status_item is not None:
            if status_item.text() != status_str:
                status_item.setText(status_str)
            status_item.setForeground(status_color)

        session_seconds = join.get_session_time().total_seconds()
        cell_updates: tuple[tuple[int, str, float | None], ...] = (
            (_COLUMN_LAST_SEEN, join.last_seen.strftime('%Y-%m-%d %H:%M:%S'), join.last_seen.timestamp()),
            (_COLUMN_SESSION_TIME, format_duration(session_seconds), session_seconds),
            (_COLUMN_MIDDLE_PORTS, ', '.join(map(str, reversed(join.ports.middle))) or '—', None),
            (_COLUMN_LAST_PORT, str(join.ports.last), join.ports.last),
            (_COLUMN_PORTS, ', '.join(map(str, join.ports.all)), len(join.ports.all)),
            (_COLUMN_PACKETS, f'{join.packets.exchanged:,}', join.packets.exchanged),
            (_COLUMN_PACKETS_RECEIVED, f'{join.packets.received:,}', join.packets.received),
            (_COLUMN_PACKETS_SENT, f'{join.packets.sent:,}', join.packets.sent),
            (_COLUMN_MIN_PACKET_LENGTH, f'{join.packets.min_len:,}', join.packets.min_len),
            (_COLUMN_AVG_PACKET_LENGTH, f'{join.packets.avg_len:,.1f} B', join.packets.avg_len),
            (_COLUMN_MAX_PACKET_LENGTH, f'{join.packets.max_len:,}', join.packets.max_len),
            (_COLUMN_BANDWIDTH, PlayerBandwidth.format_bytes(join.bandwidth.exchanged), join.bandwidth.exchanged),
            (_COLUMN_DOWNLOAD, PlayerBandwidth.format_bytes(join.bandwidth.download), join.bandwidth.download),
            (_COLUMN_UPLOAD, PlayerBandwidth.format_bytes(join.bandwidth.upload), join.bandwidth.upload),
        )
        for column, text, sort_value in cell_updates:
            cell_item = self._table.item(row, column)
            if cell_item is not None and cell_item.text() != text:
                cell_item.setText(text)
                if sort_value is not None:
                    cell_item.setData(Qt.ItemDataRole.UserRole, sort_value)

    @override
    def closeEvent(self, event: QCloseEvent) -> None:
        """Stop the periodic refresh timer on window close."""
        self._timer.stop()
        super().closeEvent(event)


_active_windows: ActiveDialogRegistry[str, PlayerJoinsWindow] = ActiveDialogRegistry()


def show_player_joins(parent: QWidget | None, player: Player) -> None:
    """Open or focus the Player Joins window for *player*."""
    existing_windows = _active_windows.active_dialogs()
    already_open = _active_windows.get(player.ip) is not None
    window = _active_windows.show_or_focus(player.ip, lambda: PlayerJoinsWindow(parent, player))
    if not already_open:
        cascade_window_if_overlapping(window, existing_windows)


def close_all_player_joins_windows() -> None:
    """Close all active Player Joins windows so their layouts persist cleanly on app exit."""
    _active_windows.close_all()
