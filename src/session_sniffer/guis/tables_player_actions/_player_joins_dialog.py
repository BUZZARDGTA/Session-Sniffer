"""PlayerJoinsWindow and show_player_joins helper."""

from typing import TYPE_CHECKING, override

from PySide6.QtCore import QSignalBlocker, Qt, QTimer
from PySide6.QtGui import QCloseEvent, QColor, QIcon
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QWidget,
)

from session_sniffer.constants.local import RESOURCES_DIR_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.constants.tables import PLAYER_JOINS_TABLE_MIN_COLUMN_WIDTHS
from session_sniffer.guis.stylesheets import player_info_header_stylesheet
from session_sniffer.guis.table_context_menu import StatTableWindowMixin, skip_if_menu_open
from session_sniffer.guis.utils import (
    ActiveDialogRegistry,
    NumericTableWidgetItem,
    apply_adaptive_window_size,
    format_duration,
    format_player_display,
    setup_stat_table,
)
from session_sniffer.models.player_traffic import PlayerBandwidth
from session_sniffer.player.registry import PlayersRegistry
from session_sniffer.text_utils import pluralize

if TYPE_CHECKING:
    from session_sniffer.models.player import Player
    from session_sniffer.models.player_traffic import PlayerJoin

_COLUMN_INDEX = 0
_COLUMN_STATUS = 1
_COLUMN_REJOIN_TIME = 2
_COLUMN_LAST_SEEN = 3
_COLUMN_SESSION_TIME = 4
_COLUMN_FIRST_PORT = 5
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

_COLOR_CONNECTED = QColor(80, 200, 80)
_COLOR_DISCONNECTED = QColor(220, 80, 60)


class PlayerJoinsWindow(StatTableWindowMixin):
    """Sortable table window showing detailed session times, timestamps, ports, and stats for each join of a player."""

    def __init__(self, parent: QWidget | None, player: Player, *, always_on_top: bool = True) -> None:
        """Initialize the Player Joins window."""
        super().__init__(parent.window() if parent is not None else None)
        self._player: Player = player

        self.setWindowTitle(f'{TITLE} - Player Joins ({format_player_display(self._player.ip, self._player.usernames)})')
        self.setWindowIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'history.svg')))

        layout = self.setup_window_layout(always_on_top=always_on_top, spacing=6)

        self._header_label = QLabel(f'Player Joins — {format_player_display(self._player.ip, self._player.usernames)}')
        self._header_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._header_label.setStyleSheet(player_info_header_stylesheet('#1e3a8a', '#3b82f6'))
        self._header_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse | Qt.TextInteractionFlag.TextSelectableByKeyboard)
        layout.addWidget(self._header_label)

        self._info_label = QLabel()
        self._info_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._info_label.setStyleSheet('color: #cbd5e0; font-size: 9pt; font-weight: 600; padding: 2px 4px;')
        self._info_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse | Qt.TextInteractionFlag.TextSelectableByKeyboard)
        layout.addWidget(self._info_label)

        self._table = QTableWidget(0, len(_HEADERS))
        self._table.setHorizontalHeaderLabels(list(_HEADERS))
        for column_index, header_text in enumerate(_HEADERS):
            header_item = self._table.horizontalHeaderItem(column_index)
            if header_item is not None and header_text in _HEADER_TOOLTIPS:
                header_item.setToolTip(_HEADER_TOOLTIPS[header_text])

        setup_stat_table(self._table, layout, sorting=True)

        bottom_layout = QHBoxLayout()
        self.setup_stat_table_controls(bottom_layout, always_on_top=always_on_top, min_column_widths=PLAYER_JOINS_TABLE_MIN_COLUMN_WIDTHS)
        bottom_layout.addStretch(1)

        self._count_label = QLabel()
        self._count_label.setStyleSheet('color: #a0aec0; font-size: 9pt;')
        bottom_layout.addWidget(self._count_label)
        bottom_layout.addSpacing(12)

        close_button = QPushButton('Close')
        close_button.setToolTip('Close this window.')
        close_button.clicked.connect(self.close)
        bottom_layout.addWidget(close_button)
        layout.addLayout(bottom_layout)

        apply_adaptive_window_size(self, min_size=(800, 420), size_1080p=(1120, 560), size_720p=(920, 480))
        self._reset_column_sizes()
        self._table.sortByColumn(_COLUMN_INDEX, Qt.SortOrder.AscendingOrder)

        self._timer = QTimer(self)
        self._timer.setInterval(1000)
        self._timer.timeout.connect(self.refresh)
        self._timer.start()

        self.refresh()

    @skip_if_menu_open
    def refresh(self) -> None:
        """Update the player joins table with current session data."""
        display = format_player_display(self._player.ip, self._player.usernames)
        new_title = f'{TITLE} - Player Joins ({display})'
        if self.windowTitle() != new_title:
            self.setWindowTitle(new_title)
        self._header_label.setText(f'Player Joins — {display}')

        is_connected = PlayersRegistry.is_player_connected(self._player)
        status_text = 'Connected' if is_connected else 'Disconnected'
        total_time_str = format_duration(self._player.datetime.get_total_session_time().total_seconds())
        country = self._player.iplookup.geolite2.country or 'N/A'
        isp = self._player.iplookup.ipapi.isp or 'N/A'

        info_parts = [
            f'Status: {status_text}',
            f'Total Join{pluralize(len(self._player.joins))}: {len(self._player.joins)}',
            f'Total Session Time: {total_time_str}',
        ]
        if country != 'N/A':
            info_parts.append(f'Country: {country}')
        if isp != 'N/A':
            info_parts.append(f'ISP: {isp}')
        self._info_label.setText('   |   '.join(info_parts))
        self._count_label.setText(f'Showing {len(self._player.joins)} join{pluralize(len(self._player.joins))}')

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
        status_str = 'Connected' if is_join_connected else 'Disconnected'
        status_color = _COLOR_CONNECTED if is_join_connected else _COLOR_DISCONNECTED

        index_item = NumericTableWidgetItem(join.join_index)
        index_item.setData(Qt.ItemDataRole.UserRole, join.join_index)
        index_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

        status_item = QTableWidgetItem(status_str)
        status_item.setForeground(status_color)
        status_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

        rejoin_time_str = join.joined_at.strftime('%Y-%m-%d %H:%M:%S')
        rejoin_item = NumericTableWidgetItem(rejoin_time_str)
        rejoin_item.setData(Qt.ItemDataRole.UserRole, join.joined_at.timestamp())
        rejoin_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

        seen_time_str = join.last_seen.strftime('%Y-%m-%d %H:%M:%S')
        seen_item = NumericTableWidgetItem(seen_time_str)
        seen_item.setData(Qt.ItemDataRole.UserRole, join.last_seen.timestamp())
        seen_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

        session_seconds = join.get_session_time().total_seconds()
        session_item = NumericTableWidgetItem(format_duration(session_seconds))
        session_item.setData(Qt.ItemDataRole.UserRole, session_seconds)
        session_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

        first_port_item = NumericTableWidgetItem(join.ports.first)
        first_port_item.setData(Qt.ItemDataRole.UserRole, join.ports.first)
        first_port_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

        middle_ports_str = ', '.join(map(str, reversed(join.ports.middle))) or '—'
        middle_item = QTableWidgetItem(middle_ports_str)
        middle_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

        last_port_item = NumericTableWidgetItem(join.ports.last)
        last_port_item.setData(Qt.ItemDataRole.UserRole, join.ports.last)
        last_port_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

        ports_str = ', '.join(map(str, join.ports.all))
        ports_item = NumericTableWidgetItem(ports_str)
        ports_item.setData(Qt.ItemDataRole.UserRole, len(join.ports.all))
        ports_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

        packets_item = NumericTableWidgetItem(join.packets.exchanged)
        packets_item.setData(Qt.ItemDataRole.UserRole, join.packets.exchanged)
        packets_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

        recv_item = NumericTableWidgetItem(join.packets.received)
        recv_item.setData(Qt.ItemDataRole.UserRole, join.packets.received)
        recv_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

        sent_item = NumericTableWidgetItem(join.packets.sent)
        sent_item.setData(Qt.ItemDataRole.UserRole, join.packets.sent)
        sent_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

        min_len_item = NumericTableWidgetItem(join.packets.min_len)
        min_len_item.setData(Qt.ItemDataRole.UserRole, join.packets.min_len)
        min_len_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

        avg_len_str = f'{join.packets.avg_len:.1f} B'
        avg_len_item = NumericTableWidgetItem(avg_len_str)
        avg_len_item.setData(Qt.ItemDataRole.UserRole, join.packets.avg_len)
        avg_len_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

        max_len_item = NumericTableWidgetItem(join.packets.max_len)
        max_len_item.setData(Qt.ItemDataRole.UserRole, join.packets.max_len)
        max_len_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

        bandwidth_str = PlayerBandwidth.format_bytes(join.bandwidth.exchanged)
        bandwidth_item = NumericTableWidgetItem(bandwidth_str)
        bandwidth_item.setData(Qt.ItemDataRole.UserRole, join.bandwidth.exchanged)
        bandwidth_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

        download_str = PlayerBandwidth.format_bytes(join.bandwidth.download)
        download_item = NumericTableWidgetItem(download_str)
        download_item.setData(Qt.ItemDataRole.UserRole, join.bandwidth.download)
        download_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

        upload_str = PlayerBandwidth.format_bytes(join.bandwidth.upload)
        upload_item = NumericTableWidgetItem(upload_str)
        upload_item.setData(Qt.ItemDataRole.UserRole, join.bandwidth.upload)
        upload_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

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
        status_str = 'Connected' if is_join_connected else 'Disconnected'
        status_color = _COLOR_CONNECTED if is_join_connected else _COLOR_DISCONNECTED

        status_item = self._table.item(row, _COLUMN_STATUS)
        if status_item is not None:
            if status_item.text() != status_str:
                status_item.setText(status_str)
            status_item.setForeground(status_color)

        seen_item = self._table.item(row, _COLUMN_LAST_SEEN)
        if seen_item is not None:
            seen_time_str = join.last_seen.strftime('%Y-%m-%d %H:%M:%S')
            if seen_item.text() != seen_time_str:
                seen_item.setText(seen_time_str)
                seen_item.setData(Qt.ItemDataRole.UserRole, join.last_seen.timestamp())

        session_item = self._table.item(row, _COLUMN_SESSION_TIME)
        if session_item is not None:
            session_seconds = join.get_session_time().total_seconds()
            duration_str = format_duration(session_seconds)
            if session_item.text() != duration_str:
                session_item.setText(duration_str)
                session_item.setData(Qt.ItemDataRole.UserRole, session_seconds)

        middle_item = self._table.item(row, _COLUMN_MIDDLE_PORTS)
        if middle_item is not None:
            middle_ports_str = ', '.join(map(str, reversed(join.ports.middle))) or '—'
            if middle_item.text() != middle_ports_str:
                middle_item.setText(middle_ports_str)

        last_port_item = self._table.item(row, _COLUMN_LAST_PORT)
        if last_port_item is not None:
            last_port_str = str(join.ports.last)
            if last_port_item.text() != last_port_str:
                last_port_item.setText(last_port_str)
                last_port_item.setData(Qt.ItemDataRole.UserRole, join.ports.last)

        ports_item = self._table.item(row, _COLUMN_PORTS)
        if ports_item is not None:
            ports_str = ', '.join(map(str, join.ports.all))
            if ports_item.text() != ports_str:
                ports_item.setText(ports_str)
                ports_item.setData(Qt.ItemDataRole.UserRole, len(join.ports.all))

        packets_item = self._table.item(row, _COLUMN_PACKETS)
        if packets_item is not None:
            packets_str = str(join.packets.exchanged)
            if packets_item.text() != packets_str:
                packets_item.setText(packets_str)
                packets_item.setData(Qt.ItemDataRole.UserRole, join.packets.exchanged)

        recv_item = self._table.item(row, _COLUMN_PACKETS_RECEIVED)
        if recv_item is not None:
            recv_str = str(join.packets.received)
            if recv_item.text() != recv_str:
                recv_item.setText(recv_str)
                recv_item.setData(Qt.ItemDataRole.UserRole, join.packets.received)

        sent_item = self._table.item(row, _COLUMN_PACKETS_SENT)
        if sent_item is not None:
            sent_str = str(join.packets.sent)
            if sent_item.text() != sent_str:
                sent_item.setText(sent_str)
                sent_item.setData(Qt.ItemDataRole.UserRole, join.packets.sent)

        min_len_item = self._table.item(row, _COLUMN_MIN_PACKET_LENGTH)
        if min_len_item is not None:
            min_len_str = str(join.packets.min_len)
            if min_len_item.text() != min_len_str:
                min_len_item.setText(min_len_str)
                min_len_item.setData(Qt.ItemDataRole.UserRole, join.packets.min_len)

        avg_len_item = self._table.item(row, _COLUMN_AVG_PACKET_LENGTH)
        if avg_len_item is not None:
            avg_len_str = f'{join.packets.avg_len:.1f} B'
            if avg_len_item.text() != avg_len_str:
                avg_len_item.setText(avg_len_str)
                avg_len_item.setData(Qt.ItemDataRole.UserRole, join.packets.avg_len)

        max_len_item = self._table.item(row, _COLUMN_MAX_PACKET_LENGTH)
        if max_len_item is not None:
            max_len_str = str(join.packets.max_len)
            if max_len_item.text() != max_len_str:
                max_len_item.setText(max_len_str)
                max_len_item.setData(Qt.ItemDataRole.UserRole, join.packets.max_len)

        bandwidth_item = self._table.item(row, _COLUMN_BANDWIDTH)
        if bandwidth_item is not None:
            bandwidth_str = PlayerBandwidth.format_bytes(join.bandwidth.exchanged)
            if bandwidth_item.text() != bandwidth_str:
                bandwidth_item.setText(bandwidth_str)
                bandwidth_item.setData(Qt.ItemDataRole.UserRole, join.bandwidth.exchanged)

        download_item = self._table.item(row, _COLUMN_DOWNLOAD)
        if download_item is not None:
            download_str = PlayerBandwidth.format_bytes(join.bandwidth.download)
            if download_item.text() != download_str:
                download_item.setText(download_str)
                download_item.setData(Qt.ItemDataRole.UserRole, join.bandwidth.download)

        upload_item = self._table.item(row, _COLUMN_UPLOAD)
        if upload_item is not None:
            upload_str = PlayerBandwidth.format_bytes(join.bandwidth.upload)
            if upload_item.text() != upload_str:
                upload_item.setText(upload_str)
                upload_item.setData(Qt.ItemDataRole.UserRole, join.bandwidth.upload)

    @override
    def closeEvent(self, event: QCloseEvent) -> None:
        """Stop the periodic refresh timer on window close."""
        self._timer.stop()
        super().closeEvent(event)


_active_windows: ActiveDialogRegistry[str, PlayerJoinsWindow] = ActiveDialogRegistry()


def show_player_joins(parent: QWidget | None, player: Player) -> None:
    """Open or focus the Player Joins window for *player*."""
    _active_windows.show_or_focus(player.ip, lambda: PlayerJoinsWindow(parent, player))
