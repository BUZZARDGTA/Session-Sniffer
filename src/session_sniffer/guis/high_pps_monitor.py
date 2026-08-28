"""High Rate Monitor window — tracks players exceeding configurable PPS and BPS thresholds."""

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, override

from PySide6.QtCore import QAbstractTableModel, QItemSelectionModel, QModelIndex, QPersistentModelIndex, QPoint, Qt, QTimer
from PySide6.QtGui import QAction, QIcon, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QMenu,
    QPushButton,
    QSpinBox,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.external import LOCAL_TZ
from session_sniffer.constants.local import RESOURCES_DIR_PATH
from session_sniffer.guis.player_rate_graph import DEFAULT_MAX_HISTORY, PlayerRateGraphWindow
from session_sniffer.guis.stylesheets import SVG_ICON_CONTEXT_MENU_STYLESHEET
from session_sniffer.guis.utils import popup_menu_at_table, set_clipboard_text, setup_table_view_headers
from session_sniffer.models.player import PlayerBandwidth
from session_sniffer.player.registry import PlayersRegistry
from session_sniffer.text_utils import pluralize

if TYPE_CHECKING:
    from session_sniffer.models.player import Player

PPS_THRESHOLD_DEFAULT = 30
PPS_THRESHOLD_MIN = 20
PPS_THRESHOLD_MAX = 50

BPS_THRESHOLD_DEFAULT_KBS = 5
BPS_THRESHOLD_MIN_KBS = 5
BPS_THRESHOLD_MAX_KBS = 500

DURATION_THRESHOLD_DEFAULT_SECONDS = 3
DURATION_THRESHOLD_MIN_SECONDS = 1
DURATION_THRESHOLD_MAX_SECONDS = 10

_BUTTON_WIDTH = 250
_UPDATE_INTERVAL_MS = 1_000
_KBS_TO_BYTES = 1024


def _make_rate_history() -> deque[int]:
    return deque(maxlen=DEFAULT_MAX_HISTORY)


@dataclass(kw_only=True, slots=True)
class _PlayerRateData:
    ip: str
    pps: int
    bps: int = 0
    usernames: list[str] = field(default_factory=list[str])

    # Rate history (rolling window matching graph length)
    pps_history: deque[int] = field(default_factory=_make_rate_history)
    bps_history: deque[int] = field(default_factory=_make_rate_history)

    # PPS tracking
    first_high_pps_time: datetime | None = None
    newer_high_pps_time: datetime | None = None
    is_high_pps: bool = False
    current_pps_duration: int = 0
    total_pps_duration: int = 0

    # BPS tracking
    first_high_bps_time: datetime | None = None
    newer_high_bps_time: datetime | None = None
    is_high_bps: bool = False
    current_bps_duration: int = 0
    total_bps_duration: int = 0

    def update_pps_stats(self, *, now: datetime, pps: int, threshold: int, required_duration: int) -> None:
        """Update high-PPS status for this player."""
        self.pps = pps
        self.pps_history.append(pps)
        if pps < threshold:
            self.is_high_pps = False
            self.newer_high_pps_time = None
            self.current_pps_duration = 0
            return

        if self.first_high_pps_time is None:
            self.first_high_pps_time = now
        if self.newer_high_pps_time is None:
            self.newer_high_pps_time = now

        self.current_pps_duration = int((now - self.newer_high_pps_time).total_seconds())
        self.total_pps_duration = int((now - self.first_high_pps_time).total_seconds())

        if self.current_pps_duration >= required_duration:
            self.is_high_pps = True

    def update_bps_stats(self, *, now: datetime, bps: int, threshold: int, required_duration: int) -> None:
        """Update high-BPS status for this player."""
        self.bps = bps
        self.bps_history.append(bps)
        if bps < threshold:
            self.is_high_bps = False
            self.newer_high_bps_time = None
            self.current_bps_duration = 0
            return

        if self.first_high_bps_time is None:
            self.first_high_bps_time = now
        if self.newer_high_bps_time is None:
            self.newer_high_bps_time = now

        self.current_bps_duration = int((now - self.newer_high_bps_time).total_seconds())
        self.total_bps_duration = int((now - self.first_high_bps_time).total_seconds())

        if self.current_bps_duration >= required_duration:
            self.is_high_bps = True


class _HighRateTableModel(QAbstractTableModel):
    _COLUMN_USERNAME = 0
    _COLUMN_IP = 1
    _COLUMN_PPS = 2
    _COLUMN_BPS = 3
    COLUMN_DURATION = 4
    _COLUMN_TOTAL_DURATION = 5
    _HEADERS = ('Username', 'IP', 'PPS', 'BPS', 'Duration (s)', 'Total Duration (s)')
    _HEADER_TOOLTIPS = (
        'Usernames associated with this IP.',
        'The IP address of the player being tracked.',
        'Packets Per Second — the number of network packets this IP is sending/receiving right now.',
        'Bytes Per Second — the amount of data (bandwidth) this IP is sending/receiving right now.',
        'How many consecutive seconds this IP has been above both PPS and BPS thresholds in the current streak.',
        'Total cumulative seconds this IP has been above both thresholds since it was first detected (includes all streaks).',
    )

    def __init__(self) -> None:
        super().__init__()
        self._tracked: dict[str, _PlayerRateData] = {}
        self._visible: list[_PlayerRateData] = []
        self.pps_threshold = PPS_THRESHOLD_DEFAULT
        self.bps_threshold = BPS_THRESHOLD_DEFAULT_KBS * _KBS_TO_BYTES
        self.required_duration = DURATION_THRESHOLD_DEFAULT_SECONDS

    # Qt overrides -----------------------------------------------------------

    @override
    def rowCount(self, parent: QModelIndex | QPersistentModelIndex | None = None) -> int:
        """Return the number of visible high-rate players."""
        if parent is None:
            parent = QModelIndex()
        return len(self._visible)

    @override
    def columnCount(self, parent: QModelIndex | QPersistentModelIndex | None = None) -> int:
        """Return the number of columns."""
        if parent is None:
            parent = QModelIndex()
        return len(self._HEADERS)

    @override
    def data(self, index: QModelIndex | QPersistentModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> object:
        """Return cell data for the given index."""
        if not index.isValid() or role != Qt.ItemDataRole.DisplayRole:
            return None
        player = self._visible[index.row()]
        column = index.column()
        if column == self._COLUMN_PPS:
            return player.pps
        if column == self._COLUMN_BPS:
            return PlayerBandwidth.format_bytes(player.bps)
        if column == self._COLUMN_IP:
            return player.ip
        if column == self._COLUMN_USERNAME:
            return ', '.join(player.usernames) if player.usernames else '—'
        return player.current_pps_duration if column == self.COLUMN_DURATION else player.total_pps_duration

    @override
    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole) -> object:
        """Return column header labels and tooltips."""
        if orientation != Qt.Orientation.Horizontal:
            return None
        if role == Qt.ItemDataRole.DisplayRole:
            return self._HEADERS[section]
        if role == Qt.ItemDataRole.ToolTipRole:
            return self._HEADER_TOOLTIPS[section]
        return None

    # Public API -------------------------------------------------------------

    def update_data(self, players: list[Player]) -> None:
        """Refresh high-rate tracking from the given connected players."""
        now = datetime.now(tz=LOCAL_TZ)
        connected_ips: set[str] = set()
        for player in players:
            connected_ips.add(player.ip)
            if player.ip not in self._tracked:
                self._tracked[player.ip] = _PlayerRateData(ip=player.ip, pps=player.packets.pps.calculated_rate, bps=player.bandwidth.bps.calculated_rate)
            self._tracked[player.ip].usernames = list(player.usernames)
            self._tracked[player.ip].update_pps_stats(
                now=now,
                pps=player.packets.pps.calculated_rate,
                threshold=self.pps_threshold,
                required_duration=self.required_duration,
            )
            self._tracked[player.ip].update_bps_stats(
                now=now,
                bps=player.bandwidth.bps.calculated_rate,
                threshold=self.bps_threshold,
                required_duration=self.required_duration,
            )

        for ip in self._tracked.keys() - connected_ips:
            del self._tracked[ip]

        new_visible = sorted(
            (player for player in self._tracked.values() if player.is_high_pps and player.is_high_bps),
            key=lambda player: (player.current_pps_duration, player.total_pps_duration, player.pps, player.bps, player.ip),
            reverse=True,
        )
        old_len = len(self._visible)
        new_len = len(new_visible)

        if old_len == new_len:
            # Only emit dataChanged when visible content actually differs
            if new_len and any(
                first_item.ip != second_item.ip
                or first_item.pps != second_item.pps
                or first_item.bps != second_item.bps
                or first_item.current_pps_duration != second_item.current_pps_duration
                or first_item.total_pps_duration != second_item.total_pps_duration
                or first_item.usernames != second_item.usernames
                for first_item, second_item in zip(new_visible, self._visible, strict=True)
            ):
                self._visible = new_visible
                self.dataChanged.emit(self.index(0, 0), self.index(new_len - 1, len(self._HEADERS) - 1))
        else:
            self.beginResetModel()
            self._visible = new_visible
            self.endResetModel()

    def reset_all(self) -> None:
        """Clear all tracked and visible player data."""
        self.beginResetModel()
        self._tracked.clear()
        self._visible = []
        self.endResetModel()

    def get_visible_player(self, row: int) -> _PlayerRateData | None:
        """Return the visible player at the given row, or None."""
        if 0 <= row < len(self._visible):
            return self._visible[row]
        return None

    def get_tracked(self, ip: str) -> _PlayerRateData | None:
        """Return the tracked data for the given IP, or None."""
        return self._tracked.get(ip)

    def get_all_visible(self) -> list[_PlayerRateData]:
        """Return a copy of the visible players list."""
        return list(self._visible)


class HighRateMonitorWidget(QWidget):
    """Widget listing players that exceed configurable PPS and BPS thresholds."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the High Rate Monitor widget."""
        super().__init__(parent)

        layout = QVBoxLayout(self)

        # Table
        self._model = _HighRateTableModel()
        self._table = QTableView()
        self._table.setModel(self._model)
        self._table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QTableView.SelectionMode.ExtendedSelection)
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._show_context_menu)
        QShortcut(QKeySequence('Ctrl+C'), self._table).activated.connect(self._copy_selected_rows)
        QShortcut(QKeySequence('Ctrl+A'), self._table).activated.connect(self._table.selectAll)
        self._table.setToolTip(
            'Players currently exceeding both PPS and BPS thresholds.\n'
            'Right-click a row to blacklist the IP or open a live rate graph.\n\n'
            'Tip: Players who are moving generate more traffic and are easier to detect.\n'
            'A stationary player may not exceed the thresholds.',
        )
        header = setup_table_view_headers(self._table)
        header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        header.setSectionsClickable(False)
        header.setSortIndicatorShown(True)
        header.setSortIndicator(self._model.COLUMN_DURATION, Qt.SortOrder.DescendingOrder)
        self._table.setSortingEnabled(False)
        layout.addWidget(self._table)

        # Parameters control panel
        params_box = QGroupBox('⚙ Thresholds')
        params_layout = QHBoxLayout(params_box)
        params_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # PPS threshold spinner
        self._pps_threshold_input = QSpinBox()
        self._pps_threshold_input.setFixedWidth(_BUTTON_WIDTH)
        self._pps_threshold_input.setRange(PPS_THRESHOLD_MIN, PPS_THRESHOLD_MAX)
        self._pps_threshold_input.setValue(PPS_THRESHOLD_DEFAULT)
        self._pps_threshold_input.setSuffix(' PPS threshold')
        self._pps_threshold_input.setToolTip(
            'Packets Per Second threshold.\n\n'
            f'Range: {PPS_THRESHOLD_MIN}-{PPS_THRESHOLD_MAX} PPS.\n'
            'A player must send/receive at least this many packets per second '
            'to be considered high-rate. Lower = more sensitive, higher = fewer false positives.\n\n'
            'Tip: Moving players generate more packets than stationary ones.',
        )
        pps_line_edit = self._pps_threshold_input.lineEdit()
        if pps_line_edit:
            pps_line_edit.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._pps_threshold_input.valueChanged.connect(self._set_pps_threshold)
        params_layout.addWidget(self._pps_threshold_input)

        # BPS threshold spinner (displayed in KB/s, stored as bytes/s)
        self._bps_threshold_input = QSpinBox()
        self._bps_threshold_input.setFixedWidth(_BUTTON_WIDTH)
        self._bps_threshold_input.setRange(BPS_THRESHOLD_MIN_KBS, BPS_THRESHOLD_MAX_KBS)
        self._bps_threshold_input.setValue(BPS_THRESHOLD_DEFAULT_KBS)
        self._bps_threshold_input.setSuffix(' KB/s threshold')
        self._bps_threshold_input.setSingleStep(5)
        self._bps_threshold_input.setToolTip(
            'Bytes Per Second (bandwidth) threshold, displayed in KB/s.\n\n'
            f'Range: {BPS_THRESHOLD_MIN_KBS}-{BPS_THRESHOLD_MAX_KBS} KB/s.\n'
            'A player must transfer at least this much data per second '
            'to be considered high-rate. Works together with the PPS threshold — '
            'both must be exceeded simultaneously.\n\n'
            'Tip: Moving players generate more bandwidth than stationary ones.',
        )
        bps_line_edit = self._bps_threshold_input.lineEdit()
        if bps_line_edit:
            bps_line_edit.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._bps_threshold_input.valueChanged.connect(self._set_bps_threshold)
        params_layout.addWidget(self._bps_threshold_input)

        # Duration spinner (shared for both PPS and BPS)
        self._duration_input = QSpinBox()
        self._duration_input.setFixedWidth(_BUTTON_WIDTH)
        self._duration_input.setRange(DURATION_THRESHOLD_MIN_SECONDS, DURATION_THRESHOLD_MAX_SECONDS)
        self._duration_input.setValue(DURATION_THRESHOLD_DEFAULT_SECONDS)
        self._duration_input.setSuffix('s (required duration)')
        self._duration_input.setToolTip(
            'How many consecutive seconds a player must stay above both thresholds '
            'before being flagged as high-rate.\n\n'
            f'Range: {DURATION_THRESHOLD_MIN_SECONDS}-{DURATION_THRESHOLD_MAX_SECONDS} seconds.\n'
            'Higher values reduce false positives from short traffic bursts. '
            'Lower values detect spikes faster but may flag normal activity.',
        )
        duration_line_edit = self._duration_input.lineEdit()
        if duration_line_edit:
            duration_line_edit.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._duration_input.valueChanged.connect(self._set_required_duration)
        params_layout.addWidget(self._duration_input)

        layout.addWidget(params_box)

        # Buttons
        buttons_layout = QHBoxLayout()
        buttons_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        open_all_graphs = QPushButton('Open Graphs for All Flagged Players')
        open_all_graphs.setToolTip(
            'Opens a live PPS/BPS rate graph window for every player currently\n'
            'listed in the table (exceeding both thresholds).\n\n'
            'Each graph updates in real time so you can visually compare traffic patterns.',
        )
        open_all_graphs.setFixedWidth(_BUTTON_WIDTH)
        open_all_graphs.clicked.connect(self._open_all_graphs)
        buttons_layout.addWidget(open_all_graphs)

        reset_button = QPushButton('Reset Scan')
        reset_button.setToolTip(
            'Clears all tracked data, rate history, and flagged players.\nThe scan restarts from scratch immediately.',
        )
        reset_button.setFixedWidth(_BUTTON_WIDTH)
        reset_button.clicked.connect(self._reset_scan)
        buttons_layout.addWidget(reset_button)

        clear_bl_button = QPushButton('Clear Blacklist')
        clear_bl_button.setToolTip(
            'Removes all IPs from the blacklist so they can be tracked again.\n\n'
            'Blacklisted IPs are ones you right-clicked and chose to exclude. '
            'This button un-excludes all of them.',
        )
        clear_bl_button.setFixedWidth(_BUTTON_WIDTH)
        clear_bl_button.clicked.connect(self._clear_blacklist)
        buttons_layout.addWidget(clear_bl_button)

        layout.addLayout(buttons_layout)

        # State
        self._blacklisted_ips: set[str] = set()
        self._graph_windows: dict[str, PlayerRateGraphWindow] = {}

        # Periodic scan timer
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._scan_players)
        self._timer.start(_UPDATE_INTERVAL_MS)
        self._scan_players()

    # Scanning ---------------------------------------------------------------

    def _scan_players(self) -> None:
        players = [player for player in PlayersRegistry.get_connected_players() if player.ip not in self._blacklisted_ips]
        self._model.update_data(players)

        for ip, graph in list(self._graph_windows.items()):
            data = self._model.get_tracked(ip)
            graph.update_rates(
                pps=data.pps if data else 0,
                bps=data.bps if data else 0,
            )
            matched_player = PlayersRegistry.get_player_by_ip(ip)
            graph.update_usernames(matched_player.usernames if matched_player is not None else [])

    # Threshold / duration ---------------------------------------------------

    def _set_pps_threshold(self, value: int) -> None:
        self._model.pps_threshold = value
        for graph in self._graph_windows.values():
            graph.set_pps_threshold(value)

    def _set_bps_threshold(self, value: int) -> None:
        self._model.bps_threshold = value * _KBS_TO_BYTES
        for graph in self._graph_windows.values():
            graph.set_bps_threshold(value * _KBS_TO_BYTES)

    def _set_required_duration(self, value: int) -> None:
        self._model.required_duration = value

    # Graphs -----------------------------------------------------------------

    def open_graph(self, ip: str) -> None:
        """Open or focus a live rate graph window for the given player IP."""
        existing = self._graph_windows.get(ip)
        if existing:
            existing.show()
            existing.raise_()
            existing.activateWindow()
            return

        graph = PlayerRateGraphWindow(
            ip=ip,
            initial_pps_threshold=self._model.pps_threshold,
            initial_bps_threshold=self._model.bps_threshold,
        )
        data = self._model.get_tracked(ip)
        if data is not None:
            graph.load_history(pps_history=list(data.pps_history), bps_history=list(data.bps_history))
        matched_player = PlayersRegistry.get_player_by_ip(ip)
        if matched_player is not None:
            graph.update_usernames(matched_player.usernames)
        graph.show()
        graph.destroyed.connect(lambda: self._graph_windows.pop(ip, None))
        self._graph_windows[ip] = graph

    def _open_all_graphs(self) -> None:
        for player in self._model.get_all_visible():
            self.open_graph(player.ip)

    # Actions ----------------------------------------------------------------

    def _reset_scan(self) -> None:
        self._model.reset_all()

    def _clear_blacklist(self) -> None:
        self._blacklisted_ips.clear()

    # Context menu -----------------------------------------------------------

    # pylint: disable=duplicate-code
    def _copy_selected_rows(self) -> None:
        """Copy selected rows from the high-rate monitor table to clipboard as tab-separated text."""
        selection_model = self._table.selectionModel()
        if not selection_model:
            return
        selected_indexes = selection_model.selectedIndexes()
        if not selected_indexes:
            return

        rows: dict[int, dict[int, str]] = {}
        for model_index in selected_indexes:
            row_index = model_index.row()
            column_index = model_index.column()
            cell_data = model_index.data(Qt.ItemDataRole.DisplayRole)
            rows.setdefault(row_index, {})[column_index] = str(cell_data) if cell_data is not None else ''

        lines: list[str] = []
        for row_index in sorted(rows):
            column_map = rows[row_index]
            lines.append('\t'.join(column_map[column_index] for column_index in sorted(column_map)))

        set_clipboard_text('\n'.join(lines))

    def _copy_all_rows(self) -> None:
        """Copy all rows in the high-rate monitor table to clipboard as tab-separated text."""
        lines: list[str] = []
        column_count = self._model.columnCount()
        row_count = self._model.rowCount()
        for row_index in range(row_count):
            cells: list[str] = []
            for column_index in range(column_count):
                index = self._model.index(row_index, column_index)
                cell_data = self._model.data(index, Qt.ItemDataRole.DisplayRole)
                cells.append(str(cell_data) if cell_data is not None else '')
            lines.append('\t'.join(cells))

        if not lines:
            return

        set_clipboard_text('\n'.join(lines))
    # pylint: enable=duplicate-code

    # pylint: disable=duplicate-code
    def _show_context_menu(self, pos: QPoint) -> None:
        index = self._table.indexAt(pos)
        if not index.isValid():
            return

        selection_model = self._table.selectionModel()
        if selection_model and not selection_model.isSelected(index):
            selection_model.select(index, QItemSelectionModel.SelectionFlag.ClearAndSelect | QItemSelectionModel.SelectionFlag.Rows)

        selected_rows = selection_model.selectedRows() if selection_model else []
        if not selected_rows:
            selected_rows = [index]

        selected_players: list[_PlayerRateData] = []
        for model_index in selected_rows:
            player_data = self._model.get_visible_player(model_index.row())
            if player_data is not None:
                selected_players.append(player_data)

        if not selected_players:
            return

        menu = QMenu(self)
        menu.setStyleSheet(SVG_ICON_CONTEXT_MENU_STYLESHEET)
        menu.setToolTipsVisible(True)

        if len(selected_players) == 1:
            data = selected_players[0]
            copy_row_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg')), 'Copy Row', self)
            copy_row_action.setShortcut('Ctrl+C')
            copy_row_action.setToolTip('Copy the selected row to the clipboard as tab-separated text.')
            copy_row_action.triggered.connect(self._copy_selected_rows)
            menu.addAction(copy_row_action)

            copy_all_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg')), 'Copy All', self)
            copy_all_action.setToolTip('Copy all visible rows to the clipboard as tab-separated text.')
            copy_all_action.setEnabled(self._model.rowCount() > 0)
            copy_all_action.triggered.connect(self._copy_all_rows)
            menu.addAction(copy_all_action)

            menu.addSeparator()

            copy_ip_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg')), f'Copy IP ({data.ip})', self)
            copy_ip_action.setToolTip("Copy this player's IP address to the clipboard.")
            copy_ip_action.triggered.connect(lambda: set_clipboard_text(data.ip))
            menu.addAction(copy_ip_action)

            usernames_text = ', '.join(data.usernames)
            copy_usernames_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg')), f'Copy Username{pluralize(len(data.usernames))}', self)
            copy_usernames_action.setToolTip('Copy associated usernames to the clipboard.')
            copy_usernames_action.setEnabled(bool(data.usernames))
            copy_usernames_action.triggered.connect(lambda: set_clipboard_text(usernames_text))
            menu.addAction(copy_usernames_action)
        else:
            all_ips = [player_data.ip for player_data in selected_players]
            all_usernames = [username for player_data in selected_players for username in player_data.usernames]

            copy_rows_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg')), f'Copy Rows ({len(selected_players)})', self)
            copy_rows_action.setShortcut('Ctrl+C')
            copy_rows_action.setToolTip('Copy selected rows to the clipboard as tab-separated text.')
            copy_rows_action.triggered.connect(self._copy_selected_rows)
            menu.addAction(copy_rows_action)

            copy_all_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg')), 'Copy All', self)
            copy_all_action.setToolTip('Copy all visible rows to the clipboard as tab-separated text.')
            copy_all_action.setEnabled(self._model.rowCount() > 0)
            copy_all_action.triggered.connect(self._copy_all_rows)
            menu.addAction(copy_all_action)

            menu.addSeparator()

            copy_ips_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg')), f'Copy IPs ({len(all_ips)})', self)
            copy_ips_action.setToolTip('Copy all selected IP addresses.')
            copy_ips_action.triggered.connect(lambda: set_clipboard_text('\n'.join(all_ips)))
            menu.addAction(copy_ips_action)

            copy_usernames_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg')), f'Copy Usernames ({len(all_usernames)})', self)
            copy_usernames_action.setToolTip('Copy all selected usernames.')
            copy_usernames_action.setEnabled(bool(all_usernames))
            copy_usernames_action.triggered.connect(lambda: set_clipboard_text('\n'.join(all_usernames)))
            menu.addAction(copy_usernames_action)

        menu.addSeparator()

        select_all_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'select_all.svg')), 'Select All', self)
        select_all_action.setShortcut('Ctrl+A')
        select_all_action.setToolTip('Select all rows in the monitor.')
        select_all_action.setEnabled(self._model.rowCount() > 0)
        select_all_action.triggered.connect(self._table.selectAll)
        menu.addAction(select_all_action)

        clear_selection_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'unselect_all.svg')), 'Clear Selection', self)
        clear_selection_action.setToolTip('Deselect all currently selected rows.')
        clear_selection_action.triggered.connect(self._table.clearSelection)
        menu.addAction(clear_selection_action)

        menu.addSeparator()

        if len(selected_players) == 1:
            data = selected_players[0]

            blacklist_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'remove.svg')), f'Blacklist IP {data.ip}', self)
            blacklist_action.setToolTip('Exclude this IP from the high-rate scan until the blacklist is cleared.')
            blacklist_action.triggered.connect(lambda: self._blacklist_ip(data.ip))
            menu.addAction(blacklist_action)

            graph_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'play.svg')), f'Show Rate Graph for {data.ip}', self)
            graph_action.setToolTip('Open a live PPS/BPS rate graph window for this player.')
            graph_action.triggered.connect(lambda: self.open_graph(data.ip))
            menu.addAction(graph_action)
        else:
            all_ips = [player_data.ip for player_data in selected_players]

            blacklist_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'remove.svg')), f'Blacklist Selected IPs ({len(all_ips)})', self)
            blacklist_action.setToolTip('Exclude selected IPs from the high-rate scan until the blacklist is cleared.')

            def _blacklist_multi() -> None:
                for ip_address in all_ips:
                    self._blacklist_ip(ip_address)

            blacklist_action.triggered.connect(_blacklist_multi)
            menu.addAction(blacklist_action)

            graph_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'play.svg')), f'Show Rate Graphs ({len(all_ips)})', self)
            graph_action.setToolTip('Open live PPS/BPS rate graph windows for all selected players.')

            def _open_graphs_multi() -> None:
                for ip_address in all_ips:
                    self.open_graph(ip_address)

            graph_action.triggered.connect(_open_graphs_multi)
            menu.addAction(graph_action)

        popup_menu_at_table(menu, self._table, pos)

        self._timer.stop()
        menu.aboutToHide.connect(lambda: self._timer.start(_UPDATE_INTERVAL_MS))
    # pylint: enable=duplicate-code

    def _blacklist_ip(self, ip: str) -> None:
        self._blacklisted_ips.add(ip)
        self._scan_players()
