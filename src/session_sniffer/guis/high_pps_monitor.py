"""High Rate Monitor window — tracks players exceeding configurable PPS and BPS thresholds."""

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING

from PyQt6.QtCore import QAbstractTableModel, QModelIndex, QPoint, Qt, QTimer
from PyQt6.QtGui import QAction
from PyQt6.QtWidgets import (
    QHeaderView,
    QMenu,
    QPushButton,
    QSpinBox,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.external import LOCAL_TZ
from session_sniffer.guis.player_rate_graph import PlayerRateGraphWindow
from session_sniffer.models.player import PlayerBandwidth
from session_sniffer.player.registry import PlayersRegistry
from session_sniffer.settings import Settings

if TYPE_CHECKING:
    from session_sniffer.models.player import Player

PPS_THRESHOLD_DEFAULT = 30
PPS_THRESHOLD_MIN = 20
PPS_THRESHOLD_MAX = 50

BPS_THRESHOLD_DEFAULT_KBS = 5
BPS_THRESHOLD_MIN_KBS = 5
BPS_THRESHOLD_MAX_KBS = 500

DURATION_THRESHOLD_DEFAULT_SECS = 3
DURATION_THRESHOLD_MIN_SECS = 1
DURATION_THRESHOLD_MAX_SECS = 10

_BUTTON_WIDTH = 250
_UPDATE_INTERVAL_MS = 1_000
_KBS_TO_BYTES = 1024


def _make_rate_history() -> deque[int]:
    return deque(maxlen=Settings.gui_rate_graph_max_history)


@dataclass(kw_only=True, slots=True)
class _PlayerRateData:
    ip: str
    pps: int
    bps: int = 0
    usernames: list[str] = field(default_factory=list)

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
    _COL_USERNAME = 0
    _COL_PPS = 1
    _COL_BPS = 2
    _COL_IP = 3
    _COL_DURATION = 4
    _COL_TOTAL_DURATION = 5
    _HEADERS = ('Username', 'PPS', 'BPS', 'IP', 'Duration (s)', 'Total Duration (s)')
    _HEADER_TOOLTIPS = (
        'Username(s) associated with this IP.',
        'Packets Per Second — the number of network packets this IP is sending/receiving right now.',
        'Bytes Per Second — the amount of data (bandwidth) this IP is sending/receiving right now.',
        'The IP address of the player being tracked.',
        'How many consecutive seconds this IP has been above both PPS and BPS thresholds in the current streak.',
        'Total cumulative seconds this IP has been above both thresholds since it was first detected (includes all streaks).',
    )

    def __init__(self) -> None:
        super().__init__()
        self._tracked: dict[str, _PlayerRateData] = {}
        self._visible: list[_PlayerRateData] = []
        self.pps_threshold = PPS_THRESHOLD_DEFAULT
        self.bps_threshold = BPS_THRESHOLD_DEFAULT_KBS * _KBS_TO_BYTES
        self.required_duration = DURATION_THRESHOLD_DEFAULT_SECS

    # Qt overrides -----------------------------------------------------------

    def rowCount(self, parent: QModelIndex | None = None) -> int:  # noqa: N802
        """Return the number of visible high-rate players."""
        if parent is None:
            parent = QModelIndex()
        return len(self._visible)

    def columnCount(self, parent: QModelIndex | None = None) -> int:  # noqa: N802
        """Return the number of columns."""
        if parent is None:
            parent = QModelIndex()
        return len(self._HEADERS)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> object:
        """Return cell data for the given index."""
        if not index.isValid() or role != Qt.ItemDataRole.DisplayRole:
            return None
        player = self._visible[index.row()]
        col = index.column()
        if col == self._COL_PPS:
            return player.pps
        if col == self._COL_BPS:
            return PlayerBandwidth.format_bytes(player.bps)
        if col == self._COL_IP:
            return player.ip
        if col == self._COL_USERNAME:
            return ', '.join(player.usernames) if player.usernames else '—'
        return player.current_pps_duration if col == self._COL_DURATION else player.total_pps_duration

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole) -> object:  # noqa: N802
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
            ip = player.ip
            connected_ips.add(ip)
            pps_rate = player.packets.pps.calculated_rate
            bps_rate = player.bandwidth.bps.calculated_rate
            if ip not in self._tracked:
                self._tracked[ip] = _PlayerRateData(ip=ip, pps=pps_rate, bps=bps_rate)
            self._tracked[ip].usernames = list(player.usernames)
            self._tracked[ip].update_pps_stats(
                now=now,
                pps=pps_rate,
                threshold=self.pps_threshold,
                required_duration=self.required_duration,
            )
            self._tracked[ip].update_bps_stats(
                now=now,
                bps=bps_rate,
                threshold=self.bps_threshold,
                required_duration=self.required_duration,
            )

        for ip in self._tracked.keys() - connected_ips:
            del self._tracked[ip]

        new_visible = sorted(
            (p for p in self._tracked.values() if p.is_high_pps and p.is_high_bps),
            key=lambda p: (p.current_pps_duration, p.total_pps_duration, p.pps, p.bps, p.ip),
            reverse=True,
        )
        old_len = len(self._visible)
        new_len = len(new_visible)

        if old_len == new_len:
            # Only emit dataChanged when visible content actually differs
            if new_len and any(
                a.ip != b.ip or a.pps != b.pps or a.bps != b.bps
                or a.current_pps_duration != b.current_pps_duration
                or a.total_pps_duration != b.total_pps_duration
                or a.usernames != b.usernames
                for a, b in zip(new_visible, self._visible, strict=True)
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
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._show_context_menu)
        self._table.setToolTip(
            'Players currently exceeding both PPS and BPS thresholds.\n'
            'Right-click a row to blacklist the IP or open a live rate graph.\n\n'
            'Tip: Players who are moving generate more traffic and are easier to detect.\n'
            'A stationary player may not exceed the thresholds.',
        )
        vertical_header = self._table.verticalHeader()
        if vertical_header is None:
            msg = 'Failed to get vertical header'
            raise RuntimeError(msg)
        vertical_header.setVisible(False)
        header = self._table.horizontalHeader()
        if header is None:
            msg = 'Failed to get horizontal header'
            raise RuntimeError(msg)
        header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        header.setSectionsClickable(False)
        header.setSortIndicatorShown(False)
        self._table.setSortingEnabled(False)
        layout.addWidget(self._table)

        # PPS threshold spinner
        self._pps_threshold_input = QSpinBox()
        self._pps_threshold_input.setFixedWidth(_BUTTON_WIDTH)
        self._pps_threshold_input.setRange(PPS_THRESHOLD_MIN, PPS_THRESHOLD_MAX)
        self._pps_threshold_input.setValue(PPS_THRESHOLD_DEFAULT)
        self._pps_threshold_input.setSuffix(' PPS threshold')
        self._pps_threshold_input.setToolTip(
            'Packets Per Second threshold.\n\n'
            f'Range: {PPS_THRESHOLD_MIN}\u2013{PPS_THRESHOLD_MAX} PPS.\n'
            'A player must send/receive at least this many packets per second '
            'to be considered high-rate. Lower = more sensitive, higher = fewer false positives.\n\n'
            'Tip: Moving players generate more packets than stationary ones.',
        )
        pps_line_edit = self._pps_threshold_input.lineEdit()
        if pps_line_edit is not None:
            pps_line_edit.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._pps_threshold_input.valueChanged.connect(self._set_pps_threshold)
        layout.addWidget(self._pps_threshold_input, alignment=Qt.AlignmentFlag.AlignHCenter)

        # BPS threshold spinner (displayed in KB/s, stored as bytes/s)
        self._bps_threshold_input = QSpinBox()
        self._bps_threshold_input.setFixedWidth(_BUTTON_WIDTH)
        self._bps_threshold_input.setRange(BPS_THRESHOLD_MIN_KBS, BPS_THRESHOLD_MAX_KBS)
        self._bps_threshold_input.setValue(BPS_THRESHOLD_DEFAULT_KBS)
        self._bps_threshold_input.setSuffix(' KB/s threshold')
        self._bps_threshold_input.setSingleStep(5)
        self._bps_threshold_input.setToolTip(
            'Bytes Per Second (bandwidth) threshold, displayed in KB/s.\n\n'
            f'Range: {BPS_THRESHOLD_MIN_KBS}\u2013{BPS_THRESHOLD_MAX_KBS} KB/s.\n'
            'A player must transfer at least this much data per second '
            'to be considered high-rate. Works together with the PPS threshold \u2014 '
            'both must be exceeded simultaneously.\n\n'
            'Tip: Moving players generate more bandwidth than stationary ones.',
        )
        bps_line_edit = self._bps_threshold_input.lineEdit()
        if bps_line_edit is not None:
            bps_line_edit.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._bps_threshold_input.valueChanged.connect(self._set_bps_threshold)
        layout.addWidget(self._bps_threshold_input, alignment=Qt.AlignmentFlag.AlignHCenter)

        # Duration spinner (shared for both PPS and BPS)
        self._duration_input = QSpinBox()
        self._duration_input.setFixedWidth(_BUTTON_WIDTH)
        self._duration_input.setRange(DURATION_THRESHOLD_MIN_SECS, DURATION_THRESHOLD_MAX_SECS)
        self._duration_input.setValue(DURATION_THRESHOLD_DEFAULT_SECS)
        self._duration_input.setSuffix('s (required duration)')
        self._duration_input.setToolTip(
            'How many consecutive seconds a player must stay above both thresholds '
            'before being flagged as high-rate.\n\n'
            f'Range: {DURATION_THRESHOLD_MIN_SECS}\u2013{DURATION_THRESHOLD_MAX_SECS} seconds.\n'
            'Higher values reduce false positives from short traffic bursts. '
            'Lower values detect spikes faster but may flag normal activity.',
        )
        duration_line_edit = self._duration_input.lineEdit()
        if duration_line_edit is not None:
            duration_line_edit.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._duration_input.valueChanged.connect(self._set_required_duration)
        layout.addWidget(self._duration_input, alignment=Qt.AlignmentFlag.AlignHCenter)

        # Buttons
        open_all_graphs = QPushButton('Open Graphs for All Flagged Players')
        open_all_graphs.setToolTip(
            'Opens a live PPS/BPS rate graph window for every player currently\n'
            'listed in the table (exceeding both thresholds).\n\n'
            'Each graph updates in real time so you can visually compare traffic patterns.',
        )
        open_all_graphs.setFixedWidth(_BUTTON_WIDTH)
        open_all_graphs.clicked.connect(self._open_all_graphs)
        layout.addWidget(open_all_graphs, alignment=Qt.AlignmentFlag.AlignHCenter)

        reset_button = QPushButton('Reset Scan')
        reset_button.setToolTip(
            'Clears all tracked data, rate history, and flagged players.\n'
            'The scan restarts from scratch immediately.',
        )
        reset_button.setFixedWidth(_BUTTON_WIDTH)
        reset_button.clicked.connect(self._reset_scan)
        layout.addWidget(reset_button, alignment=Qt.AlignmentFlag.AlignHCenter)

        clear_bl_button = QPushButton('Clear Blacklist')
        clear_bl_button.setToolTip(
            'Removes all IPs from the blacklist so they can be tracked again.\n\n'
            'Blacklisted IPs are ones you right-clicked and chose to exclude. '
            'This button un-excludes all of them.',
        )
        clear_bl_button.setFixedWidth(_BUTTON_WIDTH)
        clear_bl_button.clicked.connect(self._clear_blacklist)
        layout.addWidget(clear_bl_button, alignment=Qt.AlignmentFlag.AlignHCenter)

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
        players = [
            p for p in PlayersRegistry.get_connected_players()
            if p.ip not in self._blacklisted_ips
        ]
        self._model.update_data(players)

        for ip, graph in list(self._graph_windows.items()):
            data = self._model.get_tracked(ip)
            graph.update_rates(
                pps=data.pps if data else 0,
                bps=data.bps if data else 0,
            )

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
            max_history=Settings.gui_rate_graph_max_history,
            always_on_top=Settings.gui_rate_graph_always_on_top,
        )
        data = self._model.get_tracked(ip)
        if data is not None:
            graph.load_history(pps_history=list(data.pps_history), bps_history=list(data.bps_history))
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

    def _show_context_menu(self, pos: QPoint) -> None:
        index = self._table.indexAt(pos)
        if not index.isValid():
            return

        data = self._model.get_visible_player(index.row())
        if data is None:
            return

        menu = QMenu(self)

        blacklist_action = QAction(f'Blacklist IP {data.ip}', self)
        blacklist_action.triggered.connect(lambda: self._blacklist_ip(data.ip))
        menu.addAction(blacklist_action)

        graph_action = QAction(f'Show Rate Graph for {data.ip}', self)
        graph_action.triggered.connect(lambda: self.open_graph(data.ip))
        menu.addAction(graph_action)

        viewport = self._table.viewport()
        if viewport is None:
            msg = 'Failed to get table viewport'
            raise RuntimeError(msg)
        menu.popup(viewport.mapToGlobal(pos))

    def _blacklist_ip(self, ip: str) -> None:
        self._blacklisted_ips.add(ip)
        self._scan_players()
