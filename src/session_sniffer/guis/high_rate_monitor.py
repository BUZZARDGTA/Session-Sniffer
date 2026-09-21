"""High Rate Monitor — tracks players exceeding configurable PPS and BPS thresholds."""

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, ClassVar, override

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QCheckBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.standard import LOCAL_TZ
from session_sniffer.guis.player_rate_graph import DEFAULT_MAX_HISTORY, PlayerRateGraphWindow
from session_sniffer.models.player import PlayerBandwidth
from session_sniffer.networking.third_party_servers import is_third_party_server_ip
from session_sniffer.player.registry import PlayersRegistry
from session_sniffer.text_utils import pluralize

if TYPE_CHECKING:
    from collections.abc import Callable

    from PySide6.QtGui import QHideEvent, QShowEvent

PPS_THRESHOLD_DEFAULT = 30
PPS_THRESHOLD_MIN = 20
PPS_THRESHOLD_MAX = 50

BPS_THRESHOLD_DEFAULT_KBS = 5
BPS_THRESHOLD_MIN_KBS = 3
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


class HighRateTracker:
    """Global tracker for IPs currently flagged as high-rate."""

    flagged_ips: ClassVar[set[str]] = set()

    @classmethod
    def is_high_rate(cls, ip: str) -> bool:
        """Return whether the given IP is currently flagged as high-rate."""
        return ip in cls.flagged_ips

    @classmethod
    def set_flagged_ips(cls, ips: set[str]) -> None:
        """Update the set of flagged high-rate IPs."""
        cls.flagged_ips = ips


class HighRateMonitorWidget(QWidget):
    """Widget monitoring players that exceed configurable PPS and BPS thresholds."""

    def __init__(
        self,
        select_ips_callback: Callable[[list[str]], None] | None = None,
        deselect_ips_callback: Callable[[list[str] | None], None] | None = None,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the High Rate Monitor widget."""
        super().__init__(parent)

        self._select_ips = select_ips_callback
        self._deselect_ips = deselect_ips_callback
        self._tracked: dict[str, _PlayerRateData] = {}
        self._blacklisted_ips: set[str] = set()
        self._graph_windows: dict[str, PlayerRateGraphWindow] = {}
        self._currently_selected_ips: set[str] = set()
        self._auto_select: bool = True

        self.pps_threshold = PPS_THRESHOLD_DEFAULT
        self.bps_threshold = BPS_THRESHOLD_DEFAULT_KBS * _KBS_TO_BYTES
        self.required_duration = DURATION_THRESHOLD_DEFAULT_SECONDS

        layout = QVBoxLayout(self)

        # Status summary label
        self._status_label = QLabel('<b>Status:</b> Initializing scan…')
        self._status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._status_label.setWordWrap(True)
        layout.addWidget(self._status_label)

        # Parameters control panel
        params_box = QGroupBox('Thresholds')
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
        self._bps_threshold_input.setSingleStep(1)
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

        # Selection controls row
        selection_layout = QHBoxLayout()
        selection_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self._select_button = QPushButton('Select in Table')
        self._select_button.setToolTip('Select and scroll to all currently flagged high-rate players in the connected players table.')
        self._select_button.setFixedWidth(140)
        self._select_button.clicked.connect(self._select_flagged)
        self._select_button.setEnabled(False)
        selection_layout.addWidget(self._select_button)

        self._deselect_button = QPushButton('Deselect in Table')
        self._deselect_button.setToolTip('Deselect all currently flagged high-rate players in the connected players table.')
        self._deselect_button.setFixedWidth(140)
        self._deselect_button.clicked.connect(self._deselect_flagged)
        self._deselect_button.setEnabled(False)
        selection_layout.addWidget(self._deselect_button)

        self._auto_select_checkbox = QCheckBox('Auto-select in Table')
        self._auto_select_checkbox.setToolTip(
            'Keep high-rate players selected in the connected players table automatically.\n\n'
            'Live updates occur with every scan. Turn off for manual selection control.',
        )
        self._auto_select_checkbox.setChecked(True)
        self._auto_select_checkbox.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self._auto_select_checkbox.toggled.connect(self._on_auto_select_toggled)
        selection_layout.addWidget(self._auto_select_checkbox)

        layout.addLayout(selection_layout)

        # Action buttons row
        actions_layout = QHBoxLayout()
        actions_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        open_all_graphs = QPushButton('Open Graphs for Flagged Players')
        open_all_graphs.setToolTip(
            'Opens a live PPS/BPS rate graph window for every player currently\n'
            'exceeding both thresholds.\n\n'
            'Each graph updates in real time so you can visually compare traffic patterns.',
        )
        open_all_graphs.setFixedWidth(240)
        open_all_graphs.clicked.connect(self._open_all_graphs)
        actions_layout.addWidget(open_all_graphs)

        reset_button = QPushButton('Reset Scan')
        reset_button.setToolTip(
            'Clears all tracked data, rate history, and flagged players.\nThe scan restarts from scratch immediately.',
        )
        reset_button.setFixedWidth(130)
        reset_button.clicked.connect(self.reset_all)
        actions_layout.addWidget(reset_button)

        clear_bl_button = QPushButton('Clear Blacklist')
        clear_bl_button.setToolTip(
            'Removes all IPs from the blacklist so they can be tracked again.\n\n'
            'Blacklisted IPs are excluded from high-rate detection.',
        )
        clear_bl_button.setFixedWidth(130)
        clear_bl_button.clicked.connect(self._clear_blacklist)
        actions_layout.addWidget(clear_bl_button)

        layout.addLayout(actions_layout)

        # Periodic scan timer
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._scan_players)
        self._timer.start(_UPDATE_INTERVAL_MS)
        self._scan_players()

    # Scanning ---------------------------------------------------------------

    def _scan_players(self) -> None:
        players = [
            player
            for player in PlayersRegistry.get_connected_players()
            if player.ip not in self._blacklisted_ips and not is_third_party_server_ip(player.ip)
        ]

        now = datetime.now(tz=LOCAL_TZ)
        connected_ips: set[str] = set()
        for player in players:
            connected_ips.add(player.ip)
            if player.ip not in self._tracked:
                self._tracked[player.ip] = _PlayerRateData(
                    ip=player.ip,
                    pps=player.packets.pps.calculated_rate,
                    bps=player.bandwidth.bps.calculated_rate,
                )
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

        flagged_players = [player for player in self._tracked.values() if player.is_high_pps and player.is_high_bps]
        flagged_ips = {player.ip for player in flagged_players}
        HighRateTracker.set_flagged_ips(flagged_ips)

        if not self.isVisible():
            if self._auto_select and self._currently_selected_ips and self._deselect_ips is not None:
                self._deselect_ips(list(self._currently_selected_ips))
                self._currently_selected_ips.clear()
        elif self._auto_select and flagged_ips != self._currently_selected_ips:
            if flagged_ips:
                if self._select_ips is not None:
                    self._select_ips(list(flagged_ips))
            elif self._currently_selected_ips and self._deselect_ips is not None:
                self._deselect_ips(list(self._currently_selected_ips))
            self._currently_selected_ips = set(flagged_ips)

        for ip, graph in list(self._graph_windows.items()):
            data = self._tracked.get(ip)
            graph.update_rates(
                pps=data.pps if data else 0,
                bps=data.bps if data else 0,
            )
            matched_player = PlayersRegistry.get_player_by_ip(ip)
            graph.update_usernames(matched_player.usernames if matched_player is not None else [])

        self._update_status_display(flagged_players)

    def _update_status_display(self, flagged_players: list[_PlayerRateData]) -> None:
        num_flagged = len(flagged_players)
        if not num_flagged:
            num_connected = len(self._tracked)
            self._status_label.setText(
                f'<b>No high-rate players detected.</b><br>'
                f'<small>Monitoring {num_connected} connected IP{pluralize(num_connected)}.</small>',
            )
            return

        lines: list[str] = [
            f'<b style="color:#e74c3c;">{num_flagged} player{pluralize(num_flagged)} currently exceeding thresholds:</b>',
        ]
        for player in flagged_players:
            name_part = f' ({", ".join(player.usernames)})' if player.usernames else ''
            formatted_bps = PlayerBandwidth.format_bytes(player.bps)
            lines.append(
                f'• <b>{player.ip}</b>{name_part} — {player.pps} PPS · {formatted_bps} · streak: {player.current_pps_duration}s (total: {player.total_pps_duration}s)',
            )
        lines.append('<small>Flagged players are marked with a speedometer icon in the connected players table.</small>')
        self._status_label.setText('<br>'.join(lines))

    # Threshold / duration ---------------------------------------------------

    def _set_pps_threshold(self, value: int) -> None:
        self.pps_threshold = value
        for graph in self._graph_windows.values():
            graph.set_pps_threshold(value)

    def _set_bps_threshold(self, value: int) -> None:
        self.bps_threshold = value * _KBS_TO_BYTES
        for graph in self._graph_windows.values():
            graph.set_bps_threshold(value * _KBS_TO_BYTES)

    def _set_required_duration(self, value: int) -> None:
        self.required_duration = value

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
            initial_pps_threshold=self.pps_threshold,
            initial_bps_threshold=self.bps_threshold,
        )
        data = self._tracked.get(ip)
        if data is not None:
            graph.load_history(pps_history=list(data.pps_history), bps_history=list(data.bps_history))
        matched_player = PlayersRegistry.get_player_by_ip(ip)
        if matched_player is not None:
            graph.update_usernames(matched_player.usernames)
        graph.show()
        graph.destroyed.connect(lambda: self._graph_windows.pop(ip, None))
        self._graph_windows[ip] = graph

    def _open_all_graphs(self) -> None:
        for player in self._tracked.values():
            if player.is_high_pps and player.is_high_bps:
                self.open_graph(player.ip)

    # Actions ----------------------------------------------------------------

    def _on_auto_select_toggled(self, checked: bool) -> None:  # noqa: FBT001
        self._auto_select = checked
        self._select_button.setEnabled(not checked)
        self._deselect_button.setEnabled(not checked)
        if checked:
            flagged_ips = [p.ip for p in self._tracked.values() if p.is_high_pps and p.is_high_bps]
            if flagged_ips and self._select_ips is not None:
                self._select_ips(flagged_ips)
                self._currently_selected_ips = set(flagged_ips)
        elif self._currently_selected_ips and self._deselect_ips is not None:
            self._deselect_ips(list(self._currently_selected_ips))
            self._currently_selected_ips.clear()

    def _select_flagged(self) -> None:
        if self._select_ips is not None:
            flagged_ips = [p.ip for p in self._tracked.values() if p.is_high_pps and p.is_high_bps]
            if flagged_ips:
                self._select_ips(flagged_ips)
                self._currently_selected_ips = set(flagged_ips)

    def _deselect_flagged(self) -> None:
        if self._deselect_ips is not None:
            flagged_ips = {p.ip for p in self._tracked.values() if p.is_high_pps and p.is_high_bps}
            ips_to_deselect = list(self._currently_selected_ips | flagged_ips)
            self._deselect_ips(ips_to_deselect or None)
            self._currently_selected_ips.clear()

    def reset_all(self) -> None:
        """Clear all tracked player rate data and reset scan."""
        if self._currently_selected_ips and self._deselect_ips is not None:
            self._deselect_ips(list(self._currently_selected_ips))
        self._currently_selected_ips.clear()
        self._tracked.clear()
        HighRateTracker.set_flagged_ips(set())
        self._status_label.setText('<b>Status:</b> Scan reset. Collecting data…')

    def _clear_blacklist(self) -> None:
        self._blacklisted_ips.clear()

    def blacklist_ip(self, ip: str) -> None:
        """Add an IP to the blacklist to exclude it from high-rate detection."""
        self._blacklisted_ips.add(ip)
        self._tracked.pop(ip, None)

    def get_tracked(self, ip: str) -> _PlayerRateData | None:
        """Return the tracked rate data for the given IP, or None."""
        return self._tracked.get(ip)

    @override
    def showEvent(self, event: QShowEvent) -> None:
        """Select flagged high-rate players if auto-selection is enabled upon showing the monitor."""
        super().showEvent(event)
        if self._auto_select:
            flagged_ips = [player.ip for player in self._tracked.values() if player.is_high_pps and player.is_high_bps]
            if flagged_ips and self._select_ips is not None:
                self._select_ips(flagged_ips)
                self._currently_selected_ips = set(flagged_ips)

    @override
    def hideEvent(self, event: QHideEvent) -> None:
        """Deselect auto-selected players when the monitor window or tab is hidden."""
        super().hideEvent(event)
        if self._auto_select and self._currently_selected_ips and self._deselect_ips is not None:
            self._deselect_ips(list(self._currently_selected_ips))
            self._currently_selected_ips.clear()
