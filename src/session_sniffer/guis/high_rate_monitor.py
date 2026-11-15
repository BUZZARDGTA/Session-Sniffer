"""High Rate Monitor — tracks players exceeding configurable PPS and BPS thresholds."""

import html
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, ClassVar, override

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QCheckBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.standard import LOCAL_TZ
from session_sniffer.guis.live_language import register_language_refresh
from session_sniffer.guis.player_rate_graph import DEFAULT_MAX_HISTORY, PlayerRateGraphWindow
from session_sniffer.guis.theming import themed_qss
from session_sniffer.guis.utils import activate_window, scale_by_ui
from session_sniffer.i18n import tr, tr_plural
from session_sniffer.models.player_traffic import PlayerBandwidth
from session_sniffer.player.registry import PlayersRegistry
from session_sniffer.settings import Settings

if TYPE_CHECKING:
    from collections.abc import Callable

    from PySide6.QtGui import QHideEvent, QShowEvent

_UPDATE_INTERVAL_MS = 1_000
_KBS_TO_BYTES = 1024
_SMART_MIN_PPS_FLOOR = 20
_SMART_PPS_MULTIPLIER = 1.20
_SMART_MIN_PPS_DELTA = 3


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
    newer_high_pps_time: datetime | None = None
    is_high_pps: bool = False
    current_pps_duration: int = 0
    accumulated_pps_duration: int = 0
    total_pps_duration: int = 0

    # BPS tracking
    newer_high_bps_time: datetime | None = None
    is_high_bps: bool = False
    current_bps_duration: int = 0

    def update_pps_stats(self, *, now: datetime, pps: int, threshold: int, required_duration: int) -> None:
        """Update high-PPS status for this player."""
        self.pps = pps
        self.pps_history.append(pps)
        if pps < threshold:
            self.accumulated_pps_duration += self.current_pps_duration
            self.is_high_pps = False
            self.newer_high_pps_time = None
            self.current_pps_duration = 0
            self.total_pps_duration = self.accumulated_pps_duration
            return

        if self.newer_high_pps_time is None:
            self.newer_high_pps_time = now

        self.current_pps_duration = int((now - self.newer_high_pps_time).total_seconds())
        self.total_pps_duration = self.accumulated_pps_duration + self.current_pps_duration

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

        if self.newer_high_bps_time is None:
            self.newer_high_bps_time = now

        self.current_bps_duration = int((now - self.newer_high_bps_time).total_seconds())

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
        self.mode: str = Settings.high_rate_monitor_mode
        self._current_avg_pps: float = 0.0
        self._current_smart_threshold: int = _SMART_MIN_PPS_FLOOR
        self._auto_select: bool = Settings.high_rate_monitor_auto_select

        self.pps_threshold = Settings.high_rate_monitor_pps_threshold
        self.bps_threshold = Settings.high_rate_monitor_bps_threshold * _KBS_TO_BYTES
        self.required_duration = Settings.high_rate_monitor_duration_threshold

        layout = QVBoxLayout(self)
        self._status_mode = 'init'

        # Status summary label
        self._status_label = QLabel()
        self._status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._status_label.setWordWrap(True)
        layout.addWidget(self._status_label)

        # Selection controls row
        selection_layout = QHBoxLayout()
        selection_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self._select_button = QPushButton()
        self._select_button.setMinimumWidth(scale_by_ui(140))
        self._select_button.clicked.connect(self._select_flagged)
        self._select_button.setEnabled(not self._auto_select)
        selection_layout.addWidget(self._select_button)

        self._deselect_button = QPushButton()
        self._deselect_button.setMinimumWidth(scale_by_ui(140))
        self._deselect_button.clicked.connect(self._deselect_flagged)
        self._deselect_button.setEnabled(not self._auto_select)
        selection_layout.addWidget(self._deselect_button)

        self._auto_select_checkbox = QCheckBox()
        self._auto_select_checkbox.setChecked(self._auto_select)
        self._auto_select_checkbox.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self._auto_select_checkbox.toggled.connect(self._on_auto_select_toggled)
        selection_layout.addWidget(self._auto_select_checkbox)

        layout.addLayout(selection_layout)

        # Action buttons row
        actions_layout = QHBoxLayout()
        actions_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self._open_all_graphs_button = QPushButton()
        self._open_all_graphs_button.setMinimumWidth(scale_by_ui(240))
        self._open_all_graphs_button.clicked.connect(self._open_all_graphs)
        actions_layout.addWidget(self._open_all_graphs_button)

        self._reset_button = QPushButton()
        self._reset_button.setMinimumWidth(scale_by_ui(130))
        self._reset_button.clicked.connect(self.reset_all)
        actions_layout.addWidget(self._reset_button)

        clear_bl_button = QPushButton()
        clear_bl_button.setEnabled(False)
        clear_bl_button.setMinimumWidth(scale_by_ui(130))
        clear_bl_button.clicked.connect(self._clear_blacklist)
        actions_layout.addWidget(clear_bl_button)
        self._clear_blacklist_button = clear_bl_button

        layout.addLayout(actions_layout)

        self._apply_translations()
        register_language_refresh(self, self._apply_translations)

        # Periodic scan timer
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._scan_players)
        if Settings.high_rate_monitor_run_in_background:
            self._timer.start(_UPDATE_INTERVAL_MS)
            self._scan_players()

    def _apply_translations(self) -> None:
        """Apply translated text to controls, tooltips, and status summary."""
        self._select_button.setText(tr('Select in Table'))
        self._select_button.setToolTip(tr('Select and scroll to all currently flagged high-rate players in the connected players table.'))
        self._deselect_button.setText(tr('Deselect in Table'))
        self._deselect_button.setToolTip(tr('Deselect all currently flagged high-rate players in the connected players table.'))
        self._auto_select_checkbox.setText(tr('Auto-select in Table'))
        self._auto_select_checkbox.setToolTip(
            tr(
                'Keep high-rate players selected in the connected players table automatically.\n\n'
                'Live updates occur with every scan. Turn off for manual selection control.',
            ),
        )
        self._open_all_graphs_button.setText(tr('Open Graphs for Flagged Players'))
        self._open_all_graphs_button.setToolTip(
            tr(
                'Opens a live PPS/BPS rate graph window for every player currently flagged as high-rate traffic.\n\n'
                'Each graph updates in real time so you can visually compare traffic patterns.',
            ),
        )
        self._reset_button.setText(tr('Reset Scan'))
        self._reset_button.setToolTip(
            tr('Clears all tracked data, rate history, and flagged players.\nThe scan restarts from scratch immediately.'),
        )
        self._clear_blacklist_button.setText(tr('Clear Blacklist'))
        self._clear_blacklist_button.setToolTip(
            tr(
                'Removes all IPs from the blacklist so they can be tracked again.\n\n'
                'Blacklisted IPs are excluded from high-rate detection.',
            ),
        )
        self._refresh_status_label()

    def _refresh_status_label(self) -> None:
        """Render the status summary label according to the current monitor state."""
        if self._status_mode == 'init':
            self._status_label.setText(tr('<b>Status:</b> Initializing scan…'))
        elif self._status_mode == 'reset':
            self._status_label.setText(tr('<b>Status:</b> Scan reset. Collecting data…'))
        else:
            self._update_status_display(self._get_flagged_players())

    # Scanning ---------------------------------------------------------------

    def _get_flagged_players(self) -> list[_PlayerRateData]:
        if self.mode == 'Smart':
            return [player for player in self._tracked.values() if player.is_high_pps]
        return [player for player in self._tracked.values() if player.is_high_pps and player.is_high_bps]

    def _scan_players(self) -> None:
        players = [
            player
            for player in PlayersRegistry.get_connected_players()
            if player.ip not in self._blacklisted_ips and not player.is_third_party_server
        ]

        if self.mode == 'Smart':
            pps_values = [player.packets.pps.calculated_rate for player in players]
            self._current_avg_pps = sum(pps_values) / len(pps_values) if pps_values else 0.0
            self._current_smart_threshold = max(
                _SMART_MIN_PPS_FLOOR,
                round(self._current_avg_pps * _SMART_PPS_MULTIPLIER),
                round(self._current_avg_pps + _SMART_MIN_PPS_DELTA),
            )
            active_pps_threshold = self._current_smart_threshold
        else:
            active_pps_threshold = self.pps_threshold

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
                threshold=active_pps_threshold,
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

        flagged_players = self._get_flagged_players()
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
            graph.set_pps_threshold(active_pps_threshold)
            graph.update_rates(
                pps=data.pps if data else 0,
                bps=data.bps if data else 0,
            )
            matched_player = PlayersRegistry.get_player_by_ip(ip)
            graph.update_usernames(matched_player.usernames if matched_player is not None else [])

        self._update_status_display(flagged_players)

    def _update_status_display(self, flagged_players: list[_PlayerRateData]) -> None:
        self._status_mode = 'scanned'
        num_flagged = len(flagged_players)
        num_connected = len(self._tracked)
        if self.mode == 'Smart':
            mode_info = tr(
                'Smart mode (avg: {avg:.1f} PPS · threshold: {threshold} PPS)',
                avg=self._current_avg_pps,
                threshold=self._current_smart_threshold,
            )
        else:
            formatted_bps_thresh = PlayerBandwidth.format_bytes(self.bps_threshold)
            mode_info = tr(
                'Manual mode (thresholds: {pps} PPS · {bps})',
                pps=self.pps_threshold,
                bps=formatted_bps_thresh,
            )

        if not num_flagged:
            monitoring_text = tr_plural(
                'Monitoring {count} connected IP · {mode_info}.',
                'Monitoring {count} connected IPs · {mode_info}.',
                num_connected,
                mode_info=mode_info,
            )
            self._status_label.setText(
                f"<b>{tr('No high-rate players detected.')}</b><br><small>{monitoring_text}</small>",
            )
            return

        if self.mode == 'Manual':
            summary_text = tr_plural(
                '{count} player currently exceeding thresholds:',
                '{count} players currently exceeding thresholds:',
                num_flagged,
            )
        else:
            summary_text = tr_plural(
                '{count} player currently exceeding threshold:',
                '{count} players currently exceeding threshold:',
                num_flagged,
            )
        lines: list[str] = [
            themed_qss(
                f'<b style="color:#e74c3c;">{summary_text}</b> <small>({mode_info})</small>',
            ),
        ]
        for player in flagged_players:
            name_part = f' ({html.escape(", ".join(player.usernames))})' if player.usernames else ''
            formatted_bps = PlayerBandwidth.format_bytes(player.bps)
            stats_text = tr(
                '{pps} PPS · {bps} · streak: {streak}s (total: {total}s)',
                pps=player.pps,
                bps=formatted_bps,
                streak=player.current_pps_duration,
                total=player.total_pps_duration,
            )
            lines.append(f'• <b>{player.ip}</b>{name_part} — {stats_text}')
        lines.append(f"<small>{tr('Flagged players are marked with a speedometer icon in the connected players table.')}</small>")
        self._status_label.setText('<br>'.join(lines))

    def apply_settings(self) -> None:
        """Apply updated threshold and auto-select settings from `Settings`."""
        self.mode = Settings.high_rate_monitor_mode
        self.pps_threshold = Settings.high_rate_monitor_pps_threshold
        self.bps_threshold = Settings.high_rate_monitor_bps_threshold * _KBS_TO_BYTES
        self.required_duration = Settings.high_rate_monitor_duration_threshold
        active_pps_threshold = self._current_smart_threshold if self.mode == 'Smart' else self.pps_threshold
        for graph in self._graph_windows.values():
            graph.set_pps_threshold(active_pps_threshold)
            graph.set_bps_threshold(self.bps_threshold)
        self._auto_select_checkbox.setChecked(Settings.high_rate_monitor_auto_select)
        if self._tracked:
            self._scan_players()

    # Graphs -----------------------------------------------------------------

    def open_graph(self, ip: str) -> None:
        """Open or focus a live rate graph window for the given player IP."""
        existing = self._graph_windows.get(ip)
        if existing:
            activate_window(existing)
            return

        active_pps_threshold = self._current_smart_threshold if self.mode == 'Smart' else self.pps_threshold
        graph = PlayerRateGraphWindow(
            ip=ip,
            initial_pps_threshold=active_pps_threshold,
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
        for player in self._get_flagged_players():
            self.open_graph(player.ip)

    # Actions ----------------------------------------------------------------

    def _on_auto_select_toggled(self) -> None:
        checked = self._auto_select_checkbox.isChecked()
        self._auto_select = checked
        if Settings.high_rate_monitor_auto_select != checked:
            Settings.high_rate_monitor_auto_select = checked
            Settings.rewrite_settings_file()
        self._select_button.setEnabled(not checked)
        self._deselect_button.setEnabled(not checked)
        if checked:
            flagged_ips = [player.ip for player in self._get_flagged_players()]
            if flagged_ips and self._select_ips is not None:
                self._select_ips(flagged_ips)
                self._currently_selected_ips = set(flagged_ips)
        elif self._currently_selected_ips and self._deselect_ips is not None:
            self._deselect_ips(list(self._currently_selected_ips))
            self._currently_selected_ips.clear()

    def _select_flagged(self) -> None:
        if self._select_ips is not None:
            flagged_ips = [player.ip for player in self._get_flagged_players()]
            if flagged_ips:
                self._select_ips(flagged_ips)
                self._currently_selected_ips = set(flagged_ips)

    def _deselect_flagged(self) -> None:
        if self._deselect_ips is not None:
            flagged_ips = {player.ip for player in self._get_flagged_players()}
            ips_to_deselect = list(self._currently_selected_ips | flagged_ips)
            self._deselect_ips(ips_to_deselect or None)
            self._currently_selected_ips.clear()

    def reset_all(self) -> None:
        """Clear all tracked player rate data and reset scan."""
        if self._currently_selected_ips and self._deselect_ips is not None:
            self._deselect_ips(list(self._currently_selected_ips))
        self._currently_selected_ips.clear()
        self._tracked.clear()
        self._current_avg_pps = 0.0
        self._current_smart_threshold = _SMART_MIN_PPS_FLOOR
        HighRateTracker.set_flagged_ips(set())
        self._status_mode = 'reset'
        self._refresh_status_label()

    def _clear_blacklist(self) -> None:
        if not self._blacklisted_ips:
            self._clear_blacklist_button.setEnabled(False)
            return
        self._blacklisted_ips.clear()
        self._clear_blacklist_button.setEnabled(False)
        if self._timer.isActive():
            self._scan_players()

    def blacklist_ips(self, ip_addresses: list[str]) -> None:
        """Add multiple IPs to the blacklist to exclude them from high-rate detection."""
        if not ip_addresses:
            return
        for ip_address in ip_addresses:
            self._blacklisted_ips.add(ip_address)
            self._tracked.pop(ip_address, None)
        self._clear_blacklist_button.setEnabled(bool(self._blacklisted_ips))
        if HighRateTracker.flagged_ips.intersection(ip_addresses):
            HighRateTracker.set_flagged_ips(HighRateTracker.flagged_ips - set(ip_addresses))
        if self._timer.isActive():
            self._scan_players()

    def unblacklist_ips(self, ip_addresses: list[str]) -> None:
        """Remove multiple IPs from the blacklist to include them in high-rate detection again."""
        if not ip_addresses:
            return
        for ip_address in ip_addresses:
            self._blacklisted_ips.discard(ip_address)
        self._clear_blacklist_button.setEnabled(bool(self._blacklisted_ips))
        if self._timer.isActive():
            self._scan_players()

    def is_ip_blacklisted(self, ip_address: str) -> bool:
        """Return whether the given IP is currently blacklisted from high-rate detection."""
        return ip_address in self._blacklisted_ips

    def start_monitoring(self) -> None:
        """Start periodic rate monitoring if not already active."""
        if not self._timer.isActive():
            self._timer.start(_UPDATE_INTERVAL_MS)
            self._scan_players()

    def stop_monitoring(self) -> None:
        """Stop periodic rate monitoring and clear flagged IPs."""
        if self._timer.isActive():
            self._timer.stop()
        self.reset_all()

    @override
    def showEvent(self, event: QShowEvent) -> None:
        """Select flagged high-rate players if auto-selection is enabled upon showing the monitor."""
        super().showEvent(event)
        if self._auto_select:
            flagged_ips = [player.ip for player in self._get_flagged_players()]
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
