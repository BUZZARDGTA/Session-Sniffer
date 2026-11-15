"""High Rate Monitor — tracks players exceeding configurable PPS and BPS thresholds."""

import html
import time
from datetime import datetime
from typing import TYPE_CHECKING, override

from PySide6.QtCore import QSignalBlocker, Qt, QTimer
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.background.voice_notifications import play_spike_sound
from session_sniffer.constants.standalone import SPIKE_SOUND_MODES, SPIKE_SOUND_SCOPES
from session_sniffer.constants.standard import LOCAL_TZ
from session_sniffer.guis._high_rate_monitor_core import (
    GEIGER_GLOBAL_APPROACH_PROXIMITY,
    GEIGER_OPEN_GRAPH_MIN_PROXIMITY,
    KBS_TO_BYTES,
    SMART_MIN_BPS_KB_FLOOR,
    SMART_MIN_PPS_FLOOR,
    HighRateTracker,
    PlayerRateData,
    compute_geiger_interval,
    compute_series_proximity,
    compute_smart_thresholds,
    geiger_stage_sound_kind,
)
from session_sniffer.guis.live_language import register_language_refresh, set_i18n_colon_label
from session_sniffer.guis.player_rate_graph import (
    PlayerRateGraphWindow,
    PlayerSpikeVisualUpdate,
    SpikeAlertGraphConfig,
    SpikeAlertGraphState,
)
from session_sniffer.guis.stylesheets import COMPACT_BUTTON_STYLESHEET
from session_sniffer.guis.theming import themed_qss, themed_text_qcolor
from session_sniffer.guis.utils import activate_window, render_svg_icon_from_resource, scale_by_ui
from session_sniffer.i18n import tr, tr_plural
from session_sniffer.models.player_traffic import PlayerBandwidth
from session_sniffer.player.registry import PlayersRegistry
from session_sniffer.settings import Settings

__all__ = ['HighRateMonitorWidget', 'HighRateTracker']

if TYPE_CHECKING:
    from collections.abc import Callable

    from PySide6.QtGui import QHideEvent, QShowEvent

_UPDATE_INTERVAL_MS = 1_000
_PULSE_CHECK_INTERVAL_MS = 40
_MAX_AUTO_OPEN_GRAPHS = 6


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
        self._tracked: dict[str, PlayerRateData] = {}
        self._blacklisted_ips: set[str] = set()
        self._graph_windows: dict[str, PlayerRateGraphWindow] = {}
        self._currently_selected_ips: set[str] = set()
        self._previously_flagged_ips: set[str] = set()
        self._spiking_ips: set[str] = set()
        self._active_max_intensity_ratio: float = 1.0
        self._last_repeat_monotonic: float = 0.0

        self.mode: str = Settings.high_rate_monitor_mode
        self._current_avg_pps: float = 0.0
        self._current_avg_bps: float = 0.0
        self._current_smart_pps_threshold: int = SMART_MIN_PPS_FLOOR
        self._current_smart_bps_threshold: int = SMART_MIN_BPS_KB_FLOOR * KBS_TO_BYTES
        self._auto_select: bool = Settings.high_rate_monitor_auto_select
        self._spike_sound_scope: str = Settings.high_rate_monitor_spike_sound_scope
        self._spike_sound_mode: str = Settings.high_rate_monitor_spike_sound_mode
        self._spike_repeat_interval: int = Settings.high_rate_monitor_spike_repeat_interval
        self._spike_sound_preset: str = Settings.high_rate_monitor_spike_sound_preset
        self._spike_trigger_metric: str = Settings.high_rate_monitor_spike_trigger_metric
        self._spike_visual_alert: bool = Settings.high_rate_monitor_spike_visual_alert
        self._auto_open_graph: bool = Settings.high_rate_monitor_auto_open_graph

        self.pps_threshold = Settings.high_rate_monitor_pps_threshold
        self.bps_threshold = Settings.high_rate_monitor_bps_threshold * KBS_TO_BYTES
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

        # Spike Alerts quick-controls row
        spike_controls_layout = QHBoxLayout()
        spike_controls_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        spike_controls_layout.setSpacing(scale_by_ui(6))

        self._spike_sound_label = QLabel()
        set_i18n_colon_label(self._spike_sound_label, 'Spike Sound')
        spike_controls_layout.addWidget(self._spike_sound_label)

        self._spike_scope_combo = QComboBox()
        self._spike_scope_combo.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        for scope in SPIKE_SOUND_SCOPES:
            self._spike_scope_combo.addItem(tr(scope), scope)
        if (scope_idx := self._spike_scope_combo.findData(self._spike_sound_scope)) >= 0:
            self._spike_scope_combo.setCurrentIndex(scope_idx)
        self._spike_scope_combo.currentIndexChanged.connect(self._on_spike_scope_combo_changed)
        spike_controls_layout.addWidget(self._spike_scope_combo)

        self._spike_mode_combo = QComboBox()
        self._spike_mode_combo.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        for mode in SPIKE_SOUND_MODES:
            self._spike_mode_combo.addItem(tr(mode), mode)
        if (mode_idx := self._spike_mode_combo.findData(self._spike_sound_mode)) >= 0:
            self._spike_mode_combo.setCurrentIndex(mode_idx)
        self._spike_mode_combo.currentIndexChanged.connect(self._on_spike_mode_combo_changed)
        spike_controls_layout.addWidget(self._spike_mode_combo)

        self._spike_preview_button = QToolButton()
        self._spike_preview_button.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self._spike_preview_button.setIcon(
            render_svg_icon_from_resource('volume-2.svg', 14, 14, themed_text_qcolor('@text[#e5e7eb]', '@surface[#1f2937]').name()),
        )
        self._spike_preview_button.setStyleSheet(COMPACT_BUTTON_STYLESHEET)
        self._spike_preview_button.clicked.connect(
            lambda: play_spike_sound('Geiger3' if self._spike_sound_mode == 'Adaptive Geiger' else self._spike_sound_preset, bypass_cooldown=True),
        )
        spike_controls_layout.addWidget(self._spike_preview_button)

        spike_controls_layout.addSpacing(scale_by_ui(8))

        self._auto_open_graph_checkbox = QCheckBox()
        self._auto_open_graph_checkbox.setChecked(self._auto_open_graph)
        self._auto_open_graph_checkbox.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self._auto_open_graph_checkbox.toggled.connect(self._on_auto_open_graph_toggled)
        spike_controls_layout.addWidget(self._auto_open_graph_checkbox)

        layout.addLayout(spike_controls_layout)

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

        # Pulse timer for repeating / Adaptive Geiger spike sounds (active only during active spikes)
        self._pulse_timer = QTimer(self)
        self._pulse_timer.timeout.connect(self._on_pulse_timer_tick)

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
        for i, canonical_scope in enumerate(SPIKE_SOUND_SCOPES):
            if i < self._spike_scope_combo.count():
                self._spike_scope_combo.setItemText(i, tr(canonical_scope))
        for i, canonical_mode in enumerate(SPIKE_SOUND_MODES):
            if i < self._spike_mode_combo.count():
                self._spike_mode_combo.setItemText(i, tr(canonical_mode))
        scope_tip = tr('Choose where spike alert sounds are active (Disabled, Open Graphs, or Global).')
        self._spike_sound_label.setToolTip(scope_tip)
        self._spike_scope_combo.setToolTip(scope_tip)
        self._auto_open_graph_checkbox.setText(tr('Auto-open Graphs'))
        self._auto_open_graph_checkbox.setToolTip(
            tr('Automatically open a live Rate Graph window (without stealing focus) whenever a player is newly flagged.'),
        )
        self._refresh_spike_controls_state()
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

    def _refresh_spike_controls_state(self) -> None:
        sound_active = self._spike_sound_scope != 'Disabled'
        scope_disabled_note = tr('Disabled when Spike Sound Scope is set to Disabled.')
        self._spike_mode_combo.setEnabled(sound_active)
        mode_tip = tr('Choose how spike alert sounds behave when traffic crosses above the threshold.')
        self._spike_mode_combo.setToolTip(mode_tip if sound_active else f'{mode_tip}\n\n{scope_disabled_note}')
        self._spike_preview_button.setEnabled(sound_active)
        preview_tip = tr('Play a preview of the selected spike sound preset.')
        self._spike_preview_button.setToolTip(preview_tip if sound_active else f'{preview_tip}\n\n{scope_disabled_note}')

    def _refresh_status_label(self) -> None:
        """Render the status summary label according to the current monitor state."""
        if self._status_mode == 'init':
            self._status_label.setText(tr('<b>Status:</b> Initializing scan…'))
        elif self._status_mode == 'reset':
            self._status_label.setText(tr('<b>Status:</b> Scan reset. Collecting data…'))
        else:
            self._update_status_display(self._get_flagged_players())

    # Scanning ---------------------------------------------------------------

    def _active_thresholds(self) -> tuple[int, int]:
        if self.mode == 'Smart':
            return self._current_smart_pps_threshold, self._current_smart_bps_threshold
        return self.pps_threshold, self.bps_threshold

    def _thresholds_for_ip(self, ip: str) -> tuple[int, int]:
        if (graph := self._graph_windows.get(ip)) is not None:
            return graph.pps_threshold, graph.bps_threshold
        return self._active_thresholds()

    def _get_flagged_players(self) -> list[PlayerRateData]:
        return [player for player in self._tracked.values() if player.is_high_pps and player.is_high_bps]

    def _scan_players(self) -> None:
        players = [
            player
            for player in PlayersRegistry.get_connected_players()
            if player.ip not in self._blacklisted_ips and not player.is_third_party_server
        ]

        if self.mode == 'Smart' or any(g.monitor_mode == 'Smart' for g in self._graph_windows.values()):
            (
                self._current_avg_pps,
                self._current_avg_bps,
                self._current_smart_pps_threshold,
                self._current_smart_bps_threshold,
            ) = compute_smart_thresholds(
                [player.packets.pps.calculated_rate for player in players],
                [player.bandwidth.bps.calculated_rate for player in players],
            )
        active_pps_threshold, active_bps_threshold = self._active_thresholds()

        now = datetime.now(tz=LOCAL_TZ)
        connected_ips: set[str] = set()
        for player in players:
            connected_ips.add(player.ip)
            if player.ip not in self._tracked:
                self._tracked[player.ip] = PlayerRateData(
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
                threshold=active_bps_threshold,
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

        newly_flagged_ips = flagged_ips - self._previously_flagged_ips
        self._previously_flagged_ips = set(flagged_ips)
        if self._auto_open_graph and newly_flagged_ips:
            for ip in sorted(newly_flagged_ips):
                if len(self._graph_windows) >= _MAX_AUTO_OPEN_GRAPHS:
                    break
                if ip not in self._graph_windows:
                    self.open_graph(ip, focus=False)

        for ip, graph in list(self._graph_windows.items()):
            data = self._tracked.get(ip)
            pps_val = data.pps if data is not None else 0
            bps_val = data.bps if data is not None else 0
            if graph.monitor_mode == 'Smart':
                graph.set_pps_threshold(self._current_smart_pps_threshold)
                graph.set_bps_threshold(self._current_smart_bps_threshold)
            elif not graph.has_local_threshold_override:
                graph.set_pps_threshold(active_pps_threshold)
                graph.set_bps_threshold(active_bps_threshold)
            vis_update = self._build_visual_update(ip, data)
            graph.update_rates(pps=pps_val, bps=bps_val)
            graph.update_spike_visuals(vis_update)
            matched_player = PlayersRegistry.get_player_by_ip(ip)
            graph.update_usernames(matched_player.usernames if matched_player is not None else [])

        self._process_spike_sound_alerts()
        self._update_status_display(flagged_players)

    def _build_visual_update(self, ip: str, data: PlayerRateData | None) -> PlayerSpikeVisualUpdate:
        """Compute visual spike flags and live proximity/approach levels for *ip*."""
        if data is None:
            return PlayerSpikeVisualUpdate()
        active_pps_threshold, active_bps_threshold = self._thresholds_for_ip(ip)
        _, pps_vis, bps_vis, _ = self._evaluate_ip_spike(ip, data)
        pps_prox, pps_approaching = compute_series_proximity(
            history=data.pps_history,
            current=data.pps,
            threshold=active_pps_threshold,
            min_idle_floor=4.0,
            min_approach_delta=2.0,
        )
        bps_prox, bps_approaching = compute_series_proximity(
            history=data.bps_history,
            current=data.bps,
            threshold=active_bps_threshold,
            min_idle_floor=512.0,
            min_approach_delta=600.0,
        )
        return PlayerSpikeVisualUpdate(
            pps_spiking=pps_vis,
            bps_spiking=bps_vis,
            pps=data.pps,
            bps=data.bps,
            pps_proximity=pps_prox,
            bps_proximity=bps_prox,
            pps_approaching=pps_approaching,
            bps_approaching=bps_approaching,
        )

    def _evaluate_geiger_proximity(self, ip: str, data: PlayerRateData | None) -> tuple[bool, float]:
        """Return `(engaged, proximity_score)` for `Adaptive Geiger` mode using PPS/BPS + player approach velocity."""
        if data is None:
            return False, 0.0
        active_pps_threshold, active_bps_threshold = self._thresholds_for_ip(ip)
        is_spiking, _, _, _ = self._evaluate_ip_spike(ip, data)
        pps_prox, pps_approaching = compute_series_proximity(
            history=data.pps_history,
            current=data.pps,
            threshold=active_pps_threshold,
            min_idle_floor=4.0,
            min_approach_delta=2.0,
        )
        bps_prox, bps_approaching = compute_series_proximity(
            history=data.bps_history,
            current=data.bps,
            threshold=active_bps_threshold,
            min_idle_floor=512.0,
            min_approach_delta=600.0,
        )

        if self._spike_trigger_metric == 'BPS Only':
            score = bps_prox
            approaching = bps_approaching
        elif self._spike_trigger_metric == 'PPS Only':
            score = pps_prox
            approaching = pps_approaching
        else:
            score = max(pps_prox, bps_prox * 0.85)
            approaching = pps_approaching or bps_approaching

        if is_spiking:
            return True, max(1.0, score)
        if ip in self._graph_windows:
            min_pps_engage = max(6, round(active_pps_threshold * 0.25))
            engaged = score >= GEIGER_OPEN_GRAPH_MIN_PROXIMITY and (data.pps >= min_pps_engage or self._spike_trigger_metric == 'BPS Only')
            return (True, score) if engaged else (False, 0.0)
        if score >= GEIGER_GLOBAL_APPROACH_PROXIMITY and approaching:
            return True, score
        return False, 0.0

    def _evaluate_ip_spike(self, ip: str, data: PlayerRateData | None) -> tuple[bool, bool, bool, float]:
        """Return `(is_alert_spiking, pps_visual_spiking, bps_visual_spiking, intensity_ratio)` for a tracked IP."""
        if data is None:
            return False, False, False, 0.0

        active_pps_threshold, active_bps_threshold = self._thresholds_for_ip(ip)
        pps = data.pps
        bps = data.bps
        pps_over = 0 < active_pps_threshold <= pps
        bps_over = 0 < active_bps_threshold <= bps
        pps_ratio = (pps / active_pps_threshold) if active_pps_threshold > 0 else 0.0
        bps_ratio = (bps / active_bps_threshold) if active_bps_threshold > 0 else 0.0

        match self._spike_trigger_metric:
            case 'Follow Monitor':
                graph = self._graph_windows.get(ip)
                if graph is not None and graph.has_local_threshold_override:
                    needed = self.required_duration + 1
                    pps_tail = list(data.pps_history)[-needed:]
                    bps_tail = list(data.bps_history)[-needed:]
                    is_spiking = (
                        len(pps_tail) >= needed
                        and len(bps_tail) >= needed
                        and all(val >= active_pps_threshold for val in pps_tail)
                        and all(val >= active_bps_threshold for val in bps_tail)
                    )
                else:
                    is_spiking = data.is_high_pps and data.is_high_bps
                pps_vis = is_spiking
                bps_vis = is_spiking
                raw_ratio = max(pps_ratio, bps_ratio)
            case 'Both (PPS and BPS)':
                is_spiking = pps_over and bps_over
                pps_vis = is_spiking
                bps_vis = is_spiking
                raw_ratio = max(pps_ratio, bps_ratio)
            case 'PPS Only':
                is_spiking = pps_over
                pps_vis = pps_over
                bps_vis = False
                raw_ratio = pps_ratio
            case 'BPS Only':
                is_spiking = bps_over
                pps_vis = False
                bps_vis = bps_over
                raw_ratio = bps_ratio
            case _:
                is_spiking = pps_over or bps_over
                pps_vis = pps_over
                bps_vis = bps_over
                raw_ratio = max(pps_ratio if pps_over else 0.0, bps_ratio if bps_over else 0.0)

        return is_spiking, pps_vis, bps_vis, (max(1.0, raw_ratio) if is_spiking else 0.0)

    def _process_spike_sound_alerts(self) -> None:
        """Evaluate rising/falling spike edges and manage repeating/Adaptive Geiger audio cadence."""
        if self._spike_sound_scope == 'Disabled':
            self._spiking_ips.clear()
            if self._pulse_timer.isActive():
                self._pulse_timer.stop()
            return

        eligible_ips = (
            set(self._graph_windows.keys())
            if self._spike_sound_scope == 'Open Graphs'
            else (set(self._tracked.keys()) | set(self._graph_windows.keys()))
        )

        current_spiking_ips: set[str] = set()
        max_ratio = 0.0
        is_geiger = self._spike_sound_mode == 'Adaptive Geiger'
        for ip in eligible_ips:
            tracked_data = self._tracked.get(ip)
            if is_geiger:
                engaged, ratio = self._evaluate_geiger_proximity(ip, tracked_data)
            else:
                engaged, _, _, ratio = self._evaluate_ip_spike(ip, tracked_data)
            if engaged:
                current_spiking_ips.add(ip)
                max_ratio = max(max_ratio, ratio)

        # Exclude IPs whose graph window was merely closed while still connected in 'Open Graphs' scope.
        genuinely_ended_ips = {
            ip for ip in (self._spiking_ips - current_spiking_ips) if ip in eligible_ips or ip not in self._tracked
        }
        started_ips = current_spiking_ips - self._spiking_ips
        self._spiking_ips = current_spiking_ips
        self._active_max_intensity_ratio = max_ratio if current_spiking_ips else 0.0

        if started_ips:
            self._last_repeat_monotonic = time.monotonic()
            self._emit_active_spike_sound()
        elif genuinely_ended_ips and not current_spiking_ips and self._spike_sound_mode in ('Start & End', 'Repeating + End'):
            play_spike_sound('End', min_cooldown=0.20)

        if current_spiking_ips and self._spike_sound_mode in ('Repeating', 'Repeating + End', 'Adaptive Geiger'):
            if not self._pulse_timer.isActive():
                self._pulse_timer.start(_PULSE_CHECK_INTERVAL_MS)
            self._on_pulse_timer_tick()
        elif self._pulse_timer.isActive():
            self._pulse_timer.stop()

    def _on_pulse_timer_tick(self) -> None:
        if not self._spiking_ips or self._spike_sound_scope == 'Disabled':
            self._pulse_timer.stop()
            return
        if self._spike_sound_mode == 'Adaptive Geiger':
            target_interval = compute_geiger_interval(
                repeat_interval=self._spike_repeat_interval,
                proximity_score=self._active_max_intensity_ratio,
            )
        elif self._spike_sound_mode in ('Repeating', 'Repeating + End'):
            target_interval = float(self._spike_repeat_interval)
        else:
            self._pulse_timer.stop()
            return

        now_mono = time.monotonic()
        if (now_mono - self._last_repeat_monotonic) >= target_interval:
            self._last_repeat_monotonic = now_mono
            self._emit_active_spike_sound()

    def _emit_active_spike_sound(self) -> None:
        if self._spike_sound_mode == 'Adaptive Geiger':
            play_spike_sound(geiger_stage_sound_kind(self._active_max_intensity_ratio), min_cooldown=0.075)
            return
        play_spike_sound(self._spike_sound_preset, min_cooldown=0.20)

    def _update_status_display(self, flagged_players: list[PlayerRateData]) -> None:
        self._status_mode = 'scanned'
        num_flagged = len(flagged_players)
        num_connected = len(self._tracked)
        if self.mode == 'Smart':
            mode_info = tr(
                'Smart mode (avg: {avg_pps:.1f} PPS · {avg_bps} | thresholds: {pps} PPS · {bps})',
                avg_pps=self._current_avg_pps,
                avg_bps=PlayerBandwidth.format_bytes(round(self._current_avg_bps)),
                pps=self._current_smart_pps_threshold,
                bps=PlayerBandwidth.format_bytes(self._current_smart_bps_threshold),
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

        summary_text = tr_plural(
            '{count} player currently exceeding thresholds:',
            '{count} players currently exceeding thresholds:',
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

    def _build_graph_state(self) -> SpikeAlertGraphState:
        return SpikeAlertGraphState(
            monitor_mode=self.mode,
            manual_pps_threshold=self.pps_threshold,
            manual_bps_threshold_kb=self.bps_threshold // KBS_TO_BYTES,
            sound_scope=self._spike_sound_scope,
            sound_mode=self._spike_sound_mode,
            repeat_interval=self._spike_repeat_interval,
            sound_preset=self._spike_sound_preset,
            visual_alert=self._spike_visual_alert,
        )

    def _sync_open_graphs_state(self) -> None:
        state = self._build_graph_state()
        active_pps_threshold, active_bps_threshold = self._active_thresholds()
        for ip, graph in self._graph_windows.items():
            graph.sync_spike_alert_settings(state)
            if not graph.has_local_threshold_override:
                graph.set_pps_threshold(active_pps_threshold)
                graph.set_bps_threshold(active_bps_threshold)
            elif graph.monitor_mode == 'Smart':
                graph.set_pps_threshold(self._current_smart_pps_threshold)
                graph.set_bps_threshold(self._current_smart_bps_threshold)
            graph.update_spike_visuals(
                self._build_visual_update(ip, self._tracked.get(ip)),
                advance_streak=False,
            )

    def apply_settings(self) -> None:
        """Apply updated threshold, spike-alert, and auto-select settings from `Settings`."""
        self.mode = Settings.high_rate_monitor_mode
        self.pps_threshold = Settings.high_rate_monitor_pps_threshold
        self.bps_threshold = Settings.high_rate_monitor_bps_threshold * KBS_TO_BYTES
        self.required_duration = Settings.high_rate_monitor_duration_threshold

        self._spike_sound_scope = Settings.high_rate_monitor_spike_sound_scope
        self._spike_sound_mode = Settings.high_rate_monitor_spike_sound_mode
        self._spike_repeat_interval = Settings.high_rate_monitor_spike_repeat_interval
        self._spike_sound_preset = Settings.high_rate_monitor_spike_sound_preset
        self._spike_trigger_metric = Settings.high_rate_monitor_spike_trigger_metric
        self._spike_visual_alert = Settings.high_rate_monitor_spike_visual_alert
        self._auto_open_graph = Settings.high_rate_monitor_auto_open_graph

        with QSignalBlocker(self._spike_scope_combo):
            if (scope_idx := self._spike_scope_combo.findData(self._spike_sound_scope)) >= 0:
                self._spike_scope_combo.setCurrentIndex(scope_idx)
        with QSignalBlocker(self._spike_mode_combo):
            if (mode_idx := self._spike_mode_combo.findData(self._spike_sound_mode)) >= 0:
                self._spike_mode_combo.setCurrentIndex(mode_idx)
        with QSignalBlocker(self._auto_open_graph_checkbox):
            self._auto_open_graph_checkbox.setChecked(self._auto_open_graph)
        self._refresh_spike_controls_state()
        self._sync_open_graphs_state()
        self._auto_select_checkbox.setChecked(Settings.high_rate_monitor_auto_select)
        if self._tracked or self._graph_windows:
            self._scan_players()

    # Graphs -----------------------------------------------------------------

    def has_open_graphs(self) -> bool:
        """Return whether any live Player Rate Graph windows are currently open."""
        return bool(self._graph_windows)

    def open_graph(self, ip: str, *, focus: bool = True) -> None:
        """Open (and optionally focus) a live rate graph window for the given player IP."""
        existing = self._graph_windows.get(ip)
        if existing:
            if focus:
                activate_window(existing)
            return

        active_pps_threshold, active_bps_threshold = self._active_thresholds()
        graph = PlayerRateGraphWindow(
            ip=ip,
            initial_pps_threshold=active_pps_threshold,
            initial_bps_threshold=active_bps_threshold,
            spike_config=SpikeAlertGraphConfig(
                state=self._build_graph_state(),
                on_thresholds_changed=self._on_graph_thresholds_changed,
                on_scope_changed=self._set_spike_sound_scope,
                on_mode_changed=self._set_spike_sound_mode,
                on_repeat_interval_changed=self._set_spike_repeat_interval,
            ),
        )
        graph.destroyed.connect(lambda: self._on_graph_destroyed(ip))
        self._graph_windows[ip] = graph
        data = self._tracked.get(ip)
        if data is not None:
            graph.load_history(pps_history=list(data.pps_history), bps_history=list(data.bps_history))
            graph.update_spike_visuals(self._build_visual_update(ip, data))
            if self._spike_sound_scope == 'Open Graphs':
                if self._spike_sound_mode == 'Adaptive Geiger':
                    engaged, _ = self._evaluate_geiger_proximity(ip, data)
                else:
                    engaged, _, _, _ = self._evaluate_ip_spike(ip, data)
                if engaged:
                    self._spiking_ips.add(ip)
        matched_player = PlayersRegistry.get_player_by_ip(ip)
        if matched_player is not None:
            graph.update_usernames(matched_player.usernames)
        if not focus:
            graph.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating, on=True)
        graph.show()
        if not focus:
            graph.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating, on=False)
        if not self._timer.isActive():
            self._timer.start(_UPDATE_INTERVAL_MS)
            self._scan_players()

    def _on_graph_destroyed(self, ip: str) -> None:
        self._graph_windows.pop(ip, None)
        if not self._graph_windows and not Settings.high_rate_monitor_run_in_background and not self.window().isVisible():
            self.stop_monitoring()
            return
        if self._spike_sound_scope != 'Disabled':
            self._process_spike_sound_alerts()

    def _open_all_graphs(self) -> None:
        for player in self._get_flagged_players():
            self.open_graph(player.ip)

    def _on_graph_thresholds_changed(self, ip: str) -> None:
        graph = self._graph_windows.get(ip)
        if graph is None:
            return
        if graph.monitor_mode == 'Smart':
            (
                self._current_avg_pps,
                self._current_avg_bps,
                self._current_smart_pps_threshold,
                self._current_smart_bps_threshold,
            ) = compute_smart_thresholds(
                [player.pps for player in self._tracked.values()],
                [player.bps for player in self._tracked.values()],
            )
            graph.set_pps_threshold(self._current_smart_pps_threshold)
            graph.set_bps_threshold(self._current_smart_bps_threshold)
        graph.update_spike_visuals(
            self._build_visual_update(ip, self._tracked.get(ip)),
            advance_streak=False,
        )
        self._process_spike_sound_alerts()

    def _set_spike_repeat_interval(self, repeat_interval: int) -> None:
        self._spike_repeat_interval = repeat_interval
        if Settings.high_rate_monitor_spike_repeat_interval != repeat_interval:
            Settings.high_rate_monitor_spike_repeat_interval = repeat_interval
            Settings.rewrite_settings_file()
        self._sync_open_graphs_state()
        if self._pulse_timer.isActive():
            self._on_pulse_timer_tick()

    def _on_spike_scope_combo_changed(self, index: int) -> None:
        self._set_spike_sound_scope(str(self._spike_scope_combo.itemData(index)))

    def _on_spike_mode_combo_changed(self, index: int) -> None:
        self._set_spike_sound_mode(str(self._spike_mode_combo.itemData(index)))

    def _set_spike_sound_scope(self, scope: str) -> None:
        self._spike_sound_scope = scope
        with QSignalBlocker(self._spike_scope_combo):
            if (scope_idx := self._spike_scope_combo.findData(scope)) >= 0:
                self._spike_scope_combo.setCurrentIndex(scope_idx)
        self._refresh_spike_controls_state()
        if Settings.high_rate_monitor_spike_sound_scope != scope:
            Settings.high_rate_monitor_spike_sound_scope = scope
            Settings.rewrite_settings_file()
        self._sync_open_graphs_state()
        if scope == 'Disabled':
            self._spiking_ips.clear()
            self._pulse_timer.stop()
        else:
            self._process_spike_sound_alerts()

    def _set_spike_sound_mode(self, mode: str) -> None:
        self._spike_sound_mode = mode
        with QSignalBlocker(self._spike_mode_combo):
            if (mode_idx := self._spike_mode_combo.findData(mode)) >= 0:
                self._spike_mode_combo.setCurrentIndex(mode_idx)
        if Settings.high_rate_monitor_spike_sound_mode != mode:
            Settings.high_rate_monitor_spike_sound_mode = mode
            Settings.rewrite_settings_file()
        self._sync_open_graphs_state()
        if self._spike_sound_scope != 'Disabled':
            self._process_spike_sound_alerts()

    def _on_auto_open_graph_toggled(self) -> None:
        checked = self._auto_open_graph_checkbox.isChecked()
        self._auto_open_graph = checked
        if Settings.high_rate_monitor_auto_open_graph != checked:
            Settings.high_rate_monitor_auto_open_graph = checked
            Settings.rewrite_settings_file()

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
        self._previously_flagged_ips.clear()
        self._spiking_ips.clear()
        self._pulse_timer.stop()
        self._tracked.clear()
        self._current_avg_pps = 0.0
        self._current_avg_bps = 0.0
        self._current_smart_pps_threshold = SMART_MIN_PPS_FLOOR
        self._current_smart_bps_threshold = SMART_MIN_BPS_KB_FLOOR * KBS_TO_BYTES
        HighRateTracker.set_flagged_ips(set())
        active_pps_threshold, active_bps_threshold = self._active_thresholds()
        for graph in self._graph_windows.values():
            if graph.monitor_mode == 'Smart':
                graph.set_pps_threshold(self._current_smart_pps_threshold)
                graph.set_bps_threshold(self._current_smart_bps_threshold)
            elif not graph.has_local_threshold_override:
                graph.set_pps_threshold(active_pps_threshold)
                graph.set_bps_threshold(active_bps_threshold)
            graph.update_spike_visuals(PlayerSpikeVisualUpdate())
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
