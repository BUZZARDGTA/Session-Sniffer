"""Live PPS + BPS split graph window for an individual player."""

from collections import deque
from dataclasses import dataclass
from typing import TYPE_CHECKING, override

from PySide6.QtCore import QSignalBlocker, Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QComboBox, QHBoxLayout, QLabel, QSpinBox, QWidget

from session_sniffer.guis._spike_sound_controls import (
    SPIKE_VOLUME_MAX,
    SPIKE_VOLUME_MIN,
    SpikeSoundQuickBar,
    SpikeSoundQuickBarCallbacks,
    SpikeSoundQuickBarState,
    SpikeVolumeChangedCallback,
    SpikeVolumePersistMode,
)
from session_sniffer.guis.live_language import register_language_refresh, set_i18n_colon_label
from session_sniffer.guis.rate_graph_widget import (
    RateGraphTheme,
    RateGraphWidget,
    SpikeOverlayState,
    ThresholdDragConfig,
)
from session_sniffer.guis.utils import RateGraphWindowMixin, format_player_display, scale_by_ui
from session_sniffer.i18n import tr
from session_sniffer.models.player_traffic import PlayerBandwidth

if TYPE_CHECKING:
    from collections.abc import Callable

    from PySide6.QtWidgets import QVBoxLayout

VISIBLE_WINDOW = 60
DEFAULT_MAX_HISTORY = 3600

HISTORY_OPTIONS = {
    '1 Minute': 60,
    '5 Minutes': 300,
    '15 Minutes': 900,
    '30 Minutes': 1800,
    '1 Hour': 3600,
}


class SingleRateGraphBase(RateGraphWindowMixin):
    """Base class for single-series sliding-window rate graph windows."""

    WINDOW_TITLE: str
    LEFT_LABEL: str
    CURVE_PEN: str
    CURVE_BRUSH: tuple[int, int, int, int]
    AVG_PEN: str
    Y_FLOOR: float
    _graph_idle: bool
    _buffer: deque[float]

    def __init__(self) -> None:
        """Initialize the shared single-series graph window."""
        super().__init__()

        self._max_history = DEFAULT_MAX_HISTORY
        self._buffer_running_sum = 0.0

        self._apply_translations()
        register_language_refresh(self, self._apply_translations)
        self.resize(scale_by_ui(700), scale_by_ui(350))
        layout = self.setup_window_layout(always_on_top=True, margins=(0, 0, 0, 0), spacing=0)

        self._widget = RateGraphWidget(
            left_label=self.LEFT_LABEL,
            theme=RateGraphTheme(
                line_color=self.CURVE_PEN,
                fill_color=QColor(*self.CURVE_BRUSH),
                avg_color=self.AVG_PEN,
            ),
            visible_window=VISIBLE_WINDOW,
        )
        self._widget.set_y_range(0, self.Y_FLOOR)
        layout.addWidget(self._widget)

        self.add_rate_graph_controls(layout, HISTORY_OPTIONS, default_history=DEFAULT_MAX_HISTORY)
        self._setup_single_history_buffers()

    def _apply_translations(self) -> None:
        """Apply translated text to the window title."""
        self.setWindowTitle(tr(self.WINDOW_TITLE))

    @override
    def _on_max_history_changed(self, new_max_history: int) -> None:
        """Re-allocate the sliding buffer when Max History is changed."""
        self._max_history = new_max_history
        self._buffer = deque(self._buffer, maxlen=self._max_history)
        self._buffer_running_sum = sum(self._buffer)

    def _setup_single_history_buffers(self) -> None:
        """Initialise pre-allocated sliding-window buffers."""
        self._buffer: deque[float] = deque(maxlen=self._max_history)
        self._buffer_running_sum = 0.0
        self._graph_idle: bool = False
        for _ in range(VISIBLE_WINDOW):
            self._buffer.append(0.0)

    def _transform_sample(self, sample: float) -> float:
        """Convert an incoming sample into the value stored in the buffer."""
        return sample

    def update_graph(self, sample: float) -> None:
        """Append a new sample and refresh the graph."""
        value = self._transform_sample(sample)

        if len(self._buffer) == self._max_history:
            self._buffer_running_sum -= self._buffer[0]

        self._buffer.append(value)
        self._buffer_running_sum += value

        # Skip draw calls when the graph is already showing a stable
        # flat zero baseline and the new sample is also zero.
        if not value and self._graph_idle:
            return

        visible_data = list(self._buffer)[-VISIBLE_WINDOW:]
        visible_max = max(visible_data) if visible_data else 0.0

        self._widget.set_data(list(self._buffer))
        self._widget.set_y_range(0, max(visible_max * 1.2, self.Y_FLOOR))
        self._widget.set_average(self._buffer_running_sum / len(self._buffer) if self._buffer else 0)

        # Mark graph as idle once the visible window is fully zeroed out.
        self._graph_idle = not value and not visible_max

    def reset(self) -> None:
        """Clear all history and reset the graph to zero."""
        self._setup_single_history_buffers()
        self._widget.set_data(list(self._buffer))
        self._widget.set_y_range(0, self.Y_FLOOR)
        self._widget.set_average(0)


class DualRateGraphBase(RateGraphWindowMixin):
    """Base class for dual PPS+BPS graph windows."""

    PPS_Y_FLOOR: float = 10.0
    BPS_Y_FLOOR: float = 1.0
    _max_history: int
    _dual_graph_idle: bool
    _BYTES_TO_KBS: int = 1024
    _pps_widget: RateGraphWidget
    _bps_widget: RateGraphWidget
    _pps_buffer: deque[float]
    _bps_buffer: deque[float]
    _pps_running_sum: int
    _bps_running_sum: float

    def _setup_dual_graph_widgets(self, layout: QVBoxLayout) -> None:
        """Create PPS and BPS PlotWidgets and add them to *layout*."""
        # ── PPS graph (top) — lime green tones ──────────────────────────
        self._pps_widget = RateGraphWidget.create_pps_widget(visible_window=VISIBLE_WINDOW)
        self._pps_widget.set_y_range(0, self.PPS_Y_FLOOR)
        self._configure_pps_widget()
        layout.addWidget(self._pps_widget)

        # ── BPS graph (bottom) — cyan/teal tones ────────────────────────
        self._bps_widget = RateGraphWidget.create_bps_widget(visible_window=VISIBLE_WINDOW)
        self._bps_widget.set_y_range(0, self.BPS_Y_FLOOR)
        self._configure_bps_widget()
        layout.addWidget(self._bps_widget)

    def _configure_pps_widget(self) -> None:
        """Override to add PPS-specific configuration (threshold lines, custom limits, etc.)."""

    def _configure_bps_widget(self) -> None:
        """Override to add BPS-specific configuration (threshold lines, etc.)."""

    def _add_pre_footer_controls(self, layout: QVBoxLayout) -> None:
        """Override to insert an additional controls bar directly above the footer controls."""

    def _pps_y_ceiling(self, visible_max: float) -> float:
        """Return the upper Y-axis bound for the PPS graph."""
        return max(visible_max * 1.2, self.PPS_Y_FLOOR)

    def _bps_y_ceiling(self, visible_max: float) -> float:
        """Return the upper Y-axis bound for the BPS graph."""
        return max(visible_max * 1.2, self.BPS_Y_FLOOR)

    def _finish_graph_init(self) -> None:
        """Initialize the common window layout, widgets, and history buffers."""
        self._max_history = DEFAULT_MAX_HISTORY
        self.resize(scale_by_ui(700), scale_by_ui(500))
        layout = self.setup_window_layout(always_on_top=True, margins=(0, 0, 0, 0), spacing=0)
        self._setup_dual_graph_widgets(layout)
        self._add_pre_footer_controls(layout)
        self.add_rate_graph_controls(layout, HISTORY_OPTIONS, default_history=DEFAULT_MAX_HISTORY)
        self._setup_history_buffers()

    @override
    def _on_max_history_changed(self, new_max_history: int) -> None:
        """Re-allocate the sliding buffer when Max History is changed."""
        self._max_history = new_max_history
        self._pps_buffer = deque(self._pps_buffer, maxlen=self._max_history)
        self._bps_buffer = deque(self._bps_buffer, maxlen=self._max_history)
        self._pps_running_sum = int(sum(self._pps_buffer))
        self._bps_running_sum = sum(self._bps_buffer)

    def _setup_history_buffers(self) -> None:
        """Initialise pre-allocated sliding-window buffers."""
        self._pps_buffer: deque[float] = deque(maxlen=self._max_history)
        self._bps_buffer: deque[float] = deque(maxlen=self._max_history)

        for _ in range(VISIBLE_WINDOW):
            self._pps_buffer.append(0.0)
            self._bps_buffer.append(0.0)

        self._pps_running_sum: int = 0
        self._bps_running_sum = 0.0
        self._dual_graph_idle: bool = False

    def update_rates(self, *, pps: int, bps: int) -> None:
        """Append new PPS and BPS samples and refresh both graphs."""
        kbps = bps / self._BYTES_TO_KBS

        if len(self._pps_buffer) == self._max_history:
            self._pps_running_sum -= int(self._pps_buffer[0])
            self._bps_running_sum -= self._bps_buffer[0]

        self._pps_buffer.append(pps)
        self._bps_buffer.append(kbps)
        self._pps_running_sum += pps
        self._bps_running_sum += kbps

        if not pps and not bps and self._dual_graph_idle:
            return

        pps_list, bps_list = self._render_buffers()

        if not pps and not bps:
            _pps_visible_max = max(pps_list[-VISIBLE_WINDOW:]) if pps_list else 0.0
            _bps_visible_max = max(bps_list[-VISIBLE_WINDOW:]) if bps_list else 0.0
            self._dual_graph_idle = not _pps_visible_max and not _bps_visible_max
        else:
            self._dual_graph_idle = False

    def _render_buffers(self) -> tuple[list[float], list[float]]:
        """Render the current PPS and BPS history buffers and update auto-scaled Y ranges and averages."""
        pps_list = list(self._pps_buffer)
        bps_list = list(self._bps_buffer)

        self._pps_widget.set_data(pps_list)
        pps_visible_max = max(pps_list[-VISIBLE_WINDOW:]) if pps_list else 0.0
        self._pps_widget.set_y_range(0, self._pps_y_ceiling(pps_visible_max))
        self._pps_widget.set_average(self._pps_running_sum / len(self._pps_buffer) if self._pps_buffer else 0.0)

        self._bps_widget.set_data(bps_list)
        bps_visible_max = max(bps_list[-VISIBLE_WINDOW:]) if bps_list else 0.0
        self._bps_widget.set_y_range(0, self._bps_y_ceiling(bps_visible_max))
        self._bps_widget.set_average(self._bps_running_sum / len(self._bps_buffer) if self._bps_buffer else 0.0)

        return pps_list, bps_list


_MONITOR_MODES: tuple[str, ...] = ('Smart', 'Manual')
_PPS_THRESHOLD_MIN = 20
_PPS_THRESHOLD_MAX = 50
_BPS_THRESHOLD_KB_MIN = 3
_BPS_THRESHOLD_KB_MAX = 500
_REPEAT_INTERVAL_MIN = 1
_REPEAT_INTERVAL_MAX = 30
_STREAK_SMOOTHING_WINDOW = 3
_STREAK_HOLD_RATIO = 0.90


def _backfill_series_streak(samples: list[int], threshold: int) -> tuple[int, int]:
    """Compute trailing `(streak_seconds, peak_value)` from *samples* using 3s smoothing + 10% hold hysteresis."""
    if threshold <= 0 or not samples:
        return 0, 0
    release_limit = round(threshold * _STREAK_HOLD_RATIO)
    streak = 0
    peak = 0
    window: deque[int] = deque(maxlen=_STREAK_SMOOTHING_WINDOW)
    for raw in samples:
        window.append(raw)
        effective = max(raw, round(sum(window) / len(window)))
        limit = release_limit if streak > 0 else threshold
        if effective >= limit:
            streak += 1
            peak = max(peak, raw)
        else:
            streak = 0
            peak = 0
    return streak, peak


@dataclass(frozen=True, slots=True)
class SpikeAlertGraphState:
    """Synchronized monitor threshold and Spike Alert state for `PlayerRateGraphWindow`."""

    monitor_mode: str = 'Smart'
    manual_pps_threshold: int = 30
    manual_bps_threshold_kb: int = 5
    sound_scope: str = 'Open Graphs'
    sound_mode: str = 'Repeating'
    repeat_interval: int = 2
    sound_volume: int = 100
    visual_alert: bool = True


@dataclass(frozen=True, slots=True)
class SpikeAlertGraphConfig:
    """Initial Spike Alert settings and callbacks for `PlayerRateGraphWindow`."""

    state: SpikeAlertGraphState = SpikeAlertGraphState()
    on_thresholds_changed: Callable[[str], None] | None = None
    on_scope_changed: Callable[[str], None] | None = None
    on_mode_changed: Callable[[str], None] | None = None
    on_repeat_interval_changed: Callable[[int], None] | None = None
    on_volume_changed: SpikeVolumeChangedCallback | None = None


@dataclass(frozen=True, slots=True)
class PlayerSpikeVisualUpdate:
    """Per-tick visual spike and proximity telemetry pushed to `PlayerRateGraphWindow`."""

    pps_spiking: bool = False
    bps_spiking: bool = False
    pps: int = 0
    bps: int = 0
    pps_proximity: float = 0.0
    bps_proximity: float = 0.0
    pps_approaching: bool = False
    bps_approaching: bool = False


class PlayerRateGraphWindow(DualRateGraphBase):
    """A standalone window with separate PPS and BPS graphs stacked vertically."""

    PPS_Y_FLOOR = 100.0
    BPS_Y_FLOOR = 50.0

    def __init__(
        self,
        *,
        ip: str,
        initial_pps_threshold: int,
        initial_bps_threshold: int,
        spike_config: SpikeAlertGraphConfig | None = None,
    ) -> None:
        """Initialize the split rate graph window for the given player IP."""
        super().__init__()
        cfg = spike_config or SpikeAlertGraphConfig()
        state = cfg.state

        self.ip = ip
        self._usernames: list[str] = []
        self._pps_threshold_value = initial_pps_threshold
        self._bps_threshold_value = initial_bps_threshold
        self._global_monitor_mode = state.monitor_mode
        self._monitor_mode = state.monitor_mode
        self._has_local_threshold_override = False
        self._manual_pps_threshold = state.manual_pps_threshold
        self._manual_bps_threshold_kb = state.manual_bps_threshold_kb
        self._repeat_interval = state.repeat_interval
        self._pps_spiking = False
        self._bps_spiking = False
        self._pps_spike_streak = 0
        self._pps_spike_peak = 0
        self._bps_spike_streak = 0
        self._bps_spike_peak = 0
        self._last_visual_update = PlayerSpikeVisualUpdate()
        self._spike_sound_scope = state.sound_scope
        self._spike_sound_mode = state.sound_mode
        self._spike_sound_volume = min(SPIKE_VOLUME_MAX, max(SPIKE_VOLUME_MIN, state.sound_volume))
        self._visual_alert_enabled = state.visual_alert
        self._on_thresholds_changed = cfg.on_thresholds_changed
        self._on_spike_sound_scope_changed = cfg.on_scope_changed
        self._on_spike_sound_mode_changed = cfg.on_mode_changed
        self._on_repeat_interval_changed = cfg.on_repeat_interval_changed
        self._on_spike_sound_volume_changed = cfg.on_volume_changed
        self._monitor_mode_combo: QComboBox | None = None
        self._pps_label: QLabel | None = None
        self._pps_spinbox: QSpinBox | None = None
        self._bps_label: QLabel | None = None
        self._bps_spinbox: QSpinBox | None = None
        self._interval_label: QLabel | None = None
        self._interval_spinbox: QSpinBox | None = None
        self._spike_sound_bar: SpikeSoundQuickBar | None = None

        self._update_window_title()
        register_language_refresh(self, self._update_window_title)
        self._finish_graph_init()
        self.resize(scale_by_ui(860), scale_by_ui(535))

    @property
    def monitor_mode(self) -> str:
        """Return the threshold mode (`Smart` or `Manual`) currently active in this graph window."""
        return self._monitor_mode

    @property
    def has_local_threshold_override(self) -> bool:
        """Return whether the user locally customized thresholds in this graph window."""
        return self._has_local_threshold_override

    @property
    def pps_threshold(self) -> int:
        """Return the active PPS threshold for this graph window."""
        return self._pps_threshold_value

    @property
    def bps_threshold(self) -> int:
        """Return the active BPS threshold in bytes/s for this graph window."""
        return self._bps_threshold_value

    @override
    def _pps_y_ceiling(self, visible_max: float) -> float:
        base = max(visible_max * 1.2, self._pps_threshold_value * 1.15, self.PPS_Y_FLOOR)
        return max(base, self._pps_widget.y_max) if self._pps_widget.is_dragging_threshold else base

    @override
    def _bps_y_ceiling(self, visible_max: float) -> float:
        bps_kb = self._bps_threshold_value / self._BYTES_TO_KBS
        base = max(visible_max * 1.2, bps_kb * 1.15, self.BPS_Y_FLOOR)
        return max(base, self._bps_widget.y_max) if self._bps_widget.is_dragging_threshold else base

    @override
    def _add_pre_footer_controls(self, layout: QVBoxLayout) -> None:
        controls_bar = QWidget()
        row = QHBoxLayout(controls_bar)
        row.setContentsMargins(8, 6, 8, 0)
        row.setSpacing(scale_by_ui(6))

        thresholds_label = QLabel()
        set_i18n_colon_label(thresholds_label, 'Thresholds')
        row.addWidget(thresholds_label)

        monitor_mode_combo = QComboBox()
        monitor_mode_combo.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        for mode_opt in _MONITOR_MODES:
            monitor_mode_combo.addItem(tr(mode_opt), mode_opt)
        if (m_idx := monitor_mode_combo.findData(self._monitor_mode)) >= 0:
            monitor_mode_combo.setCurrentIndex(m_idx)
        monitor_mode_combo.currentIndexChanged.connect(self._handle_monitor_mode_combo_changed)
        row.addWidget(monitor_mode_combo)
        self._monitor_mode_combo = monitor_mode_combo

        row.addSpacing(scale_by_ui(6))

        pps_label = QLabel()
        set_i18n_colon_label(pps_label, 'PPS')
        row.addWidget(pps_label)
        self._pps_label = pps_label

        pps_spin = QSpinBox()
        pps_spin.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        pps_spin.setRange(
            _PPS_THRESHOLD_MIN,
            _PPS_THRESHOLD_MAX if self._monitor_mode == 'Manual' else max(_PPS_THRESHOLD_MAX, self._pps_threshold_value),
        )
        pps_spin.setValue(
            self._manual_pps_threshold
            if self._monitor_mode == 'Manual'
            else max(_PPS_THRESHOLD_MIN, self._pps_threshold_value),
        )
        pps_spin.lineEdit().setTextMargins(scale_by_ui(5), 0, 0, 0)
        pps_spin.valueChanged.connect(self._handle_pps_spinbox_changed)
        row.addWidget(pps_spin)
        self._pps_spinbox = pps_spin

        row.addSpacing(scale_by_ui(6))

        bps_label = QLabel()
        set_i18n_colon_label(bps_label, 'BPS')
        row.addWidget(bps_label)
        self._bps_label = bps_label

        bps_spin = QSpinBox()
        bps_spin.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        bps_spin.setRange(_BPS_THRESHOLD_KB_MIN, _BPS_THRESHOLD_KB_MAX)
        bps_spin.setValue(
            self._manual_bps_threshold_kb
            if self._monitor_mode == 'Manual'
            else min(_BPS_THRESHOLD_KB_MAX, max(_BPS_THRESHOLD_KB_MIN, round(self._bps_threshold_value / self._BYTES_TO_KBS))),
        )
        bps_spin.lineEdit().setTextMargins(scale_by_ui(5), 0, 0, 0)
        bps_spin.valueChanged.connect(self._handle_bps_spinbox_changed)
        row.addWidget(bps_spin)
        self._bps_spinbox = bps_spin

        row.addSpacing(scale_by_ui(10))

        interval_label = QLabel()
        set_i18n_colon_label(interval_label, 'Interval')
        row.addWidget(interval_label)
        self._interval_label = interval_label

        interval_spin = QSpinBox()
        interval_spin.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        interval_spin.setRange(_REPEAT_INTERVAL_MIN, _REPEAT_INTERVAL_MAX)
        interval_spin.setValue(min(_REPEAT_INTERVAL_MAX, max(_REPEAT_INTERVAL_MIN, self._repeat_interval)))
        interval_spin.lineEdit().setTextMargins(scale_by_ui(5), 0, 0, 0)
        interval_spin.valueChanged.connect(self._handle_interval_spinbox_changed)
        row.addWidget(interval_spin)
        self._interval_spinbox = interval_spin

        row.addStretch()

        def _refresh_threshold_bar_language() -> None:
            for i, canonical_mode in enumerate(_MONITOR_MODES):
                if i < monitor_mode_combo.count():
                    monitor_mode_combo.setItemText(i, tr(canonical_mode))
            pps_spin.setSuffix(f" {tr('PPS')}")
            bps_spin.setSuffix(f" {tr('KB/s')}")
            interval_spin.setSuffix(f" {tr('seconds')}")
            mode_desc = tr(
                'Detection mode for flagging high packet-rate players.\n\n'
                'Smart: Dynamically calculates the average PPS and BPS of connected players and flags players '
                'exceeding the session averages with a margin and minimum floor.\n'
                'Manual: Flags players exceeding fixed PPS and BPS thresholds.',
            )
            local_note = tr('Changes here apply only to this graph window and do not modify global settings.')
            mode_tip = f'{mode_desc}\n\n{local_note}'
            thresholds_label.setToolTip(mode_tip)
            monitor_mode_combo.setToolTip(mode_tip)
            self._refresh_dependent_control_states()

        _refresh_threshold_bar_language()
        register_language_refresh(controls_bar, _refresh_threshold_bar_language)
        layout.addWidget(controls_bar)

    @override
    def _create_extra_rate_graph_controls(self) -> list[QWidget]:
        initial_bar_state = SpikeSoundQuickBarState(self._spike_sound_scope, self._spike_sound_mode, self._spike_sound_volume)
        bar_callbacks = SpikeSoundQuickBarCallbacks(
            on_scope_changed=self._handle_scope_changed,
            on_mode_changed=self._handle_mode_changed,
            on_volume_changed=self._handle_volume_changed,
        )
        self._spike_sound_bar = SpikeSoundQuickBar(initial_bar_state, bar_callbacks)
        return [self._spike_sound_bar]

    def _refresh_dependent_control_states(self) -> None:
        sound_active = self._spike_sound_scope != 'Disabled'
        repeats_active = sound_active and self._spike_sound_mode in ('Repeating', 'Repeating + End', 'Adaptive Geiger')
        is_manual = self._monitor_mode == 'Manual'
        scope_disabled_note = tr('Disabled when Spike Sound Scope is set to Disabled.')
        repeat_disabled_note = tr('Only applies when Spike Sound Behavior repeats while spiking (Repeating, Repeating + End, or Adaptive Geiger).')
        smart_disabled_note = tr('Disabled in Smart mode (packet rate thresholds are calculated dynamically from the session average).')
        drag_tip = tr('Tip: Drag the dashed threshold line directly on the graph to adjust it on the fly.')
        local_note = tr('Changes here apply only to this graph window and do not modify global settings.')

        if self._pps_label is not None and self._pps_spinbox is not None:
            self._pps_label.setEnabled(is_manual)
            self._pps_spinbox.setEnabled(is_manual)
            pps_base_tip = f"{tr('Minimum Packets Per Second required to flag a player as high-rate traffic.')}\n\n{drag_tip}\n{local_note}"
            pps_tip = pps_base_tip if is_manual else f'{pps_base_tip}\n\n{smart_disabled_note}'
            self._pps_label.setToolTip(pps_tip)
            self._pps_spinbox.setToolTip(pps_tip)

        if self._bps_label is not None and self._bps_spinbox is not None:
            self._bps_label.setEnabled(is_manual)
            self._bps_spinbox.setEnabled(is_manual)
            bps_base_tip = f"{tr('Minimum bandwidth in kilobytes per second (KB/s) required to flag a player as high-rate traffic.')}\n\n{drag_tip}\n{local_note}"
            bps_tip = bps_base_tip if is_manual else f'{bps_base_tip}\n\n{smart_disabled_note}'
            self._bps_label.setToolTip(bps_tip)
            self._bps_spinbox.setToolTip(bps_tip)

        if self._interval_label is not None and self._interval_spinbox is not None:
            self._interval_label.setEnabled(repeats_active)
            self._interval_spinbox.setEnabled(repeats_active)
            interval_base_tip = tr(
                'Base interval in seconds between repeated spike sounds while a spike remains active '
                '(used as the baseline cadence in Adaptive Geiger mode).',
            )
            disabled_reason = scope_disabled_note if not sound_active else repeat_disabled_note
            interval_tip = interval_base_tip if repeats_active else f'{interval_base_tip}\n\n{disabled_reason}'
            self._interval_label.setToolTip(interval_tip)
            self._interval_spinbox.setToolTip(interval_tip)

    def _handle_monitor_mode_combo_changed(self, index: int) -> None:
        if self._monitor_mode_combo is None:
            return
        mode = str(self._monitor_mode_combo.itemData(index))
        self._monitor_mode = mode
        if mode == 'Manual':
            self._has_local_threshold_override = True
            if self._pps_spinbox is not None:
                with QSignalBlocker(self._pps_spinbox):
                    self._pps_spinbox.setMaximum(_PPS_THRESHOLD_MAX)
                    self._pps_spinbox.setValue(self._manual_pps_threshold)
            if self._bps_spinbox is not None:
                with QSignalBlocker(self._bps_spinbox):
                    self._bps_spinbox.setValue(self._manual_bps_threshold_kb)
            self.set_pps_threshold(self._manual_pps_threshold)
            self.set_bps_threshold(self._manual_bps_threshold_kb * self._BYTES_TO_KBS)
        else:
            self._has_local_threshold_override = self._global_monitor_mode != 'Smart'
        self._refresh_dependent_control_states()
        if self._on_thresholds_changed is not None:
            self._on_thresholds_changed(self.ip)

    def _handle_pps_spinbox_changed(self, value: int) -> None:
        self._has_local_threshold_override = True
        self._manual_pps_threshold = value
        self.set_pps_threshold(value)
        if self._on_thresholds_changed is not None:
            self._on_thresholds_changed(self.ip)

    def _handle_bps_spinbox_changed(self, value: int) -> None:
        self._has_local_threshold_override = True
        self._manual_bps_threshold_kb = value
        self.set_bps_threshold(value * self._BYTES_TO_KBS)
        if self._on_thresholds_changed is not None:
            self._on_thresholds_changed(self.ip)

    def _handle_interval_spinbox_changed(self, value: int) -> None:
        self._repeat_interval = value
        if self._on_repeat_interval_changed is not None:
            self._on_repeat_interval_changed(value)

    def _switch_to_manual_on_drag(self) -> None:
        self._has_local_threshold_override = True
        if self._monitor_mode == 'Manual':
            return
        self._manual_pps_threshold = min(_PPS_THRESHOLD_MAX, max(_PPS_THRESHOLD_MIN, self._pps_threshold_value))
        self._manual_bps_threshold_kb = min(
            _BPS_THRESHOLD_KB_MAX,
            max(_BPS_THRESHOLD_KB_MIN, round(self._bps_threshold_value / self._BYTES_TO_KBS)),
        )
        self._pps_threshold_value = self._manual_pps_threshold
        self._bps_threshold_value = self._manual_bps_threshold_kb * self._BYTES_TO_KBS
        self._monitor_mode = 'Manual'
        if self._monitor_mode_combo is not None:
            with QSignalBlocker(self._monitor_mode_combo):
                if (m_idx := self._monitor_mode_combo.findData('Manual')) >= 0:
                    self._monitor_mode_combo.setCurrentIndex(m_idx)
        if self._pps_spinbox is not None:
            with QSignalBlocker(self._pps_spinbox):
                self._pps_spinbox.setMaximum(_PPS_THRESHOLD_MAX)
                self._pps_spinbox.setValue(self._manual_pps_threshold)
        if self._bps_spinbox is not None:
            with QSignalBlocker(self._bps_spinbox):
                self._bps_spinbox.setValue(self._manual_bps_threshold_kb)
        self._refresh_dependent_control_states()

    def _on_pps_drag_preview(self, value: int) -> None:
        self._switch_to_manual_on_drag()
        self._pps_threshold_value = value
        self._manual_pps_threshold = value
        if self._pps_spinbox is not None:
            with QSignalBlocker(self._pps_spinbox):
                self._pps_spinbox.setValue(value)
        if self._on_thresholds_changed is not None:
            self._on_thresholds_changed(self.ip)

    def _on_pps_drag_commit(self, value: int) -> None:
        self._on_pps_drag_preview(value)
        if hasattr(self, '_pps_buffer'):
            self._render_buffers()

    def _on_bps_drag_preview(self, value_kb: int) -> None:
        self._switch_to_manual_on_drag()
        self._manual_bps_threshold_kb = value_kb
        self._bps_threshold_value = value_kb * self._BYTES_TO_KBS
        if self._bps_spinbox is not None:
            with QSignalBlocker(self._bps_spinbox):
                self._bps_spinbox.setValue(value_kb)
        if self._on_thresholds_changed is not None:
            self._on_thresholds_changed(self.ip)

    def _on_bps_drag_commit(self, value_kb: int) -> None:
        self._on_bps_drag_preview(value_kb)
        if hasattr(self, '_bps_buffer'):
            self._render_buffers()

    def _handle_scope_changed(self, scope: str) -> None:
        self._spike_sound_scope = scope
        self._refresh_dependent_control_states()
        if self._on_spike_sound_scope_changed is not None:
            self._on_spike_sound_scope_changed(scope)

    def _handle_mode_changed(self, mode: str) -> None:
        self._spike_sound_mode = mode
        self._refresh_dependent_control_states()
        if self._on_spike_sound_mode_changed is not None:
            self._on_spike_sound_mode_changed(mode)

    def _handle_volume_changed(self, volume: int, persist_mode: SpikeVolumePersistMode) -> None:
        self._spike_sound_volume = volume
        if self._on_spike_sound_volume_changed is not None:
            self._on_spike_sound_volume_changed(volume, persist_mode)

    def sync_spike_alert_settings(self, state: SpikeAlertGraphState) -> None:
        """Synchronize global threshold defaults and Spike Alert settings without overwriting per-graph threshold overrides."""
        self._global_monitor_mode = state.monitor_mode
        if not self._has_local_threshold_override:
            self._monitor_mode = state.monitor_mode
            self._manual_pps_threshold = state.manual_pps_threshold
            self._manual_bps_threshold_kb = state.manual_bps_threshold_kb
            if self._monitor_mode_combo is not None:
                with QSignalBlocker(self._monitor_mode_combo):
                    if (m_idx := self._monitor_mode_combo.findData(state.monitor_mode)) >= 0:
                        self._monitor_mode_combo.setCurrentIndex(m_idx)
            if self._pps_spinbox is not None and not self._pps_widget.is_dragging_threshold:
                with QSignalBlocker(self._pps_spinbox):
                    self._pps_spinbox.setMaximum(
                        _PPS_THRESHOLD_MAX if state.monitor_mode == 'Manual' else max(_PPS_THRESHOLD_MAX, self._pps_threshold_value),
                    )
                    self._pps_spinbox.setValue(
                        state.manual_pps_threshold
                        if state.monitor_mode == 'Manual'
                        else max(_PPS_THRESHOLD_MIN, self._pps_threshold_value),
                    )
            if self._bps_spinbox is not None and not self._bps_widget.is_dragging_threshold:
                with QSignalBlocker(self._bps_spinbox):
                    self._bps_spinbox.setValue(
                        state.manual_bps_threshold_kb
                        if state.monitor_mode == 'Manual'
                        else min(_BPS_THRESHOLD_KB_MAX, max(_BPS_THRESHOLD_KB_MIN, round(self._bps_threshold_value / self._BYTES_TO_KBS))),
                    )
        self._repeat_interval = state.repeat_interval
        self._spike_sound_scope = state.sound_scope
        self._spike_sound_mode = state.sound_mode
        self._spike_sound_volume = min(SPIKE_VOLUME_MAX, max(SPIKE_VOLUME_MIN, state.sound_volume))
        visual_changed = self._visual_alert_enabled != state.visual_alert
        self._visual_alert_enabled = state.visual_alert
        if self._interval_spinbox is not None:
            with QSignalBlocker(self._interval_spinbox):
                self._interval_spinbox.setValue(min(_REPEAT_INTERVAL_MAX, max(_REPEAT_INTERVAL_MIN, state.repeat_interval)))
        if self._spike_sound_bar is not None:
            self._spike_sound_bar.sync_state(
                SpikeSoundQuickBarState(self._spike_sound_scope, self._spike_sound_mode, self._spike_sound_volume),
            )
        self._refresh_dependent_control_states()
        if visual_changed:
            self._pps_widget.set_heat_gradient(enabled=self._visual_alert_enabled)
            self._bps_widget.set_heat_gradient(enabled=self._visual_alert_enabled)
            self._apply_visual_spike_widgets()

    def _update_window_title(self) -> None:
        """Update the window title to reflect the current player identity and language."""
        player_display = format_player_display(self.ip, self._usernames) if self._usernames else self.ip
        self.setWindowTitle(tr('Rate Graph — {player}', player=player_display))

    @override
    def _configure_pps_widget(self) -> None:
        self._pps_widget.set_threshold_color('#66bb6a')
        self._pps_widget.set_heat_gradient(enabled=self._visual_alert_enabled)
        self._pps_widget.set_threshold_drag_config(
            ThresholdDragConfig(
                min_value=_PPS_THRESHOLD_MIN,
                max_value=_PPS_THRESHOLD_MAX,
                unit_label='PPS',
                on_preview=self._on_pps_drag_preview,
                on_commit=self._on_pps_drag_commit,
            ),
        )
        self.set_pps_threshold(self._pps_threshold_value)

    @override
    def _configure_bps_widget(self) -> None:
        self._bps_widget.set_threshold_color('#4dd0e1')
        self._bps_widget.set_heat_gradient(enabled=self._visual_alert_enabled)
        self._bps_widget.set_threshold_drag_config(
            ThresholdDragConfig(
                min_value=_BPS_THRESHOLD_KB_MIN,
                max_value=_BPS_THRESHOLD_KB_MAX,
                unit_label='KB/s',
                on_preview=self._on_bps_drag_preview,
                on_commit=self._on_bps_drag_commit,
            ),
        )
        self.set_bps_threshold(self._bps_threshold_value)

    def update_usernames(self, usernames: list[str]) -> None:
        """Update the window title to reflect current usernames."""
        self._usernames = list(usernames)
        self._update_window_title()

    def set_pps_threshold(self, threshold: int) -> None:
        """Update the PPS threshold marker line."""
        if self._pps_widget.is_dragging_threshold:
            return
        self._pps_threshold_value = threshold
        self._pps_widget.set_threshold(float(threshold))
        if self._monitor_mode == 'Smart' and self._pps_spinbox is not None:
            with QSignalBlocker(self._pps_spinbox):
                self._pps_spinbox.setMaximum(max(_PPS_THRESHOLD_MAX, threshold))
                self._pps_spinbox.setValue(max(_PPS_THRESHOLD_MIN, threshold))
        if hasattr(self, '_pps_buffer'):
            pps_visible_max = max(list(self._pps_buffer)[-VISIBLE_WINDOW:]) if self._pps_buffer else 0.0
            self._pps_widget.set_y_range(0, self._pps_y_ceiling(pps_visible_max))

    def set_bps_threshold(self, threshold: int) -> None:
        """Update the BPS threshold marker line (accepts bytes/s, converts to KB/s)."""
        if self._bps_widget.is_dragging_threshold:
            return
        self._bps_threshold_value = threshold
        self._bps_widget.set_threshold(threshold / self._BYTES_TO_KBS)
        if self._monitor_mode == 'Smart' and self._bps_spinbox is not None:
            with QSignalBlocker(self._bps_spinbox):
                self._bps_spinbox.setValue(
                    min(_BPS_THRESHOLD_KB_MAX, max(_BPS_THRESHOLD_KB_MIN, round(threshold / self._BYTES_TO_KBS))),
                )
        if hasattr(self, '_bps_buffer'):
            bps_visible_max = max(list(self._bps_buffer)[-VISIBLE_WINDOW:]) if self._bps_buffer else 0.0
            self._bps_widget.set_y_range(0, self._bps_y_ceiling(bps_visible_max))

    def update_spike_visuals(self, update: PlayerSpikeVisualUpdate, *, advance_streak: bool = True) -> None:
        """Update per-panel spike streak counters, peak values, and heat/proximity overlays."""
        self._last_visual_update = update
        self._pps_spiking = update.pps_spiking
        self._bps_spiking = update.bps_spiking
        if update.pps_spiking:
            if advance_streak or not self._pps_spike_streak:
                self._pps_spike_streak += 1
            self._pps_spike_peak = max(self._pps_spike_peak, update.pps)
        else:
            self._pps_spike_streak = 0
            self._pps_spike_peak = 0

        if update.bps_spiking:
            if advance_streak or not self._bps_spike_streak:
                self._bps_spike_streak += 1
            self._bps_spike_peak = max(self._bps_spike_peak, update.bps)
        else:
            self._bps_spike_streak = 0
            self._bps_spike_peak = 0

        self._apply_visual_spike_widgets()

    def _apply_visual_spike_widgets(self) -> None:
        if not self._visual_alert_enabled:
            self._pps_widget.set_spike_state(SpikeOverlayState())
            self._bps_widget.set_spike_state(SpikeOverlayState())
            return

        upd = self._last_visual_update
        self._pps_widget.set_spike_state(
            SpikeOverlayState(
                active=self._pps_spiking,
                proximity_level=upd.pps_proximity,
                approaching=upd.pps_approaching,
                streak_seconds=self._pps_spike_streak,
                peak_text=f'{self._pps_spike_peak} PPS' if self._pps_spiking else '',
                current_rate_text=f'{upd.pps} PPS',
            ),
        )
        self._bps_widget.set_spike_state(
            SpikeOverlayState(
                active=self._bps_spiking,
                proximity_level=upd.bps_proximity,
                approaching=upd.bps_approaching,
                streak_seconds=self._bps_spike_streak,
                peak_text=PlayerBandwidth.format_bytes(self._bps_spike_peak) if self._bps_spiking else '',
                current_rate_text=PlayerBandwidth.format_bytes(upd.bps),
            ),
        )

    def load_history(self, *, pps_history: list[int], bps_history: list[int]) -> None:
        """Backfill both graphs with previously recorded rate samples."""
        pps_trimmed = pps_history[-self._max_history :]
        bps_trimmed = bps_history[-self._max_history :]
        pad_len = max(0, VISIBLE_WINDOW - len(pps_trimmed))

        self._pps_buffer.clear()
        self._bps_buffer.clear()

        for _ in range(pad_len):
            self._pps_buffer.append(0.0)
            self._bps_buffer.append(0.0)

        for pps_value in pps_trimmed:
            self._pps_buffer.append(pps_value)
        for bps_value in bps_trimmed:
            self._bps_buffer.append(float(bps_value) / self._BYTES_TO_KBS)

        self._pps_running_sum = int(sum(self._pps_buffer))
        self._bps_running_sum = sum(self._bps_buffer)
        self._pps_spike_streak, self._pps_spike_peak = _backfill_series_streak(pps_trimmed, self._pps_threshold_value)
        self._bps_spike_streak, self._bps_spike_peak = _backfill_series_streak(bps_trimmed, self._bps_threshold_value)

        self._render_buffers()
