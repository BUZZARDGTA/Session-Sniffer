"""Capture statistics window."""

import os
import time
from collections import deque
from typing import TYPE_CHECKING, override

from PySide6.QtCore import QSize, Qt, Signal
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QCheckBox, QFormLayout, QGroupBox, QHBoxLayout, QLabel, QPushButton, QVBoxLayout

from session_sniffer.capture.arp_spoofing import ArpSpoofingController
from session_sniffer.capture.process import get_process_creation_time
from session_sniffer.guis.live_language import register_language_refresh, set_i18n_colon_label
from session_sniffer.guis.player_rate_graph import DEFAULT_MAX_HISTORY, HISTORY_OPTIONS, VISIBLE_WINDOW
from session_sniffer.guis.rate_graph_widget import RateGraphWidget
from session_sniffer.guis.stylesheets import (
    GRAPH_BPS_POPOUT_BUTTON_STYLESHEET,
    GRAPH_LATENCY_POPOUT_BUTTON_STYLESHEET,
    GRAPH_PPS_POPOUT_BUTTON_STYLESHEET,
)
from session_sniffer.guis.theming import ICONS_DIR_PATH
from session_sniffer.guis.utils import RateGraphWindowMixin, format_duration, scale_by_ui
from session_sniffer.i18n import tr
from session_sniffer.models.player_traffic import PlayerBandwidth
from session_sniffer.player.registry import PlayersRegistry
from session_sniffer.rendering_core.types import CaptureState, CaptureStats
from session_sniffer.settings import Settings

if TYPE_CHECKING:
    from PySide6.QtCore import SignalInstance

_FLOOR_MS = 1.0
_FLOOR_PPS = 10
_FLOOR_KBS = 1.0
_BYTES_TO_KBS = 1024
_MIN_PPM_SAMPLES = 2


class CaptureStatisticsWindow(RateGraphWindowMixin):
    """A standalone window showing capture statistics, latency, and live graphs."""

    WINDOW_TITLE = 'Capture Statistics'

    open_packets_latency_graph_requested = Signal()
    open_session_pps_graph_requested = Signal()
    open_session_bps_graph_requested = Signal()

    def __init__(self) -> None:
        """Initialize the capture statistics window."""
        super().__init__()

        self._max_history = DEFAULT_MAX_HISTORY
        self._has_refreshed = False
        self._group_titles: list[tuple[QGroupBox, str]] = []
        self._popout_buttons: list[tuple[QPushButton, str]] = []

        self.resize(scale_by_ui(1200), scale_by_ui(620))
        layout = self.setup_window_layout(always_on_top=True, spacing=6)

        body_layout = QHBoxLayout()
        body_layout.setSpacing(6)

        left_column = QHBoxLayout()
        left_column.setSpacing(6)
        left_column_a = QVBoxLayout()
        left_column_a.setSpacing(6)
        left_column_b = QVBoxLayout()
        left_column_b.setSpacing(6)

        def add_form_row(form: QFormLayout, canonical_label: str, field: QLabel) -> None:
            row_label = QLabel()
            set_i18n_colon_label(row_label, canonical_label)
            form.addRow(row_label, field)

        capture_config_group = QGroupBox()
        self._group_titles.append((capture_config_group, 'Capture Config'))
        capture_config_form = QFormLayout(capture_config_group)
        self._label_interface = QLabel('—')
        self._label_ip = QLabel('—')
        self._label_interface_type = QLabel('—')
        self._label_arp = QLabel('—')
        self._label_feature_set = QLabel('—')
        self._label_discord = QLabel('—')
        add_form_row(capture_config_form, 'Interface', self._label_interface)
        add_form_row(capture_config_form, 'IP', self._label_ip)
        add_form_row(capture_config_form, 'Type', self._label_interface_type)
        add_form_row(capture_config_form, 'ARP Spoofing', self._label_arp)
        add_form_row(capture_config_form, 'Feature Set', self._label_feature_set)
        add_form_row(capture_config_form, 'Discord RPC', self._label_discord)
        left_column_a.addWidget(capture_config_group)

        players_group = QGroupBox()
        self._group_titles.append((players_group, 'Players'))
        players_form = QFormLayout(players_group)
        self._label_connected = QLabel('0')
        self._label_disconnected = QLabel('0')
        self._label_total = QLabel('0')
        add_form_row(players_form, 'Total', self._label_total)
        add_form_row(players_form, 'Connected', self._label_connected)
        add_form_row(players_form, 'Disconnected', self._label_disconnected)
        left_column_a.addWidget(players_group)

        stability_group = QGroupBox()
        self._group_titles.append((stability_group, 'Stability'))
        stability_form = QFormLayout(stability_group)
        self._label_restarts = QLabel('0')
        self._label_uptime = QLabel(format_duration(0))
        self._label_total_uptime = QLabel(format_duration(0))
        self._label_packets_dropped = QLabel('0')
        self._label_overflow_dropped = QLabel('0')
        add_form_row(stability_form, 'Total App Uptime', self._label_total_uptime)
        add_form_row(stability_form, 'Capture Uptime', self._label_uptime)
        add_form_row(stability_form, 'Capture Restarts', self._label_restarts)
        add_form_row(stability_form, 'Packets Dropped', self._label_packets_dropped)
        add_form_row(stability_form, 'Overflow Dropped', self._label_overflow_dropped)
        left_column_a.addWidget(stability_group)

        self._process_started_at: float = get_process_creation_time(os.getpid()) or time.time()

        performance_group = QGroupBox()
        self._group_titles.append((performance_group, 'Performance'))
        performance_form = QFormLayout(performance_group)
        self._label_cpu = QLabel('0%')
        self._label_peak_cpu = QLabel('0%')
        self._label_ram = QLabel()
        self._label_peak_ram = QLabel()
        self._label_threads = QLabel('0')
        self._label_peak_threads = QLabel('0')
        self._label_disk_read_rate = QLabel()
        self._label_disk_write_rate = QLabel()
        self._label_disk_read_total = QLabel()
        self._label_disk_write_total = QLabel()
        add_form_row(performance_form, 'Peak CPU', self._label_peak_cpu)
        add_form_row(performance_form, 'CPU', self._label_cpu)
        add_form_row(performance_form, 'Peak RAM', self._label_peak_ram)
        add_form_row(performance_form, 'RAM', self._label_ram)
        add_form_row(performance_form, 'Peak Threads', self._label_peak_threads)
        add_form_row(performance_form, 'Threads', self._label_threads)
        add_form_row(performance_form, 'Disk Read Total', self._label_disk_read_total)
        add_form_row(performance_form, 'Disk Read Rate', self._label_disk_read_rate)
        add_form_row(performance_form, 'Disk Write Total', self._label_disk_write_total)
        add_form_row(performance_form, 'Disk Write Rate', self._label_disk_write_rate)
        left_column_a.addWidget(performance_group)
        left_column_a.addStretch()

        traffic_group = QGroupBox()
        self._group_titles.append((traffic_group, 'Traffic'))
        traffic_form = QFormLayout(traffic_group)
        self._label_bandwidth = QLabel(PlayerBandwidth.format_bytes(0))
        self._label_download = QLabel(PlayerBandwidth.format_bytes(0))
        self._label_upload = QLabel(PlayerBandwidth.format_bytes(0))
        self._label_total_bandwidth = QLabel(PlayerBandwidth.format_bytes(0))
        self._label_total_download = QLabel(PlayerBandwidth.format_bytes(0))
        self._label_total_upload = QLabel(PlayerBandwidth.format_bytes(0))
        self._label_bps = QLabel(PlayerBandwidth.format_bytes(0))
        self._label_bpm = QLabel(PlayerBandwidth.format_bytes(0))
        self._label_peak_bps = QLabel(PlayerBandwidth.format_bytes(0))
        self._label_peak_bpm = QLabel(PlayerBandwidth.format_bytes(0))
        self._label_pps = QLabel('0')
        add_form_row(traffic_form, 'T. Bandwidth (↓↑)', self._label_total_bandwidth)
        add_form_row(traffic_form, 'Bandwidth (↓↑)', self._label_bandwidth)
        add_form_row(traffic_form, 'T. Download (↓)', self._label_total_download)
        add_form_row(traffic_form, 'Download (↓)', self._label_download)
        add_form_row(traffic_form, 'T. Upload (↑)', self._label_total_upload)
        add_form_row(traffic_form, 'Upload (↑)', self._label_upload)
        add_form_row(traffic_form, 'Peak BPS', self._label_peak_bps)
        add_form_row(traffic_form, 'BPS', self._label_bps)
        add_form_row(traffic_form, 'Peak BPM', self._label_peak_bpm)
        add_form_row(traffic_form, 'BPM', self._label_bpm)
        left_column_b.addWidget(traffic_group)

        packets_group = QGroupBox()
        self._group_titles.append((packets_group, 'Packets'))
        packets_form = QFormLayout(packets_group)
        self._label_ppm = QLabel('0')
        self._label_peak_ppm = QLabel('0')
        self._label_total_packets = QLabel('0')
        self._label_peak_pps = QLabel('0')
        add_form_row(packets_form, 'Total', self._label_total_packets)
        add_form_row(packets_form, 'Peak PPM', self._label_peak_ppm)
        add_form_row(packets_form, 'PPM', self._label_ppm)
        add_form_row(packets_form, 'Peak PPS', self._label_peak_pps)
        add_form_row(packets_form, 'PPS', self._label_pps)
        left_column_b.addWidget(packets_group)

        self._latency_group = QGroupBox()
        self._latency_group.setMinimumWidth(scale_by_ui(150))
        latency_form = QFormLayout(self._latency_group)
        self._label_latest = QLabel()
        self._label_avg = QLabel()
        self._label_min = QLabel()
        self._label_max = QLabel()
        add_form_row(latency_form, 'Latest', self._label_latest)
        add_form_row(latency_form, 'Average', self._label_avg)
        add_form_row(latency_form, 'Min', self._label_min)
        add_form_row(latency_form, 'Max', self._label_max)
        self._checkbox_all_time = QCheckBox()
        self._checkbox_all_time.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self._checkbox_all_time.toggled.connect(self._on_all_time_toggled)
        latency_form.addRow(self._checkbox_all_time)
        left_column_b.addWidget(self._latency_group)
        left_column_b.addStretch()

        left_column.addLayout(left_column_a)
        left_column.addLayout(left_column_b)

        form_spacing = scale_by_ui(2)
        form_margin_h = scale_by_ui(6)
        form_margin_v = scale_by_ui(4)
        for stats_form in (
            capture_config_form,
            players_form,
            stability_form,
            performance_form,
            traffic_form,
            packets_form,
            latency_form,
        ):
            stats_form.setVerticalSpacing(form_spacing)
            stats_form.setContentsMargins(form_margin_h, form_margin_v, form_margin_h, form_margin_v)

        right_column = QVBoxLayout()
        right_column.setSpacing(6)

        self._bps_widget = RateGraphWidget.create_bps_widget(visible_window=VISIBLE_WINDOW)
        self._bps_widget.set_y_range(0, _FLOOR_KBS)
        right_column.addWidget(
            self._create_graph_group(
                title='Bandwidth (KB/s)',
                widget=self._bps_widget,
                popout_tooltip='Open BPS Graph in a separate window',
                popout_stylesheet=GRAPH_BPS_POPOUT_BUTTON_STYLESHEET,
                popout_signal=self.open_session_bps_graph_requested,
            ),
        )

        self._pps_widget = RateGraphWidget.create_pps_widget(visible_window=VISIBLE_WINDOW)
        self._pps_widget.set_y_range(0, _FLOOR_PPS)
        right_column.addWidget(
            self._create_graph_group(
                title='Packets per Second (PPS)',
                widget=self._pps_widget,
                popout_tooltip='Open PPS Graph in a separate window',
                popout_stylesheet=GRAPH_PPS_POPOUT_BUTTON_STYLESHEET,
                popout_signal=self.open_session_pps_graph_requested,
            ),
        )

        self._latency_widget = RateGraphWidget.create_latency_widget(visible_window=VISIBLE_WINDOW)
        self._latency_widget.set_y_range(0, _FLOOR_MS)
        right_column.addWidget(
            self._create_graph_group(
                title='Latency (ms/s)',
                widget=self._latency_widget,
                popout_tooltip='Open Packets Latency Graph in a separate window',
                popout_stylesheet=GRAPH_LATENCY_POPOUT_BUTTON_STYLESHEET,
                popout_signal=self.open_packets_latency_graph_requested,
            ),
        )

        body_layout.addLayout(left_column)
        body_layout.addLayout(right_column, 1)
        layout.addLayout(body_layout)
        self.add_rate_graph_controls(layout, HISTORY_OPTIONS, default_history=DEFAULT_MAX_HISTORY)

        self._latency_buffer: deque[float] = deque(maxlen=self._max_history)
        self._pps_buffer: deque[float] = deque(maxlen=self._max_history)
        self._bps_buffer: deque[float] = deque(maxlen=self._max_history)
        for _ in range(VISIBLE_WINDOW):
            self._latency_buffer.append(0.0)
            self._pps_buffer.append(0.0)
            self._bps_buffer.append(0.0)

        self._latency_running_sum: float = 0.0
        self._pps_running_sum: int = 0
        self._bps_running_sum: float = 0.0

        self._last_latency_ms: float = 0.0
        self._last_latency_ts: float = 0.0
        self._last_avg_ms: float | None = None
        self._last_min_ms: float | None = None
        self._last_max_ms: float | None = None

        self._ppm_sample_buffer: deque[int] = deque(maxlen=61)
        self._peak_ppm: int = 0
        self._graphs_all_zero: bool = False

        self._load_history()
        self._apply_translations()
        register_language_refresh(self, self._apply_translations)

    def _create_graph_group(
        self,
        *,
        title: str,
        widget: RateGraphWidget,
        popout_tooltip: str,
        popout_stylesheet: str,
        popout_signal: SignalInstance,
    ) -> QGroupBox:
        """Create a graph group box with a top-right Pop Out button and configured rate graph widget."""
        group = QGroupBox()
        self._group_titles.append((group, title))
        layout = QVBoxLayout(group)
        popout_row = QHBoxLayout()
        popout_row.setContentsMargins(0, 0, 0, 0)
        popout_row.addStretch()
        popout_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'external-link.svg')), '')
        self._popout_buttons.append((popout_button, popout_tooltip))
        popout_button.setCursor(Qt.CursorShape.PointingHandCursor)
        popout_button.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        popout_button.setIconSize(QSize(13, 13))
        popout_button.setStyleSheet(popout_stylesheet)
        popout_button.clicked.connect(popout_signal)
        popout_row.addWidget(popout_button)
        layout.addLayout(popout_row)
        layout.addWidget(widget)
        return group

    @override
    def _on_max_history_changed(self, new_max_history: int) -> None:
        """Re-allocate the sliding buffer when Max History is changed."""
        self._max_history = new_max_history
        self._latency_buffer = deque(self._latency_buffer, maxlen=self._max_history)
        self._pps_buffer = deque(self._pps_buffer, maxlen=self._max_history)
        self._bps_buffer = deque(self._bps_buffer, maxlen=self._max_history)
        self._latency_running_sum = sum(self._latency_buffer)
        self._pps_running_sum = int(sum(self._pps_buffer))
        self._bps_running_sum = sum(self._bps_buffer)

    # Public API —————————————————————————————————————————————————————————————

    def refresh(self) -> None:
        """Refresh stats labels and advance all three live graphs by one sample."""
        self._has_refreshed = True
        self._label_restarts.setText(str(CaptureStats.restarted_times))
        self._label_packets_dropped.setText(str(CaptureStats.packets_dropped))
        self._label_overflow_dropped.setText(str(CaptureStats.packets_overflow_dropped))

        self._label_peak_cpu.setText(f'{CaptureStats.app_peak_cpu_percent:.1f}%')
        self._label_cpu.setText(f'{CaptureStats.app_cpu_percent:.1f}%')
        self._label_peak_threads.setText(str(CaptureStats.app_peak_threads))
        self._label_threads.setText(str(CaptureStats.app_active_threads))

        self._label_interface.setText(CaptureState.interface_name or '—')
        self._label_ip.setText(CaptureState.interface_ip or '—')
        self._label_interface_type.setText(CaptureState.interface_type or '—')
        self._label_feature_set.setText(Settings.capture_feature_set or '—')
        self._refresh_translatable_metrics()

        connected_count = PlayersRegistry.get_connected_count()
        disconnected_count = PlayersRegistry.get_disconnected_count()
        total_count = PlayersRegistry.get_total_count()
        self._label_connected.setText(str(connected_count))
        self._label_disconnected.setText(str(disconnected_count))
        self._label_total.setText(str(total_count))

        current_bandwidth = CaptureStats.global_bandwidth
        current_download = CaptureStats.global_download
        current_upload = CaptureStats.global_upload
        total_download = 0
        total_upload = 0
        for player in PlayersRegistry.get_players_map().values():
            bandwidth = player.bandwidth
            total_download += bandwidth.total_download
            total_upload += bandwidth.total_upload
        total_bandwidth = total_download + total_upload

        self._label_bandwidth.setText(PlayerBandwidth.format_bytes(current_bandwidth))
        self._label_download.setText(PlayerBandwidth.format_bytes(current_download))
        self._label_upload.setText(PlayerBandwidth.format_bytes(current_upload))
        self._label_total_bandwidth.setText(PlayerBandwidth.format_bytes(total_bandwidth))
        self._label_total_download.setText(PlayerBandwidth.format_bytes(total_download))
        self._label_total_upload.setText(PlayerBandwidth.format_bytes(total_upload))

        self._label_bps.setText(PlayerBandwidth.format_bytes(CaptureStats.global_bps_rate))
        self._label_bpm.setText(PlayerBandwidth.format_bytes(CaptureStats.global_bpm_rate))
        self._label_peak_bpm.setText(PlayerBandwidth.format_bytes(CaptureStats.peak_bpm_rate))
        self._label_pps.setText(str(CaptureStats.global_pps_rate))
        self._label_peak_pps.setText(str(CaptureStats.peak_pps_rate))
        self._label_peak_bps.setText(PlayerBandwidth.format_bytes(CaptureStats.peak_bps_rate))

        kbps = CaptureStats.global_bps_rate / _BYTES_TO_KBS

        if len(self._latency_buffer) == self._max_history:
            self._latency_running_sum -= self._latency_buffer[0]
            self._pps_running_sum -= int(self._pps_buffer[0])
            self._bps_running_sum -= self._bps_buffer[0]

        self._latency_buffer.append(CaptureStats.global_avg_latency_ms)
        self._latency_running_sum += CaptureStats.global_avg_latency_ms
        self._pps_buffer.append(CaptureStats.global_pps_rate)
        self._pps_running_sum += CaptureStats.global_pps_rate
        self._bps_buffer.append(kbps)
        self._bps_running_sum += kbps

        latency_data = list(self._latency_buffer)
        pps_data = list(self._pps_buffer)
        bps_data = list(self._bps_buffer)

        self._ppm_sample_buffer.append(CaptureStats.total_packets_captured)
        if self._ppm_sample_buffer and self._ppm_sample_buffer[-1] < self._ppm_sample_buffer[0]:
            self._ppm_sample_buffer.clear()
            self._ppm_sample_buffer.append(CaptureStats.total_packets_captured)
            self._peak_ppm = 0
        ppm_count = max(0, self._ppm_sample_buffer[-1] - self._ppm_sample_buffer[0]) if len(self._ppm_sample_buffer) >= _MIN_PPM_SAMPLES else 0
        self._peak_ppm = max(self._peak_ppm, ppm_count)
        self._label_ppm.setText(str(ppm_count))
        self._label_peak_ppm.setText(str(self._peak_ppm))
        self._label_total_packets.setText(str(CaptureStats.total_packets_captured))

        all_time = self._checkbox_all_time.isChecked()
        window = latency_data if all_time else latency_data[-VISIBLE_WINDOW:]

        nonzero_latencies = [latency_value for latency_value in window if latency_value > 0]
        if CaptureStats.global_avg_latency_ms > 0:
            self._last_latency_ms = CaptureStats.global_avg_latency_ms
            self._last_latency_ts = time.monotonic()
        if nonzero_latencies:
            self._last_avg_ms = sum(nonzero_latencies) / len(nonzero_latencies)
            self._last_min_ms = min(nonzero_latencies)
            self._last_max_ms = max(nonzero_latencies)
        else:
            self._last_avg_ms = None
            self._last_min_ms = None
            self._last_max_ms = None
        self._refresh_latency_labels()

        _latency_visible_max = max(latency_data[-VISIBLE_WINDOW:]) if latency_data else 0.0
        _pps_visible_max = max(pps_data[-VISIBLE_WINDOW:]) if pps_data else 0.0
        _bps_visible_max = max(bps_data[-VISIBLE_WINDOW:]) if bps_data else 0.0

        _all_values_zero = not CaptureStats.global_pps_rate and not kbps and not CaptureStats.global_avg_latency_ms
        _visible_all_zero = not _latency_visible_max and not _pps_visible_max and not _bps_visible_max

        if not (_all_values_zero and self._graphs_all_zero):
            self._latency_widget.set_data(latency_data)
            self._pps_widget.set_data(pps_data)
            self._bps_widget.set_data(bps_data)

            self._latency_widget.set_y_range(0, max(_latency_visible_max * 1.2, _FLOOR_MS))
            self._pps_widget.set_y_range(0, max(_pps_visible_max * 1.2, _FLOOR_PPS))
            self._bps_widget.set_y_range(0, max(_bps_visible_max * 1.2, _FLOOR_KBS))

            if len(self._latency_buffer) > 0:
                self._latency_widget.set_average(self._latency_running_sum / len(self._latency_buffer))
                self._pps_widget.set_average(self._pps_running_sum / len(self._pps_buffer))
                self._bps_widget.set_average(self._bps_running_sum / len(self._bps_buffer))

        self._graphs_all_zero = _all_values_zero and _visible_all_zero

    def reset(self) -> None:
        """Clear all history buffers and reset all graphs to zero."""
        self._latency_buffer.clear()
        self._pps_buffer.clear()
        self._bps_buffer.clear()
        zeros = [0.0] * VISIBLE_WINDOW
        self._latency_buffer.extend(zeros)
        self._pps_buffer.extend(zeros)
        self._bps_buffer.extend(zeros)

        self._latency_running_sum = 0.0
        self._pps_running_sum = 0
        self._bps_running_sum = 0.0

        self._ppm_sample_buffer.clear()
        self._peak_ppm = 0
        self._last_latency_ms = 0.0
        self._last_latency_ts = 0.0
        self._last_avg_ms = None
        self._last_min_ms = None
        self._last_max_ms = None

        self._latency_widget.set_data(zeros)
        self._latency_widget.set_y_range(0, _FLOOR_MS)
        self._latency_widget.set_average(0)

        self._pps_widget.set_data(zeros)
        self._pps_widget.set_y_range(0, _FLOOR_PPS)
        self._pps_widget.set_average(0)

        self._bps_widget.set_data(zeros)
        self._bps_widget.set_y_range(0, _FLOOR_KBS)
        self._bps_widget.set_average(0)
        self._graphs_all_zero = False

        self._label_connected.setText(str(PlayersRegistry.get_connected_count()))
        self._label_disconnected.setText(str(PlayersRegistry.get_disconnected_count()))
        self._label_total.setText(str(PlayersRegistry.get_total_count()))

        self._label_total_packets.setText('0')
        self._label_ppm.setText('0')
        self._label_peak_ppm.setText('0')
        self._label_pps.setText('0')
        self._label_peak_pps.setText('0')
        self._label_bandwidth.setText(PlayerBandwidth.format_bytes(0))
        self._label_download.setText(PlayerBandwidth.format_bytes(0))
        self._label_upload.setText(PlayerBandwidth.format_bytes(0))
        self._label_total_bandwidth.setText(PlayerBandwidth.format_bytes(0))
        self._label_total_download.setText(PlayerBandwidth.format_bytes(0))
        self._label_total_upload.setText(PlayerBandwidth.format_bytes(0))
        self._label_bps.setText(PlayerBandwidth.format_bytes(0))
        self._label_bpm.setText(PlayerBandwidth.format_bytes(0))
        self._label_peak_bps.setText(PlayerBandwidth.format_bytes(0))
        self._label_peak_bpm.setText(PlayerBandwidth.format_bytes(0))
        self._refresh_latency_labels()

    def _load_history(self) -> None:
        """Backfill graphs with recorded samples from `CaptureStats.capture_health_samples`."""
        samples = list(CaptureStats.capture_health_samples)
        if not samples:
            return

        trimmed = samples[-self._max_history :]
        padding_length = max(0, VISIBLE_WINDOW - len(trimmed))

        self._latency_buffer.clear()
        self._pps_buffer.clear()
        self._bps_buffer.clear()

        for _ in range(padding_length):
            self._latency_buffer.append(0.0)
            self._pps_buffer.append(0.0)
            self._bps_buffer.append(0.0)

        for sample in trimmed:
            self._latency_buffer.append(sample[0])
            self._pps_buffer.append(float(sample[1]))
            self._bps_buffer.append(float(sample[2]) / _BYTES_TO_KBS)

        self._latency_running_sum = sum(self._latency_buffer)
        self._pps_running_sum = int(sum(self._pps_buffer))
        self._bps_running_sum = sum(self._bps_buffer)

    # Internal ————————————————————————————————————————————————————————————————

    def _apply_translations(self) -> None:
        """Apply translated text to window chrome, static controls, and formatted labels."""
        self.setWindowTitle(tr(self.WINDOW_TITLE))
        for group, canonical_title in self._group_titles:
            group.setTitle(tr(canonical_title))
        for button, canonical_tooltip in self._popout_buttons:
            button.setText(f" {tr('Pop Out')}")
            button.setToolTip(tr(canonical_tooltip))
        self._checkbox_all_time.setText(tr('All time'))
        self._on_all_time_toggled()
        self._refresh_translatable_metrics()
        self._refresh_latency_labels()

    def _refresh_translatable_metrics(self) -> None:
        """Render unit-formatted metrics, uptime, and status strings in the active language."""
        if not self._has_refreshed:
            self._label_uptime.setText(format_duration(0))
            self._label_total_uptime.setText(format_duration(0))
            self._label_disk_read_rate.setText(tr('{value:.2f} MB/s', value=0.0))
            self._label_disk_write_rate.setText(tr('{value:.2f} MB/s', value=0.0))
            self._label_disk_read_total.setText(tr('{value} MB', value=0))
            self._label_disk_write_total.setText(tr('{value} MB', value=0))
            self._label_peak_ram.setText(tr('{value} MB', value=0))
            self._label_ram.setText(tr('{value} MB', value=0))
            return

        self._label_disk_read_rate.setText(tr('{value:.2f} MB/s', value=CaptureStats.app_disk_read_rate_mb))
        self._label_disk_write_rate.setText(tr('{value:.2f} MB/s', value=CaptureStats.app_disk_write_rate_mb))
        self._label_disk_read_total.setText(tr('{value:.1f} MB', value=CaptureStats.app_disk_read_total_mb))
        self._label_disk_write_total.setText(tr('{value:.1f} MB', value=CaptureStats.app_disk_write_total_mb))
        self._label_peak_ram.setText(tr('{value} MB', value=int(CaptureStats.app_peak_memory_mb)))
        self._label_ram.setText(tr('{value} MB', value=int(CaptureStats.app_memory_mb)))

        if Settings.capture_arp_spoofing:
            arp_label = tr('Running') if ArpSpoofingController.is_running() else tr('Stopped')
        elif CaptureState.is_neighbour_interface:
            arp_label = tr('Enabled')
        else:
            arp_label = tr('Disabled')
        self._label_arp.setText(arp_label)

        if Settings.discord_presence:
            self._label_discord.setText(tr('Connected') if CaptureState.discord_rpc_connected else tr('Waiting'))
        else:
            self._label_discord.setText(tr('Disabled'))

        elapsed_seconds = int(time.monotonic() - CaptureStats.capture_started_at)
        self._label_uptime.setText(format_duration(elapsed_seconds))
        total_elapsed = int(time.time() - self._process_started_at)
        self._label_total_uptime.setText(format_duration(total_elapsed))

    def _refresh_latency_labels(self) -> None:
        """Render the four latency summary labels in the active language."""
        placeholder = tr('— ms')
        if self._last_latency_ts > 0 and time.monotonic() - self._last_latency_ts < VISIBLE_WINDOW:
            self._label_latest.setText(tr('{value:.2f} ms', value=self._last_latency_ms))
        else:
            self._label_latest.setText(placeholder)

        if self._last_avg_ms is not None and self._last_min_ms is not None and self._last_max_ms is not None:
            self._label_avg.setText(tr('{value:.2f} ms', value=self._last_avg_ms))
            self._label_min.setText(tr('{value:.2f} ms', value=self._last_min_ms))
            self._label_max.setText(tr('{value:.2f} ms', value=self._last_max_ms))
        else:
            self._label_avg.setText(placeholder)
            self._label_min.setText(placeholder)
            self._label_max.setText(placeholder)

    def _on_all_time_toggled(self) -> None:
        self._latency_group.setTitle(tr('Latency (all time)') if self._checkbox_all_time.isChecked() else tr('Latency (60s)'))
