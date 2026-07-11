"""Capture statistics window."""

import time
from collections import deque
from typing import override

import psutil
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QIcon
from PySide6.QtWidgets import QCheckBox, QFormLayout, QGroupBox, QHBoxLayout, QLabel, QPushButton, QVBoxLayout

from session_sniffer.constants.local import RESOURCES_DIR_PATH
from session_sniffer.guis.player_rate_graph import DEFAULT_MAX_HISTORY, HISTORY_OPTIONS, VISIBLE_WINDOW
from session_sniffer.guis.rate_graph_widget import RateGraphTheme, RateGraphWidget
from session_sniffer.guis.utils import RateGraphWindowMixin, format_duration
from session_sniffer.models.player import PlayerBandwidth
from session_sniffer.player.registry import PlayersRegistry
from session_sniffer.rendering_core.types import CaptureState, CaptureStats
from session_sniffer.settings import Settings

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

        self.setWindowTitle(self.WINDOW_TITLE)
        self.resize(1200, 620)
        layout = self.setup_window_layout(always_on_top=True, spacing=6)

        body_layout = QHBoxLayout()
        body_layout.setSpacing(6)

        left_column = QHBoxLayout()
        left_column.setSpacing(6)
        left_column_a = QVBoxLayout()
        left_column_a.setSpacing(6)
        left_column_b = QVBoxLayout()
        left_column_b.setSpacing(6)

        capture_config_group = QGroupBox('Capture Config')
        capture_config_form = QFormLayout(capture_config_group)
        self._lbl_interface = QLabel('—')
        self._lbl_ip = QLabel('—')
        self._lbl_interface_type = QLabel('—')
        self._lbl_arp = QLabel('—')
        self._lbl_vpn = QLabel('—')
        self._lbl_feature_set = QLabel('—')
        self._lbl_discord = QLabel('—')
        capture_config_form.addRow('Interface:', self._lbl_interface)
        capture_config_form.addRow('IP:', self._lbl_ip)
        capture_config_form.addRow('Type:', self._lbl_interface_type)
        capture_config_form.addRow('ARP Spoofing:', self._lbl_arp)
        capture_config_form.addRow('VPN Mode:', self._lbl_vpn)
        capture_config_form.addRow('Feature Set:', self._lbl_feature_set)
        capture_config_form.addRow('Discord RPC:', self._lbl_discord)
        left_column_a.addWidget(capture_config_group)

        players_group = QGroupBox('Players')
        players_form = QFormLayout(players_group)
        self._lbl_connected = QLabel('0')
        self._lbl_disconnected = QLabel('0')
        self._lbl_total = QLabel('0')
        players_form.addRow('Total:', self._lbl_total)
        players_form.addRow('Connected:', self._lbl_connected)
        players_form.addRow('Disconnected:', self._lbl_disconnected)
        left_column_a.addWidget(players_group)

        stability_group = QGroupBox('Stability')
        stability_form = QFormLayout(stability_group)
        self._lbl_restarts = QLabel('0')
        self._lbl_uptime = QLabel('0s')
        self._lbl_total_uptime = QLabel('0s')
        self._lbl_packets_dropped = QLabel('0')
        stability_form.addRow('Total App Uptime:', self._lbl_total_uptime)
        stability_form.addRow('Capture Uptime:', self._lbl_uptime)
        stability_form.addRow('Capture Restarts:', self._lbl_restarts)
        stability_form.addRow('Packets Dropped:', self._lbl_packets_dropped)
        left_column_a.addWidget(stability_group)

        self._process_started_at: float = psutil.Process().create_time()

        performance_group = QGroupBox('Performance')
        performance_form = QFormLayout(performance_group)
        self._lbl_cpu = QLabel('0%')
        self._lbl_ram = QLabel('0 MB')
        self._lbl_disk_read_rate = QLabel('0.00 MB/s')
        self._lbl_disk_write_rate = QLabel('0.00 MB/s')
        self._lbl_disk_read_total = QLabel('0 MB')
        self._lbl_disk_write_total = QLabel('0 MB')
        performance_form.addRow('CPU:', self._lbl_cpu)
        performance_form.addRow('RAM:', self._lbl_ram)
        performance_form.addRow('Disk Read Total:', self._lbl_disk_read_total)
        performance_form.addRow('Disk Read Rate:', self._lbl_disk_read_rate)
        performance_form.addRow('Disk Write Total:', self._lbl_disk_write_total)
        performance_form.addRow('Disk Write Rate:', self._lbl_disk_write_rate)
        left_column_a.addWidget(performance_group)
        left_column_a.addStretch()

        traffic_group = QGroupBox('Traffic')
        traffic_form = QFormLayout(traffic_group)
        self._lbl_bandwidth = QLabel('0 B')
        self._lbl_download = QLabel('0 B')
        self._lbl_upload = QLabel('0 B')
        self._lbl_total_bandwidth = QLabel('0 B')
        self._lbl_total_download = QLabel('0 B')
        self._lbl_total_upload = QLabel('0 B')
        self._lbl_bps = QLabel('0 B')
        self._lbl_bpm = QLabel('0 B')
        self._lbl_peak_bps = QLabel('0 B')
        self._lbl_peak_bpm = QLabel('0 B')
        self._lbl_pps = QLabel('0')
        traffic_form.addRow('T. Bandwidth (↓↑):', self._lbl_total_bandwidth)
        traffic_form.addRow('Bandwidth (↓↑):', self._lbl_bandwidth)
        traffic_form.addRow('T. Download (↓):', self._lbl_total_download)
        traffic_form.addRow('Download (↓):', self._lbl_download)
        traffic_form.addRow('T. Upload (↑):', self._lbl_total_upload)
        traffic_form.addRow('Upload (↑):', self._lbl_upload)
        traffic_form.addRow('Peak BPS:', self._lbl_peak_bps)
        traffic_form.addRow('BPS:', self._lbl_bps)
        traffic_form.addRow('Peak BPM:', self._lbl_peak_bpm)
        traffic_form.addRow('BPM:', self._lbl_bpm)
        left_column_b.addWidget(traffic_group)

        packets_group = QGroupBox('Packets')
        packets_form = QFormLayout(packets_group)
        self._lbl_ppm = QLabel('0')
        self._lbl_peak_ppm = QLabel('0')
        self._lbl_total_packets = QLabel('0')
        self._lbl_peak_pps = QLabel('0')
        packets_form.addRow('Total:', self._lbl_total_packets)
        packets_form.addRow('Peak PPM:', self._lbl_peak_ppm)
        packets_form.addRow('PPM:', self._lbl_ppm)
        packets_form.addRow('Peak PPS:', self._lbl_peak_pps)
        packets_form.addRow('PPS:', self._lbl_pps)
        left_column_b.addWidget(packets_group)

        self._latency_group = QGroupBox('Packet Latency (60s)')
        latency_form = QFormLayout(self._latency_group)
        self._lbl_latest = QLabel('— ms')
        self._lbl_avg = QLabel('— ms')
        self._lbl_min = QLabel('— ms')
        self._lbl_max = QLabel('— ms')
        latency_form.addRow('Latest:', self._lbl_latest)
        latency_form.addRow('Average:', self._lbl_avg)
        latency_form.addRow('Min:', self._lbl_min)
        latency_form.addRow('Max:', self._lbl_max)
        self._chk_all_time = QCheckBox('All time')
        self._chk_all_time.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self._chk_all_time.toggled.connect(self._on_all_time_toggled)
        latency_form.addRow(self._chk_all_time)
        left_column_b.addWidget(self._latency_group)
        left_column_b.addStretch()

        left_column.addLayout(left_column_a)
        left_column.addLayout(left_column_b)

        right_column = QVBoxLayout()
        right_column.setSpacing(6)

        bps_graph_group = QGroupBox('Bandwidth (KB/s)')
        bps_graph_layout = QVBoxLayout(bps_graph_group)
        self._bps_widget = RateGraphWidget.create_bps_widget(visible_window=VISIBLE_WINDOW)
        self._bps_widget.set_y_range(0, _FLOOR_KBS)
        bps_popout_row = QHBoxLayout()
        bps_popout_row.setContentsMargins(0, 0, 0, 0)
        bps_popout_row.addStretch()
        bps_popout_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'export.svg')), ' Pop Out')
        bps_popout_button.setToolTip('Open BPS Graph in a separate window')
        bps_popout_button.setCursor(Qt.CursorShape.PointingHandCursor)
        bps_popout_button.setStyleSheet(
            'QPushButton { background-color: transparent; border: none; color: #88c0d0; font-size: 11px; text-decoration: underline; } QPushButton:hover { color: #ffffff; }'
        )
        bps_popout_button.clicked.connect(self.open_session_bps_graph_requested)
        bps_popout_row.addWidget(bps_popout_button)
        bps_graph_layout.addLayout(bps_popout_row)
        bps_graph_layout.addWidget(self._bps_widget)
        right_column.addWidget(bps_graph_group)

        pps_graph_group = QGroupBox('Packets per Second (PPS)')
        pps_graph_layout = QVBoxLayout(pps_graph_group)
        self._pps_widget = RateGraphWidget.create_pps_widget(visible_window=VISIBLE_WINDOW)
        self._pps_widget.set_y_range(0, _FLOOR_PPS)
        pps_popout_row = QHBoxLayout()
        pps_popout_row.setContentsMargins(0, 0, 0, 0)
        pps_popout_row.addStretch()
        pps_popout_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'export.svg')), ' Pop Out')
        pps_popout_button.setToolTip('Open PPS Graph in a separate window')
        pps_popout_button.setCursor(Qt.CursorShape.PointingHandCursor)
        pps_popout_button.setStyleSheet(
            'QPushButton { background-color: transparent; border: none; color: #88c0d0; font-size: 11px; text-decoration: underline; } QPushButton:hover { color: #ffffff; }'
        )
        pps_popout_button.clicked.connect(self.open_session_pps_graph_requested)
        pps_popout_row.addWidget(pps_popout_button)
        pps_graph_layout.addLayout(pps_popout_row)
        pps_graph_layout.addWidget(self._pps_widget)
        right_column.addWidget(pps_graph_group)

        latency_graph_group = QGroupBox('Latency (ms/s)')
        latency_graph_layout = QVBoxLayout(latency_graph_group)
        self._latency_widget = RateGraphWidget(
            left_label='Latency (ms/s)',
            theme=RateGraphTheme(
                line_color='#ff9800',
                fill_color=QColor(255, 152, 0, 60),
                avg_color='#e65100',
            ),
            visible_window=VISIBLE_WINDOW,
        )
        self._latency_widget.set_y_range(0, _FLOOR_MS)
        latency_popout_row = QHBoxLayout()
        latency_popout_row.setContentsMargins(0, 0, 0, 0)
        latency_popout_row.addStretch()
        latency_popout_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'export.svg')), ' Pop Out')
        latency_popout_button.setToolTip('Open Packets Latency Graph in a separate window')
        latency_popout_button.setCursor(Qt.CursorShape.PointingHandCursor)
        latency_popout_button.setStyleSheet(
            'QPushButton { background-color: transparent; border: none; color: #88c0d0; font-size: 11px; text-decoration: underline; } QPushButton:hover { color: #ffffff; }'
        )
        latency_popout_button.clicked.connect(self.open_packets_latency_graph_requested)
        latency_popout_row.addWidget(latency_popout_button)
        latency_graph_layout.addLayout(latency_popout_row)
        latency_graph_layout.addWidget(self._latency_widget)
        right_column.addWidget(latency_graph_group)

        body_layout.addLayout(left_column)
        body_layout.addLayout(right_column, 1)
        layout.addLayout(body_layout)
        self.add_rate_graph_controls(layout, HISTORY_OPTIONS)

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

        self._ppm_sample_buf: deque[int] = deque(maxlen=61)
        self._peak_ppm: int = 0
        self._graphs_all_zero: bool = False

        self._load_history()

    @override
    def _on_max_history_changed(self, new_max_history: int) -> None:
        """Re-allocate the sliding buffer when Max History is changed."""
        self._max_history = new_max_history
        self._latency_buffer = deque(self._latency_buffer, maxlen=self._max_history)
        self._pps_buffer = deque(self._pps_buffer, maxlen=self._max_history)
        self._bps_buffer = deque(self._bps_buffer, maxlen=self._max_history)

    # Public API —————————————————————————————————————————————————————————————

    def refresh(self) -> None:
        """Refresh stats labels and advance all three live graphs by one sample."""
        self._lbl_restarts.setText(str(CaptureStats.restarted_times))
        self._lbl_packets_dropped.setText(str(CaptureStats.packets_dropped))

        self._lbl_disk_read_rate.setText(f'{CaptureStats.app_disk_read_rate_mb:.2f} MB/s')
        self._lbl_disk_write_rate.setText(f'{CaptureStats.app_disk_write_rate_mb:.2f} MB/s')
        self._lbl_disk_read_total.setText(f'{CaptureStats.app_disk_read_total_mb:.1f} MB')
        self._lbl_disk_write_total.setText(f'{CaptureStats.app_disk_write_total_mb:.1f} MB')
        self._lbl_cpu.setText(f'{CaptureStats.app_cpu_percent:.1f}%')
        self._lbl_ram.setText(f'{int(CaptureStats.app_memory_mb)} MB')

        arp_label = ('Enabled' if Settings.capture_arp_spoofing else 'Disabled') if CaptureState.is_neighbour_interface else 'Disabled'
        self._lbl_interface.setText(CaptureState.interface_name or '—')
        self._lbl_ip.setText(CaptureState.interface_ip or '—')
        self._lbl_interface_type.setText(CaptureState.interface_type or '—')
        self._lbl_arp.setText(arp_label)
        self._lbl_vpn.setText('Enabled' if CaptureState.vpn_mode_enabled else 'Disabled')
        self._lbl_feature_set.setText(Settings.capture_feature_set or '—')
        if Settings.discord_presence:
            self._lbl_discord.setText('Connected' if CaptureState.discord_rpc_connected else 'Waiting')
        else:
            self._lbl_discord.setText('Disabled')

        elapsed_seconds = int(time.monotonic() - CaptureStats.capture_started_at)
        self._lbl_uptime.setText(format_duration(elapsed_seconds))

        total_elapsed = int(time.time() - self._process_started_at)
        self._lbl_total_uptime.setText(format_duration(total_elapsed))

        all_players = PlayersRegistry.get_all_players()
        connected_players = PlayersRegistry.get_connected_players()
        self._lbl_connected.setText(str(len(connected_players)))
        self._lbl_disconnected.setText(str(len(all_players) - len(connected_players)))
        self._lbl_total.setText(str(len(all_players)))

        self._lbl_bandwidth.setText(PlayerBandwidth.format_bytes(sum(player.bandwidth.exchanged for player in all_players)))
        self._lbl_download.setText(PlayerBandwidth.format_bytes(sum(player.bandwidth.download for player in all_players)))
        self._lbl_upload.setText(PlayerBandwidth.format_bytes(sum(player.bandwidth.upload for player in all_players)))
        self._lbl_total_bandwidth.setText(PlayerBandwidth.format_bytes(sum(player.bandwidth.total_exchanged for player in all_players)))
        self._lbl_total_download.setText(PlayerBandwidth.format_bytes(sum(player.bandwidth.total_download for player in all_players)))
        self._lbl_total_upload.setText(PlayerBandwidth.format_bytes(sum(player.bandwidth.total_upload for player in all_players)))

        self._lbl_bps.setText(PlayerBandwidth.format_bytes(CaptureStats.global_bps_rate))
        self._lbl_bpm.setText(PlayerBandwidth.format_bytes(CaptureStats.global_bpm_rate))
        self._lbl_peak_bpm.setText(PlayerBandwidth.format_bytes(CaptureStats.peak_bpm_rate))
        self._lbl_pps.setText(str(CaptureStats.global_pps_rate))
        self._lbl_peak_pps.setText(str(CaptureStats.peak_pps_rate))
        self._lbl_peak_bps.setText(PlayerBandwidth.format_bytes(CaptureStats.peak_bps_rate))

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

        self._ppm_sample_buf.append(CaptureStats.total_packets_captured)
        ppm_count = self._ppm_sample_buf[-1] - self._ppm_sample_buf[0] if len(self._ppm_sample_buf) >= _MIN_PPM_SAMPLES else 0
        self._peak_ppm = max(self._peak_ppm, ppm_count)
        self._lbl_ppm.setText(str(ppm_count))
        self._lbl_peak_ppm.setText(str(self._peak_ppm))
        self._lbl_total_packets.setText(str(CaptureStats.total_packets_captured))

        all_time = self._chk_all_time.isChecked()
        window = latency_data if all_time else latency_data[-VISIBLE_WINDOW:]

        nonzero = [v for v in window if v > 0]
        if CaptureStats.global_avg_latency_ms > 0:
            self._last_latency_ms = CaptureStats.global_avg_latency_ms
            self._last_latency_ts = time.monotonic()
        if self._last_latency_ts > 0 and time.monotonic() - self._last_latency_ts < VISIBLE_WINDOW:
            self._lbl_latest.setText(f'{self._last_latency_ms:.2f} ms')
        else:
            self._lbl_latest.setText('— ms')
        if nonzero:
            self._lbl_avg.setText(f'{sum(nonzero) / len(nonzero):.2f} ms')
            self._lbl_min.setText(f'{min(nonzero):.2f} ms')
            self._lbl_max.setText(f'{max(nonzero):.2f} ms')
        else:
            self._lbl_avg.setText('— ms')
            self._lbl_min.setText('— ms')
            self._lbl_max.setText('— ms')

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
        for _ in range(VISIBLE_WINDOW):
            self._latency_buffer.append(0.0)
            self._pps_buffer.append(0.0)
            self._bps_buffer.append(0.0)

        self._latency_running_sum = 0.0
        self._pps_running_sum = 0
        self._bps_running_sum = 0.0

        zeros = [0.0] * VISIBLE_WINDOW

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

    def _load_history(self) -> None:
        """Backfill graphs with recorded samples from `CaptureStats.capture_health_samples`."""
        samples = list(CaptureStats.capture_health_samples)
        if not samples:
            return

        trimmed = samples[-self._max_history :]
        pad_len = max(0, VISIBLE_WINDOW - len(trimmed))

        self._latency_buffer.clear()
        self._pps_buffer.clear()
        self._bps_buffer.clear()

        for _ in range(pad_len):
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

    def _on_all_time_toggled(self, checked: bool) -> None:  # noqa: FBT001
        self._latency_group.setTitle('Packet Latency (all time)' if checked else 'Packet Latency (60s)')
