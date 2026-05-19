"""Capture statistics window."""

import time
from datetime import UTC, datetime, timedelta

import numpy as np
import pyqtgraph as pg  # pyright: ignore[reportMissingTypeStubs]
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import QCheckBox, QFormLayout, QGroupBox, QHBoxLayout, QLabel, QPushButton, QVBoxLayout

from session_sniffer.guis.player_rate_graph import VISIBLE_WINDOW, DragCursorViewBox, PositiveTicksAxis, SlidingWindowMixin, build_rate_plot_widget
from session_sniffer.guis.utils import ToggleAlwaysOnTopMixin
from session_sniffer.models.player import PlayerBandwidth
from session_sniffer.player.registry import PlayersRegistry
from session_sniffer.rendering_core.types import CaptureStats

_FLOOR_MS = 1.0
_FLOOR_PPS = 10
_FLOOR_KBS = 1.0
_BYTES_TO_KBS = 1024


class CaptureStatisticsWindow(SlidingWindowMixin, ToggleAlwaysOnTopMixin):
    """A standalone window showing capture statistics, latency, and live graphs."""

    WINDOW_TITLE = 'Capture Statistics'

    open_packets_latency_graph_requested = pyqtSignal()
    open_session_pps_graph_requested = pyqtSignal()
    open_session_bps_graph_requested = pyqtSignal()

    def __init__(self, *, max_history: int, always_on_top: bool = True) -> None:
        """Initialize the capture statistics window."""
        super().__init__()

        self._max_history = max_history

        self.setWindowTitle(self.WINDOW_TITLE)
        self.resize(1200, 620)
        layout = self._setup_window_layout(always_on_top=always_on_top, spacing=6)

        # Two-column body: stats on the left, graphs on the right
        body_layout = QHBoxLayout()
        body_layout.setSpacing(6)

        # ── Left column — stats panels ────────────────────────────────────
        left_col = QVBoxLayout()
        left_col.setSpacing(6)

        # Stability group
        stability_group = QGroupBox('Stability')
        stability_form = QFormLayout(stability_group)
        self._lbl_restarts = QLabel('0')
        self._lbl_uptime = QLabel('0s')
        stability_form.addRow('Capture Restarts:', self._lbl_restarts)
        stability_form.addRow('Uptime:', self._lbl_uptime)
        left_col.addWidget(stability_group)

        # Players group
        players_group = QGroupBox('Players')
        players_form = QFormLayout(players_group)
        self._lbl_connected = QLabel('0')
        self._lbl_disconnected = QLabel('0')
        self._lbl_total = QLabel('0')
        players_form.addRow('Connected:', self._lbl_connected)
        players_form.addRow('Disconnected:', self._lbl_disconnected)
        players_form.addRow('Total:', self._lbl_total)
        left_col.addWidget(players_group)

        # Traffic group
        traffic_group = QGroupBox('Traffic')
        traffic_form = QFormLayout(traffic_group)
        self._lbl_bandwidth = QLabel('0 B')
        self._lbl_download = QLabel('0 B')
        self._lbl_upload = QLabel('0 B')
        self._lbl_total_bandwidth = QLabel('0 B')
        self._lbl_total_download = QLabel('0 B')
        self._lbl_total_upload = QLabel('0 B')
        self._lbl_bps = QLabel('0 B')
        self._lbl_pps = QLabel('0')
        traffic_form.addRow('T. Bandwidth (\u2193\u2191):', self._lbl_total_bandwidth)
        traffic_form.addRow('Bandwidth (\u2193\u2191):', self._lbl_bandwidth)
        traffic_form.addRow('T. Download (\u2193):', self._lbl_total_download)
        traffic_form.addRow('Download (\u2193):', self._lbl_download)
        traffic_form.addRow('T. Upload (\u2191):', self._lbl_total_upload)
        traffic_form.addRow('Upload (\u2191):', self._lbl_upload)
        traffic_form.addRow('BPS (current):', self._lbl_bps)
        left_col.addWidget(traffic_group)

        # Packets group
        packets_group = QGroupBox('Packets')
        packets_form = QFormLayout(packets_group)
        self._lbl_ppm = QLabel('0')
        self._lbl_total_packets = QLabel('0')
        packets_form.addRow('Total:', self._lbl_total_packets)
        packets_form.addRow('PPM:', self._lbl_ppm)
        packets_form.addRow('PPS:', self._lbl_pps)
        left_col.addWidget(packets_group)

        # Latency stats group
        self._latency_group = QGroupBox('Packet Latency (last 60s)')
        latency_form = QFormLayout(self._latency_group)
        self._lbl_latest = QLabel('\u2014 ms')
        self._lbl_avg = QLabel('\u2014 ms')
        self._lbl_min = QLabel('\u2014 ms')
        self._lbl_max = QLabel('\u2014 ms')
        latency_form.addRow('Latest:', self._lbl_latest)
        latency_form.addRow('Average:', self._lbl_avg)
        latency_form.addRow('Min:', self._lbl_min)
        latency_form.addRow('Max:', self._lbl_max)
        self._chk_all_time = QCheckBox('All time')
        self._chk_all_time.toggled.connect(self._on_all_time_toggled)
        latency_form.addRow(self._chk_all_time)
        left_col.addWidget(self._latency_group)

        left_col.addStretch()

        # ── Right column — live graphs ────────────────────────────────────
        right_col = QVBoxLayout()
        right_col.setSpacing(6)

        # Latency graph — orange tones
        latency_graph_group = QGroupBox('Latency (ms/s)')
        latency_graph_layout = QVBoxLayout(latency_graph_group)
        latency_popout_row = QHBoxLayout()
        latency_popout_row.addStretch()
        latency_popout_btn = QPushButton('⤢ Pop Out')
        latency_popout_btn.setToolTip('Open Packets Latency Graph in a separate window')
        latency_popout_btn.clicked.connect(self.open_packets_latency_graph_requested)
        latency_popout_row.addWidget(latency_popout_btn)
        latency_graph_layout.addLayout(latency_popout_row)
        self._latency_widget = pg.PlotWidget(
            axisItems={'bottom': PositiveTicksAxis(orientation='bottom')},
            viewBox=DragCursorViewBox(),
        )
        self._latency_widget.setMouseEnabled(x=True, y=True)
        self._latency_widget.setMenuEnabled(False)
        self._latency_widget.setBackground('black')
        self._latency_widget.showGrid(x=True, y=True)
        self._latency_widget.setLimits(yMin=0, xMax=0, xMin=-self._max_history)
        self._latency_widget.setLabel('left', 'Latency (ms/s)')
        self._latency_widget.setLabel('bottom', 'Time (seconds ago)')
        latency_plot = self._latency_widget.getPlotItem()  # pyright: ignore[reportUnknownVariableType]
        if latency_plot is None:
            msg = 'Failed to get latency plot item'
            raise RuntimeError(msg)
        latency_plot.getAxis('left').setTextPen(pg.mkPen('#ff9800'))  # pyright: ignore[reportUnknownVariableType]
        self._latency_curve = self._latency_widget.plot(pen=pg.mkPen('#ff9800', width=2))
        self._latency_curve.setFillLevel(0)
        self._latency_curve.setBrush(pg.mkBrush(255, 152, 0, 60))
        self._latency_avg_line = pg.InfiniteLine(angle=0, pen=pg.mkPen('#e65100', width=1, style=Qt.PenStyle.DotLine))
        self._latency_widget.addItem(self._latency_avg_line)
        latency_graph_layout.addWidget(self._latency_widget)
        right_col.addWidget(latency_graph_group)

        # BPS graph — cyan/teal tones
        bps_graph_group = QGroupBox('Bandwidth (KB/s)')
        bps_graph_layout = QVBoxLayout(bps_graph_group)
        bps_popout_row = QHBoxLayout()
        bps_popout_row.addStretch()
        bps_popout_btn = QPushButton('⤢ Pop Out')
        bps_popout_btn.setToolTip('Open BPS Graph in a separate window')
        bps_popout_btn.clicked.connect(self.open_session_bps_graph_requested)
        bps_popout_row.addWidget(bps_popout_btn)
        bps_graph_layout.addLayout(bps_popout_row)
        self._bps_widget, bps_plot = build_rate_plot_widget('KB/s', self._max_history, 'BPS')
        bps_plot.getAxis('left').setTextPen(pg.mkPen('#00bcd4'))  # pyright: ignore[reportUnknownVariableType]
        self._bps_curve = self._bps_widget.plot(pen=pg.mkPen('#00bcd4', width=2))
        self._bps_curve.setFillLevel(0)
        self._bps_curve.setBrush(pg.mkBrush(0, 188, 212, 60))
        self._bps_avg_line = pg.InfiniteLine(angle=0, pen=pg.mkPen('#0097a7', width=1, style=Qt.PenStyle.DotLine))
        self._bps_widget.addItem(self._bps_avg_line)
        bps_graph_layout.addWidget(self._bps_widget)
        right_col.addWidget(bps_graph_group)

        # PPS graph — lime green tones
        pps_graph_group = QGroupBox('Packets per Second (PPS)')
        pps_graph_layout = QVBoxLayout(pps_graph_group)
        pps_popout_row = QHBoxLayout()
        pps_popout_row.addStretch()
        pps_popout_btn = QPushButton('⤢ Pop Out')
        pps_popout_btn.setToolTip('Open PPS Graph in a separate window')
        pps_popout_btn.clicked.connect(self.open_session_pps_graph_requested)
        pps_popout_row.addWidget(pps_popout_btn)
        pps_graph_layout.addLayout(pps_popout_row)
        self._pps_widget, pps_plot = build_rate_plot_widget('PPS', self._max_history, 'PPS')
        pps_plot.getAxis('left').setTextPen(pg.mkPen('lime'))  # pyright: ignore[reportUnknownVariableType]
        self._pps_curve = self._pps_widget.plot(pen=pg.mkPen('lime', width=2))
        self._pps_curve.setFillLevel(0)
        self._pps_curve.setBrush(pg.mkBrush(0, 255, 0, 60))
        self._pps_avg_line = pg.InfiniteLine(angle=0, pen=pg.mkPen('#388e3c', width=1, style=Qt.PenStyle.DotLine))
        self._pps_widget.addItem(self._pps_avg_line)
        pps_graph_layout.addWidget(self._pps_widget)
        right_col.addWidget(pps_graph_group)

        body_layout.addLayout(left_col)
        body_layout.addLayout(right_col, 1)
        layout.addLayout(body_layout)

        self._add_always_on_top_checkbox(layout, always_on_top=always_on_top)

        # Shared sliding-window x-cache (one advance per tick covers all three graphs)
        self._buf_len = VISIBLE_WINDOW
        self._x_cache_len = VISIBLE_WINDOW
        self._x_cache = np.arange(-VISIBLE_WINDOW + 1, 1, dtype=np.float64)

        # Per-graph buffers
        self._latency_buf = np.zeros(self._max_history, dtype=np.float64)
        self._latency_sum: float = 0.0
        self._pps_buf = np.zeros(self._max_history, dtype=np.float64)
        self._pps_sum: float = 0.0
        self._bps_buf = np.zeros(self._max_history, dtype=np.float64)
        self._bps_sum: float = 0.0

        self._last_latency_ms: float = 0.0
        self._last_latency_ts: float = 0.0

        self._load_history()

    # Public API —————————————————————————————————————————————————————————————

    def refresh(self) -> None:
        """Refresh stats labels and advance all three live graphs by one sample."""
        self._lbl_restarts.setText(str(CaptureStats.restarted_times))

        elapsed = int(time.monotonic() - CaptureStats.capture_started_at)
        h, rem = divmod(elapsed, 3600)
        m, s = divmod(rem, 60)
        if h:
            self._lbl_uptime.setText(f'{h}h {m}m {s}s')
        elif m:
            self._lbl_uptime.setText(f'{m}m {s}s')
        else:
            self._lbl_uptime.setText(f'{s}s')

        all_players = PlayersRegistry.get_all_players()
        connected_players = PlayersRegistry.get_connected_players()
        self._lbl_connected.setText(str(len(connected_players)))
        self._lbl_disconnected.setText(str(len(all_players) - len(connected_players)))
        self._lbl_total.setText(str(len(all_players)))

        self._lbl_bandwidth.setText(PlayerBandwidth.format_bytes(sum(p.bandwidth.exchanged for p in all_players)))
        self._lbl_download.setText(PlayerBandwidth.format_bytes(sum(p.bandwidth.download for p in all_players)))
        self._lbl_upload.setText(PlayerBandwidth.format_bytes(sum(p.bandwidth.upload for p in all_players)))
        self._lbl_total_bandwidth.setText(PlayerBandwidth.format_bytes(sum(p.bandwidth.total_exchanged for p in all_players)))
        self._lbl_total_download.setText(PlayerBandwidth.format_bytes(sum(p.bandwidth.total_download for p in all_players)))
        self._lbl_total_upload.setText(PlayerBandwidth.format_bytes(sum(p.bandwidth.total_upload for p in all_players)))

        pps = CaptureStats.global_pps_rate
        bps = CaptureStats.global_bps_rate
        self._lbl_bps.setText(PlayerBandwidth.format_bytes(bps))
        self._lbl_pps.setText(str(pps))

        latency_ms = CaptureStats.global_avg_latency_ms
        kbps = CaptureStats.global_bps_rate / _BYTES_TO_KBS

        # Advance the shared sliding window once per tick
        n = self._buf_len
        if n < self._max_history:
            self._latency_buf[n] = latency_ms
            self._latency_sum += latency_ms
            self._pps_buf[n] = pps
            self._pps_sum += pps
            self._bps_buf[n] = kbps
            self._bps_sum += kbps
            n = self._grow_cache(n)
        else:
            self._latency_sum += latency_ms - self._latency_buf[0]
            self._latency_buf[:-1] = self._latency_buf[1:]
            self._latency_buf[-1] = latency_ms
            self._pps_sum += pps - self._pps_buf[0]
            self._pps_buf[:-1] = self._pps_buf[1:]
            self._pps_buf[-1] = pps
            self._bps_sum += kbps - self._bps_buf[0]
            self._bps_buf[:-1] = self._bps_buf[1:]
            self._bps_buf[-1] = kbps

        latency_data = self._latency_buf[:n]
        pps_data = self._pps_buf[:n]
        bps_data = self._bps_buf[:n]

        # ── Packets stats ─────────────────────────────────────────────────
        cutoff = datetime.now(tz=UTC) - timedelta(seconds=VISIBLE_WINDOW)
        ppm_count = 0
        for ts, _ in reversed(CaptureStats.packets_latencies):
            if ts < cutoff:
                break
            ppm_count += 1
        self._lbl_ppm.setText(str(ppm_count))
        self._lbl_total_packets.setText(str(CaptureStats.total_packets_captured))

        # ── Latency stats (windowed) ──────────────────────────────────────
        all_time = self._chk_all_time.isChecked()
        window = latency_data if all_time else latency_data[-VISIBLE_WINDOW:]

        nonzero = window[window > 0]
        if latency_ms > 0:
            self._last_latency_ms = latency_ms
            self._last_latency_ts = time.monotonic()
        if self._last_latency_ts > 0 and time.monotonic() - self._last_latency_ts < VISIBLE_WINDOW:
            self._lbl_latest.setText(f'{self._last_latency_ms:.2f} ms')
        else:
            self._lbl_latest.setText('\u2014 ms')
        if nonzero.size > 0:
            self._lbl_avg.setText(f'{float(np.mean(nonzero)):.2f} ms')
            self._lbl_min.setText(f'{float(np.min(nonzero)):.2f} ms')
            self._lbl_max.setText(f'{float(np.max(nonzero)):.2f} ms')
        else:
            self._lbl_avg.setText('— ms')
            self._lbl_min.setText('— ms')
            self._lbl_max.setText('— ms')

        self._latency_curve.setData(self._x_cache, latency_data)
        self._pps_curve.setData(self._x_cache, pps_data)
        self._bps_curve.setData(self._x_cache, bps_data)

        if self._is_at_live_edge(self._latency_widget):
            self._latency_widget.setXRange(-VISIBLE_WINDOW, 0)
        if self._is_at_live_edge(self._pps_widget):
            self._pps_widget.setXRange(-VISIBLE_WINDOW, 0)
        if self._is_at_live_edge(self._bps_widget):
            self._bps_widget.setXRange(-VISIBLE_WINDOW, 0)

        self._latency_widget.setYRange(0, max(float(np.max(latency_data[-VISIBLE_WINDOW:])) * 1.2, _FLOOR_MS))
        self._pps_widget.setYRange(0, max(float(np.max(pps_data[-VISIBLE_WINDOW:])) * 1.2, _FLOOR_PPS))
        self._bps_widget.setYRange(0, max(float(np.max(bps_data[-VISIBLE_WINDOW:])) * 1.2, _FLOOR_KBS))

        if n:
            self._latency_avg_line.setPos(self._latency_sum / n)
            self._pps_avg_line.setPos(self._pps_sum / n)
            self._bps_avg_line.setPos(self._bps_sum / n)

    def reset(self) -> None:
        """Clear all history buffers and reset all graphs to zero."""
        self._latency_buf[:] = 0.0
        self._latency_sum = 0.0
        self._pps_buf[:] = 0.0
        self._pps_sum = 0.0
        self._bps_buf[:] = 0.0
        self._bps_sum = 0.0
        self._buf_len = VISIBLE_WINDOW
        self._x_cache = np.arange(-VISIBLE_WINDOW + 1, 1, dtype=np.float64)
        self._x_cache_len = VISIBLE_WINDOW

        zeros = np.zeros(VISIBLE_WINDOW, dtype=np.float64)
        self._latency_curve.setData(self._x_cache, zeros)
        self._latency_widget.setXRange(-VISIBLE_WINDOW, 0)
        self._latency_widget.setYRange(0, _FLOOR_MS)
        self._latency_avg_line.setPos(0)

        self._pps_curve.setData(self._x_cache, zeros)
        self._pps_widget.setXRange(-VISIBLE_WINDOW, 0)
        self._pps_widget.setYRange(0, _FLOOR_PPS)
        self._pps_avg_line.setPos(0)

        self._bps_curve.setData(self._x_cache, zeros)
        self._bps_widget.setXRange(-VISIBLE_WINDOW, 0)
        self._bps_widget.setYRange(0, _FLOOR_KBS)
        self._bps_avg_line.setPos(0)

    def _load_history(self) -> None:
        """Backfill graphs with recorded samples from `CaptureStats.capture_health_samples`."""
        samples = list(CaptureStats.capture_health_samples)
        if not samples:
            return

        trimmed = samples[-self._max_history:]
        pad_len = max(0, VISIBLE_WINDOW - len(trimmed))
        n = pad_len + len(trimmed)

        self._buf_len = n
        self._x_cache = np.arange(-n + 1, 1, dtype=np.float64)
        self._x_cache_len = n

        latency_vals = [s[0] for s in trimmed]
        pps_vals = [s[1] for s in trimmed]
        bps_vals = [s[2] / _BYTES_TO_KBS for s in trimmed]

        self._latency_buf[:pad_len] = 0.0
        self._latency_buf[pad_len:n] = latency_vals
        self._latency_sum = float(np.sum(self._latency_buf[:n]))

        self._pps_buf[:pad_len] = 0.0
        self._pps_buf[pad_len:n] = pps_vals
        self._pps_sum = float(np.sum(self._pps_buf[:n]))

        self._bps_buf[:pad_len] = 0.0
        self._bps_buf[pad_len:n] = bps_vals
        self._bps_sum = float(np.sum(self._bps_buf[:n]))

    # Internal ————————————————————————————————————————————————————————————————

    def _on_all_time_toggled(self, checked: bool) -> None:  # noqa: FBT001
        self._latency_group.setTitle('Packet Latency (all time)' if checked else 'Packet Latency (last 60s)')

    @staticmethod
    def _is_at_live_edge(widget: pg.PlotWidget) -> bool:  # pyright: ignore[reportMissingTypeStubs]
        x_range: list[float] = widget.viewRange()[0]
        return x_range[1] >= -2  # noqa: PLR2004
