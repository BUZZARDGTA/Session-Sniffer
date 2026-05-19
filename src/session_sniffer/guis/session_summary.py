"""Session-wide summary statistics window."""

import time

from PyQt6.QtWidgets import QFormLayout, QGroupBox, QLabel

from session_sniffer.guis.utils import ToggleAlwaysOnTopMixin
from session_sniffer.models.player import PlayerBandwidth
from session_sniffer.player.registry import PlayersRegistry
from session_sniffer.rendering_core.types import CaptureStats


class SessionSummaryWindow(ToggleAlwaysOnTopMixin):
    """A standalone window showing aggregated session-wide statistics."""

    def __init__(self, *, always_on_top: bool = True) -> None:
        """Initialize the session summary window."""
        super().__init__()

        self._opened_at = time.monotonic()
        self._peak_pps: int = 0
        self._peak_bps: int = 0

        self.setWindowTitle('Session Summary')
        self.resize(400, 360)
        layout = self._setup_window_layout(always_on_top=always_on_top, spacing=6)

        # Players group
        players_group = QGroupBox('Players')
        players_form = QFormLayout(players_group)
        self._lbl_connected = QLabel('0')
        self._lbl_total = QLabel('0')
        players_form.addRow('Connected:', self._lbl_connected)
        players_form.addRow('Total:', self._lbl_total)
        layout.addWidget(players_group)

        # Bandwidth group
        bandwidth_group = QGroupBox('Bandwidth (current session)')
        bandwidth_form = QFormLayout(bandwidth_group)
        self._lbl_bandwidth = QLabel('0 B')
        self._lbl_download = QLabel('0 B')
        self._lbl_upload = QLabel('0 B')
        bandwidth_form.addRow('Total Exchanged:', self._lbl_bandwidth)
        bandwidth_form.addRow('Downloaded:', self._lbl_download)
        bandwidth_form.addRow('Uploaded:', self._lbl_upload)
        layout.addWidget(bandwidth_group)

        # Rates group
        rates_group = QGroupBox('Rates')
        rates_form = QFormLayout(rates_group)
        self._lbl_pps = QLabel('0 PPS')
        self._lbl_bps = QLabel('0 B/s')
        self._lbl_peak_pps = QLabel('0 PPS')
        self._lbl_peak_bps = QLabel('0 B/s')
        rates_form.addRow('Current PPS:', self._lbl_pps)
        rates_form.addRow('Current BPS:', self._lbl_bps)
        rates_form.addRow('Peak PPS:', self._lbl_peak_pps)
        rates_form.addRow('Peak BPS:', self._lbl_peak_bps)
        layout.addWidget(rates_group)

        # Misc group
        misc_group = QGroupBox('Misc')
        misc_form = QFormLayout(misc_group)
        self._lbl_uptime = QLabel('0s')
        self._lbl_restarts = QLabel('0')
        misc_form.addRow('Window Uptime:', self._lbl_uptime)
        misc_form.addRow('Capture Restarts:', self._lbl_restarts)
        layout.addWidget(misc_group)

        self._add_always_on_top_checkbox(layout, always_on_top=always_on_top)

    # Public API —————————————————————————————————————————————————————————————

    def refresh(self) -> None:
        """Refresh all displayed statistics."""
        connected = PlayersRegistry.get_connected_players()
        all_players = PlayersRegistry.get_all_players()

        total_bandwidth = sum(p.bandwidth.exchanged for p in all_players)
        total_download = sum(p.bandwidth.download for p in all_players)
        total_upload = sum(p.bandwidth.upload for p in all_players)

        pps = CaptureStats.global_pps_rate
        bps = CaptureStats.global_bps_rate
        self._peak_pps = max(self._peak_pps, pps)
        self._peak_bps = max(self._peak_bps, bps)

        elapsed = int(time.monotonic() - self._opened_at)
        h, rem = divmod(elapsed, 3600)
        m, s = divmod(rem, 60)
        if h:
            uptime = f'{h}h {m}m {s}s'
        elif m:
            uptime = f'{m}m {s}s'
        else:
            uptime = f'{s}s'

        self._lbl_connected.setText(str(len(connected)))
        self._lbl_total.setText(str(len(all_players)))
        self._lbl_bandwidth.setText(PlayerBandwidth.format_bytes(total_bandwidth))
        self._lbl_download.setText(PlayerBandwidth.format_bytes(total_download))
        self._lbl_upload.setText(PlayerBandwidth.format_bytes(total_upload))
        self._lbl_pps.setText(f'{pps} PPS')
        self._lbl_bps.setText(f'{PlayerBandwidth.format_bytes(bps)}/s')
        self._lbl_peak_pps.setText(f'{self._peak_pps} PPS')
        self._lbl_peak_bps.setText(f'{PlayerBandwidth.format_bytes(self._peak_bps)}/s')
        self._lbl_uptime.setText(uptime)
        self._lbl_restarts.setText(str(CaptureStats.restarted_times))
