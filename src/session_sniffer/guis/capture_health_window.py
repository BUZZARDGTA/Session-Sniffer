"""Capture health and performance statistics window."""

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QCheckBox,
    QFormLayout,
    QGroupBox,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.rendering_core.types import TsharkStats


class CaptureHealthWindow(QWidget):
    """A standalone window showing tshark capture health and latency statistics."""

    def __init__(self, *, always_on_top: bool = True) -> None:
        """Initialize the capture health window."""
        super().__init__()

        self.setWindowTitle('Capture Health')
        self.resize(380, 280)
        if always_on_top:
            self.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        # Stability group
        stability_group = QGroupBox('Stability')
        stability_form = QFormLayout(stability_group)
        self._lbl_restarts = QLabel('0')
        self._lbl_vpn_mode = QLabel('No')
        stability_form.addRow('Tshark Restarts:', self._lbl_restarts)
        stability_form.addRow('VPN Mode:', self._lbl_vpn_mode)
        layout.addWidget(stability_group)

        # Latency group
        latency_group = QGroupBox('Packet Latency (all recorded samples)')
        latency_form = QFormLayout(latency_group)
        self._lbl_samples = QLabel('0')
        self._lbl_latest = QLabel('— ms')
        self._lbl_avg = QLabel('— ms')
        self._lbl_min = QLabel('— ms')
        self._lbl_max = QLabel('— ms')
        latency_form.addRow('Samples:', self._lbl_samples)
        latency_form.addRow('Latest:', self._lbl_latest)
        latency_form.addRow('Average:', self._lbl_avg)
        latency_form.addRow('Min:', self._lbl_min)
        latency_form.addRow('Max:', self._lbl_max)
        layout.addWidget(latency_group)

        always_on_top_checkbox = QCheckBox('Always on Top')
        always_on_top_checkbox.setToolTip('Keep this window above all other windows.\nThis toggle does not change the saved default.')
        always_on_top_checkbox.setChecked(always_on_top)
        always_on_top_checkbox.toggled.connect(self._toggle_always_on_top)
        layout.addWidget(always_on_top_checkbox)

    # Public API —————————————————————————————————————————————————————————————

    def refresh(self) -> None:
        """Refresh all displayed capture health statistics."""
        latencies = list(TsharkStats.packets_latencies)
        n = len(latencies)

        self._lbl_restarts.setText(str(TsharkStats.restarted_times))
        self._lbl_vpn_mode.setText('Yes' if TsharkStats.vpn_mode_enabled else 'No')
        self._lbl_samples.setText(str(n))

        if latencies:
            all_ms = [lat.total_seconds() * 1000 for _, lat in latencies]
            self._lbl_latest.setText(f'{all_ms[-1]:.2f} ms')
            self._lbl_avg.setText(f'{sum(all_ms) / n:.2f} ms')
            self._lbl_min.setText(f'{min(all_ms):.2f} ms')
            self._lbl_max.setText(f'{max(all_ms):.2f} ms')
        else:
            self._lbl_latest.setText('\u2014 ms')
            self._lbl_avg.setText('\u2014 ms')
            self._lbl_min.setText('\u2014 ms')
            self._lbl_max.setText('\u2014 ms')

    # Internal ————————————————————————————————————————————————————————————————

    def _toggle_always_on_top(self, checked: bool) -> None:  # noqa: FBT001
        if checked:
            self.setWindowFlags(self.windowFlags() | Qt.WindowType.WindowStaysOnTopHint)
        else:
            self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowStaysOnTopHint)
        self.show()
