"""Native PySide6 window for ICMP, TCP port, and web ping diagnostics."""

import html
import time
from threading import Event
from typing import Final, override

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QCloseEvent, QFont, QIcon, QTextCursor
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QGroupBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.local import RESOURCES_DIR_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.error_messages import ensure_instance
from session_sniffer.guis._crashing_qthread import CrashingQThread
from session_sniffer.guis.stylesheets import (
    DIALOG_BUTTON_STYLESHEET,
    DIALOG_DANGER_BUTTON_STYLESHEET,
    DIALOG_PRIMARY_BUTTON_STYLESHEET,
)
from session_sniffer.guis.utils import scale_by_ui
from session_sniffer.networking.ping import (
    CheckHostPingEngine,
    IcmpEchoEngine,
    PingMode,
    PingProbeResult,
    PingStatistics,
    TcpPortProbeEngine,
)

_RTT_HIGH_THRESHOLD_MS: Final[float] = 120.0
_DEFAULT_PORT: Final[int] = 80
_MIN_PORT: Final[int] = 1
_MAX_PORT: Final[int] = 65535


class PingWorkerThread(CrashingQThread):
    """Background worker thread executing continuous ping probes."""

    result_received = Signal(object)
    finished_signal = Signal()

    def __init__(
        self,
        target_host: str,
        mode: PingMode,
        port: int | None,
        interval_seconds: float,
        timeout_seconds: float,
    ) -> None:
        """Initialize the ping worker thread."""
        super().__init__()
        self._target_host = target_host
        self._mode = mode
        self._port = port
        self._interval_seconds = interval_seconds
        self._timeout_seconds = timeout_seconds
        self._cancel_event = Event()

    def cancel(self) -> None:
        """Signal the worker thread to stop probing."""
        self._cancel_event.set()

    @override
    def _run(self) -> None:
        """Worker loop executing periodic ping requests."""
        sequence_number = 1

        if self._mode == PingMode.ICMP:
            icmp_engine = IcmpEchoEngine()
            try:
                while not self._cancel_event.is_set():
                    result = icmp_engine.ping(
                        self._target_host,
                        timeout_seconds=self._timeout_seconds,
                        sequence=sequence_number,
                    )
                    self.result_received.emit(result)
                    sequence_number += 1
                    if self._cancel_event.wait(self._interval_seconds):
                        break
            finally:
                icmp_engine.close()

        elif self._mode == PingMode.TCP:
            port_to_probe = self._port if self._port is not None else _DEFAULT_PORT
            while not self._cancel_event.is_set():
                result = TcpPortProbeEngine.probe(
                    self._target_host,
                    port_to_probe,
                    timeout_seconds=self._timeout_seconds,
                    sequence=sequence_number,
                )
                self.result_received.emit(result)
                sequence_number += 1
                if self._cancel_event.wait(self._interval_seconds):
                    break

        elif self._mode == PingMode.WEB:
            while not self._cancel_event.is_set():
                results = CheckHostPingEngine.probe(self._target_host, sequence=sequence_number)
                for probe_result in results:
                    self.result_received.emit(probe_result)
                sequence_number += 1
                web_interval = max(self._interval_seconds, 10.0)
                if self._cancel_event.wait(web_interval):
                    break

        self.finished_signal.emit()


class PingTabWidget(QWidget):
    """A tab page for managing pings to a specific target."""

    def __init__(
        self,
        target_ip: str,
        *,
        mode: PingMode = PingMode.ICMP,
        port: int | None = None,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the ping tab widget."""
        super().__init__(parent)
        self._target_ip = target_ip
        self._worker_thread: PingWorkerThread | None = None
        self._statistics = PingStatistics()

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(8, 8, 8, 8)
        main_layout.setSpacing(6)

        # --- Controls Bar ---
        controls_group = QGroupBox('Probe Configuration')
        controls_layout = QHBoxLayout(controls_group)
        controls_layout.setContentsMargins(8, 8, 8, 8)
        controls_layout.setSpacing(8)

        target_label = QLabel('Target:')
        self._target_input = QLineEdit(target_ip)
        self._target_input.setPlaceholderText('Host or IPv4 address')
        self._target_input.setMinimumWidth(scale_by_ui(160))

        mode_label = QLabel('Mode:')
        self._mode_combo = QComboBox()
        self._mode_combo.addItem(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'ping.svg')), 'ICMP (Standard)', PingMode.ICMP)
        self._mode_combo.addItem(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'settings.svg')), 'TCP Port', PingMode.TCP)
        self._mode_combo.addItem(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'website.svg')), 'Web (Check-Host)', PingMode.WEB)
        if mode == PingMode.TCP:
            self._mode_combo.setCurrentIndex(1)
        elif mode == PingMode.WEB:
            self._mode_combo.setCurrentIndex(2)

        self._port_label = QLabel('Port:')
        self._port_spinbox = QSpinBox()
        self._port_spinbox.setRange(_MIN_PORT, _MAX_PORT)
        self._port_spinbox.setValue(port if port is not None else _DEFAULT_PORT)

        interval_label = QLabel('Interval:')
        self._interval_spinbox = QDoubleSpinBox()
        self._interval_spinbox.setRange(0.2, 10.0)
        self._interval_spinbox.setSingleStep(0.5)
        self._interval_spinbox.setValue(1.0)
        self._interval_spinbox.setSuffix(' s')

        timeout_label = QLabel('Timeout:')
        self._timeout_spinbox = QDoubleSpinBox()
        self._timeout_spinbox.setRange(0.5, 10.0)
        self._timeout_spinbox.setSingleStep(0.5)
        self._timeout_spinbox.setValue(2.0)
        self._timeout_spinbox.setSuffix(' s')

        self._start_stop_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'play.svg')), ' Start')
        self._start_stop_button.setStyleSheet(DIALOG_PRIMARY_BUTTON_STYLESHEET)
        self._start_stop_button.clicked.connect(self._toggle_start_stop)

        controls_layout.addWidget(target_label)
        controls_layout.addWidget(self._target_input)
        controls_layout.addWidget(mode_label)
        controls_layout.addWidget(self._mode_combo)
        controls_layout.addWidget(self._port_label)
        controls_layout.addWidget(self._port_spinbox)
        controls_layout.addWidget(interval_label)
        controls_layout.addWidget(self._interval_spinbox)
        controls_layout.addWidget(timeout_label)
        controls_layout.addWidget(self._timeout_spinbox)
        controls_layout.addStretch()
        controls_layout.addWidget(self._start_stop_button)

        main_layout.addWidget(controls_group)

        # --- Log Console ---
        self._console_log = QTextEdit()
        self._console_log.setReadOnly(True)
        console_font = QFont('Consolas', 10)
        console_font.setStyleHint(QFont.StyleHint.Monospace)
        self._console_log.setFont(console_font)
        self._console_log.setStyleSheet(
            'QTextEdit { background-color: #141414; color: #e0e0e0; border: 1px solid #2d3640; border-radius: 4px; padding: 6px; }',
        )
        main_layout.addWidget(self._console_log, stretch=1)

        # --- Statistics & Bottom Actions Bar ---
        bottom_group = QGroupBox('Live Statistics')
        bottom_layout = QHBoxLayout(bottom_group)
        bottom_layout.setContentsMargins(8, 8, 8, 8)
        bottom_layout.setSpacing(12)

        self._stats_label = QLabel('Ready. Press Start to begin pinging.')
        self._stats_label.setStyleSheet('color: #a5b4c4; font-size: 9pt;')

        self._autoscroll_checkbox = QCheckBox('Auto-scroll')
        self._autoscroll_checkbox.setChecked(True)

        copy_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg')), ' Copy Log')
        copy_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        copy_button.clicked.connect(self._copy_log)

        clear_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'clear_all.svg')), ' Clear')
        clear_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        clear_button.clicked.connect(self._clear_log)

        bottom_layout.addWidget(self._stats_label, stretch=1)
        bottom_layout.addWidget(self._autoscroll_checkbox)
        bottom_layout.addWidget(copy_button)
        bottom_layout.addWidget(clear_button)

        main_layout.addWidget(bottom_group)

        self._mode_combo.currentIndexChanged.connect(self._on_mode_changed)
        self._on_mode_changed()

    @property
    def target_ip(self) -> str:
        """Return the target IP or hostname configured for this tab."""
        return self._target_input.text().strip()

    @property
    def is_running(self) -> bool:
        """Return True if this tab is currently running a ping worker thread."""
        return self._worker_thread is not None and self._worker_thread.isRunning()

    def start_ping(self) -> None:
        """Start the ping worker if not already running."""
        if self.is_running:
            return

        target_host = self.target_ip
        if not target_host:
            QMessageBox.warning(self, 'Input Error', 'Please specify a target IP address or hostname.')
            return

        mode_data = self._mode_combo.currentData()
        current_mode = PingMode(str(mode_data))
        port_value = self._port_spinbox.value() if current_mode == PingMode.TCP else None
        interval_value = self._interval_spinbox.value()
        timeout_value = self._timeout_spinbox.value()

        self._start_stop_button.setText(' Stop')
        self._start_stop_button.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'stop.svg')))
        self._start_stop_button.setStyleSheet(DIALOG_DANGER_BUTTON_STYLESHEET)
        self._target_input.setEnabled(False)
        self._mode_combo.setEnabled(False)
        self._port_spinbox.setEnabled(False)

        header_message = f'Starting {current_mode.value} ping to {target_host}'
        if port_value is not None:
            header_message += f':{port_value}'
        self._append_log_line(f'<span style="color: #3a96dd; font-weight: bold;">{html.escape(header_message)}…</span>')

        self._worker_thread = PingWorkerThread(
            target_host=target_host,
            mode=current_mode,
            port=port_value,
            interval_seconds=interval_value,
            timeout_seconds=timeout_value,
        )
        self._worker_thread.result_received.connect(self._on_probe_result)
        self._worker_thread.finished_signal.connect(self._on_worker_finished)
        self._worker_thread.start()

    def stop_ping(self) -> None:
        """Signal the worker thread to stop and restore controls."""
        if self._worker_thread is not None and self._worker_thread.isRunning():
            self._worker_thread.cancel()
            self._worker_thread.wait(2000)

        self._on_worker_finished()

    def _toggle_start_stop(self) -> None:
        """Toggle between starting and stopping ping execution."""
        if self.is_running:
            self.stop_ping()
        else:
            self.start_ping()

    def _on_worker_finished(self) -> None:
        """Handle worker thread termination."""
        self._worker_thread = None
        self._start_stop_button.setText(' Start')
        self._start_stop_button.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'play.svg')))
        self._start_stop_button.setStyleSheet(DIALOG_PRIMARY_BUTTON_STYLESHEET)
        self._target_input.setEnabled(True)
        self._mode_combo.setEnabled(True)
        self._on_mode_changed()

    def _on_mode_changed(self) -> None:
        """Update port input visibility based on current mode."""
        mode_data = self._mode_combo.currentData()
        current_mode = PingMode(str(mode_data))
        is_tcp = current_mode == PingMode.TCP
        self._port_label.setVisible(is_tcp)
        self._port_spinbox.setVisible(is_tcp)
        self._port_spinbox.setEnabled(is_tcp and not self.is_running)

    def _on_probe_result(self, result_object: object) -> None:
        """Process and display a received probe result."""
        result = ensure_instance(result_object, PingProbeResult)
        self._statistics.update(result)
        self._update_statistics_display()

        timestamp_string = time.strftime('%H:%M:%S', time.localtime(result.timestamp))
        sequence_prefix = f'[{timestamp_string}] #{result.sequence}:'

        if result.is_successful:
            round_trip_time = result.round_trip_time_ms if result.round_trip_time_ms is not None else 0.0
            rtt_color = '#f1c40f' if round_trip_time > _RTT_HIGH_THRESHOLD_MS else '#2ecc71'

            if result.port is not None:
                message = f'Connected to {result.target_ip}:{result.port} — time={round_trip_time:.2f}ms'
            elif result.time_to_live is not None:
                message = f'Reply from {result.target_ip}: bytes=32 time={round_trip_time:.1f}ms TTL={result.time_to_live}'
            else:
                message = f'Reply from {result.target_host} ({result.target_ip}): time={round_trip_time:.2f}ms'

            html_line = f'<span style="color: #7f8c8d;">{sequence_prefix}</span> <span style="color: {rtt_color}; font-weight: 500;">{html.escape(message)}</span>'
        else:
            failure_message = f'Target {result.target_ip}: {result.status_message}'
            html_line = f'<span style="color: #7f8c8d;">{sequence_prefix}</span> <span style="color: #e74c3c; font-weight: bold;">{html.escape(failure_message)}</span>'

        self._append_log_line(html_line)

    def _update_statistics_display(self) -> None:
        """Refresh the live statistics card with current values."""
        stats = self._statistics
        summary_parts = [
            (
                f'<b>Packets:</b> Sent = {stats.total_sent}, Received = {stats.total_received}, '
                f'Lost = {stats.total_failed} (<span style="color: {"#e74c3c" if stats.packet_loss_percentage > 0 else "#2ecc71"};">'
                f'{stats.packet_loss_percentage:.1f}% loss</span>)'
            ),
        ]

        if stats.minimum_rtt_ms is not None and stats.average_rtt_ms is not None and stats.maximum_rtt_ms is not None:
            jitter_string = f', Jitter = {stats.jitter_ms:.2f} ms' if stats.jitter_ms is not None else ''
            summary_parts.append(
                f'<b>RTT:</b> Min = {stats.minimum_rtt_ms:.2f} ms, Avg = {stats.average_rtt_ms:.2f} ms, Max = {stats.maximum_rtt_ms:.2f} ms{jitter_string}',
            )

        self._stats_label.setText(' | '.join(summary_parts))

    def _append_log_line(self, html_line: str) -> None:
        """Append a formatted HTML line to the console log."""
        self._console_log.append(html_line)
        if self._autoscroll_checkbox.isChecked():
            cursor = self._console_log.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.End)
            self._console_log.setTextCursor(cursor)

    def _copy_log(self) -> None:
        """Copy console text to clipboard."""
        plain_text = self._console_log.toPlainText()
        if plain_text:
            QApplication.clipboard().setText(plain_text)

    def _clear_log(self) -> None:
        """Clear the console log and reset statistics."""
        self._console_log.clear()
        self._statistics = PingStatistics()
        self._stats_label.setText('Log cleared. Statistics reset.')


class PingWindow(QWidget):
    """Dedicated modeless window providing ICMP, TCP, and web ping diagnostics."""

    _instance: PingWindow | None = None

    def __init__(
        self,
        targets: str | list[str],
        *,
        mode: PingMode = PingMode.ICMP,
        port: int | None = None,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the Ping Diagnostics window."""
        super().__init__(parent, Qt.WindowType.Window)
        self.setWindowTitle(f'{TITLE} - Ping Diagnostics')
        self.setWindowIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'ping.svg')))
        self.resize(scale_by_ui(860), scale_by_ui(560))

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(8)

        self._tab_widget = QTabWidget()
        self._tab_widget.setTabsClosable(True)
        self._tab_widget.tabCloseRequested.connect(self._close_tab)
        main_layout.addWidget(self._tab_widget, stretch=1)

        # --- Window Footer Bar ---
        footer_layout = QHBoxLayout()
        footer_layout.setContentsMargins(4, 4, 4, 4)
        footer_layout.setSpacing(8)

        start_all_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'play.svg')), ' Start All')
        start_all_button.setStyleSheet(DIALOG_PRIMARY_BUTTON_STYLESHEET)
        start_all_button.clicked.connect(self.start_all_tabs)

        stop_all_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'stop.svg')), ' Stop All')
        stop_all_button.setStyleSheet(DIALOG_DANGER_BUTTON_STYLESHEET)
        stop_all_button.clicked.connect(self.stop_all_tabs)

        add_target_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'add.svg')), ' Add Target…')
        add_target_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        add_target_button.clicked.connect(self._prompt_add_target)

        close_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'close.svg')), ' Close')
        close_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        close_button.clicked.connect(self.close)

        footer_layout.addWidget(start_all_button)
        footer_layout.addWidget(stop_all_button)
        footer_layout.addWidget(add_target_button)
        footer_layout.addStretch()
        footer_layout.addWidget(close_button)

        main_layout.addLayout(footer_layout)

        target_list = [targets] if isinstance(targets, str) else targets
        for target in target_list:
            self.add_target_tab(target, mode=mode, port=port, auto_start=True)

    @classmethod
    def open_window(
        cls,
        targets: str | list[str],
        *,
        mode: PingMode = PingMode.ICMP,
        port: int | None = None,
        parent: QWidget | None = None,
    ) -> PingWindow:
        """Open or reuse the active PingWindow and activate it."""
        if cls._instance is None or not cls._instance.isVisible():
            cls._instance = cls(targets, mode=mode, port=port, parent=parent)
        else:
            target_list = [targets] if isinstance(targets, str) else targets
            for target in target_list:
                cls._instance.add_target_tab(target, mode=mode, port=port, auto_start=True)

        cls._instance.show()
        cls._instance.raise_()
        cls._instance.activateWindow()
        return cls._instance

    def add_target_tab(
        self,
        target_ip: str,
        *,
        mode: PingMode = PingMode.ICMP,
        port: int | None = None,
        auto_start: bool = True,
    ) -> None:
        """Add a new target tab or focus existing tab for this IP."""
        normalized_ip = target_ip.strip()
        if not normalized_ip:
            return

        for i in range(self._tab_widget.count()):
            tab = self._tab_widget.widget(i)
            if isinstance(tab, PingTabWidget) and tab.target_ip == normalized_ip:
                self._tab_widget.setCurrentIndex(i)
                if auto_start and not tab.is_running:
                    tab.start_ping()
                return

        tab_page = PingTabWidget(normalized_ip, mode=mode, port=port, parent=self._tab_widget)
        tab_label = f'{normalized_ip}' if port is None or mode != PingMode.TCP else f'{normalized_ip}:{port}'
        new_index = self._tab_widget.addTab(tab_page, tab_label)
        self._tab_widget.setCurrentIndex(new_index)

        if auto_start:
            tab_page.start_ping()

    def start_all_tabs(self) -> None:
        """Start ping probing on all tabs."""
        for i in range(self._tab_widget.count()):
            tab = self._tab_widget.widget(i)
            if isinstance(tab, PingTabWidget):
                tab.start_ping()

    def stop_all_tabs(self) -> None:
        """Stop ping probing on all tabs."""
        for i in range(self._tab_widget.count()):
            tab = self._tab_widget.widget(i)
            if isinstance(tab, PingTabWidget):
                tab.stop_ping()

    def _close_tab(self, index: int) -> None:
        """Close and terminate a tab."""
        tab = self._tab_widget.widget(index)
        if isinstance(tab, PingTabWidget):
            tab.stop_ping()
        self._tab_widget.removeTab(index)
        if not self._tab_widget.count():
            self.close()

    def _prompt_add_target(self) -> None:
        """Prompt user for a new IP address or hostname to add."""
        new_target, success = QInputDialog.getText(
            self,
            'Add Ping Target',
            'Enter target IPv4 address or hostname to ping:',
        )
        if success and new_target.strip():
            self.add_target_tab(new_target.strip(), auto_start=True)

    @override
    def closeEvent(self, event: QCloseEvent) -> None:
        """Stop all workers before closing window."""
        self.stop_all_tabs()
        super().closeEvent(event)
