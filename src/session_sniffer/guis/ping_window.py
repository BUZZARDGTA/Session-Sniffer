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
    PingProbeConfiguration,
    PingProbeResult,
    PingStatistics,
    TcpPortProbeEngine,
    UdpPortProbeEngine,
)

_DEFAULT_TARGET: Final[str] = '127.0.0.1'
_RTT_HIGH_THRESHOLD_MS: Final[float] = 120.0
_DEFAULT_PORT: Final[int] = 80
_MIN_PORT: Final[int] = 1
_MAX_PORT: Final[int] = 65535
_DEFAULT_COUNT: Final[int] = 4
_DEFAULT_INTERVAL_MS: Final[int] = 250
_DEFAULT_TIMEOUT_MS: Final[int] = 1000
_DEFAULT_PAYLOAD_BYTES: Final[int] = 32


class PingWorkerThread(CrashingQThread):
    """Background worker thread executing ping probes."""

    result_received = Signal(object)
    finished_signal = Signal()

    def __init__(self, configuration: PingProbeConfiguration) -> None:
        """Initialize the ping worker thread."""
        super().__init__()
        self._configuration = configuration
        self._cancel_event = Event()

    def cancel(self) -> None:
        """Signal the worker thread to stop probing."""
        self._cancel_event.set()

    @override
    def _run(self) -> None:
        """Worker loop executing periodic ping requests."""
        sequence_number = 1
        config = self._configuration

        if config.mode == PingMode.ICMP:
            icmp_engine = IcmpEchoEngine()
            try:
                while not self._cancel_event.is_set():
                    result = icmp_engine.ping(
                        config.target_host,
                        timeout_seconds=config.timeout_seconds,
                        sequence=sequence_number,
                        payload_size=config.payload_size,
                    )
                    self.result_received.emit(result)
                    if config.count > 0 and sequence_number >= config.count:
                        break
                    sequence_number += 1
                    if self._cancel_event.wait(config.interval_seconds):
                        break
            finally:
                icmp_engine.close()

        elif config.mode == PingMode.TCP:
            port_to_probe = config.port if config.port is not None else _DEFAULT_PORT
            while not self._cancel_event.is_set():
                result = TcpPortProbeEngine.probe(
                    config.target_host,
                    port_to_probe,
                    timeout_seconds=config.timeout_seconds,
                    sequence=sequence_number,
                )
                self.result_received.emit(result)
                if config.count > 0 and sequence_number >= config.count:
                    break
                sequence_number += 1
                if self._cancel_event.wait(config.interval_seconds):
                    break

        elif config.mode == PingMode.UDP:
            port_to_probe = config.port if config.port is not None else _DEFAULT_PORT
            while not self._cancel_event.is_set():
                result = UdpPortProbeEngine.probe(
                    config.target_host,
                    port_to_probe,
                    timeout_seconds=config.timeout_seconds,
                    sequence=sequence_number,
                    payload_size=config.payload_size,
                )
                self.result_received.emit(result)
                if config.count > 0 and sequence_number >= config.count:
                    break
                sequence_number += 1
                if self._cancel_event.wait(config.interval_seconds):
                    break

        else:  # PingMode.WEB
            while not self._cancel_event.is_set():
                results = CheckHostPingEngine.probe(config.target_host, sequence=sequence_number)
                for probe_result in results:
                    self.result_received.emit(probe_result)
                if config.count > 0 and sequence_number >= config.count:
                    break
                sequence_number += 1
                web_interval = max(config.interval_seconds, 10.0)
                if self._cancel_event.wait(web_interval):
                    break

        self.finished_signal.emit()


class PingTabWidget(QWidget):
    """A tab page for managing pings to a specific target."""

    def __init__(
        self,
        target_ip: str | None = None,
        *,
        mode: PingMode = PingMode.ICMP,
        port: int | None = None,
        tab_widget: QTabWidget | None = None,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the ping tab widget."""
        super().__init__(parent)
        self._tab_widget = tab_widget
        self._worker_thread: PingWorkerThread | None = None
        self._statistics = PingStatistics()

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(8, 8, 8, 8)
        main_layout.setSpacing(6)

        # --- Controls Bar ---
        controls_group = QGroupBox('Probe Configuration')
        controls_layout = QVBoxLayout(controls_group)
        controls_layout.setContentsMargins(8, 8, 8, 8)
        controls_layout.setSpacing(6)

        row1_layout = QHBoxLayout()
        row1_layout.setSpacing(8)

        target_label = QLabel('Target:')
        target_text = '' if target_ip is None or target_ip.strip() == _DEFAULT_TARGET else target_ip.strip()
        self._target_input = QLineEdit(target_text)
        self._target_input.setPlaceholderText(_DEFAULT_TARGET)
        self._target_input.setMinimumWidth(scale_by_ui(160))
        self._target_input.textChanged.connect(self._on_target_or_port_changed)

        mode_label = QLabel('Protocol:')
        self._mode_combo = QComboBox()
        self._mode_combo.addItem(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'ping.svg')), 'ICMP (Standard)', PingMode.ICMP)
        self._mode_combo.addItem(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'ping.svg')), 'TCP Port', PingMode.TCP)
        self._mode_combo.addItem(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'ping.svg')), 'UDP Port', PingMode.UDP)
        self._mode_combo.addItem(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'website.svg')), 'Web (Check-Host)', PingMode.WEB)
        if mode == PingMode.TCP:
            self._mode_combo.setCurrentIndex(1)
        elif mode == PingMode.UDP:
            self._mode_combo.setCurrentIndex(2)
        elif mode == PingMode.WEB:
            self._mode_combo.setCurrentIndex(3)

        self._port_label = QLabel('Port:')
        self._port_spinbox = QSpinBox()
        self._port_spinbox.setRange(_MIN_PORT, _MAX_PORT)
        self._port_spinbox.setValue(port if port is not None else _DEFAULT_PORT)
        self._port_spinbox.valueChanged.connect(self._on_target_or_port_changed)

        self._start_stop_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'play.svg')), ' Start')
        self._start_stop_button.setStyleSheet(DIALOG_PRIMARY_BUTTON_STYLESHEET)
        self._start_stop_button.clicked.connect(self._toggle_start_stop)

        row1_layout.addWidget(target_label)
        row1_layout.addWidget(self._target_input, stretch=2)
        row1_layout.addWidget(mode_label)
        row1_layout.addWidget(self._mode_combo, stretch=1)
        row1_layout.addWidget(self._port_label)
        row1_layout.addWidget(self._port_spinbox)
        row1_layout.addWidget(self._start_stop_button)

        row2_layout = QHBoxLayout()
        row2_layout.setSpacing(8)

        count_label = QLabel('Count:')
        self._count_spinbox = QSpinBox()
        self._count_spinbox.setRange(0, 10000)
        self._count_spinbox.setSpecialValueText('Continuous (0)')
        self._count_spinbox.setValue(_DEFAULT_COUNT)

        interval_label = QLabel('Interval:')
        self._interval_spinbox = QSpinBox()
        self._interval_spinbox.setRange(50, 10000)
        self._interval_spinbox.setSingleStep(50)
        self._interval_spinbox.setValue(_DEFAULT_INTERVAL_MS)
        self._interval_spinbox.setSuffix(' ms')

        timeout_label = QLabel('Timeout:')
        self._timeout_spinbox = QSpinBox()
        self._timeout_spinbox.setRange(100, 10000)
        self._timeout_spinbox.setSingleStep(100)
        self._timeout_spinbox.setValue(_DEFAULT_TIMEOUT_MS)
        self._timeout_spinbox.setSuffix(' ms')

        self._payload_label = QLabel('Payload:')
        self._payload_spinbox = QSpinBox()
        self._payload_spinbox.setRange(0, 65500)
        self._payload_spinbox.setSingleStep(32)
        self._payload_spinbox.setValue(_DEFAULT_PAYLOAD_BYTES)
        self._payload_spinbox.setSuffix(' bytes')

        row2_layout.addWidget(count_label)
        row2_layout.addWidget(self._count_spinbox)
        row2_layout.addWidget(interval_label)
        row2_layout.addWidget(self._interval_spinbox)
        row2_layout.addWidget(timeout_label)
        row2_layout.addWidget(self._timeout_spinbox)
        row2_layout.addWidget(self._payload_label)
        row2_layout.addWidget(self._payload_spinbox)
        row2_layout.addStretch()

        self._hint_label = QLabel()
        self._hint_label.setStyleSheet('color: #8c9ba8; font-size: 8.5pt;')

        controls_layout.addLayout(row1_layout)
        controls_layout.addLayout(row2_layout)
        controls_layout.addWidget(self._hint_label)

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
        return self._target_input.text().strip() or self._target_input.placeholderText().strip()

    @property
    def tab_label(self) -> str:
        """Return the tab title reflecting current target host, mode, and port."""
        mode_data = self._mode_combo.currentData()
        current_mode = PingMode(str(mode_data)) if mode_data is not None else PingMode.ICMP
        has_port = current_mode in (PingMode.TCP, PingMode.UDP)
        if has_port:
            return f'{self.target_ip}:{self._port_spinbox.value()}'
        return self.target_ip

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
        has_port = current_mode in (PingMode.TCP, PingMode.UDP)
        port_value = self._port_spinbox.value() if has_port else None
        interval_seconds = self._interval_spinbox.value() / 1000.0
        timeout_seconds = self._timeout_spinbox.value() / 1000.0
        count_value = self._count_spinbox.value()
        payload_size_value = self._payload_spinbox.value()

        self._start_stop_button.setText(' Stop')
        self._start_stop_button.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'stop.svg')))
        self._start_stop_button.setStyleSheet(DIALOG_DANGER_BUTTON_STYLESHEET)
        self._target_input.setEnabled(False)
        self._mode_combo.setEnabled(False)
        self._port_spinbox.setEnabled(False)
        self._count_spinbox.setEnabled(False)
        self._interval_spinbox.setEnabled(False)
        self._timeout_spinbox.setEnabled(False)
        self._payload_spinbox.setEnabled(False)

        header_message = f'Starting {current_mode.value} ping to {target_host}'
        if port_value is not None:
            header_message += f':{port_value}'
        if count_value > 0:
            header_message += f' (count={count_value})'
        self._append_log_line(f'<span style="color: #3a96dd; font-weight: bold;">{html.escape(header_message)}…</span>')

        configuration = PingProbeConfiguration(
            target_host=target_host,
            mode=current_mode,
            port=port_value,
            interval_seconds=interval_seconds,
            timeout_seconds=timeout_seconds,
            count=count_value,
            payload_size=payload_size_value,
        )
        self._worker_thread = PingWorkerThread(configuration)
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
        self._count_spinbox.setEnabled(True)
        self._interval_spinbox.setEnabled(True)
        self._timeout_spinbox.setEnabled(True)
        self._payload_spinbox.setEnabled(True)
        self._on_mode_changed()

    def _on_mode_changed(self) -> None:
        """Update port, payload, and helper hint visibility based on current mode."""
        mode_data = self._mode_combo.currentData()
        current_mode = PingMode(str(mode_data))
        is_port_required = current_mode in (PingMode.TCP, PingMode.UDP)
        is_payload_applicable = current_mode in (PingMode.ICMP, PingMode.UDP)
        is_active = self.is_running

        self._port_label.setEnabled(is_port_required)
        self._port_spinbox.setEnabled(is_port_required and not is_active)

        self._payload_label.setEnabled(is_payload_applicable)
        self._payload_spinbox.setEnabled(is_payload_applicable and not is_active)

        if current_mode == PingMode.ICMP:
            self._hint_label.setText('ICMP does not require a port. ICMP may require Administrator privileges on some systems.')
        elif current_mode == PingMode.TCP:
            self._hint_label.setText('TCP port connectivity probe (SYN/ACK).')
        elif current_mode == PingMode.UDP:
            self._hint_label.setText('UDP reachability & latency probe (Response or ICMP Port Unreachable detection).')
        else:  # PingMode.WEB
            self._hint_label.setText('Multi-vantage distributed HTTP ping via Check-Host.net (does not require a port).')

        self._on_target_or_port_changed()

    def _on_target_or_port_changed(self) -> None:
        """Update tab label in parent tab widget when target or port changes."""
        if self._tab_widget is not None:
            tab_index = self._tab_widget.indexOf(self)
            if tab_index >= 0:
                self._tab_widget.setTabText(tab_index, self.tab_label)

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
                message = f'Reply from {result.target_ip}:{result.port} ({result.status_message}): time={round_trip_time:.2f}ms'
            elif result.time_to_live is not None:
                message = f'Reply from {result.target_ip}: bytes={result.payload_bytes} time={round_trip_time:.1f}ms TTL={result.time_to_live}'
            else:
                message = f'Reply from {result.target_host} ({result.target_ip}): time={round_trip_time:.2f}ms'

            html_line = f'<span style="color: #7f8c8d;">{sequence_prefix}</span> <span style="color: {rtt_color}; font-weight: 500;">{html.escape(message)}</span>'
        else:
            failure_message = f'Target {result.target_ip}'
            if result.port is not None:
                failure_message += f':{result.port}'
            failure_message += f': {result.status_message}'
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
        targets: str | list[str] | None = None,
        *,
        mode: PingMode = PingMode.ICMP,
        port: int | None = None,
    ) -> None:
        """Initialize the Ping Diagnostics window."""
        super().__init__(None, Qt.WindowType.Window)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self.destroyed.connect(lambda: setattr(PingWindow, '_instance', None) if PingWindow._instance is self else None)
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

        if targets is None:
            target_list: list[str | None] = [None]
        elif isinstance(targets, str):
            target_list = [targets]
        else:
            target_list = list(targets)

        for target in target_list:
            should_auto_start = target is not None and target.strip() != _DEFAULT_TARGET
            self.add_target_tab(target, mode=mode, port=port, auto_start=should_auto_start)

    @classmethod
    def open_window(
        cls,
        targets: str | list[str] | None = None,
        *,
        mode: PingMode = PingMode.ICMP,
        port: int | None = None,
    ) -> PingWindow:
        """Open or reuse the active PingWindow and activate it."""
        if cls._instance is None:
            cls._instance = cls(targets, mode=mode, port=port)
        elif targets is not None:
            target_list = [targets] if isinstance(targets, str) else list(targets)
            for target in target_list:
                should_auto_start = target.strip() != _DEFAULT_TARGET
                cls._instance.add_target_tab(target, mode=mode, port=port, auto_start=should_auto_start)

        cls._instance.show()
        cls._instance.raise_()
        cls._instance.activateWindow()
        return cls._instance

    @classmethod
    def close_window(cls) -> None:
        """Close the active PingWindow if one is open."""
        if cls._instance is not None:
            cls._instance.close()

    def add_target_tab(
        self,
        target_ip: str | None = None,
        *,
        mode: PingMode = PingMode.ICMP,
        port: int | None = None,
        auto_start: bool = True,
    ) -> None:
        """Add a new target tab or focus existing tab for this IP."""
        normalized_ip = target_ip.strip() if target_ip is not None else ''
        effective_ip = normalized_ip if normalized_ip and normalized_ip != _DEFAULT_TARGET else _DEFAULT_TARGET

        for i in range(self._tab_widget.count()):
            tab = self._tab_widget.widget(i)
            if isinstance(tab, PingTabWidget) and tab.target_ip == effective_ip:
                self._tab_widget.setCurrentIndex(i)
                if auto_start and not tab.is_running:
                    tab.start_ping()
                return

        tab_page = PingTabWidget(normalized_ip or None, mode=mode, port=port, tab_widget=self._tab_widget, parent=self._tab_widget)
        new_index = self._tab_widget.addTab(tab_page, tab_page.tab_label)
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
            target_str = new_target.strip()
            should_auto_start = target_str != _DEFAULT_TARGET
            self.add_target_tab(target_str, auto_start=should_auto_start)

    @override
    def closeEvent(self, event: QCloseEvent) -> None:
        """Stop all workers before closing window."""
        self.stop_all_tabs()
        super().closeEvent(event)
