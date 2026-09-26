"""Native PySide6 window for high-performance TCP and UDP port scanning."""

import csv
import socket
import webbrowser
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import Event
from typing import Final, override

from PySide6.QtCore import QPoint, Qt, Signal
from PySide6.QtGui import QCloseEvent, QFont, QIcon, QResizeEvent, QShowEvent
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.local import RESOURCES_DIR_PATH
from session_sniffer.constants.standalone import (
    DEFAULT_MIN_COLUMN_WIDTH,
    TITLE,
)
from session_sniffer.error_messages import ensure_instance
from session_sniffer.guis._crashing_qthread import CrashingQThread
from session_sniffer.guis.ping_window import PingWindow
from session_sniffer.guis.stylesheets import (
    DIALOG_BUTTON_STYLESHEET,
    DIALOG_DANGER_BUTTON_STYLESHEET,
    DIALOG_PRIMARY_BUTTON_STYLESHEET,
    SVG_ICON_CONTEXT_MENU_STYLESHEET,
)
from session_sniffer.guis.table_column_resizing import TableColumnResizeController, setup_table_header_context_menu
from session_sniffer.guis.utils import scale_by_ui, set_clipboard_text
from session_sniffer.networking.ping import PingMode
from session_sniffer.networking.port_scanner import (
    DEFAULT_SCAN_THREADS,
    DEFAULT_SCAN_TIMEOUT_SECONDS,
    MAX_SCAN_THREADS,
    PORT_PRESETS,
    PortScanConfiguration,
    PortScanProtocol,
    PortScanResult,
    PortScanState,
    PortScanStatistics,
    parse_port_specification,
    probe_single_target,
)

_DEFAULT_TARGET: Final[str] = '127.0.0.1'
_COLUMN_PORT: Final[int] = 0
_COLUMN_PROTOCOL: Final[int] = 1
_COLUMN_STATE: Final[int] = 2
_COLUMN_SERVICE: Final[int] = 3
_COLUMN_LATENCY: Final[int] = 4
_COLUMN_BANNER: Final[int] = 5
_TOTAL_COLUMNS: Final[int] = 6


class PortScannerWorkerThread(CrashingQThread):
    """Background worker thread executing concurrent port scan probes."""

    scan_progress = Signal(int, int, int, float, float)
    result_found = Signal(object)
    scan_complete = Signal()

    def __init__(self, scan_config: PortScanConfiguration) -> None:
        """Initialize the port scanner worker thread."""
        super().__init__()
        self._scan_config = scan_config
        self._abort_signal = Event()

    def cancel(self) -> None:
        """Signal the worker thread to abort scanning."""
        self._abort_signal.set()

    @override
    def _run(self) -> None:
        """Execute concurrent port scanning using a worker thread pool."""
        config = self._scan_config
        probe_tasks: list[tuple[int, str]] = []

        if config.protocol in (PortScanProtocol.TCP, PortScanProtocol.BOTH):
            probe_tasks.extend((port, 'TCP') for port in config.ports)

        if config.protocol in (PortScanProtocol.UDP, PortScanProtocol.BOTH):
            probe_tasks.extend((port, 'UDP') for port in config.ports)

        total_probes = len(probe_tasks)
        stats = PortScanStatistics(total_probes=total_probes)

        if not total_probes:
            self.scan_complete.emit()
            return

        worker_count = min(max(1, config.threads), total_probes, MAX_SCAN_THREADS)

        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            future_to_task: dict[Future[PortScanResult], tuple[int, str]] = {}
            for port, protocol in probe_tasks:
                if self._abort_signal.is_set():
                    break
                future = executor.submit(
                    probe_single_target,
                    config.target_ip,
                    port,
                    protocol,
                    config.timeout_seconds,
                    grab_banner=config.grab_banner,
                )
                future_to_task[future] = (port, protocol)

            for future in as_completed(future_to_task):
                if self._abort_signal.is_set():
                    executor.shutdown(wait=False, cancel_futures=True)
                    break

                probe_result = future.result()
                stats.completed_probes += 1

                if probe_result.state == PortScanState.OPEN:
                    stats.open_count += 1
                elif probe_result.state == PortScanState.CLOSED:
                    stats.closed_count += 1
                else:
                    stats.filtered_count += 1

                self.result_found.emit(probe_result)
                self.scan_progress.emit(
                    stats.completed_probes,
                    stats.total_probes,
                    stats.open_count,
                    stats.elapsed_seconds,
                    stats.scan_speed_ports_per_second,
                )

        self.scan_complete.emit()


class PortScannerTabWidget(QWidget):
    """Tab page managing port scanning against a specific host or IP address."""

    def __init__(
        self,
        target: str | None = None,
        *,
        ports_preset: str = 'Top 100 Common',
        tab_widget: QTabWidget | None = None,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the port scanner tab widget."""
        super().__init__(parent)
        self._tab_widget = tab_widget
        self._worker_thread: PortScannerWorkerThread | None = None
        self._results: list[PortScanResult] = []

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(8, 8, 8, 8)
        main_layout.setSpacing(6)

        target_text = '' if target is None or target.strip() == _DEFAULT_TARGET else target.strip()
        controls_box = self._create_controls_box(target_text, ports_preset)
        main_layout.addWidget(controls_box)

        # --- Progress Bar & Real-time Metrics ---
        progress_layout = QHBoxLayout()
        progress_layout.setSpacing(10)

        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 100)
        self._progress_bar.setValue(0)
        self._progress_bar.setTextVisible(True)
        self._progress_bar.setFixedHeight(scale_by_ui(18))

        self._metrics_label = QLabel('Ready. Press Start Scan to begin.')
        self._metrics_label.setStyleSheet('color: #a5b4c4; font-size: 8.5pt;')

        progress_layout.addWidget(self._progress_bar, stretch=1)
        progress_layout.addWidget(self._metrics_label)
        main_layout.addLayout(progress_layout)

        # --- Results Table ---
        self._results_table = QTableWidget(0, _TOTAL_COLUMNS)
        self._results_table.setHorizontalHeaderLabels(
            [
                'Port',
                'Protocol',
                'State',
                'Service',
                'Latency (ms)',
                'Banner / Details',
            ]
        )
        self._results_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._results_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._results_table.setAlternatingRowColors(True)
        self._results_table.verticalHeader().setVisible(False)
        self._results_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._results_table.customContextMenuRequested.connect(self._show_table_context_menu)

        self._column_resizer: TableColumnResizeController = TableColumnResizeController(self._results_table)
        header = self._results_table.horizontalHeader()
        header.setStretchLastSection(False)
        header.setMinimumSectionSize(scale_by_ui(DEFAULT_MIN_COLUMN_WIDTH))
        header.sectionResized.connect(self._column_resizer.on_section_resized)
        setup_table_header_context_menu(self._results_table, on_reset=self._reset_column_sizes)
        self._reset_column_sizes()

        table_font = QFont('Consolas', 9)
        table_font.setStyleHint(QFont.StyleHint.Monospace)
        self._results_table.setFont(table_font)
        self._results_table.setStyleSheet(
            'QTableWidget { background-color: #141414; alternate-background-color: #1b1b1b; '
            'color: #e0e0e0; gridline-color: #2d3640; border: 1px solid #2d3640; border-radius: 4px; } '
            'QHeaderView::section { background-color: #202020; color: #a5b4c4; padding: 4px; border: 1px solid #2d3640; }',
        )
        main_layout.addWidget(self._results_table, stretch=1)

        # --- Footer Toolbar ---
        toolbar_layout = QHBoxLayout()
        toolbar_layout.setSpacing(8)

        self._show_open_only_checkbox = QCheckBox('Show Open Ports Only')
        self._show_open_only_checkbox.setChecked(True)
        self._show_open_only_checkbox.toggled.connect(self._apply_table_filter)

        copy_selected_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg')), ' Copy Selected')
        copy_selected_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        copy_selected_button.clicked.connect(self._copy_selected_rows)

        copy_all_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg')), ' Copy All Open')
        copy_all_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        copy_all_button.clicked.connect(self._copy_all_open)

        export_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'save.svg')), ' Export…')
        export_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        export_button.clicked.connect(self._export_results)

        clear_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'clear_all.svg')), ' Clear')
        clear_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        clear_button.clicked.connect(self._clear_results)

        toolbar_layout.addWidget(self._show_open_only_checkbox)
        toolbar_layout.addStretch()
        toolbar_layout.addWidget(copy_selected_button)
        toolbar_layout.addWidget(copy_all_button)
        toolbar_layout.addWidget(export_button)
        toolbar_layout.addWidget(clear_button)

        main_layout.addLayout(toolbar_layout)

    @property
    def target(self) -> str:
        """Return the target configured for this tab."""
        return self._target_input.text().strip() or self._target_input.placeholderText().strip()

    @property
    def is_running(self) -> bool:
        """Return True if a port scan worker thread is active."""
        return self._worker_thread is not None and self._worker_thread.isRunning()

    def _on_preset_changed(self, preset_name: str) -> None:
        """Update ports input when preset selection changes."""
        if preset_name in PORT_PRESETS:
            self._ports_input.setText(PORT_PRESETS[preset_name])

    def _on_ports_text_edited(self) -> None:
        """Switch preset dropdown to Custom when user edits ports field directly."""
        custom_index = self._preset_combo.findText('Custom')
        if custom_index >= 0 and self._preset_combo.currentIndex() != custom_index:
            self._preset_combo.setCurrentIndex(custom_index)

    def _create_controls_box(self, initial_target: str, ports_preset: str) -> QGroupBox:
        """Construct the configuration controls panel for the tab."""
        box = QGroupBox('Scan Configuration')
        box_layout = QVBoxLayout(box)
        box_layout.setContentsMargins(8, 8, 8, 8)
        box_layout.setSpacing(6)

        target_row = QHBoxLayout()
        target_row.setSpacing(8)

        target_label = QLabel('Target:')
        self._target_input = QLineEdit(initial_target)
        self._target_input.setPlaceholderText(_DEFAULT_TARGET)
        self._target_input.setMinimumWidth(scale_by_ui(160))
        self._target_input.textChanged.connect(self._on_target_text_changed)

        preset_label = QLabel('Preset:')
        self._preset_combo = QComboBox()
        for preset_name in PORT_PRESETS:
            self._preset_combo.addItem(preset_name)
        self._preset_combo.addItem('Custom')
        preset_index = self._preset_combo.findText(ports_preset)
        if preset_index >= 0:
            self._preset_combo.setCurrentIndex(preset_index)
        self._preset_combo.currentTextChanged.connect(self._on_preset_changed)

        ports_label = QLabel('Ports:')
        initial_ports = PORT_PRESETS.get(ports_preset, '1-1024')
        self._ports_input = QLineEdit(initial_ports)
        self._ports_input.setPlaceholderText('e.g. 80, 443, 1-1024')
        self._ports_input.textEdited.connect(self._on_ports_text_edited)

        self._start_stop_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'play.svg')), ' Start Scan')
        self._start_stop_button.setStyleSheet(DIALOG_PRIMARY_BUTTON_STYLESHEET)
        self._start_stop_button.clicked.connect(self._toggle_start_stop)

        target_row.addWidget(target_label)
        target_row.addWidget(self._target_input, stretch=2)
        target_row.addWidget(preset_label)
        target_row.addWidget(self._preset_combo, stretch=1)
        target_row.addWidget(ports_label)
        target_row.addWidget(self._ports_input, stretch=2)
        target_row.addWidget(self._start_stop_button)

        options_row = QHBoxLayout()
        options_row.setSpacing(8)

        proto_label = QLabel('Protocol:')
        self._protocol_combo = QComboBox()
        self._protocol_combo.addItem('TCP', PortScanProtocol.TCP)
        self._protocol_combo.addItem('UDP', PortScanProtocol.UDP)
        self._protocol_combo.addItem('TCP + UDP', PortScanProtocol.BOTH)

        threads_label = QLabel('Threads:')
        self._threads_spinbox = QSpinBox()
        self._threads_spinbox.setRange(1, MAX_SCAN_THREADS)
        self._threads_spinbox.setSingleStep(32)
        self._threads_spinbox.setValue(DEFAULT_SCAN_THREADS)

        timeout_label = QLabel('Timeout:')
        self._timeout_spinbox = QSpinBox()
        self._timeout_spinbox.setRange(100, 10000)
        self._timeout_spinbox.setSingleStep(100)
        self._timeout_spinbox.setValue(int(DEFAULT_SCAN_TIMEOUT_SECONDS * 1000))
        self._timeout_spinbox.setSuffix(' ms')

        self._banner_checkbox = QCheckBox('Grab Service Banners')
        self._banner_checkbox.setChecked(True)

        options_row.addWidget(proto_label)
        options_row.addWidget(self._protocol_combo)
        options_row.addWidget(threads_label)
        options_row.addWidget(self._threads_spinbox)
        options_row.addWidget(timeout_label)
        options_row.addWidget(self._timeout_spinbox)
        options_row.addWidget(self._banner_checkbox)
        options_row.addStretch()

        box_layout.addLayout(target_row)
        box_layout.addLayout(options_row)
        return box

    def _on_target_text_changed(self) -> None:
        """Update tab text in parent tab widget when target changes."""
        if self._tab_widget is not None:
            tab_index = self._tab_widget.indexOf(self)
            if tab_index >= 0:
                self._tab_widget.setTabText(tab_index, self.target)

    def start_scan(self) -> None:
        """Validate configuration and initiate concurrent port scanning."""
        if self.is_running:
            return

        target_host = self.target
        if not target_host:
            QMessageBox.warning(self, 'Input Error', 'Please specify a target IP address or hostname.')
            return

        try:
            target_ip = socket.gethostbyname(target_host)
        except OSError as error:
            QMessageBox.warning(self, 'DNS Resolution Error', f'Failed to resolve target host:\n{error}')
            return

        try:
            parsed_ports = parse_port_specification(self._ports_input.text())
        except ValueError as error:
            QMessageBox.warning(self, 'Port Format Error', str(error))
            return

        proto_data = self._protocol_combo.currentData()
        protocol = PortScanProtocol(str(proto_data))
        threads_count = self._threads_spinbox.value()
        timeout_seconds = self._timeout_spinbox.value() / 1000.0
        grab_banners = self._banner_checkbox.isChecked()

        configuration = PortScanConfiguration(
            target_host=target_host,
            target_ip=target_ip,
            ports=parsed_ports,
            protocol=protocol,
            timeout_seconds=timeout_seconds,
            threads=threads_count,
            grab_banner=grab_banners,
        )

        self._clear_results()
        self._progress_bar.setValue(0)
        self._metrics_label.setText(f'Starting scan of {len(parsed_ports)} ports on {target_host} ({target_ip})…')

        self._start_stop_button.setText(' Stop Scan')
        self._start_stop_button.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'stop.svg')))
        self._start_stop_button.setStyleSheet(DIALOG_DANGER_BUTTON_STYLESHEET)
        self._target_input.setEnabled(False)
        self._preset_combo.setEnabled(False)
        self._ports_input.setEnabled(False)
        self._protocol_combo.setEnabled(False)
        self._threads_spinbox.setEnabled(False)
        self._timeout_spinbox.setEnabled(False)
        self._banner_checkbox.setEnabled(False)

        self._worker_thread = PortScannerWorkerThread(configuration)
        self._worker_thread.result_found.connect(self._on_result_received)
        self._worker_thread.scan_progress.connect(self._on_progress_updated)
        self._worker_thread.scan_complete.connect(self._on_worker_finished)
        self._worker_thread.start()

    def stop_scan(self) -> None:
        """Abort the active port scan."""
        active_worker = self._worker_thread
        if active_worker is not None and active_worker.isRunning():
            active_worker.cancel()
            active_worker.wait(2000)
        self._on_worker_finished()

    def _toggle_start_stop(self) -> None:
        """Toggle between starting and stopping the scan."""
        if not self.is_running:
            self.start_scan()
            return
        self.stop_scan()

    def _on_worker_finished(self) -> None:
        """Restore control states upon worker thread completion."""
        self._worker_thread = None
        self._start_stop_button.setText(' Start Scan')
        self._start_stop_button.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'play.svg')))
        self._start_stop_button.setStyleSheet(DIALOG_PRIMARY_BUTTON_STYLESHEET)
        self._target_input.setEnabled(True)
        self._preset_combo.setEnabled(True)
        self._ports_input.setEnabled(True)
        self._protocol_combo.setEnabled(True)
        self._threads_spinbox.setEnabled(True)
        self._timeout_spinbox.setEnabled(True)
        self._banner_checkbox.setEnabled(True)
        if self._column_resizer.custom_widths is None:
            self._setup_column_resizing()

    def _on_progress_updated(
        self,
        completed_probes: int,
        total_probes: int,
        open_count: int,
        elapsed_seconds: float,
        speed_ports_per_sec: float,
    ) -> None:
        """Update live progress bar and scan rate metrics."""
        percentage = int((completed_probes / total_probes) * 100) if total_probes > 0 else 0
        self._progress_bar.setValue(percentage)
        duration_minutes = int(elapsed_seconds) // 60
        duration_remainder_seconds = int(elapsed_seconds) % 60
        duration_string = f'{duration_minutes:02d}:{duration_remainder_seconds:02d}'

        self._metrics_label.setText(
            f'Scanned: {completed_probes} / {total_probes} ({percentage}%) | '
            f'Open: <b style="color: #2ecc71;">{open_count}</b> | '
            f'Speed: {speed_ports_per_sec:.0f} ports/s | '
            f'Elapsed: {duration_string}',
        )

    def _on_result_received(self, result_object: object) -> None:
        """Append a newly discovered port probe result to the table."""
        result = ensure_instance(result_object, PortScanResult)
        self._results.append(result)

        if self._show_open_only_checkbox.isChecked() and result.state != PortScanState.OPEN:
            return

        self._add_row_for_result(result)

    def _add_row_for_result(self, result: PortScanResult) -> None:
        """Construct and insert a table row for a probe result."""
        row = self._results_table.rowCount()
        self._results_table.insertRow(row)

        port_item = QTableWidgetItem(str(result.port))
        port_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

        protocol_item = QTableWidgetItem(result.protocol)
        protocol_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

        state_item = QTableWidgetItem(result.state.value)
        state_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        if result.state == PortScanState.OPEN:
            state_item.setForeground(Qt.GlobalColor.green)
        elif result.state == PortScanState.CLOSED:
            state_item.setForeground(Qt.GlobalColor.red)
        else:
            state_item.setForeground(Qt.GlobalColor.yellow)

        service_item = QTableWidgetItem(result.service_name)
        latency_text = f'{result.latency_ms:.1f}' if result.latency_ms is not None else '-'
        latency_item = QTableWidgetItem(latency_text)
        latency_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

        banner_text = result.banner or ''
        banner_item = QTableWidgetItem(banner_text)

        self._results_table.setItem(row, _COLUMN_PORT, port_item)
        self._results_table.setItem(row, _COLUMN_PROTOCOL, protocol_item)
        self._results_table.setItem(row, _COLUMN_STATE, state_item)
        self._results_table.setItem(row, _COLUMN_SERVICE, service_item)
        self._results_table.setItem(row, _COLUMN_LATENCY, latency_item)
        self._results_table.setItem(row, _COLUMN_BANNER, banner_item)

    def _apply_table_filter(self) -> None:
        """Re-render the table according to the current open-only filter."""
        self._results_table.setRowCount(0)
        show_open_only = self._show_open_only_checkbox.isChecked()
        for result in self._results:
            if show_open_only and result.state != PortScanState.OPEN:
                continue
            self._add_row_for_result(result)
        if self._column_resizer.custom_widths is None:
            self._setup_column_resizing()

    def _copy_selected_rows(self) -> None:
        """Copy selected table rows to the clipboard as tab-separated values."""
        selected_ranges = self._results_table.selectedRanges()
        if not selected_ranges:
            return

        lines: list[str] = []
        for selection_range in selected_ranges:
            for row in range(selection_range.topRow(), selection_range.bottomRow() + 1):
                row_values: list[str] = []
                for col in range(_TOTAL_COLUMNS):
                    item = self._results_table.item(row, col)
                    row_values.append(item.text() if item else '')
                lines.append('\t'.join(row_values))

        if lines:
            set_clipboard_text('\n'.join(lines))

    def _copy_all_open(self) -> None:
        """Copy all open ports to the clipboard as a comma-separated list."""
        open_ports = [str(r.port) for r in self._results if r.state == PortScanState.OPEN]
        if open_ports:
            set_clipboard_text(', '.join(open_ports))

    def _export_results(self) -> None:
        """Export current scan results to a CSV or text file."""
        if not self._results:
            QMessageBox.information(self, 'No Results', 'There are no scan results to export.')
            return

        export_filter = 'CSV Files (*.csv);;Text Files (*.txt)'
        file_path, _ = QFileDialog.getSaveFileName(self, 'Export Scan Results', f'port_scan_{self.target}.csv', export_filter)
        if not file_path:
            return

        is_csv = file_path.lower().endswith('.csv')
        try:
            with Path(file_path).open('w', newline='', encoding='utf-8') as file:
                if is_csv:
                    writer = csv.writer(file)
                    writer.writerow(['Port', 'Protocol', 'State', 'Service', 'Latency (ms)', 'Banner'])
                    for result in self._results:
                        writer.writerow(
                            [
                                result.port,
                                result.protocol,
                                result.state.value,
                                result.service_name,
                                f'{result.latency_ms:.1f}' if result.latency_ms is not None else '',
                                result.banner or '',
                            ]
                        )
                else:
                    file.write(f'Port Scan Results for {self.target}\n')
                    file.write('=' * 60 + '\n')
                    for result in self._results:
                        latency_str = f' ({result.latency_ms:.1f}ms)' if result.latency_ms is not None else ''
                        banner_str = f' - {result.banner}' if result.banner else ''
                        file.write(f'{result.port}/{result.protocol}: {result.state.value} [{result.service_name}]{latency_str}{banner_str}\n')
            QMessageBox.information(self, 'Export Complete', f'Saved {len(self._results)} port scan records to:\n{file_path}')
        except OSError as error:
            QMessageBox.warning(self, 'Export Failed', f'Failed to write scan results file:\n{error}')

    def _clear_results(self) -> None:
        """Clear all stored scan results and empty the table."""
        self._results.clear()
        self._results_table.setRowCount(0)

    @override
    def resizeEvent(self, a0: QResizeEvent) -> None:
        """Adjust column widths when the tab widget is resized."""
        super().resizeEvent(a0)
        self._setup_column_resizing()

    @override
    def showEvent(self, a0: QShowEvent) -> None:
        """Adjust column widths when the tab widget is shown."""
        super().showEvent(a0)
        self._setup_column_resizing()

    def _setup_column_resizing(self) -> None:
        """Apply smart column resizing to the results table."""
        self._column_resizer.setup_column_resizing()

    def _reset_column_sizes(self) -> None:
        """Reset column widths back to their initial default layout."""
        self._column_resizer.reset_column_sizes()
        self._progress_bar.setValue(0)
        self._metrics_label.setText('Results cleared.')

    def _show_table_context_menu(self, position: QPoint) -> None:
        """Display right-click context menu on table items."""
        selected_items = self._results_table.selectedItems()
        if not selected_items:
            return

        current_row = self._results_table.currentRow()
        if current_row < 0:
            return

        port_item = self._results_table.item(current_row, _COLUMN_PORT)
        proto_item = self._results_table.item(current_row, _COLUMN_PROTOCOL)
        if not port_item:
            return

        port_str = port_item.text()
        proto_str = proto_item.text() if proto_item else 'TCP'
        port_num = int(port_str) if port_str.isdigit() else 0

        menu = QMenu(self)
        menu.setStyleSheet(SVG_ICON_CONTEXT_MENU_STYLESHEET)

        copy_port_action = menu.addAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg')), f'Copy Port ({port_str})')
        copy_port_action.triggered.connect(lambda: set_clipboard_text(port_str))

        target_host = self.target
        copy_target_port_action = menu.addAction(
            QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg')),
            f'Copy {target_host}:{port_str}',
        )
        copy_target_port_action.triggered.connect(lambda: set_clipboard_text(f'{target_host}:{port_str}'))

        menu.addSeparator()

        ping_action = menu.addAction(
            QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'play.svg')),
            f'Ping {target_host}:{port_str} ({proto_str})',
        )

        def _do_ping_port() -> None:
            mode = PingMode.UDP if proto_str == 'UDP' else PingMode.TCP
            PingWindow.open_window(target_host, mode=mode, port=int(port_str))

        ping_action.triggered.connect(_do_ping_port)

        if port_num in (80, 443, 8000, 8080, 8443, 8888, 3000, 5000, 9090):
            url_scheme = 'https' if port_num in (443, 8443) else 'http'
            browser_url = f'{url_scheme}://{target_host}:{port_num}'
            open_browser_action = menu.addAction(
                QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'website.svg')),
                f'Open in Browser ({browser_url})',
            )
            open_browser_action.triggered.connect(lambda: webbrowser.open(browser_url))

        global_position = self._results_table.viewport().mapToGlobal(position)
        menu.exec(global_position)


class PortScannerWindow(QWidget):
    """Modeless multi-target window providing concurrent TCP and UDP port scanning."""

    _instance: PortScannerWindow | None = None

    def __init__(self, targets: str | list[str] | None = None, *, ports_preset: str = 'Top 100 Common') -> None:
        """Initialize the Port Scanner window."""
        super().__init__(None, Qt.WindowType.Window)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self.destroyed.connect(lambda: setattr(PortScannerWindow, '_instance', None) if PortScannerWindow._instance is self else None)
        self.setWindowTitle(f'{TITLE} - Port Scanner')
        self.setWindowIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'port_scanner.svg')))
        self.resize(scale_by_ui(920), scale_by_ui(640))

        window_layout = QVBoxLayout(self)
        window_layout.setContentsMargins(10, 10, 10, 10)
        window_layout.setSpacing(8)

        self._tab_widget = QTabWidget()
        self._tab_widget.setTabsClosable(True)
        self._tab_widget.tabCloseRequested.connect(self._close_tab)
        window_layout.addWidget(self._tab_widget, stretch=1)

        window_layout.addLayout(self._build_footer_action_bar())

        if targets is None:
            target_items: list[str | None] = [None]
        elif isinstance(targets, str):
            target_items = [targets]
        else:
            target_items = list(targets)

        for target_name in target_items:
            self.add_target_tab(target_name, ports_preset=ports_preset, auto_start=False)

    def _build_footer_action_bar(self) -> QHBoxLayout:
        bar_layout = QHBoxLayout()
        bar_layout.setContentsMargins(4, 4, 4, 4)
        bar_layout.setSpacing(8)

        scan_all_btn = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'play.svg')), ' Scan All')
        scan_all_btn.setStyleSheet(DIALOG_PRIMARY_BUTTON_STYLESHEET)
        scan_all_btn.clicked.connect(self.start_all_tabs)

        stop_all_btn = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'stop.svg')), ' Stop All')
        stop_all_btn.setStyleSheet(DIALOG_DANGER_BUTTON_STYLESHEET)
        stop_all_btn.clicked.connect(self.stop_all_tabs)

        add_target_btn = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'add.svg')), ' Add Target…')
        add_target_btn.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        add_target_btn.clicked.connect(self._prompt_add_target)

        close_btn = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'close.svg')), ' Close')
        close_btn.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        close_btn.clicked.connect(self.close)

        bar_layout.addWidget(scan_all_btn)
        bar_layout.addWidget(stop_all_btn)
        bar_layout.addWidget(add_target_btn)
        bar_layout.addStretch()
        bar_layout.addWidget(close_btn)
        return bar_layout

    @classmethod
    def open_window(
        cls,
        targets: str | list[str] | None = None,
        *,
        ports_preset: str = 'Top 100 Common',
    ) -> PortScannerWindow:
        """Open or reuse the active PortScannerWindow and bring it to foreground."""
        active_window = cls._instance
        if active_window is None:
            active_window = cls(targets, ports_preset=ports_preset)
            cls._instance = active_window
        elif targets is not None:
            targets_list = [targets] if isinstance(targets, str) else list(targets)
            for target_host in targets_list:
                active_window.add_target_tab(target_host, ports_preset=ports_preset, auto_start=False)

        active_window.show()
        active_window.raise_()
        active_window.activateWindow()
        return active_window

    @classmethod
    def close_window(cls) -> None:
        """Close the active PortScannerWindow if one is open."""
        active_window = cls._instance
        if active_window is not None:
            active_window.close()

    def add_target_tab(
        self,
        target: str | None = None,
        *,
        ports_preset: str = 'Top 100 Common',
        auto_start: bool = False,
    ) -> None:
        """Add a new target scanning tab or focus existing tab for this target."""
        normalized_target = target.strip() if target is not None else ''
        effective_target = normalized_target if normalized_target and normalized_target != _DEFAULT_TARGET else _DEFAULT_TARGET

        for i in range(self._tab_widget.count()):
            tab = self._tab_widget.widget(i)
            if isinstance(tab, PortScannerTabWidget) and tab.target == effective_target:
                self._tab_widget.setCurrentIndex(i)
                if auto_start and not tab.is_running:
                    tab.start_scan()
                return

        tab_page = PortScannerTabWidget(normalized_target or None, ports_preset=ports_preset, tab_widget=self._tab_widget, parent=self._tab_widget)
        new_index = self._tab_widget.addTab(tab_page, tab_page.target)
        self._tab_widget.setCurrentIndex(new_index)

        if auto_start:
            tab_page.start_scan()

    def start_all_tabs(self) -> None:
        """Trigger scan on all open tabs."""
        for i in range(self._tab_widget.count()):
            tab = self._tab_widget.widget(i)
            if isinstance(tab, PortScannerTabWidget):
                tab.start_scan()

    def stop_all_tabs(self) -> None:
        """Stop scanning on all open tabs."""
        for i in range(self._tab_widget.count()):
            tab = self._tab_widget.widget(i)
            if isinstance(tab, PortScannerTabWidget):
                tab.stop_scan()

    def _close_tab(self, index: int) -> None:
        """Stop scan on a tab and close it."""
        target_tab = self._tab_widget.widget(index)
        if isinstance(target_tab, PortScannerTabWidget):
            target_tab.stop_scan()
        self._tab_widget.removeTab(index)
        if not self._tab_widget.count():
            self.close()

    def _prompt_add_target(self) -> None:
        """Prompt user for a new IP address or hostname to scan."""
        dialog_title = 'Add Port Scan Target'
        dialog_prompt = 'Enter target IPv4 address or hostname to scan:'
        new_target, success = QInputDialog.getText(self, dialog_title, dialog_prompt)
        if success and new_target.strip():
            self.add_target_tab(new_target.strip(), auto_start=False)

    @override
    def closeEvent(self, event: QCloseEvent) -> None:
        """Stop all workers before closing window."""
        self.stop_all_tabs()
        super().closeEvent(event)
