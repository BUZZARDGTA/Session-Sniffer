"""User-friendly dialog for selecting a running game or application to sniff."""

import html
import re
from typing import override

from PySide6.QtCore import QPoint, QSignalBlocker, QSize, Qt
from PySide6.QtGui import QAction, QIcon, QKeySequence, QResizeEvent, QShortcut, QShowEvent
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMenu,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.capture.process import (
    get_process_image_path,
    get_running_applications,
    is_process_running,
    matches_process_name,
)
from session_sniffer.constants.local import RESOURCES_DIR_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.constants.tables import (
    DEFAULT_MIN_COLUMN_WIDTH,
    TARGET_PROCESS_TABLE_MIN_COLUMN_WIDTHS,
)
from session_sniffer.guis.delegates import SearchHighlightDelegate
from session_sniffer.guis.stylesheets import SVG_ICON_CONTEXT_MENU_STYLESHEET
from session_sniffer.guis.table_column_resizing import TableColumnResizeController, setup_table_header_context_menu
from session_sniffer.guis.utils import (
    apply_search_icon,
    get_process_icon,
    scale_by_ui,
    set_clipboard_text,
)
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings import Settings


class TargetProcessDialog(QDialog):
    """User-friendly dialog allowing users to pick a running game or application to sniff."""

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        initial_pid: int | None = None,
        initial_process_name: str | None = None,
        initial_track_by_name: bool | None = None,
    ) -> None:
        """Initialize the target process selection dialog."""
        super().__init__(parent)
        self.selected_pid: int = Settings.capture_filter_process_pid if initial_pid is None else initial_pid
        self.selected_process_name: str | None = (
            Settings.capture_filter_process_name if initial_pid is None and initial_process_name is None else initial_process_name
        )
        self.selected_track_by_name: bool = (
            Settings.capture_filter_process_track_by_name if initial_track_by_name is None else initial_track_by_name
        )
        self.setWindowTitle(f'{TITLE} - Select Game or Application to Sniff')
        self.setMinimumSize(scale_by_ui(800), scale_by_ui(520))

        main_layout = QVBoxLayout(self)

        # Status banner
        self._status_label = QLabel()
        self._status_label.setTextFormat(Qt.TextFormat.RichText)
        self._status_label.setStyleSheet('padding: 8px; background-color: rgba(255, 255, 255, 0.05); border-radius: 4px;')
        main_layout.addWidget(self._status_label)

        # Search bar and filter controls
        search_layout = QHBoxLayout()
        search_label = QLabel('Search:')
        self._search_input = QLineEdit()
        self._search_input.setPlaceholderText('Type to filter games or applications (e.g. GTA, Call of Duty, Discord)...')
        self._search_input.textChanged.connect(self._filter_process_list)
        apply_search_icon(self._search_input)
        search_layout.addWidget(search_label)
        search_layout.addWidget(self._search_input)

        refresh_icon = QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'refresh-cw.svg'))
        refresh_button = QPushButton(refresh_icon, ' Refresh')
        refresh_button.setToolTip('Refresh the list of currently running processes')
        refresh_button.clicked.connect(self._populate_process_table)
        search_layout.addWidget(refresh_button)
        main_layout.addLayout(search_layout)

        # Options
        options_layout = QVBoxLayout()
        options_layout.setSpacing(scale_by_ui(4))
        self._user_apps_only_checkbox = QCheckBox('Show user applications and games only (hide background system services)')
        self._user_apps_only_checkbox.setChecked(True)
        self._user_apps_only_checkbox.toggled.connect(self._populate_process_table)
        options_layout.addWidget(self._user_apps_only_checkbox)

        self._track_by_name_checkbox = QCheckBox('Track target process by executable name (auto-detect restarts / editions)')
        self._track_by_name_checkbox.setToolTip(
            'Keep tracking the selected process name instead of a static PID. '
            'Automatically re-detects the process when restarted and switches seamlessly between GTA V editions.',
        )
        self._track_by_name_checkbox.setChecked(self.selected_track_by_name)
        self._track_by_name_checkbox.toggled.connect(self._on_track_by_name_toggled)
        options_layout.addWidget(self._track_by_name_checkbox)

        main_layout.addLayout(options_layout)

        # Main process table
        self._table = QTableWidget()
        self._table.setColumnCount(3)
        self._table.setHorizontalHeaderLabels(('Application / Process Name', 'PID', 'Executable Path'))
        self._table.verticalHeader().setVisible(False)
        self._table.setIconSize(QSize(scale_by_ui(18), scale_by_ui(18)))
        self._table.setWordWrap(False)
        self._table.setTextElideMode(Qt.TextElideMode.ElideRight)
        self._table.setItemDelegate(SearchHighlightDelegate(self._table, self._search_input.text))
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setVerticalScrollMode(QTableWidget.ScrollMode.ScrollPerPixel)
        self._table.setHorizontalScrollMode(QTableWidget.ScrollMode.ScrollPerPixel)
        self._table.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._show_table_context_menu)
        self._column_resizer: TableColumnResizeController = TableColumnResizeController(
            self._table,
            min_column_widths=TARGET_PROCESS_TABLE_MIN_COLUMN_WIDTHS,
        )
        setup_table_header_context_menu(self._table, on_reset=self._column_resizer.reset_column_sizes)
        header = self._table.horizontalHeader()
        header.setStretchLastSection(False)
        header.setMinimumSectionSize(scale_by_ui(DEFAULT_MIN_COLUMN_WIDTH))
        header.sectionResized.connect(self._column_resizer.on_section_resized)
        QShortcut(QKeySequence('Ctrl+C'), self._table).activated.connect(self._copy_selected_row)
        self._table.itemDoubleClicked.connect(self._on_table_row_double_clicked)
        self._table.itemSelectionChanged.connect(self._on_table_selection_changed)
        main_layout.addWidget(self._table)

        # Manual PID disclosure (collapsible / advanced)
        self._manual_container = QWidget()
        manual_layout = QHBoxLayout(self._manual_container)
        manual_layout.setContentsMargins(0, 0, 0, 0)
        manual_label = QLabel('Manual PID Entry (Advanced):')
        self._pid_spinbox = QSpinBox()
        self._pid_spinbox.setRange(0, 4194304)
        self._pid_spinbox.setSpecialValueText('Disabled')
        self._pid_spinbox.setValue(self.selected_pid)
        self._pid_spinbox.valueChanged.connect(self._on_manual_pid_changed)
        manual_layout.addWidget(manual_label)
        manual_layout.addWidget(self._pid_spinbox)
        manual_layout.addStretch()
        self._manual_container.setVisible(False)

        self._show_manual_checkbox = QCheckBox('Show manual PID entry (advanced)')
        self._show_manual_checkbox.toggled.connect(self._on_show_manual_toggled)
        main_layout.addWidget(self._show_manual_checkbox)
        main_layout.addWidget(self._manual_container)

        # Bottom action buttons
        action_layout = QHBoxLayout()

        action_layout.addStretch()

        target_icon = QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'target.svg'))
        self._sniff_selected_button = QPushButton(target_icon, ' Sniff Selected Process')
        self._sniff_selected_button.setEnabled(False)
        self._sniff_selected_button.setStyleSheet('font-weight: bold; padding: 6px 16px;')
        self._sniff_selected_button.clicked.connect(self._on_sniff_selected_clicked)
        action_layout.addWidget(self._sniff_selected_button)

        cancel_button = QPushButton('Cancel')
        cancel_button.clicked.connect(self.reject)
        action_layout.addWidget(cancel_button)

        main_layout.addLayout(action_layout)

        self._cached_processes: list[tuple[int, str, str]] = []
        self._user_selected_pid: int | None = None
        self._user_selected_name: str | None = None
        self._manual_pid_entered: bool = False
        if not CaptureState.is_local_capture():
            self._table.setEnabled(False)
            self._pid_spinbox.setEnabled(False)
            self._track_by_name_checkbox.setEnabled(False)
            self._sniff_selected_button.setEnabled(False)
        self._populate_process_table()

    def _update_status_label(self) -> None:
        """Update the status label describing the dialog's target process filter state."""
        if not CaptureState.is_local_capture():
            self._status_label.setText(
                '<b>Status:</b> Process PID sniffing is <span style="color: #f44336; font-weight: bold;">DISABLED</span> '
                'when capturing an external device (ARP spoofing / neighbour capture).',
            )
            return

        current_pid = self.selected_pid
        track_by_name = self.selected_track_by_name
        tracked_name = self.selected_process_name

        if current_pid <= 0 and not (track_by_name and tracked_name is not None):
            self._status_label.setText('<b>Status:</b> Currently sniffing <b>ALL network traffic</b> (no process filter active).')
            return

        matched_pid, matched_name = self._resolve_running_target(current_pid, tracked_name, track_by_name=track_by_name)
        is_running = matched_pid > 0
        display_pid = matched_pid if is_running else current_pid
        process_name = html.escape(matched_name or tracked_name or 'Unknown Process')

        if is_running:
            status_badge = '<span style="color: #4CAF50; font-weight: bold;">● RUNNING</span>'
            pid_info = f' (PID: {display_pid})' if display_pid > 0 else ''
            mode_info = ' [Tracking by Name]' if track_by_name else ''
            self._status_label.setText(f'<b>Status:</b> Exclusively sniffing <b>{process_name}</b>{pid_info}{mode_info} — {status_badge}')
        else:
            status_badge = '<span style="color: #f44336; font-weight: bold;">● NOT RUNNING</span>'
            if track_by_name and tracked_name is not None:
                self._status_label.setText(
                    f'<b>Status:</b> Exclusively tracking <b>{html.escape(tracked_name)}</b> by name — {status_badge} (waiting to launch)',
                )
            else:
                pid_info = f' (PID: {display_pid})' if display_pid > 0 else ''
                self._status_label.setText(f'<b>Status:</b> Exclusively sniffing <b>{process_name}</b>{pid_info} — {status_badge}')

    def _resolve_running_target(
        self,
        target_pid: int,
        target_name: str | None,
        *,
        track_by_name: bool,
    ) -> tuple[int, str | None]:
        """Resolve whether the dialog's target process is currently running."""
        if target_pid > 0:
            for pid, name, _ in self._cached_processes:
                if pid == target_pid:
                    if target_name is None or matches_process_name(name, target_name):
                        return pid, name
                    break
            if is_process_running(target_pid):
                image_path = get_process_image_path(target_pid)
                actual_name = image_path.name if image_path is not None else None
                if (
                    target_name is None
                    or (actual_name is not None and matches_process_name(actual_name, target_name))
                ):
                    return target_pid, (actual_name or target_name)

        if track_by_name and target_name is not None:
            for pid, name, _ in self._cached_processes:
                if matches_process_name(name, target_name):
                    return pid, name
            if self._user_apps_only_checkbox.isChecked():
                for pid, name, _ in get_running_applications(user_apps_only=False):
                    if matches_process_name(name, target_name):
                        return pid, name
            if (
                target_name == Settings.capture_filter_process_name
                and CaptureState.target_process_running
                and Settings.capture_filter_process_pid > 0
                and is_process_running(Settings.capture_filter_process_pid)
            ):
                return Settings.capture_filter_process_pid, CaptureState.target_process_name or target_name

        return 0, None

    @staticmethod
    def _process_sort_key(item: tuple[int, str, str], normalized_query: str) -> tuple[int, str, int]:
        """Compute sorting priority and tie-breaker for process matching."""
        pid, name, _exe_path = item
        name_lower = name.lower()
        pid_string = str(pid)
        if name_lower in (normalized_query, f'{normalized_query}.exe'):
            priority = 0
        elif name_lower.startswith(normalized_query):
            priority = 1
        elif any(part.startswith(normalized_query) for part in re.split(r'[\s._\-]+', name_lower)):
            priority = 2
        elif normalized_query in name_lower:
            priority = 3
        elif pid_string.startswith(normalized_query):
            priority = 4
        else:
            priority = 5
        return (priority, name_lower, pid)

    def _effective_tracked_process_name(self) -> str | None:
        """Return the process name currently selected or configured for name-based tracking."""
        if self._manual_pid_entered:
            return None
        if self._user_selected_pid is not None:
            return self._user_selected_name
        return self.selected_process_name

    def _populate_process_table(self) -> None:
        """Populate the process table with running applications and games."""
        user_apps_only = self._user_apps_only_checkbox.isChecked()
        self._cached_processes = get_running_applications(user_apps_only=user_apps_only)
        if self._user_selected_pid is not None and all(pid != self._user_selected_pid for pid, _, _ in self._cached_processes):
            previous_selected_name = self._user_selected_name
            self._user_selected_pid = 0
            self._user_selected_name = None
            if previous_selected_name is not None and self._track_by_name_checkbox.isChecked():
                matched_pid, matched_name = self._resolve_running_target(
                    0,
                    previous_selected_name,
                    track_by_name=True,
                )
                if matched_pid > 0 and any(pid == matched_pid for pid, _, _ in self._cached_processes):
                    self._user_selected_pid = matched_pid
                    self._user_selected_name = matched_name or previous_selected_name
                else:
                    self._user_selected_name = previous_selected_name
                    self.selected_pid = 0
                    self.selected_process_name = previous_selected_name
        self._update_status_label()
        self._filter_process_list(self._search_input.text())
        self._column_resizer.setup_column_resizing()

    def _filter_process_list(self, filter_text: str) -> None:
        """Filter and sort table rows according to the search query."""
        normalized_query = filter_text.strip().lower()

        if normalized_query:
            matching_processes: list[tuple[int, str, str]] = [
                process for process in self._cached_processes if normalized_query in process[1].lower() or normalized_query in str(process[0])
            ]
            matching_processes.sort(key=lambda process: self._process_sort_key(process, normalized_query))
        else:
            matching_processes = list(self._cached_processes)

        current_target_pid = self.selected_pid
        track_by_name = self.selected_track_by_name
        target_name = self.selected_process_name
        has_tracked_target_name = track_by_name and target_name is not None
        active_target_pid = 0
        if current_target_pid > 0 or has_tracked_target_name:
            active_target_pid, _ = self._resolve_running_target(
                current_target_pid,
                target_name,
                track_by_name=has_tracked_target_name,
            )
        selected_row_to_restore: int | None = None
        active_target_row: int | None = None

        self._table.setUpdatesEnabled(False)
        with QSignalBlocker(self._table):
            self._table.setRowCount(0)
            self._table.setRowCount(len(matching_processes))

            for row_index, (pid, name, exe_path) in enumerate(matching_processes):
                name_item = QTableWidgetItem(name)
                name_item.setData(Qt.ItemDataRole.UserRole, pid)
                name_item.setData(Qt.ItemDataRole.UserRole + 1, name)
                name_item.setIcon(get_process_icon(exe_path))

                pid_item = QTableWidgetItem(str(pid))
                pid_item.setToolTip(f'{name} (PID: {pid})')
                path_item = QTableWidgetItem(exe_path)
                if exe_path:
                    path_item.setToolTip(exe_path)

                is_active_target = 0 < active_target_pid == pid

                if is_active_target:
                    active_target_row = row_index
                    name_item.setText(f'{name} (Active Target)')
                    name_item.setToolTip(
                        f'{name} (PID: {pid}) - Active Target\n{exe_path}' if exe_path else f'{name} (PID: {pid}) - Active Target',
                    )
                elif exe_path:
                    name_item.setToolTip(f'{name} (PID: {pid})\n{exe_path}')
                else:
                    name_item.setToolTip(f'{name} (PID: {pid})')

                self._table.setItem(row_index, 0, name_item)
                self._table.setItem(row_index, 1, pid_item)
                self._table.setItem(row_index, 2, path_item)

                if self._user_selected_pid is not None and pid == self._user_selected_pid:
                    selected_row_to_restore = row_index

            if self._manual_pid_entered:
                row_to_select = None
            elif self._user_selected_pid is not None:
                row_to_select = selected_row_to_restore
            else:
                row_to_select = active_target_row

            if row_to_select is not None:
                self._table.selectRow(row_to_select)
            else:
                self._table.clearSelection()

        self._table.setUpdatesEnabled(True)

        if normalized_query:
            self._table.verticalScrollBar().setValue(0)
        elif row_to_select is not None:
            scroll_target = self._table.item(row_to_select, 0)
            if scroll_target is not None:
                self._table.scrollToItem(scroll_target)

        has_selection = bool(self._table.selectedItems())
        if has_selection:
            selected_row = self._table.selectedItems()[0].row()
            selected_name_item = self._table.item(selected_row, 0)
            if selected_name_item is not None:
                pid_value = selected_name_item.data(Qt.ItemDataRole.UserRole)
                if isinstance(pid_value, int):
                    with QSignalBlocker(self._pid_spinbox):
                        self._pid_spinbox.setValue(pid_value)
        elif not self._manual_pid_entered:
            fallback_pid = 0
            if not normalized_query:
                if self._user_selected_pid is not None and self._user_selected_pid > 0:
                    fallback_pid = self._user_selected_pid
                elif self._user_selected_pid is None:
                    fallback_pid, _ = self._resolve_running_target(
                        self.selected_pid,
                        self.selected_process_name,
                        track_by_name=self.selected_track_by_name,
                    )
                    if (
                        not fallback_pid
                        and not (self._track_by_name_checkbox.isChecked() and self.selected_process_name is not None)
                        and self.selected_pid > 0
                    ):
                        fallback_pid = self.selected_pid
            with QSignalBlocker(self._pid_spinbox):
                self._pid_spinbox.setValue(fallback_pid)
        self._update_sniff_button_state()

        self._table.viewport().update()

    def _update_sniff_button_state(self) -> None:
        """Enable or disable the confirm button based on current dialog selection state."""
        has_selection = bool(self._table.selectedItems())
        has_pid = self._pid_spinbox.value() > 0
        has_tracked_name = (
            self._track_by_name_checkbox.isChecked()
            and self._effective_tracked_process_name() is not None
            and (has_selection or not self._search_input.text().strip())
        )
        self._sniff_selected_button.setEnabled(
            (has_selection or has_pid or has_tracked_name) and CaptureState.is_local_capture(),
        )

    def _on_show_manual_toggled(self) -> None:
        """Toggle visibility of manual PID entry and reset manual state when hidden."""
        is_checked = self._show_manual_checkbox.isChecked()
        self._manual_container.setVisible(is_checked)
        if not is_checked and self._manual_pid_entered:
            self._manual_pid_entered = False
            self._filter_process_list(self._search_input.text())

    def _on_manual_pid_changed(self, _pid_value: int) -> None:
        """Clear table selection and update button state when a manual PID is entered."""
        self._manual_pid_entered = True
        self._user_selected_pid = None
        self._user_selected_name = None
        with QSignalBlocker(self._table):
            self._table.clearSelection()
        self._update_sniff_button_state()

    def _on_table_selection_changed(self) -> None:
        """Handle row selection change to update buttons and spinbox."""
        selected_items = self._table.selectedItems()
        has_selection = bool(selected_items)
        self._manual_pid_entered = False
        if has_selection:
            selected_row = selected_items[0].row()
            name_item = self._table.item(selected_row, 0)
            if name_item is not None:
                pid_value = name_item.data(Qt.ItemDataRole.UserRole)
                name_value = name_item.data(Qt.ItemDataRole.UserRole + 1)
                if isinstance(pid_value, int):
                    self._user_selected_pid = pid_value
                    self._user_selected_name = str(name_value) if name_value else None
                    with QSignalBlocker(self._pid_spinbox):
                        self._pid_spinbox.setValue(pid_value)
        else:
            self._user_selected_pid = 0
            self._user_selected_name = None
            with QSignalBlocker(self._pid_spinbox):
                self._pid_spinbox.setValue(0)
        self._update_sniff_button_state()

    def _on_table_row_double_clicked(self, item: QTableWidgetItem) -> None:
        """Double-clicking any process selects it immediately."""
        name_item = self._table.item(item.row(), 0)
        if name_item is not None:
            pid_value = name_item.data(Qt.ItemDataRole.UserRole)
            name_value = name_item.data(Qt.ItemDataRole.UserRole + 1)
            if isinstance(pid_value, int):
                self._apply_selection(pid_value, str(name_value) if name_value else None)
                self.accept()

    def _on_sniff_selected_clicked(self) -> None:
        """Sniff the currently selected process in the table."""
        if self._manual_container.isVisible() and self._pid_spinbox.hasFocus():
            self._apply_selection(self._pid_spinbox.value())
            self.accept()
            return

        selected_items = self._table.selectedItems()
        if selected_items:
            selected_row = selected_items[0].row()
            name_item = self._table.item(selected_row, 0)
            if name_item is not None:
                pid_value = name_item.data(Qt.ItemDataRole.UserRole)
                name_value = name_item.data(Qt.ItemDataRole.UserRole + 1)
                if isinstance(pid_value, int):
                    self._apply_selection(pid_value, str(name_value) if name_value else None)
                    self.accept()
                    return

        # Fallback to spinbox value
        self._apply_selection(self._pid_spinbox.value())
        self.accept()

    def _apply_selection(self, pid: int, process_name: str | None = None) -> None:
        """Store target process selection on the dialog instance."""
        if not CaptureState.is_local_capture():
            return
        track_by_name = self._track_by_name_checkbox.isChecked()
        if process_name is None:
            if pid > 0:
                for cached_pid, cached_name, _ in self._cached_processes:
                    if cached_pid == pid:
                        process_name = cached_name
                        break
                if process_name is None:
                    image_path = get_process_image_path(pid)
                    if image_path is not None:
                        process_name = image_path.name
            if process_name is None and not self._manual_pid_entered:
                process_name = self._effective_tracked_process_name()
        self.selected_pid = pid
        self.selected_process_name = process_name if (pid > 0 or track_by_name) else None
        self.selected_track_by_name = track_by_name and self.selected_process_name is not None

    def _on_track_by_name_toggled(self) -> None:
        """Update track-by-name state and refresh table highlights."""
        is_checked = self._track_by_name_checkbox.isChecked()
        if (
            not is_checked
            and self.selected_track_by_name
            and not self._manual_pid_entered
        ):
            matched_pid, matched_name = self._resolve_running_target(
                self.selected_pid,
                self.selected_process_name,
                track_by_name=True,
            )
            if matched_pid > 0:
                self.selected_pid = matched_pid
                if matched_name is not None:
                    self.selected_process_name = matched_name
            else:
                self.selected_pid = 0
        self.selected_track_by_name = is_checked
        self._update_status_label()
        self._filter_process_list(self._search_input.text())

    @override
    def resizeEvent(self, a0: QResizeEvent) -> None:
        """Adjust column widths when the dialog is resized."""
        super().resizeEvent(a0)
        self._column_resizer.setup_column_resizing()

    @override
    def showEvent(self, a0: QShowEvent) -> None:
        """Handle dialog show event to ensure column widths adapt to actual layout size."""
        super().showEvent(a0)
        self._column_resizer.setup_column_resizing()

    def _copy_selected_row(self) -> None:
        """Copy selected process row details to clipboard as tab-separated values."""
        selected_items = self._table.selectedItems()
        if not selected_items:
            return
        row = selected_items[0].row()
        name_item = self._table.item(row, 0)
        pid_item = self._table.item(row, 1)
        path_item = self._table.item(row, 2)
        raw_name = name_item.data(Qt.ItemDataRole.UserRole + 1) if name_item else None
        process_name = str(raw_name) if raw_name else (name_item.text() if name_item else '')
        pid_str = pid_item.text() if pid_item else ''
        exe_path = path_item.text() if path_item else ''
        set_clipboard_text(f'{process_name}\t{pid_str}\t{exe_path}')

    def _show_table_context_menu(self, position: QPoint) -> None:
        """Show context menu for table rows with copy and column sizing options."""
        index = self._table.indexAt(position)
        if not index.isValid():
            return

        row = index.row()
        item = self._table.item(row, index.column())
        if item is not None and not item.isSelected():
            self._table.clearSelection()
            self._table.selectRow(row)

        name_item = self._table.item(row, 0)
        pid_item = self._table.item(row, 1)
        path_item = self._table.item(row, 2)

        raw_name = name_item.data(Qt.ItemDataRole.UserRole + 1) if name_item else None
        process_name = str(raw_name) if raw_name else (name_item.text() if name_item else '')
        pid_str = pid_item.text() if pid_item else ''
        exe_path = path_item.text() if path_item else ''

        menu = QMenu(self)
        menu.setStyleSheet(SVG_ICON_CONTEXT_MENU_STYLESHEET)
        menu.setToolTipsVisible(True)

        target_icon = QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'target.svg'))
        sniff_action = QAction(target_icon, f"Sniff '{process_name}'", menu)
        sniff_action.setToolTip(f'Select {process_name} (PID: {pid_str}) and filter network capture to it.')
        sniff_action.triggered.connect(self._on_sniff_selected_clicked)
        menu.addAction(sniff_action)

        menu.addSeparator()

        copy_row_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg')), 'Copy Row', menu)
        copy_row_action.setShortcut('Ctrl+C')
        copy_row_action.setToolTip('Copy selected row details to the clipboard.')
        copy_row_action.triggered.connect(self._copy_selected_row)
        menu.addAction(copy_row_action)

        if exe_path:
            copy_path_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg')), 'Copy Executable Path', menu)
            copy_path_action.setToolTip('Copy the full executable path to the clipboard.')
            copy_path_action.triggered.connect(lambda: set_clipboard_text(exe_path))
            menu.addAction(copy_path_action)

        if process_name:
            copy_name_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg')), 'Copy Process Name', menu)
            copy_name_action.setToolTip('Copy the process name to the clipboard.')
            copy_name_action.triggered.connect(lambda: set_clipboard_text(process_name))
            menu.addAction(copy_name_action)

        viewport = self._table.viewport()
        if viewport:
            menu.popup(viewport.mapToGlobal(position))
