"""User-friendly dialog for selecting a running game or application to sniff."""

from typing import override

from PySide6.QtCore import QFileInfo, QPoint, QSize, Qt
from PySide6.QtGui import QAction, QIcon, QKeySequence, QResizeEvent, QShortcut
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QFileIconProvider,
    QHBoxLayout,
    QHeaderView,
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

from session_sniffer.capture.process import get_running_applications
from session_sniffer.capture.process_monitor import ensure_process_monitor_running
from session_sniffer.constants.local import RESOURCES_DIR_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis.stylesheets import SVG_ICON_CONTEXT_MENU_STYLESHEET
from session_sniffer.guis.table_column_resizing import add_column_sizing_actions, setup_table_header_context_menu
from session_sniffer.guis.utils import (
    ElidedTextTooltipDelegate,
    apply_search_icon,
    scale_by_ui,
    set_clipboard_text,
)
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings import Settings


class TargetProcessDialog(QDialog):
    """User-friendly dialog allowing users to pick a running game or application to sniff."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the target process selection dialog."""
        super().__init__(parent)
        self.setWindowTitle(f'{TITLE} - Select Game or Application to Sniff')
        self.setMinimumSize(scale_by_ui(800), scale_by_ui(520))

        main_layout = QVBoxLayout(self)

        # Status banner
        self._status_label = QLabel()
        self._status_label.setTextFormat(Qt.TextFormat.RichText)
        self._status_label.setStyleSheet('padding: 8px; background-color: rgba(255, 255, 255, 0.05); border-radius: 4px;')
        self._update_status_label()
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

        refresh_icon = QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'refresh.svg'))
        refresh_button = QPushButton(refresh_icon, ' Refresh')
        refresh_button.setToolTip('Refresh the list of currently running processes')
        refresh_button.clicked.connect(self._populate_process_table)
        search_layout.addWidget(refresh_button)
        main_layout.addLayout(search_layout)

        # Options row
        options_layout = QHBoxLayout()
        self._user_apps_only_checkbox = QCheckBox('Show user applications and games only (hide background system services)')
        self._user_apps_only_checkbox.setChecked(True)
        self._user_apps_only_checkbox.toggled.connect(self._populate_process_table)
        options_layout.addWidget(self._user_apps_only_checkbox)
        options_layout.addStretch()
        main_layout.addLayout(options_layout)

        # Main process table
        self._table = QTableWidget()
        self._table.setColumnCount(3)
        self._table.setHorizontalHeaderLabels(('Application / Process Name', 'PID', 'Executable Path'))
        self._table.verticalHeader().setVisible(False)
        self._table.setIconSize(QSize(scale_by_ui(18), scale_by_ui(18)))
        self._table.setWordWrap(False)
        self._table.setTextElideMode(Qt.TextElideMode.ElideRight)
        self._table.setItemDelegate(ElidedTextTooltipDelegate(self._table))
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setVerticalScrollMode(QTableWidget.ScrollMode.ScrollPerPixel)
        self._table.setHorizontalScrollMode(QTableWidget.ScrollMode.ScrollPerPixel)
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._show_table_context_menu)
        setup_table_header_context_menu(self._table, on_reset=self._reset_column_sizes)
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
        self._pid_spinbox.setSpecialValueText('Disabled (0)')
        self._pid_spinbox.setValue(Settings.capture_filter_process_pid)
        manual_layout.addWidget(manual_label)
        manual_layout.addWidget(self._pid_spinbox)
        manual_layout.addStretch()
        self._manual_container.setVisible(False)

        self._show_manual_checkbox = QCheckBox('Show manual PID entry (advanced)')
        self._show_manual_checkbox.toggled.connect(self._manual_container.setVisible)
        main_layout.addWidget(self._show_manual_checkbox)
        main_layout.addWidget(self._manual_container)

        # Bottom action buttons
        action_layout = QHBoxLayout()

        globe_icon = QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'globe.svg'))
        disable_button = QPushButton(globe_icon, ' Sniff All Traffic (Disable Filter)')
        disable_button.setToolTip('Remove process filtering and capture all network traffic on the adapter')
        disable_button.clicked.connect(self._on_disable_clicked)
        action_layout.addWidget(disable_button)

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

        self._icon_provider = QFileIconProvider()
        self._icon_cache: dict[str, QIcon] = {}
        self._default_file_icon = self._icon_provider.icon(QFileIconProvider.IconType.File)
        self.selected_pid: int = Settings.capture_filter_process_pid
        self._populate_process_table()

    def _update_status_label(self) -> None:
        """Update the status label describing the active capture filter state."""
        current_pid = Settings.capture_filter_process_pid
        if current_pid <= 0:
            self._status_label.setText('<b>Status:</b> Currently sniffing <b>ALL network traffic</b> (no process filter active).')
        else:
            is_running = CaptureState.target_process_running
            process_name = CaptureState.target_process_name or 'Unknown Process'
            status_badge = (
                '<span style="color: #4CAF50; font-weight: bold;">● RUNNING</span>' if is_running else '<span style="color: #f44336; font-weight: bold;">● NOT RUNNING</span>'
            )
            self._status_label.setText(f'<b>Status:</b> Exclusively sniffing <b>{process_name}</b> (PID: {current_pid}) — {status_badge}')

    def _get_process_icon(self, exe_path: str) -> QIcon:
        """Retrieve and cache the executable icon for a process."""
        if not exe_path:
            return self._default_file_icon

        icon = self._icon_cache.get(exe_path)
        if icon is not None:
            return icon

        file_info = QFileInfo(exe_path)
        if file_info.exists():
            icon = self._icon_provider.icon(file_info)
            if icon.isNull():
                icon = self._default_file_icon
        else:
            icon = self._default_file_icon

        self._icon_cache[exe_path] = icon
        return icon

    def _populate_process_table(self) -> None:
        """Populate the process table with running applications and games."""
        self._table.setRowCount(0)
        user_apps_only = self._user_apps_only_checkbox.isChecked()
        processes = get_running_applications(user_apps_only=user_apps_only)

        self._table.setRowCount(len(processes))
        selected_row_index: int | None = None
        current_target_pid = Settings.capture_filter_process_pid

        for row_index, (pid, name, exe_path) in enumerate(processes):
            name_item = QTableWidgetItem(name)
            name_item.setData(Qt.ItemDataRole.UserRole, pid)
            name_item.setIcon(self._get_process_icon(exe_path))

            pid_item = QTableWidgetItem(str(pid))
            pid_item.setToolTip(f'{name} (PID: {pid})')
            path_item = QTableWidgetItem(exe_path)
            if exe_path:
                path_item.setToolTip(exe_path)

            if pid == current_target_pid:
                selected_row_index = row_index
                name_item.setText(f'{name} (Active Target)')
                name_item.setToolTip(f'{name} (PID: {pid}) - Active Target\n{exe_path}' if exe_path else f'{name} (PID: {pid}) - Active Target')
            elif exe_path:
                name_item.setToolTip(f'{name} (PID: {pid})\n{exe_path}')
            else:
                name_item.setToolTip(f'{name} (PID: {pid})')

            self._table.setItem(row_index, 0, name_item)
            self._table.setItem(row_index, 1, pid_item)
            self._table.setItem(row_index, 2, path_item)

        if selected_row_index is not None:
            self._table.selectRow(selected_row_index)
            scroll_target = self._table.item(selected_row_index, 0)
            if scroll_target is not None:
                self._table.scrollToItem(scroll_target)

        self._filter_process_list(self._search_input.text())
        self._reset_column_sizes()

    def _filter_process_list(self, filter_text: str) -> None:
        """Filter table rows according to the search query."""
        normalized_query = filter_text.strip().lower()
        for row_index in range(self._table.rowCount()):
            if not normalized_query:
                self._table.showRow(row_index)
                continue

            name_item = self._table.item(row_index, 0)
            pid_item = self._table.item(row_index, 1)

            name_text = name_item.text().lower() if name_item else ''
            pid_text = pid_item.text().lower() if pid_item else ''

            if normalized_query in name_text or normalized_query in pid_text:
                self._table.showRow(row_index)
            else:
                self._table.hideRow(row_index)

    def _on_table_selection_changed(self) -> None:
        """Handle row selection change to update buttons and spinbox."""
        selected_items = self._table.selectedItems()
        has_selection = bool(selected_items)
        self._sniff_selected_button.setEnabled(has_selection)

        if has_selection:
            selected_row = selected_items[0].row()
            name_item = self._table.item(selected_row, 0)
            if name_item is not None:
                pid_value = name_item.data(Qt.ItemDataRole.UserRole)
                if isinstance(pid_value, int):
                    self._pid_spinbox.setValue(pid_value)

    def _on_table_row_double_clicked(self, item: QTableWidgetItem) -> None:
        """Double-clicking any process selects it immediately."""
        name_item = self._table.item(item.row(), 0)
        if name_item is not None:
            pid_value = name_item.data(Qt.ItemDataRole.UserRole)
            if isinstance(pid_value, int):
                self._apply_pid(pid_value)
                self.accept()

    def _on_sniff_selected_clicked(self) -> None:
        """Sniff the currently selected process in the table."""
        if self._manual_container.isVisible() and self._pid_spinbox.hasFocus():
            self._apply_pid(self._pid_spinbox.value())
            self.accept()
            return

        selected_items = self._table.selectedItems()
        if selected_items:
            selected_row = selected_items[0].row()
            name_item = self._table.item(selected_row, 0)
            if name_item is not None:
                pid_value = name_item.data(Qt.ItemDataRole.UserRole)
                if isinstance(pid_value, int):
                    self._apply_pid(pid_value)
                    self.accept()
                    return

        # Fallback to spinbox value
        self._apply_pid(self._pid_spinbox.value())
        self.accept()

    def _on_disable_clicked(self) -> None:
        """Disable process filtering and capture all traffic."""
        self._apply_pid(0)
        self.accept()

    def _apply_pid(self, pid: int) -> None:
        """Store target PID, save settings, and trigger process monitor."""
        self.selected_pid = pid
        Settings.capture_filter_process_pid = pid
        Settings.rewrite_settings_file()
        ensure_process_monitor_running()
        self._update_status_label()

    @override
    def resizeEvent(self, a0: QResizeEvent) -> None:
        """Adjust column widths when the dialog is resized."""
        super().resizeEvent(a0)
        if a0.oldSize().width() > 0 and a0.size().width() != a0.oldSize().width():
            viewport = self._table.viewport()
            available_width = viewport.width() if viewport and viewport.width() > 0 else self._table.width()
            used_width = self._table.columnWidth(0) + self._table.columnWidth(1)
            self._table.setColumnWidth(2, max(scale_by_ui(250), available_width - used_width))

    def _reset_column_sizes(self) -> None:
        """Reset column widths back to their initial default layout."""
        header = self._table.horizontalHeader()
        if not header:
            return
        header.setStretchLastSection(False)
        for column_index in range(3):
            header.setSectionResizeMode(column_index, QHeaderView.ResizeMode.Interactive)

        self._table.resizeColumnToContents(0)
        self._table.resizeColumnToContents(1)

        viewport = self._table.viewport()
        available_width = viewport.width() if viewport and viewport.width() > 0 else self._table.width()
        used_width = self._table.columnWidth(0) + self._table.columnWidth(1)
        remaining_width = max(scale_by_ui(250), available_width - used_width)
        self._table.setColumnWidth(2, remaining_width)

    def _copy_selected_row(self) -> None:
        """Copy selected process row details to clipboard as tab-separated values."""
        selected_items = self._table.selectedItems()
        if not selected_items:
            return
        row = selected_items[0].row()
        name_item = self._table.item(row, 0)
        pid_item = self._table.item(row, 1)
        path_item = self._table.item(row, 2)
        process_name = name_item.text() if name_item else ''
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

        process_name = name_item.text() if name_item else ''
        pid_str = pid_item.text() if pid_item else ''
        exe_path = path_item.text() if path_item else ''

        menu = QMenu(self)
        menu.setStyleSheet(SVG_ICON_CONTEXT_MENU_STYLESHEET)
        menu.setToolTipsVisible(True)

        target_icon = QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'target.svg'))
        sniff_action = QAction(target_icon, f"🎯 Sniff '{process_name}'", menu)
        sniff_action.setToolTip(f'Select {process_name} (PID: {pid_str}) and filter network capture to it.')
        sniff_action.triggered.connect(self._on_sniff_selected_clicked)
        menu.addAction(sniff_action)

        menu.addSeparator()

        copy_row_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg')), '📋 Copy Row', menu)
        copy_row_action.setShortcut('Ctrl+C')
        copy_row_action.setToolTip('Copy selected row details to the clipboard.')
        copy_row_action.triggered.connect(self._copy_selected_row)
        menu.addAction(copy_row_action)

        if exe_path:
            copy_path_action = QAction('📋 Copy Executable Path', menu)
            copy_path_action.setToolTip('Copy the full executable path to the clipboard.')
            copy_path_action.triggered.connect(lambda: set_clipboard_text(exe_path))
            menu.addAction(copy_path_action)

        if process_name:
            copy_name_action = QAction('📋 Copy Process Name', menu)
            copy_name_action.setToolTip('Copy the process name to the clipboard.')
            copy_name_action.triggered.connect(lambda: set_clipboard_text(process_name))
            menu.addAction(copy_name_action)

        menu.addSeparator()

        add_column_sizing_actions(
            menu,
            self._table,
            clicked_column=index.column(),
            on_reset=self._reset_column_sizes,
        )

        viewport = self._table.viewport()
        if viewport:
            menu.popup(viewport.mapToGlobal(position))
