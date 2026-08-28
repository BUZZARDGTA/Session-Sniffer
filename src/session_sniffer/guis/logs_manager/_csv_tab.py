"""CSV log tab — reusable for UserIP_Logging.csv and Detection_Logging.csv."""

import csv
import shutil
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from typing import TYPE_CHECKING

from PySide6.QtCore import QItemSelectionModel, QModelIndex, QPoint, Qt, QUrl
from PySide6.QtGui import QAction, QDesktopServices, QIcon, QKeySequence, QShortcut, QStandardItem, QStandardItemModel
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMenu,
    QMessageBox,
    QPushButton,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.local import RESOURCES_DIR_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis.file_watch import DebouncedFileWatcher
from session_sniffer.guis.logs_manager._helpers import (
    DATE_COLUMN_NAME,
    DATE_FILTER_7_DAYS,
    DATE_FILTER_30_DAYS,
    DATE_FILTER_CHOICES,
    DATE_FILTER_TODAY,
    MAX_CSV_ROWS,
    MultiColumnFilterProxy,
    create_search_input,
    file_metadata_text,
    open_file_location,
    purge_log_file,
)
from session_sniffer.guis.stylesheets import DIALOG_BUTTON_STYLESHEET, DIALOG_DANGER_BUTTON_STYLESHEET, SVG_ICON_CONTEXT_MENU_STYLESHEET
from session_sniffer.guis.tables_player_actions import ping_ip, show_detailed_ip_lookup, tcp_port_ping, tcp_port_ping_multi
from session_sniffer.guis.utils import ElidedTextTooltipDelegate, set_clipboard_text
from session_sniffer.text_utils import pluralize

if TYPE_CHECKING:
    from pathlib import Path


@dataclass(slots=True)
class CsvLogTabConfig:
    """Configuration bundle for `CsvLogTab`."""

    file_path: Path
    expected_headers: tuple[str, ...]
    default_sort_columns: tuple[str, ...] = field(default_factory=tuple)
    default_sort_order: Qt.SortOrder = Qt.SortOrder.AscendingOrder
    stretch_column: int | None = None
    column_min_widths: dict[int, int] = field(default_factory=dict[int, int])


class CsvLogTab(QWidget):
    """Structured CSV log viewer with table, search, filter, sort, and management actions."""

    def __init__(
        self,
        config: CsvLogTabConfig,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._file_path = config.file_path
        self._expected_headers = config.expected_headers
        self._default_sort_columns = config.default_sort_columns
        self._default_sort_order = config.default_sort_order
        self._stretch_column = config.stretch_column
        self._column_min_widths = config.column_min_widths
        self._all_rows: list[list[str]] = []
        self._truncated = False
        self._initial_loaded = False

        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)

        # --- Top bar: search + column filter + date filter + refresh + count ---
        top_bar = QHBoxLayout()

        self._search_input = create_search_input(top_bar, 'Filter entries…', self._on_search_changed)

        top_bar.addWidget(QLabel('Column:'))
        self._column_combo = QComboBox()
        self._column_combo.addItem('All Columns', -1)
        for i, column_name in enumerate(self._expected_headers):
            self._column_combo.addItem(column_name, i)
        self._column_combo.currentIndexChanged.connect(self._on_column_filter_changed)
        top_bar.addWidget(self._column_combo)

        top_bar.addWidget(QLabel('Period:'))
        self._date_combo = QComboBox()
        for choice in DATE_FILTER_CHOICES:
            self._date_combo.addItem(choice)
        self._date_combo.currentTextChanged.connect(self._on_date_filter_changed)
        top_bar.addWidget(self._date_combo)

        self._count_label = QLabel('')
        top_bar.addWidget(self._count_label)

        layout.addLayout(top_bar)

        # --- Table ---
        self._model = QStandardItemModel(self)
        self._model.setHorizontalHeaderLabels(list(self._expected_headers))

        self._proxy = MultiColumnFilterProxy(self)
        self._proxy.setSourceModel(self._model)
        self._proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)

        self._table = QTableView()
        self._table.setModel(self._proxy)
        self._table.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self._table.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self._table.setShowGrid(True)
        self._table.setGridStyle(Qt.PenStyle.SolidLine)
        self._table.setCornerButtonEnabled(False)
        self._table.setSortingEnabled(True)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setAlternatingRowColors(True)

        QShortcut(QKeySequence('Ctrl+C'), self._table).activated.connect(self._copy_selected)
        QShortcut(QKeySequence('Ctrl+A'), self._table).activated.connect(self._table.selectAll)

        v_header = self._table.verticalHeader()
        if v_header:
            v_header.setVisible(False)
            v_header.setDefaultSectionSize(26)

        h_header = self._table.horizontalHeader()
        if h_header:
            h_header.setHighlightSections(False)
            if self._stretch_column is not None:
                h_header.setStretchLastSection(False)
                h_header.setSectionResizeMode(self._stretch_column, QHeaderView.ResizeMode.Stretch)
            else:
                h_header.setStretchLastSection(True)
            for column, width in self._column_min_widths.items():
                h_header.resizeSection(column, width)
            h_header.setSectionsMovable(True)
            h_header.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
            h_header.customContextMenuRequested.connect(self._on_header_context_menu)

        layout.addWidget(self._table, stretch=1)

        self._table.setItemDelegate(ElidedTextTooltipDelegate(self._table))
        self._table.setWordWrap(False)

        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._on_table_context_menu)

        # --- File metadata ---
        self._metadata_label = QLabel('')
        layout.addWidget(self._metadata_label)

        # --- Bottom buttons ---
        button_row = QHBoxLayout()

        copy_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg')), ' Copy Selected')
        copy_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        copy_button.setToolTip('Copy selected rows to clipboard')
        copy_button.clicked.connect(self._copy_selected)
        button_row.addWidget(copy_button)

        export_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'export.svg')), ' Export As...')
        export_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        export_button.setToolTip('Export the full log to a new CSV file')
        export_button.clicked.connect(self._export_as)
        button_row.addWidget(export_button)

        button_row.addStretch()

        delete_rows_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'remove.svg')), ' Delete Selected Rows')
        delete_rows_button.setStyleSheet(DIALOG_DANGER_BUTTON_STYLESHEET)
        delete_rows_button.setToolTip('Remove selected rows from the log file')
        delete_rows_button.clicked.connect(self._delete_selected_rows)
        button_row.addWidget(delete_rows_button)

        purge_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'remove.svg')), ' Purge File')
        purge_button.setStyleSheet(DIALOG_DANGER_BUTTON_STYLESHEET)
        purge_button.setToolTip('Clear all entries from this log file (creates a backup first)')
        purge_button.clicked.connect(self._purge_file)
        button_row.addWidget(purge_button)

        label = ' Open Folder Location' if self._file_path.is_dir() else ' Open File Location'
        open_location_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'folder.svg')), label)
        open_location_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        open_location_button.setToolTip('Open the containing folder in Windows Explorer')
        open_location_button.clicked.connect(lambda: open_file_location(self._file_path))
        button_row.addWidget(open_location_button)

        open_file_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'text_editor.svg')), ' Open File')
        open_file_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        open_file_button.setToolTip('Open the log file in the default text editor')
        open_file_button.clicked.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(self._file_path))))
        button_row.addWidget(open_file_button)

        layout.addLayout(button_row)

        # --- Auto-refresh from disk ---
        self._watcher = DebouncedFileWatcher(self, self.load_data)
        self._watcher.watch(files=[self._file_path], directories=[self._file_path.parent])

        # Initial load
        self.load_data()

    # ------------------------------------------------------------------
    # Data loading
    # ------------------------------------------------------------------

    def load_data(self) -> None:
        """Read the CSV file and populate the table model."""
        scrollbar = self._table.verticalScrollBar()
        previous_scroll = scrollbar.value() if scrollbar else 0

        self._model.removeRows(0, self._model.rowCount())
        self._all_rows.clear()
        self._truncated = False

        if not self._file_path.exists():
            self._update_counts()
            self._metadata_label.setText(file_metadata_text(self._file_path))
            self._initial_loaded = True
            return

        with self._file_path.open(newline='', encoding='utf-8') as file:
            reader = csv.reader(file)
            file_headers = next(reader, None)
            if file_headers is None:
                self._update_counts()
                self._metadata_label.setText(file_metadata_text(self._file_path))
                self._initial_loaded = True
                return

            self._model.setHorizontalHeaderLabels(file_headers)
            self._rebuild_column_combo(file_headers)

            skipped = 0
            for row_num, row in enumerate(reader):
                if row_num >= MAX_CSV_ROWS:
                    self._truncated = True
                    break
                if len(row) != len(file_headers):
                    skipped += 1
                    continue
                items = [QStandardItem(cell) for cell in row]
                for item in items:
                    item.setEditable(False)
                self._model.appendRow(items)
                self._all_rows.append(row)

            # Only surface malformed-row warnings on the first load; auto-refreshes stay silent.
            if skipped and not self._initial_loaded:
                QMessageBox.warning(
                    self,
                    TITLE,
                    f'Skipped {skipped} malformed row(s) while loading {self._file_path.name}.',
                )

        if self._initial_loaded:
            if scrollbar:
                scrollbar.setValue(min(previous_scroll, scrollbar.maximum()))
        else:
            self._apply_default_sort()
            self._initial_loaded = True
        self._update_counts()
        self._metadata_label.setText(file_metadata_text(self._file_path))

    def _apply_default_sort(self) -> None:
        """Apply the default sort using stable-sort chaining."""
        if not self._default_sort_columns:
            return
        header_labels = [self._model.headerData(column, Qt.Orientation.Horizontal) for column in range(self._model.columnCount())]
        primary_column_index: int | None = None
        # Sort in reverse order so the first column in the tuple ends up as the primary sort key.
        for column_name in reversed(self._default_sort_columns):
            if column_name in header_labels:
                column_index = header_labels.index(column_name)
                self._proxy.sort(column_index, self._default_sort_order)
                primary_column_index = column_index
        # Sync the header sort indicator with the primary sort column.
        if primary_column_index is not None:
            h_header = self._table.horizontalHeader()
            if h_header:
                h_header.setSortIndicator(primary_column_index, self._default_sort_order)

    # ------------------------------------------------------------------
    # Filtering
    # ------------------------------------------------------------------

    def _rebuild_column_combo(self, headers: list[str]) -> None:
        """Rebuild the column filter combo box from actual file headers."""
        self._column_combo.blockSignals(True)  # noqa: FBT003
        self._column_combo.clear()
        self._column_combo.addItem('All Columns', -1)
        for i, header in enumerate(headers):
            self._column_combo.addItem(header, i)
        self._column_combo.blockSignals(False)  # noqa: FBT003

    def _on_search_changed(self, text: str) -> None:
        self._proxy.setFilterFixedString(text)
        self._update_counts()

    def _on_column_filter_changed(self) -> None:
        column = self._column_combo.currentData()
        if column is None:
            column = -1
        self._proxy.set_filter_column(column)
        self._update_counts()

    def _on_date_filter_changed(self, choice: str) -> None:
        headers = [self._model.headerData(i, Qt.Orientation.Horizontal) for i in range(self._model.columnCount())]
        date_column = -1
        for i, header in enumerate(headers):
            if header == DATE_COLUMN_NAME:
                date_column = i
                break

        cutoff: datetime | None = None
        now = datetime.now(tz=UTC)
        if choice == DATE_FILTER_TODAY:
            cutoff = now.replace(hour=0, minute=0, second=0, microsecond=0)
        elif choice == DATE_FILTER_7_DAYS:
            cutoff = (now - timedelta(days=7)).replace(hour=0, minute=0, second=0, microsecond=0)
        elif choice == DATE_FILTER_30_DAYS:
            cutoff = (now - timedelta(days=30)).replace(hour=0, minute=0, second=0, microsecond=0)

        self._proxy.set_date_filter(date_column, cutoff)
        self._update_counts()

    def _update_counts(self) -> None:
        total = self._model.rowCount()
        visible = self._proxy.rowCount()
        parts = [f'{total} entries']
        if visible != total:
            parts.append(f'{visible} visible')
        if self._truncated:
            parts.append(f'(display limited to {MAX_CSV_ROWS:,} rows)')
        self._count_label.setText('  |  '.join(parts))

    # ------------------------------------------------------------------
    # Column visibility
    # ------------------------------------------------------------------

    def _on_header_context_menu(self, pos: QPoint) -> None:
        h_header = self._table.horizontalHeader()
        if not h_header:
            return
        menu = QMenu(self)
        for column in range(self._model.columnCount()):
            name = self._model.headerData(column, Qt.Orientation.Horizontal)
            action = QAction(str(name), menu)
            action.setCheckable(True)
            action.setChecked(not self._table.isColumnHidden(column))
            action.setData(column)
            action.toggled.connect(self._toggle_column_visibility)
            menu.addAction(action)
        menu.popup(h_header.mapToGlobal(pos))

    def _on_table_context_menu(self, pos: QPoint) -> None:
        """Show a context menu on a right-clicked table row with quick-access actions."""
        index = self._table.indexAt(pos)
        selection_model = self._table.selectionModel()
        if selection_model and index.isValid() and not selection_model.isSelected(index):
            selection_model.select(index, QItemSelectionModel.SelectionFlag.ClearAndSelect | QItemSelectionModel.SelectionFlag.Rows)

        selected_rows = selection_model.selectedRows() if selection_model else []
        has_selection = bool(selected_rows)

        menu = QMenu(self)
        menu.setStyleSheet(SVG_ICON_CONTEXT_MENU_STYLESHEET)
        menu.setToolTipsVisible(True)

        copy_label = f'Copy Selected Rows ({len(selected_rows)})' if len(selected_rows) > 1 else 'Copy Selected Row'
        copy_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg')), copy_label, menu)
        copy_action.setShortcut('Ctrl+C')
        copy_action.setToolTip('Copy selected rows to the clipboard as comma-separated values.')
        copy_action.setEnabled(has_selection)
        copy_action.triggered.connect(self._copy_selected)
        menu.addAction(copy_action)

        copy_all_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg')), 'Copy All', menu)
        copy_all_action.setToolTip('Copy all visible rows to the clipboard as comma-separated values.')
        copy_all_action.setEnabled(self._proxy.rowCount() > 0)
        copy_all_action.triggered.connect(self._copy_all)
        menu.addAction(copy_all_action)

        menu.addSeparator()

        select_all_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'select_all.svg')), 'Select All', menu)
        select_all_action.setShortcut('Ctrl+A')
        select_all_action.setToolTip('Select all visible rows.')
        select_all_action.setEnabled(self._proxy.rowCount() > 0)
        select_all_action.triggered.connect(self._table.selectAll)
        menu.addAction(select_all_action)

        clear_selection_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'unselect_all.svg')), 'Clear Selection', menu)
        clear_selection_action.setToolTip('Deselect all rows.')
        clear_selection_action.triggered.connect(self._table.clearSelection)
        menu.addAction(clear_selection_action)

        selected_ips = self._get_selected_ips(index, selection_model)

        if len(selected_ips) == 1:
            menu.addSeparator()

            lookup_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'info.svg')), 'IP Lookup Details…', menu)
            lookup_action.setToolTip('Show detailed IP lookup information for this IP address.')
            lookup_action.triggered.connect(lambda _checked=False, ip_address=selected_ips[0]: show_detailed_ip_lookup(self, ip_address))
            menu.addAction(lookup_action)

            # pylint: disable=duplicate-code
            ping_menu = QMenu('Ping', menu)
            ping_menu.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'ping.svg')))
            ping_menu.setStyleSheet(SVG_ICON_CONTEXT_MENU_STYLESHEET)
            ping_menu.setToolTipsVisible(True)

            normal_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'play.svg')), 'Normal (ICMP)', self)
            normal_action.setToolTip('Checks if selected IP address responds to pings.')
            normal_action.triggered.connect(lambda _checked=False, ip_address=selected_ips[0]: ping_ip(ip_address))
            ping_menu.addAction(normal_action)

            tcp_ping_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'settings.svg')), 'TCP Port (paping.exe)', self)
            tcp_ping_action.setToolTip('Checks if selected IP address responds to TCP pings on a given port.')
            tcp_ping_action.triggered.connect(lambda _checked=False, ip_address=selected_ips[0]: tcp_port_ping(self, ip_address))
            ping_menu.addAction(tcp_ping_action)

            menu.addMenu(ping_menu)
            # pylint: enable=duplicate-code

        elif len(selected_ips) > 1:
            menu.addSeparator()
            _target_ips = list(selected_ips)

            # pylint: disable=duplicate-code
            ping_menu = QMenu('Ping', menu)
            ping_menu.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'ping.svg')))
            ping_menu.setStyleSheet(SVG_ICON_CONTEXT_MENU_STYLESHEET)
            ping_menu.setToolTipsVisible(True)

            normal_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'play.svg')), 'Normal (ICMP)', self)
            normal_action.setToolTip('Checks if selected IP addresses respond to pings.')

            def _ping_all_csv() -> None:
                for ip_address in _target_ips:
                    ping_ip(ip_address)

            normal_action.triggered.connect(_ping_all_csv)
            ping_menu.addAction(normal_action)

            tcp_menu = QMenu('TCP Port (paping.exe)', ping_menu)
            tcp_menu.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'settings.svg')))
            tcp_menu.setStyleSheet(SVG_ICON_CONTEXT_MENU_STYLESHEET)
            tcp_menu.setToolTipsVisible(True)

            tcp_one_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'settings.svg')), 'One Port for All', tcp_menu)
            tcp_one_action.setToolTip('Ask for a port once, then TCP ping all selected IPs on that port.')

            def _do_tcp_ping_multi() -> None:
                tcp_port_ping_multi(self, _target_ips)

            tcp_one_action.triggered.connect(_do_tcp_ping_multi)
            tcp_menu.addAction(tcp_one_action)

            tcp_custom_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'settings.svg')), 'Individual Port per IP', tcp_menu)
            tcp_custom_action.setToolTip('Ask for a separate port for each selected IP.')

            def _do_tcp_ping_individual() -> None:
                for ip_address in _target_ips:
                    tcp_port_ping(self, ip_address)

            tcp_custom_action.triggered.connect(_do_tcp_ping_individual)
            tcp_menu.addAction(tcp_custom_action)

            ping_menu.addMenu(tcp_menu)
            menu.addMenu(ping_menu)
            # pylint: enable=duplicate-code

        menu.addSeparator()

        delete_action = QAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'remove.svg')), 'Delete Selected Rows', menu)
        delete_action.setToolTip('Remove selected rows from the log file permanently.')
        delete_action.setEnabled(has_selection)
        delete_action.triggered.connect(self._delete_selected_rows)
        menu.addAction(delete_action)

        viewport = self._table.viewport()
        if viewport:
            menu.popup(viewport.mapToGlobal(pos))

    def _get_selected_ips(self, index: QModelIndex, selection_model: QItemSelectionModel | None) -> list[str]:
        """Extract unique IPv4 addresses from current table selection or clicked row."""
        selected_ips: list[str] = []
        if selection_model:
            for selected_model_index in selection_model.selectedRows():
                source_model_index = self._proxy.mapToSource(selected_model_index)
                self._extract_ips_from_row(source_model_index.row(), selected_ips)

        if not selected_ips and index.isValid():
            source_index = self._proxy.mapToSource(index)
            self._extract_ips_from_row(source_index.row(), selected_ips)

        return selected_ips

    def _extract_ips_from_row(self, row: int, target_list: list[str]) -> None:
        """Helper to scan columns of *row* for IPv4 strings and append to *target_list*."""
        for column_index in range(self._model.columnCount()):
            item = self._model.item(row, column_index)
            if item and item.text():
                cell_text = item.text().strip()
                try:
                    IPv4Address(cell_text)
                    if cell_text not in target_list:
                        target_list.append(cell_text)
                except ValueError:
                    pass

    def _toggle_column_visibility(self, checked: bool) -> None:  # noqa: FBT001
        action = self.sender()
        if isinstance(action, QAction):
            column = action.data()
            self._table.setColumnHidden(column, not checked)

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _copy_selected(self) -> None:
        selection_model = self._table.selectionModel()
        if not selection_model:
            return
        indexes = selection_model.selectedRows()
        if not indexes:
            return
        lines: list[str] = []
        column_count = self._model.columnCount()
        for i in sorted(indexes, key=lambda i: i.row()):
            source_row = self._proxy.mapToSource(i).row()
            cells: list[str] = []
            for column in range(column_count):
                item = self._model.item(source_row, column)
                cells.append(item.text() if item else '')
            lines.append(','.join(cells))

        set_clipboard_text('\n'.join(lines))

    def _copy_all(self) -> None:
        lines: list[str] = []
        column_count = self._model.columnCount()
        row_count = self._proxy.rowCount()
        for row_index in range(row_count):
            source_row = self._proxy.mapToSource(self._proxy.index(row_index, 0)).row()
            cells: list[str] = []
            for column_index in range(column_count):
                item = self._model.item(source_row, column_index)
                cells.append(item.text() if item else '')
            lines.append(','.join(cells))

        if not lines:
            return

        set_clipboard_text('\n'.join(lines))

    def _export_as(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self,
            'Export Log As',
            str(self._file_path.with_suffix('.export.csv')),
            'CSV Files (*.csv);;All Files (*)',
        )
        if not path:
            return
        shutil.copy2(self._file_path, path)
        self._show_status(f'Exported to {path}')

    def _delete_selected_rows(self) -> None:
        selection_model = self._table.selectionModel()
        if not selection_model:
            return
        indexes = selection_model.selectedRows()
        if not indexes:
            QMessageBox.information(self, TITLE, 'No rows selected.')
            return
        count = len(indexes)
        reply = QMessageBox.question(
            self,
            TITLE,
            f'Delete {count} selected row{pluralize(count)} from {self._file_path.name}?\n\nThis cannot be undone.',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        source_rows = sorted((self._proxy.mapToSource(i).row() for i in indexes), reverse=True)
        for row in source_rows:
            self._model.removeRow(row)

        self._rewrite_csv_from_model()
        self._update_counts()
        self._metadata_label.setText(file_metadata_text(self._file_path))

    def _purge_file(self) -> None:
        message = purge_log_file(self, self._file_path, item_label='entries')
        if message is not None:
            self._show_status(message)
            self.load_data()

    def _rewrite_csv_from_model(self) -> None:
        """Rewrite the CSV file from the current model contents."""
        headers = [self._model.headerData(i, Qt.Orientation.Horizontal) for i in range(self._model.columnCount())]
        with self._file_path.open('w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(headers)
            for row_index in range(self._model.rowCount()):
                cells: list[str] = []
                for column in range(self._model.columnCount()):
                    item = self._model.item(row_index, column)
                    cells.append(item.text() if item else '')
                writer.writerow(cells)

    def _show_status(self, message: str) -> None:
        QMessageBox.information(self, TITLE, message)
