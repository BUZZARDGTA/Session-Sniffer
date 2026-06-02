"""CSV log tab — reusable for UserIP_Logging.csv and Detection_Logging.csv."""
import csv
import shutil
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from PyQt6.QtCore import QPoint, Qt, QUrl
from PyQt6.QtGui import QAction, QDesktopServices, QStandardItem, QStandardItemModel
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QApplication,
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

from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis.logs_manager._helpers import (
    DATE_COLUMN_NAME,
    DATE_FILTER_7_DAYS,
    DATE_FILTER_30_DAYS,
    DATE_FILTER_CHOICES,
    DATE_FILTER_TODAY,
    MAX_CSV_ROWS,
    MultiColumnFilterProxy,
    create_refresh_button,
    create_search_input,
    file_metadata_text,
    open_file_location,
    purge_log_file,
)
from session_sniffer.guis.stylesheets import DIALOG_BUTTON_STYLESHEET, DIALOG_DANGER_BUTTON_STYLESHEET
from session_sniffer.guis.userip_manager_helpers import ElidedTooltipFilter

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

        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)

        # --- Top bar: search + column filter + date filter + refresh + count ---
        top_bar = QHBoxLayout()

        self._search_input = create_search_input(top_bar, 'Filter entries…', self._on_search_changed)

        top_bar.addWidget(QLabel('Column:'))
        self._column_combo = QComboBox()
        self._column_combo.addItem('All Columns', -1)
        for i, col_name in enumerate(self._expected_headers):
            self._column_combo.addItem(col_name, i)
        self._column_combo.currentIndexChanged.connect(self._on_column_filter_changed)
        top_bar.addWidget(self._column_combo)

        top_bar.addWidget(QLabel('Period:'))
        self._date_combo = QComboBox()
        for choice in DATE_FILTER_CHOICES:
            self._date_combo.addItem(choice)
        self._date_combo.currentTextChanged.connect(self._on_date_filter_changed)
        top_bar.addWidget(self._date_combo)

        refresh_button = create_refresh_button(self.load_data)
        top_bar.addWidget(refresh_button)

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
        self._table.setSortingEnabled(True)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setAlternatingRowColors(True)

        v_header = self._table.verticalHeader()
        if v_header is not None:
            v_header.setDefaultSectionSize(24)

        h_header = self._table.horizontalHeader()
        if h_header is not None:
            if self._stretch_column is not None:
                h_header.setStretchLastSection(False)
                h_header.setSectionResizeMode(self._stretch_column, QHeaderView.ResizeMode.Stretch)
            else:
                h_header.setStretchLastSection(True)
            for col, width in self._column_min_widths.items():
                h_header.resizeSection(col, width)
            h_header.setSectionsMovable(True)
            h_header.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
            h_header.customContextMenuRequested.connect(self._on_header_context_menu)

        layout.addWidget(self._table, stretch=1)

        self._tooltip_filter = ElidedTooltipFilter(self._table)
        viewport = self._table.viewport()
        if viewport is not None:
            viewport.installEventFilter(self._tooltip_filter)

        # --- File metadata ---
        self._metadata_label = QLabel('')
        layout.addWidget(self._metadata_label)

        # --- Bottom buttons ---
        button_row = QHBoxLayout()

        copy_button = QPushButton('📋 Copy Selected')
        copy_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        copy_button.setToolTip('Copy selected rows to clipboard')
        copy_button.clicked.connect(self._copy_selected)
        button_row.addWidget(copy_button)

        export_button = QPushButton('💾 Export As...')
        export_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        export_button.setToolTip('Export the full log to a new CSV file')
        export_button.clicked.connect(self._export_as)
        button_row.addWidget(export_button)

        button_row.addStretch()

        delete_rows_button = QPushButton('🗑️ Delete Selected Rows')
        delete_rows_button.setStyleSheet(DIALOG_DANGER_BUTTON_STYLESHEET)
        delete_rows_button.setToolTip('Remove selected rows from the log file')
        delete_rows_button.clicked.connect(self._delete_selected_rows)
        button_row.addWidget(delete_rows_button)

        purge_button = QPushButton('🗑️ Purge File')
        purge_button.setStyleSheet(DIALOG_DANGER_BUTTON_STYLESHEET)
        purge_button.setToolTip('Clear all entries from this log file (creates a backup first)')
        purge_button.clicked.connect(self._purge_file)
        button_row.addWidget(purge_button)

        open_location_button = QPushButton('📂 Open File Location')
        open_location_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        open_location_button.setToolTip('Open the containing folder in Windows Explorer')
        open_location_button.clicked.connect(lambda: open_file_location(self._file_path))
        button_row.addWidget(open_location_button)

        edit_file_button = QPushButton('📝 Edit File')
        edit_file_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        edit_file_button.setToolTip('Open the log file in the default text editor')
        edit_file_button.clicked.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(self._file_path))))
        button_row.addWidget(edit_file_button)

        layout.addLayout(button_row)

        # Initial load
        self.load_data()

    # ------------------------------------------------------------------
    # Data loading
    # ------------------------------------------------------------------

    def load_data(self) -> None:
        """Read the CSV file and populate the table model."""
        self._model.removeRows(0, self._model.rowCount())
        self._all_rows.clear()
        self._truncated = False

        if not self._file_path.exists():
            self._update_counts()
            self._metadata_label.setText(file_metadata_text(self._file_path))
            return

        with self._file_path.open(newline='', encoding='utf-8') as f:
            reader = csv.reader(f)
            file_headers = next(reader, None)
            if file_headers is None:
                self._update_counts()
                self._metadata_label.setText(file_metadata_text(self._file_path))
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

            if skipped:
                QMessageBox.warning(
                    self, TITLE,
                    f'Skipped {skipped} malformed row(s) while loading {self._file_path.name}.',
                )

        self._apply_default_sort()
        self._update_counts()
        self._metadata_label.setText(file_metadata_text(self._file_path))

    def _apply_default_sort(self) -> None:
        """Apply the default sort using stable-sort chaining."""
        if not self._default_sort_columns:
            return
        header_labels = [self._model.headerData(c, Qt.Orientation.Horizontal) for c in range(self._model.columnCount())]
        primary_col_index: int | None = None
        # Sort in reverse order so the first column in the tuple ends up as the primary sort key.
        for col_name in reversed(self._default_sort_columns):
            if col_name in header_labels:
                col_index = header_labels.index(col_name)
                self._proxy.sort(col_index, self._default_sort_order)
                primary_col_index = col_index
        # Sync the header sort indicator with the primary sort column.
        if primary_col_index is not None:
            h_header = self._table.horizontalHeader()
            if h_header is not None:
                h_header.setSortIndicator(primary_col_index, self._default_sort_order)

    # ------------------------------------------------------------------
    # Filtering
    # ------------------------------------------------------------------

    def _rebuild_column_combo(self, headers: list[str]) -> None:
        """Rebuild the column filter combo box from actual file headers."""
        self._column_combo.blockSignals(True)  # noqa: FBT003
        self._column_combo.clear()
        self._column_combo.addItem('All Columns', -1)
        for i, h in enumerate(headers):
            self._column_combo.addItem(h, i)
        self._column_combo.blockSignals(False)  # noqa: FBT003

    def _on_search_changed(self, text: str) -> None:
        self._proxy.setFilterFixedString(text)
        self._update_counts()

    def _on_column_filter_changed(self) -> None:
        col = self._column_combo.currentData()
        if col is None:
            col = -1
        self._proxy.set_filter_column(col)
        self._update_counts()

    def _on_date_filter_changed(self, choice: str) -> None:
        headers = [self._model.headerData(i, Qt.Orientation.Horizontal) for i in range(self._model.columnCount())]
        date_col = -1
        for i, h in enumerate(headers):
            if h == DATE_COLUMN_NAME:
                date_col = i
                break

        cutoff: datetime | None = None
        now = datetime.now(tz=UTC)
        if choice == DATE_FILTER_TODAY:
            cutoff = now.replace(hour=0, minute=0, second=0, microsecond=0)
        elif choice == DATE_FILTER_7_DAYS:
            cutoff = (now - timedelta(days=7)).replace(hour=0, minute=0, second=0, microsecond=0)
        elif choice == DATE_FILTER_30_DAYS:
            cutoff = (now - timedelta(days=30)).replace(hour=0, minute=0, second=0, microsecond=0)

        self._proxy.set_date_filter(date_col, cutoff)
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
        if h_header is None:
            return
        menu = QMenu(self)
        for col in range(self._model.columnCount()):
            name = self._model.headerData(col, Qt.Orientation.Horizontal)
            action = QAction(str(name), menu)
            action.setCheckable(True)
            action.setChecked(not self._table.isColumnHidden(col))
            action.setData(col)
            action.toggled.connect(self._toggle_column_visibility)
            menu.addAction(action)
        menu.popup(h_header.mapToGlobal(pos))

    def _toggle_column_visibility(self, checked: bool) -> None:  # noqa: FBT001
        action = self.sender()
        if isinstance(action, QAction):
            col = action.data()
            self._table.setColumnHidden(col, not checked)

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _copy_selected(self) -> None:
        selection_model = self._table.selectionModel()
        if selection_model is None:
            return
        indexes = selection_model.selectedRows()
        if not indexes:
            QMessageBox.information(self, TITLE, 'No rows selected.')
            return
        lines: list[str] = []
        col_count = self._model.columnCount()
        for idx in sorted(indexes, key=lambda i: i.row()):
            source_row = self._proxy.mapToSource(idx).row()
            cells: list[str] = []
            for c in range(col_count):
                item = self._model.item(source_row, c)
                cells.append(item.text() if item else '')
            lines.append(','.join(cells))

        clipboard = QApplication.clipboard()
        if clipboard is not None:
            clipboard.setText('\n'.join(lines))
        self._show_status(f'Copied {len(lines)} row(s) to clipboard.')

    def _export_as(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, 'Export Log As', str(self._file_path.with_suffix('.export.csv')), 'CSV Files (*.csv);;All Files (*)',
        )
        if not path:
            return
        shutil.copy2(self._file_path, path)
        self._show_status(f'Exported to {path}')

    def _delete_selected_rows(self) -> None:
        selection_model = self._table.selectionModel()
        if selection_model is None:
            return
        indexes = selection_model.selectedRows()
        if not indexes:
            QMessageBox.information(self, TITLE, 'No rows selected.')
            return
        count = len(indexes)
        reply = QMessageBox.question(
            self, TITLE, f'Delete {count} selected row(s) from {self._file_path.name}?\n\nThis cannot be undone.',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        source_rows = sorted((self._proxy.mapToSource(idx).row() for idx in indexes), reverse=True)
        for row in source_rows:
            self._model.removeRow(row)

        self._rewrite_csv_from_model()
        self._update_counts()
        self._metadata_label.setText(file_metadata_text(self._file_path))

    def _purge_file(self) -> None:
        msg = purge_log_file(self, self._file_path, item_label='entries')
        if msg is not None:
            self._show_status(msg)
            self.load_data()

    def _rewrite_csv_from_model(self) -> None:
        """Rewrite the CSV file from the current model contents."""
        headers = [self._model.headerData(i, Qt.Orientation.Horizontal) for i in range(self._model.columnCount())]
        with self._file_path.open('w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            for row_idx in range(self._model.rowCount()):
                cells: list[str] = []
                for c in range(self._model.columnCount()):
                    item = self._model.item(row_idx, c)
                    cells.append(item.text() if item else '')
                writer.writerow(cells)

    def _show_status(self, message: str) -> None:
        QMessageBox.information(self, TITLE, message)
