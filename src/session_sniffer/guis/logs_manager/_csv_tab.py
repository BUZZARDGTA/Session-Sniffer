"""CSV log tab — reusable for UserIP_Logging.csv and Detection_Logging.csv."""

import csv
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from ipaddress import IPv4Address
from typing import TYPE_CHECKING, override

from PySide6.QtCore import QItemSelectionModel, QModelIndex, QPoint, QSignalBlocker, Qt, Signal
from PySide6.QtGui import (
    QAction,
    QIcon,
    QKeySequence,
    QResizeEvent,
    QShortcut,
    QShowEvent,
    QStandardItem,
    QStandardItemModel,
)
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

from session_sniffer.constants.standalone import TITLE
from session_sniffer.constants.standard import LOCAL_TZ
from session_sniffer.guis.delegates import SearchHighlightDelegate
from session_sniffer.guis.file_watch import DebouncedFileWatcher
from session_sniffer.guis.live_language import CANONICAL_HEADER_ROLE, register_language_refresh, set_i18n_colon_label
from session_sniffer.guis.loading_overlay import run_blocking_with_loading
from session_sniffer.guis.logs_manager._helpers import (
    DATE_COLUMN_NAME,
    DATE_FILTER_7_DAYS,
    DATE_FILTER_30_DAYS,
    DATE_FILTER_CHOICES,
    DATE_FILTER_TODAY,
    MAX_CSV_ROWS,
    MultiColumnFilterProxy,
    add_purge_and_location_buttons,
    create_search_input,
    file_metadata_text,
    purge_log_file,
)
from session_sniffer.guis.stylesheets import DIALOG_BUTTON_STYLESHEET, DIALOG_DANGER_BUTTON_STYLESHEET, SVG_ICON_CONTEXT_MENU_STYLESHEET
from session_sniffer.guis.table_column_resizing import add_column_sizing_actions
from session_sniffer.guis.tables_player_actions import (
    create_ping_menu,
    scan_ports_ip,
    show_detailed_ip_lookup,
)
from session_sniffer.guis.theming import ICONS_DIR_PATH
from session_sniffer.guis.utils import animate_button_feedback, set_clipboard_text
from session_sniffer.i18n import tr, tr_plural

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path


_DEFAULT_HEADER_BASE_WIDTHS: dict[str, int] = {
    'Database': 120,
    'Detection': 220,
    'Usernames': 180,
    'IP': 125,
    'Date': 95,
    'Time': 85,
    'Country': 160,
}

_KNOWN_CSV_HEADERS: frozenset[str] = frozenset(_DEFAULT_HEADER_BASE_WIDTHS)


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

    purge_state_changed = Signal()

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
        self._truncated = False
        self._initial_loaded = False
        self._raw_csv_headers: list[str] = list(self._expected_headers)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)

        # --- Top bar: search + column filter + date filter + refresh + count ---
        top_bar = QHBoxLayout()

        self._search_input = create_search_input(top_bar, tr('Filter entries\u2026'), self._on_search_changed)

        column_label = QLabel()
        set_i18n_colon_label(column_label, 'Column')
        top_bar.addWidget(column_label)
        self._column_combo = QComboBox()
        self._column_combo.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self._column_combo.addItem(tr('All Columns'), -1)
        for i, column_name in enumerate(self._expected_headers):
            self._column_combo.addItem(self._display_header(column_name), i)
        self._column_combo.currentIndexChanged.connect(self._on_column_filter_changed)
        top_bar.addWidget(self._column_combo)

        period_label = QLabel()
        set_i18n_colon_label(period_label, 'Period')
        top_bar.addWidget(period_label)
        self._date_combo = QComboBox()
        self._date_combo.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        for choice in DATE_FILTER_CHOICES:
            self._date_combo.addItem(tr(choice), choice)
        self._date_combo.currentIndexChanged.connect(self._on_date_filter_changed)
        top_bar.addWidget(self._date_combo)

        self._count_label = QLabel('')
        top_bar.addWidget(self._count_label)

        layout.addLayout(top_bar)

        # --- Table ---
        self._model = QStandardItemModel(self)
        self._set_model_headers(self._expected_headers)

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
        QShortcut(QKeySequence('Delete'), self._table, context=Qt.ShortcutContext.WidgetShortcut).activated.connect(self._delete_selected_rows)

        v_header = self._table.verticalHeader()
        if v_header:
            v_header.setVisible(False)
            v_header.setDefaultSectionSize(26)

        horizontal_header = self._table.horizontalHeader()
        if horizontal_header:
            horizontal_header.setHighlightSections(False)
            horizontal_header.setStretchLastSection(False)
            horizontal_header.setSectionsMovable(True)
            horizontal_header.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
            horizontal_header.customContextMenuRequested.connect(self._on_header_context_menu)
        self._reset_column_sizes()

        layout.addWidget(self._table, stretch=1)

        self._table.setItemDelegate(
            SearchHighlightDelegate(
                self._table,
                self._search_input.text,
                self._get_active_search_column,
            ),
        )
        self._table.setWordWrap(False)

        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._on_table_context_menu)

        # --- File metadata ---
        self._metadata_label = QLabel('')
        layout.addWidget(self._metadata_label)

        # --- Bottom buttons ---
        button_row = QHBoxLayout()

        copy_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'copy.svg')), f" {tr('Copy Selected')}")
        copy_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        copy_button.setToolTip(tr('Copy selected rows to clipboard'))
        copy_button.setEnabled(False)
        copy_button.clicked.connect(self._copy_selected)
        button_row.addWidget(copy_button)
        self._copy_button = copy_button

        export_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'upload.svg')), f" {tr('Export As...')}")
        export_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        export_button.setToolTip(tr('Export the full log to a new CSV file'))
        export_button.setEnabled(False)
        export_button.clicked.connect(self._export_as)
        button_row.addWidget(export_button)
        self._export_button = export_button

        button_row.addStretch()

        delete_rows_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'remove.svg')), f" {tr('Delete Selected Rows')}")
        delete_rows_button.setStyleSheet(DIALOG_DANGER_BUTTON_STYLESHEET)
        delete_rows_button.setToolTip(tr('Remove selected rows from the log file'))
        delete_rows_button.setEnabled(False)
        delete_rows_button.clicked.connect(self._delete_selected_rows)
        button_row.addWidget(delete_rows_button)
        self._delete_rows_button = delete_rows_button

        self._purge_button, self._open_file_button = add_purge_and_location_buttons(
            button_row,
            self._purge_file,
            self._file_path,
            add_stretch=False,
        )

        if selection_model := self._table.selectionModel():
            selection_model.selectionChanged.connect(self._update_selection_buttons)

        layout.addLayout(button_row)

        # --- Auto-refresh from disk ---
        self._watcher = DebouncedFileWatcher(self, self.load_data)
        self._watching_stopped = False

        # Initial load
        self.load_data()
        register_language_refresh(self, self._retranslate)

    @staticmethod
    def _display_header(raw_header: str) -> str:
        """Return localized header label for known CSV columns, or *raw_header* verbatim."""
        return tr(raw_header) if raw_header in _KNOWN_CSV_HEADERS else raw_header

    def _set_model_headers(self, raw_headers: Sequence[str]) -> None:
        """Populate horizontal header items with localized labels and canonical `CANONICAL_HEADER_ROLE`."""
        self._raw_csv_headers = list(raw_headers)
        self._model.setColumnCount(len(self._raw_csv_headers))
        for col, raw_header in enumerate(self._raw_csv_headers):
            item = QStandardItem(self._display_header(raw_header))
            item.setData(raw_header, CANONICAL_HEADER_ROLE)
            self._model.setHorizontalHeaderItem(col, item)

    def _retranslate(self) -> None:
        """Refresh all UI labels, headers, and counts after a live language change."""
        self._search_input.setPlaceholderText(tr('Filter entries\u2026'))
        self._copy_button.setToolTip(tr('Copy selected rows to clipboard'))
        self._export_button.setText(f" {tr('Export As...')}")
        self._export_button.setToolTip(tr('Export the full log to a new CSV file'))
        self._delete_rows_button.setToolTip(tr('Remove selected rows from the log file'))

        prev_col = self._get_active_search_column()
        prev_canonical = self._raw_csv_headers[prev_col] if 0 <= prev_col < len(self._raw_csv_headers) else None
        self._set_model_headers(self._raw_csv_headers)
        self._rebuild_column_combo(self._raw_csv_headers, prev_canonical)

        with QSignalBlocker(self._date_combo):
            for idx in range(self._date_combo.count()):
                choice = str(self._date_combo.itemData(idx) or '')
                if choice:
                    self._date_combo.setItemText(idx, tr(choice))

        self._update_counts()
        self._metadata_label.setText(file_metadata_text(self._file_path))

    def start_watching(self) -> None:
        """Start auto-refresh watcher from disk."""
        self._watcher.watch(files=[self._file_path], directories=[self._file_path.parent])
        if self._watching_stopped:
            self._watching_stopped = False
            self.load_data()

    def stop_watching(self) -> None:
        """Stop auto-refresh watcher from disk."""
        self._watching_stopped = True
        self._watcher.stop()

    @property
    def can_purge(self) -> bool:
        """Return whether this log currently contains entries to purge."""
        return self._purge_button.isEnabled()

    # ------------------------------------------------------------------
    # Data loading
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_csv_file(file_path: Path) -> tuple[list[str] | None, list[list[str]], int, bool]:
        """Read *file_path* up to `MAX_CSV_ROWS` and return `(headers, valid_rows, skipped, truncated)`."""
        with file_path.open(newline='', encoding='utf-8') as file:
            reader = csv.reader(file)
            file_headers = next(reader, None)
            if file_headers is None:
                return None, [], 0, False
            skipped = 0
            truncated = False
            valid_rows: list[list[str]] = []
            for row_num, row in enumerate(reader):
                if row_num >= MAX_CSV_ROWS:
                    truncated = True
                    break
                if len(row) != len(file_headers):
                    skipped += 1
                    continue
                valid_rows.append(row)
            return file_headers, valid_rows, skipped, truncated

    def load_data(self) -> None:
        """Read the CSV file and populate the table model."""
        self._purge_button.setEnabled(False)
        self._open_file_button.setEnabled(self._file_path.is_file())
        scrollbar = self._table.verticalScrollBar()
        previous_scroll = scrollbar.value() if scrollbar else 0

        self._model.removeRows(0, self._model.rowCount())
        self._proxy.set_source_rows(())
        self._truncated = False

        if not self._file_path.exists():
            self._update_counts()
            self._metadata_label.setText(file_metadata_text(self._file_path))
            self.purge_state_changed.emit()
            return

        file_headers, valid_rows, skipped, self._truncated = self._parse_csv_file(self._file_path)
        if file_headers is None:
            self._update_counts()
            self._metadata_label.setText(file_metadata_text(self._file_path))
            self.purge_state_changed.emit()
            return

        prev_col = self._get_active_search_column()
        prev_canonical = self._raw_csv_headers[prev_col] if 0 <= prev_col < len(self._raw_csv_headers) else None
        self._set_model_headers(file_headers)
        self._rebuild_column_combo(file_headers, prev_canonical)

        if valid_rows:
            dynamic_sort_filter = self._proxy.dynamicSortFilter()
            self._proxy.setDynamicSortFilter(False)
            try:
                self._model.insertRows(0, len(valid_rows))
                with QSignalBlocker(self._model):
                    for row_idx, row in enumerate(valid_rows):
                        for col_idx, cell in enumerate(row):
                            item = QStandardItem(cell)
                            item.setEditable(False)
                            self._model.setItem(row_idx, col_idx, item)
                self._proxy.set_source_rows(valid_rows)
            finally:
                self._proxy.setDynamicSortFilter(dynamic_sort_filter)
                self._proxy.invalidate()

        # Only surface malformed-row warnings on the first load; auto-refreshes stay silent.
        if skipped and not self._initial_loaded:
            QMessageBox.warning(
                self,
                TITLE,
                tr_plural(
                    'Skipped {count} malformed row while loading {filename}.',
                    'Skipped {count} malformed rows while loading {filename}.',
                    skipped,
                    filename=self._file_path.name,
                ),
            )

        if self._initial_loaded:
            if scrollbar:
                scrollbar.setValue(min(previous_scroll, scrollbar.maximum()))
            self._adjust_stretch_column_width()
        else:
            self._apply_default_sort()
            self._initial_loaded = True
            self._reset_column_sizes()
        self._update_counts()
        self._metadata_label.setText(file_metadata_text(self._file_path))
        self._purge_button.setEnabled(self._model.rowCount() > 0)
        self.purge_state_changed.emit()

    def _apply_default_sort(self) -> None:
        """Apply the default sort using stable-sort chaining."""
        if not self._default_sort_columns:
            return
        header_labels = list(self._raw_csv_headers)
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

    def _rebuild_column_combo(self, headers: Sequence[str], previous_canonical: str | None = None) -> None:
        """Rebuild the column filter combo box from canonical file headers."""
        with QSignalBlocker(self._column_combo):
            self._column_combo.clear()
            self._column_combo.addItem(tr('All Columns'), -1)
            for i, header in enumerate(headers):
                self._column_combo.addItem(self._display_header(header), i)
            if previous_canonical is not None and previous_canonical in headers:
                restored_index = self._column_combo.findData(headers.index(previous_canonical))
                if restored_index >= 0:
                    self._column_combo.setCurrentIndex(restored_index)
        self._proxy.set_filter_column(self._get_active_search_column())

    def _get_active_search_column(self) -> int:
        column_data = self._column_combo.currentData()
        return column_data if isinstance(column_data, int) else -1

    def set_search(self, text: str) -> None:
        """Programmatically set the search text and focus the search input."""
        self._search_input.setText(text)
        self._search_input.setFocus()

    def _on_search_changed(self, text: str) -> None:
        self._proxy.setFilterFixedString(text)
        self._update_counts()
        viewport = self._table.viewport()
        if viewport:
            viewport.update()

    def _on_column_filter_changed(self) -> None:
        column = self._column_combo.currentData()
        if column is None:
            column = -1
        self._proxy.set_filter_column(column)
        self._update_counts()
        viewport = self._table.viewport()
        if viewport:
            viewport.update()

    def _on_date_filter_changed(self, _index: int = 0) -> None:
        choice = str(self._date_combo.currentData() or '')
        date_column = self._raw_csv_headers.index(DATE_COLUMN_NAME) if DATE_COLUMN_NAME in self._raw_csv_headers else -1

        cutoff: datetime | None = None
        now = datetime.now(tz=LOCAL_TZ)
        if choice == DATE_FILTER_TODAY:
            cutoff = now.replace(hour=0, minute=0, second=0, microsecond=0)
        elif choice == DATE_FILTER_7_DAYS:
            cutoff = (now - timedelta(days=7)).replace(hour=0, minute=0, second=0, microsecond=0)
        elif choice == DATE_FILTER_30_DAYS:
            cutoff = (now - timedelta(days=30)).replace(hour=0, minute=0, second=0, microsecond=0)

        self._proxy.set_date_filter(date_column, cutoff)
        self._update_counts()

    def _update_selection_buttons(self, *_args: object) -> None:
        selection_model = self._table.selectionModel()
        selected_rows = selection_model.selectedRows() if selection_model else []
        sel_count = len(selected_rows)
        has_selection = sel_count > 0
        self._copy_button.setEnabled(has_selection)
        self._copy_button.setText(f" {tr('Copy Selected ({count})', count=sel_count)}" if sel_count > 1 else f" {tr('Copy Selected')}")
        self._delete_rows_button.setEnabled(has_selection)
        self._delete_rows_button.setText(
            f" {tr('Delete Selected Rows ({count})', count=sel_count)}" if sel_count > 1 else f" {tr('Delete Selected Rows')}",
        )

    def _update_counts(self) -> None:
        total = self._model.rowCount()
        visible = self._proxy.rowCount()
        parts = [tr_plural('{count} entry', '{count} entries', total)]
        if visible != total:
            parts.append(tr('{count} visible', count=visible))
        if self._truncated:
            parts.append(tr('(display limited to {max_rows:,} rows)', max_rows=MAX_CSV_ROWS))
        self._count_label.setText('  |  '.join(parts))
        self._export_button.setEnabled(total > 0 and self._file_path.is_file())
        self._update_selection_buttons()

    @override
    def showEvent(self, event: QShowEvent) -> None:
        """Adjust column widths when the log tab is shown."""
        super().showEvent(event)
        self._adjust_stretch_column_width()

    @override
    def resizeEvent(self, event: QResizeEvent) -> None:
        """Adjust column widths when the log tab is resized."""
        super().resizeEvent(event)
        self._adjust_stretch_column_width()

    def _adjust_stretch_column_width(self) -> None:
        """Stretch the configured stretch column (or last visible column) to fill the remaining viewport width."""
        horizontal_header = self._table.horizontalHeader()
        if not horizontal_header:
            return
        total_columns = self._model.columnCount()
        if not total_columns:
            return
        viewport = self._table.viewport()
        available_width = viewport.width() if viewport and viewport.width() > 0 else self._table.width()

        if self._stretch_column is not None and 0 <= self._stretch_column < total_columns and not horizontal_header.isSectionHidden(self._stretch_column):
            configured_widths = sum(
                self._table.columnWidth(column_index)
                for column_index in range(total_columns)
                if column_index != self._stretch_column and not horizontal_header.isSectionHidden(column_index)
            )
            stretch_width = max(150, available_width - configured_widths)
            horizontal_header.resizeSection(self._stretch_column, stretch_width)
        else:
            last_visible_column: int | None = None
            for column_index in range(total_columns):
                if not horizontal_header.isSectionHidden(column_index):
                    last_visible_column = column_index
            if last_visible_column is not None:
                other_widths = sum(
                    self._table.columnWidth(column_index)
                    for column_index in range(total_columns)
                    if column_index != last_visible_column and not horizontal_header.isSectionHidden(column_index)
                )
                last_width = max(100, available_width - other_widths)
                horizontal_header.resizeSection(last_visible_column, last_width)

    def _reset_column_sizes(self) -> None:
        """Reset column widths back to their initial default layout and stretch flexible column."""
        horizontal_header = self._table.horizontalHeader()
        if not horizontal_header:
            return
        total_columns = self._model.columnCount()
        if not total_columns:
            return
        for column_index in range(total_columns):
            horizontal_header.setSectionResizeMode(column_index, QHeaderView.ResizeMode.Interactive)
            if column_index in self._column_min_widths:
                horizontal_header.resizeSection(column_index, self._column_min_widths[column_index])
            else:
                header_name = self._raw_csv_headers[column_index] if column_index < len(self._raw_csv_headers) else ''
                base_width = _DEFAULT_HEADER_BASE_WIDTHS.get(header_name, 100)
                horizontal_header.resizeSection(column_index, base_width)
        self._adjust_stretch_column_width()

    # ------------------------------------------------------------------
    # Column visibility & Context Menus
    # ------------------------------------------------------------------

    def _on_header_context_menu(self, pos: QPoint) -> None:
        h_header = self._table.horizontalHeader()
        if not h_header:
            return
        clicked_column = h_header.logicalIndexAt(pos)
        menu = QMenu(self)
        menu.setStyleSheet(SVG_ICON_CONTEXT_MENU_STYLESHEET)
        menu.setToolTipsVisible(True)
        add_column_sizing_actions(menu, self._table, clicked_column=clicked_column, on_reset=self._reset_column_sizes)
        menu.addSeparator()
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

        copy_label = tr('Copy Selected Rows ({count})', count=len(selected_rows)) if len(selected_rows) > 1 else tr('Copy Selected Row')
        copy_action = QAction(QIcon(str(ICONS_DIR_PATH / 'copy.svg')), copy_label, menu)
        copy_action.setShortcut('Ctrl+C')
        copy_action.setToolTip(
            tr_plural(
                'Copy selected row to the clipboard as comma-separated values.',
                'Copy selected rows to the clipboard as comma-separated values.',
                len(selected_rows),
            ),
        )
        copy_action.setEnabled(has_selection)
        copy_action.triggered.connect(self._copy_selected)
        menu.addAction(copy_action)

        copy_all_action = QAction(QIcon(str(ICONS_DIR_PATH / 'copy.svg')), tr('Copy All'), menu)
        copy_all_action.setToolTip(tr('Copy all visible rows to the clipboard as comma-separated values.'))
        copy_all_action.setEnabled(self._proxy.rowCount() > 0)
        copy_all_action.triggered.connect(self._copy_all)
        menu.addAction(copy_all_action)

        menu.addSeparator()

        select_all_action = QAction(QIcon(str(ICONS_DIR_PATH / 'square-check.svg')), tr('Select All'), menu)
        select_all_action.setShortcut('Ctrl+A')
        select_all_action.setToolTip(tr('Select all visible rows.'))
        select_all_action.setEnabled(self._proxy.rowCount() > 0)
        select_all_action.triggered.connect(self._table.selectAll)
        menu.addAction(select_all_action)

        clear_selection_action = QAction(QIcon(str(ICONS_DIR_PATH / 'square.svg')), tr('Clear Selection'), menu)
        clear_selection_action.setToolTip(tr('Deselect all rows.'))
        clear_selection_action.triggered.connect(self._table.clearSelection)
        menu.addAction(clear_selection_action)

        selected_ips = self._get_selected_ips(index, selection_model)

        if len(selected_ips) == 1:
            menu.addSeparator()

            lookup_action = QAction(QIcon(str(ICONS_DIR_PATH / 'info.svg')), tr('IP Lookup Details\u2026'), menu)
            lookup_action.setToolTip(tr('Show detailed IP lookup information for this IP address.'))
            lookup_action.triggered.connect(lambda _checked=False, ip_address=selected_ips[0]: show_detailed_ip_lookup(ip_address))
            menu.addAction(lookup_action)

            create_ping_menu(self, menu, selected_ips)

            scan_ports_action = QAction(QIcon(str(ICONS_DIR_PATH / 'radar.svg')), tr('Scan Ports\u2026'), menu)
            scan_ports_action.setToolTip(tr('Scan TCP and UDP ports on this host.'))
            scan_ports_action.triggered.connect(lambda _checked=False, ip_address=selected_ips[0]: scan_ports_ip(ip_address))
            menu.addAction(scan_ports_action)
        elif len(selected_ips) > 1:
            menu.addSeparator()
            _target_ips = list(selected_ips)
            create_ping_menu(self, menu, _target_ips)

            scan_ports_action = QAction(QIcon(str(ICONS_DIR_PATH / 'radar.svg')), tr('Scan Ports\u2026'), menu)
            scan_ports_action.setToolTip(tr('Scan TCP and UDP ports on the selected hosts.'))

            def _scan_all_csv() -> None:
                scan_ports_ip(_target_ips)

            scan_ports_action.triggered.connect(_scan_all_csv)
            menu.addAction(scan_ports_action)

        menu.addSeparator()

        delete_label = tr('Delete Selected Rows ({count})', count=len(selected_rows)) if len(selected_rows) > 1 else tr('Delete Selected Row')
        delete_action = QAction(QIcon(str(ICONS_DIR_PATH / 'remove.svg')), delete_label, menu)
        delete_action.setShortcut('Delete')
        delete_action.setToolTip(tr('Remove selected rows from the log file permanently.'))
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

    def _toggle_column_visibility(self) -> None:
        action = self.sender()
        if isinstance(action, QAction):
            column = action.data()
            self._table.setColumnHidden(column, not action.isChecked())
            self._adjust_stretch_column_width()

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
        for model_index in sorted(indexes, key=lambda index: index.row()):
            source_row = self._proxy.mapToSource(model_index).row()
            cells: list[str] = []
            for column in range(column_count):
                item = self._model.item(source_row, column)
                cells.append(item.text() if item else '')
            lines.append(','.join(cells))

        set_clipboard_text('\n'.join(lines))
        animate_button_feedback(self._copy_button, feedback_text=f" {tr('Copied!')}", feedback_tooltip=tr('Copied to clipboard!'))

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
        if not self._file_path.is_file():
            return
        path, _ = QFileDialog.getSaveFileName(
            self,
            tr('Export Log As'),
            str(self._file_path.with_suffix('.export.csv')),
            f"{tr('CSV Files')} (*.csv);;{tr('All Files')} (*)",
        )
        if not path:
            return
        if self.isVisible():
            run_blocking_with_loading(
                self.window(),
                tr('Exporting CSV Log\u2026'),
                tr('Copying {filename}\u2026', filename=self._file_path.name),
                lambda: shutil.copy2(self._file_path, path),
            )
        else:
            shutil.copy2(self._file_path, path)
        self._show_status(tr('Exported to {path}', path=path))

    def _delete_selected_rows(self) -> None:
        selection_model = self._table.selectionModel()
        if not selection_model:
            return
        indexes = selection_model.selectedRows()
        if not indexes:
            return
        count = len(indexes)
        reply = QMessageBox.question(
            self,
            TITLE,
            tr_plural(
                'Delete {count} selected row from {filename}?\n\nThis cannot be undone.',
                'Delete {count} selected rows from {filename}?\n\nThis cannot be undone.',
                count,
                filename=self._file_path.name,
            ),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        source_rows = sorted((self._proxy.mapToSource(i).row() for i in indexes), reverse=True)
        dynamic_sort_filter = self._proxy.dynamicSortFilter()
        self._proxy.setDynamicSortFilter(False)
        try:
            for row in source_rows:
                self._model.removeRow(row)
            self._proxy.remove_source_rows(source_rows)
        finally:
            self._proxy.setDynamicSortFilter(dynamic_sort_filter)
            self._proxy.invalidate()

        was_truncated = self._truncated
        self._rewrite_csv_from_model()
        if was_truncated:
            self.load_data()
        else:
            self._update_counts()
            self._metadata_label.setText(file_metadata_text(self._file_path))
            self._purge_button.setEnabled(self._model.rowCount() > 0)
            self.purge_state_changed.emit()

    def _purge_file(self) -> None:
        if not self._model.rowCount():
            self._purge_button.setEnabled(False)
            return
        message = purge_log_file(self, self._file_path, item_label='entries')
        if message is not None:
            self._show_status(message)
            self.load_data()

    def _rewrite_csv_from_model(self) -> None:
        """Rewrite the CSV file from the current model contents."""
        headers = list(self._raw_csv_headers)
        model_rows = [
            [(item.text() if (item := self._model.item(row_index, column)) else '') for column in range(self._model.columnCount())]
            for row_index in range(self._model.rowCount())
        ]
        truncated = self._truncated
        file_path = self._file_path

        def _write_csv() -> None:
            overflow_rows: list[list[str]] = []
            if truncated and file_path.exists():
                with file_path.open(newline='', encoding='utf-8') as file:
                    reader = csv.reader(file)
                    next(reader, None)
                    overflow_rows = [row for row_num, row in enumerate(reader) if row_num >= MAX_CSV_ROWS]

            with file_path.open('w', newline='', encoding='utf-8') as file:
                writer = csv.writer(file)
                writer.writerow(headers)
                writer.writerows(model_rows)
                if overflow_rows:
                    writer.writerows(overflow_rows)

        if self.isVisible():
            run_blocking_with_loading(
                self.window(),
                tr('Updating CSV Log\u2026'),
                tr('Writing {filename}\u2026', filename=file_path.name),
                _write_csv,
            )
        else:
            _write_csv()

    def _show_status(self, message: str) -> None:
        QMessageBox.information(self, TITLE, message)
