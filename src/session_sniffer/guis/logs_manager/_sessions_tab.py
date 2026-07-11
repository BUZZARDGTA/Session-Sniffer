"""Sessions logging tab — folder tree + file viewer."""

import queue
import shutil
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, cast

from prettytable import PrettyTable, TableStyle
from pydantic import ValidationError
from PySide6.QtCore import QItemSelectionModel, QModelIndex, QPoint, Qt, QTimer, QUrl
from PySide6.QtGui import QColor, QDesktopServices, QIcon, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFileSystemModel,
    QHBoxLayout,
    QLabel,
    QMenu,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTextEdit,
    QTreeView,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.local import RESOURCES_DIR_PATH
from session_sniffer.constants.standalone import DATETIME_TRACKING_COLUMNS, SEARCHABLE_COLUMN_EXCLUSIONS, TITLE
from session_sniffer.guis.file_watch import DebouncedFileWatcher
from session_sniffer.guis.logs_manager._helpers import (
    copy_viewer_text_to_clipboard,
    create_log_viewer,
    create_search_input,
    open_file_location,
    prepare_search,
    setup_copy_save_button_row,
    setup_metadata_label,
)
from session_sniffer.guis.stylesheets import (
    DIALOG_BUTTON_STYLESHEET,
    DIALOG_DANGER_BUTTON_STYLESHEET,
    SVG_ICON_CONTEXT_MENU_STYLESHEET,
)
from session_sniffer.guis.userip_manager_helpers import human_readable_size
from session_sniffer.guis.utils import SPINNER_FRAMES, ElidedTextTooltipDelegate
from session_sniffer.models import SessionLogFile
from session_sniffer.settings import Settings

if TYPE_CHECKING:
    from typing import Any

_SEARCH_ALL = 'All Searchable Columns'
_SEARCH_COLUMN_USERNAMES = 'Usernames'
_SEARCH_COLUMN_IP = 'IP Address'
_SEARCH_COLUMN_HOSTNAME = 'Hostname'
_SEARCH_COLUMN_COUNTRY = 'Country'
_SEARCH_COLUMN_CITY = 'City'
_SEARCH_COLUMN_ISP = 'ISP'
_SEARCH_COLUMN_ASN = 'ASN'
_SEARCH_COLUMN_LAST_PORT = 'Last Port'
_SEARCH_COLUMN_MIDDLE_PORTS = 'Middle Ports'
_SEARCH_COLUMN_FIRST_PORT = 'First Port'
_SINGLE_FILE_VIEWER_PLACEHOLDER = 'Select a session JSON file from the tree to view its contents.'
_GLOBAL_SEARCH_VIEWER_PLACEHOLDER = 'Press Enter to search across all session JSON files.'


def _build_searchable_columns() -> tuple[str, ...]:
    columns: list[str] = []
    seen: set[str] = set()

    for source_columns in (Settings.GUI_ALL_CONNECTED_COLUMNS, Settings.GUI_ALL_DISCONNECTED_COLUMNS):
        for column in source_columns:
            if column in SEARCHABLE_COLUMN_EXCLUSIONS or column in seen:
                continue
            seen.add(column)
            columns.append(column)

    return (_SEARCH_ALL, *columns)


_SEARCHABLE_COLUMNS: tuple[str, ...] = _build_searchable_columns()


@dataclass(frozen=True, slots=True)
class _SessionTableRenderConfig:
    title: str
    sort_column: str
    descending: bool


class SessionsLogTab(QWidget):
    """Browse and view session JSON files in a YYYY/MM/DD folder hierarchy."""

    def __init__(self, sessions_dir: Path, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._sessions_dir = sessions_dir
        self._current_file: Path | None = None
        self._selected_path: Path | None = None
        self._global_search_active = False
        self._current_rendered_text = ''
        self._global_search_generation = 0
        self._global_search_thread: threading.Thread | None = None
        self._global_search_results_queue: queue.SimpleQueue[tuple[int, list[str], int, int]] = queue.SimpleQueue()
        self._loading_spinner_index = 0

        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)

        # --- Top bar ---
        top_bar = QHBoxLayout()

        self._search_input = create_search_input(top_bar, 'Search in displayed file…', self._on_search_changed)
        self._search_input.returnPressed.connect(self._on_search_return_pressed)

        self._search_column_combo = QComboBox()
        self._search_column_combo.addItems(_SEARCHABLE_COLUMNS)
        self._search_column_combo.setToolTip('Select which session fields to search')
        self._search_column_combo.currentTextChanged.connect(self._on_search_column_changed)
        top_bar.addWidget(QLabel('Column:'))
        top_bar.addWidget(self._search_column_combo)

        self._global_search_checkbox = QCheckBox('Search All Files')
        self._global_search_checkbox.setToolTip('Search across all session JSON files (read-only)')
        self._global_search_checkbox.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self._global_search_checkbox.toggled.connect(self._on_global_search_toggled)
        top_bar.addWidget(self._global_search_checkbox)

        self._match_label = QLabel('')
        top_bar.addWidget(self._match_label)

        self._loading_label = QLabel('')
        self._loading_label.setVisible(False)
        top_bar.addWidget(self._loading_label)

        self._file_info_label = QLabel('')
        top_bar.addWidget(self._file_info_label)

        layout.addLayout(top_bar)

        # --- Splitter: tree (left) | viewer (right) ---
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left: file tree
        self._sessions_dir.mkdir(parents=True, exist_ok=True)

        self._tree_container = QWidget()
        tree_container_layout = QVBoxLayout(self._tree_container)
        tree_container_layout.setContentsMargins(0, 0, 0, 0)
        tree_container_layout.setSpacing(0)

        self._fs_model = QFileSystemModel()
        self._fs_model.setRootPath(str(self._sessions_dir))
        self._fs_model.setNameFilters(['*.json'])
        self._fs_model.setNameFilterDisables(False)

        self._tree = QTreeView()
        self._tree.setModel(self._fs_model)
        self._tree.setRootIndex(self._fs_model.index(str(self._sessions_dir)))
        self._tree.setHeaderHidden(True)
        self._tree.setItemDelegate(ElidedTextTooltipDelegate(self._tree))
        self._tree.setWordWrap(False)
        self._tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._tree.customContextMenuRequested.connect(self._on_tree_context_menu)
        for column in (1, 2, 3):
            self._tree.setColumnHidden(column, True)  # noqa: FBT003
        self._tree.clicked.connect(self._on_tree_clicked)
        self._tree.activated.connect(self._on_tree_activated)
        selection_model = self._tree.selectionModel()
        if selection_model:
            selection_model.currentChanged.connect(self._on_tree_current_changed)
        self._tree.setMinimumWidth(200)

        tree_container_layout.addWidget(self._tree)
        splitter.addWidget(self._tree_container)

        # Right: text viewer
        self._viewer = create_log_viewer()
        self._viewer.setPlaceholderText(_SINGLE_FILE_VIEWER_PLACEHOLDER)

        splitter.addWidget(self._viewer)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 3)

        layout.addWidget(splitter, stretch=1)

        self._search_spinner_timer = QTimer(self)
        self._search_spinner_timer.setInterval(80)
        self._search_spinner_timer.timeout.connect(self._animate_search_spinner)

        self._search_poll_timer = QTimer(self)
        self._search_poll_timer.setInterval(40)
        self._search_poll_timer.timeout.connect(self._poll_global_search_result)

        # --- Directory metadata ---
        self._metadata_label = setup_metadata_label(layout)

        # --- Bottom buttons ---
        # pylint: disable=duplicate-code
        button_row = setup_copy_save_button_row(
            layout,
            self._copy_all,
            self._save_as,
            copy_tooltip='Copy all displayed text to clipboard',
            save_tooltip='Save the displayed file to a new location',
        )
        # pylint: enable=duplicate-code

        button_row.addStretch()

        self._delete_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'remove.svg')), ' Delete')
        self._delete_button.setStyleSheet(DIALOG_DANGER_BUTTON_STYLESHEET)
        self._delete_button.setToolTip('Delete the currently selected file or folder')
        self._delete_button.clicked.connect(self._delete_selected)
        button_row.addWidget(self._delete_button)

        self._open_location_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'folder.svg')), ' Open Folder Location')
        self._open_location_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        self._open_location_button.setToolTip('Open the containing folder in Windows Explorer')
        self._open_location_button.clicked.connect(self._open_location)
        button_row.addWidget(self._open_location_button)

        self._open_file_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'text_editor.svg')), ' Open File')
        self._open_file_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        self._open_file_button.setToolTip('Open the selected log file in the default text editor')
        self._open_file_button.clicked.connect(self._open_file)
        self._open_file_button.setEnabled(False)
        button_row.addWidget(self._open_file_button)

        # Live-refresh the currently displayed session file when it changes on disk.
        self._file_watcher = DebouncedFileWatcher(self, self._on_current_file_changed)

        # Initial metadata
        self.update_dir_metadata()

    # ------------------------------------------------------------------
    # Directory metadata
    # ------------------------------------------------------------------

    def update_dir_metadata(self) -> None:
        """Update the metadata label with total size and file count of the sessions directory."""
        if not self._sessions_dir.exists():
            self._metadata_label.setText(f'{self._sessions_dir.name}  —  Directory not found')
            return
        total_size = 0
        file_count = 0
        for f in self._sessions_dir.rglob('*.json'):
            if f.is_file():
                total_size += f.stat().st_size
                file_count += 1
        self._metadata_label.setText(
            f'{self._sessions_dir.name}  |  {human_readable_size(total_size)}  |  {file_count} json file(s)',
        )

    # ------------------------------------------------------------------
    # Tree interaction
    # ------------------------------------------------------------------

    def _on_tree_clicked(self, index: QModelIndex) -> None:
        self._handle_tree_selection(index)

    def _on_tree_activated(self, index: QModelIndex) -> None:
        self._handle_tree_selection(index)

    def _on_tree_context_menu(self, pos: QPoint) -> None:
        index = self._tree.indexAt(pos)
        if not index.isValid():
            return

        self._tree.setCurrentIndex(index)

        path = Path(self._fs_model.filePath(index))
        is_dir = path.is_dir()

        menu = QMenu(self)
        menu.setStyleSheet(SVG_ICON_CONTEXT_MENU_STYLESHEET)

        if not is_dir:
            open_action = menu.addAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'text_editor.svg')), 'Open File')
            if open_action:
                open_action.triggered.connect(self._open_file)

        location_text = 'Open Folder Location' if is_dir else 'Open File Location'
        location_action = menu.addAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'folder.svg')), location_text)
        if location_action:
            location_action.triggered.connect(self._open_location)

        menu.addSeparator()

        delete_action = menu.addAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'remove.svg')), 'Delete')
        if delete_action:
            delete_action.triggered.connect(self._delete_selected)

        viewport = self._tree.viewport()
        if viewport:
            menu.exec(viewport.mapToGlobal(pos))  # ty: ignore[invalid-argument-type]

    def _on_tree_current_changed(self, current: QModelIndex, _previous: QModelIndex) -> None:
        self._handle_tree_selection(current)

    def _handle_tree_selection(self, index: QModelIndex) -> None:
        if not index.isValid():
            self._selected_path = None
            self._file_watcher.stop()
            self._current_file = None
            self._current_rendered_text = ''
            self._viewer.setPlainText('')
            self._file_info_label.setText('')
            self._match_label.setText('')
            self._viewer.setExtraSelections([])
            self._delete_button.setText(' Delete')
            self._delete_button.setToolTip('Delete the currently selected file or folder')
            self._open_location_button.setText(' Open Folder Location')
            self._open_file_button.setEnabled(False)
            return
        selected = Path(self._fs_model.filePath(index))
        self._selected_path = selected
        if selected.is_file():
            self._load_file(selected)
            self._delete_button.setText(' Delete File')
            self._delete_button.setToolTip('Delete the currently selected session JSON file')
            self._open_location_button.setText(' Open File Location')
            self._open_file_button.setEnabled(True)
        elif selected.is_dir():
            self._file_watcher.stop()
            self._current_file = None
            self._current_rendered_text = ''
            self._viewer.setPlainText('')
            total_size = 0
            file_count = 0
            for f in selected.rglob('*.json'):
                if f.is_file():
                    total_size += f.stat().st_size
                    file_count += 1
            self._file_info_label.setText(
                f'{selected.name}  (folder)  |  {human_readable_size(total_size)}  |  {file_count} json file(s)',
            )
            self._match_label.setText('')
            self._viewer.setExtraSelections([])
            self._delete_button.setText(' Delete Folder')
            self._delete_button.setToolTip('Delete the currently selected folder and all its contents')
            self._open_location_button.setText(' Open Folder Location')
            self._open_file_button.setEnabled(False)

    def _load_file(self, file_path: Path) -> None:
        self._current_file = file_path
        self._file_watcher.watch(files=[file_path])
        text = self._render_session_file(file_path)
        self._current_rendered_text = text
        self._viewer.setPlainText(text)
        line_count = text.count('\n') + (1 if text and not text.endswith('\n') else 0)
        self._file_info_label.setText(
            f'{file_path.name}  |  {human_readable_size(file_path.stat().st_size)}  |  {line_count:,} rendered lines',
        )

        if self._search_input.text():
            self._on_search_changed(self._search_input.text())

    def _on_current_file_changed(self) -> None:
        """Re-render the displayed session file after it changes on disk."""
        if self._global_search_active or self._current_file is None or not self._current_file.is_file():
            return
        scrollbar = self._viewer.verticalScrollBar()
        previous_scroll = scrollbar.value() if scrollbar else 0
        at_bottom = scrollbar and previous_scroll >= scrollbar.maximum() - 5
        self._load_file(self._current_file)
        if scrollbar:
            scrollbar.setValue(scrollbar.maximum() if at_bottom else min(previous_scroll, scrollbar.maximum()))

    # ------------------------------------------------------------------
    # Search
    # ------------------------------------------------------------------

    def _on_search_column_changed(self, _value: str) -> None:
        self._on_search_changed(self._search_input.text())

    def _on_search_changed(self, text: str) -> None:
        if self._global_search_active:
            # Global search is expensive; only triggered on Enter, not per-keystroke.
            return

        selected_column = self._search_column_combo.currentText()
        if text and self._current_file is not None and not self._file_has_search_match(self._current_file, text, selected_column):
            self._viewer.setExtraSelections([])
            self._match_label.setText('No matches')
            return

        document = prepare_search(text, self._match_label, self._viewer)
        if document is None:
            return
        matched_cursors: list[QTextCursor] = []
        cursor = document.find(text)
        while not cursor.isNull():
            matched_cursors.append(QTextCursor(cursor))
            cursor = document.find(text, cursor)

        highlight_format = QTextCharFormat()
        highlight_format.setBackground(QColor('#665c00'))
        highlight_format.setForeground(QColor('#ffffff'))

        selections: list[Any] = []
        for match_cursor in matched_cursors:
            selection = cast('Any', QTextEdit.ExtraSelection())
            selection.cursor = match_cursor
            selection.format = highlight_format
            selections.append(selection)
        self._viewer.setExtraSelections(selections)

        if matched_cursors:
            self._viewer.setTextCursor(matched_cursors[0])
            self._viewer.centerCursor()

        self._match_label.setText(f'{len(matched_cursors)} match(es)' if matched_cursors else 'No matches')

    def _on_search_return_pressed(self) -> None:
        """Run global search on Enter. Activates global mode if not already active."""
        if self._global_search_active:
            self._start_global_search(self._search_input.text())
        else:
            self._global_search_checkbox.setChecked(True)

    def _on_global_search_toggled(self, checked: bool) -> None:  # noqa: FBT001
        """Switch between single-file view mode and global search mode."""
        if checked:
            self._file_watcher.stop()
            self._global_search_active = True
            self._clear_tree_selection()
            self._tree_container.setVisible(False)
            self._search_input.setPlaceholderText('Search across all session JSON files (press Enter)…')
            self._viewer.setPlaceholderText(_GLOBAL_SEARCH_VIEWER_PLACEHOLDER)
            self._tree.setEnabled(False)
            self._start_global_search(self._search_input.text())
        else:
            self._global_search_active = False
            self._stop_loading_animation()
            self._tree_container.setVisible(True)
            self._search_input.setPlaceholderText('Search in displayed file…')
            self._viewer.setPlaceholderText(_SINGLE_FILE_VIEWER_PLACEHOLDER)
            self._tree.setEnabled(True)
            self._viewer.setExtraSelections([])
            if self._current_file is not None:
                self._load_file(self._current_file)
            else:
                self._viewer.setPlainText('')
                self._match_label.setText('')
                self._file_info_label.setText('')
                self._current_rendered_text = ''

    def _clear_tree_selection(self) -> None:
        selection_model = self._tree.selectionModel()
        if selection_model:
            selection_model.clearSelection()
            selection_model.setCurrentIndex(QModelIndex(), QItemSelectionModel.SelectionFlag.Clear)
        self._tree.setCurrentIndex(QModelIndex())
        self._file_watcher.stop()
        self._selected_path = None
        self._current_file = None
        self._current_rendered_text = ''
        self._file_info_label.setText('')
        self._match_label.setText('')
        self._viewer.setPlainText('')

    def _start_global_search(self, text: str) -> None:
        """Clear the display and start an animated background search across all JSON files."""
        self._viewer.setExtraSelections([])
        self._current_rendered_text = ''
        self._selected_path = None
        self._current_file = None
        self._file_info_label.setText('')
        self._match_label.setText('')
        self._viewer.setPlainText('')

        if not text:
            self._loading_label.setVisible(False)
            self._search_spinner_timer.stop()
            self._search_poll_timer.stop()
            return

        self._global_search_generation += 1
        generation = self._global_search_generation
        selected_column = self._search_column_combo.currentText()

        self._loading_spinner_index = 0
        self._loading_label.setText(self._build_loading_text())
        self._loading_label.setVisible(True)
        self._search_spinner_timer.start()
        self._search_poll_timer.start()

        def worker() -> None:
            result_lines: list[str] | None = None
            total_matches = 0
            files_with_matches = 0
            try:
                result_lines, total_matches, files_with_matches = self._build_global_search_result(text, selected_column)
            finally:
                if result_lines is None:
                    result_lines = ['Global search failed unexpectedly. Please try again.']
            self._global_search_results_queue.put((generation, result_lines, total_matches, files_with_matches))

        self._global_search_thread = threading.Thread(target=worker, name=f'SessionsGlobalSearch-{generation}', daemon=True)
        self._global_search_thread.start()

    def _build_global_search_result(self, text: str, selected_column: str) -> tuple[list[str], int, int]:
        """Build the rendered output for a global JSON session search."""
        if not self._sessions_dir.exists():
            return ['[Sessions directory not found]'], 0, 0

        search_lower = text.lower()
        result_lines: list[str] = []
        file_blocks: list[tuple[Path, int, list[tuple[int, str, list[str] | None]], list[str]]] = []
        parsed_table_rows_by_length: dict[int, list[list[str]]] = {}
        total_matches = 0
        files_with_matches = 0

        for file_index, json_path in enumerate(sorted(self._sessions_dir.rglob('*.json')), start=1):
            if not json_path.is_file():
                continue

            # Yield periodically so the GUI thread keeps animating the spinner on heavy searches.
            if not file_index % 3:
                time.sleep(0)

            structured_matches = self._collect_structured_search_matches(json_path, search_lower, selected_column)
            if not structured_matches:
                continue

            lines = self._render_session_file(json_path).splitlines()
            line_number_width = len(str(len(lines)))

            relative = json_path.relative_to(self._sessions_dir)
            line_matches: list[tuple[int, str, list[str] | None]] = []
            for line_num, line in enumerate(lines, start=1):
                if not line_num % 400:
                    time.sleep(0)
                if search_lower in line.lower():
                    parsed_cells = self._try_parse_prettytable_row(line)
                    if parsed_cells is not None:
                        row_length = len(parsed_cells)
                        parsed_table_rows_by_length.setdefault(row_length, []).append(parsed_cells)
                    line_matches.append((line_num, line, parsed_cells))
                    total_matches += 1

            if line_matches:
                files_with_matches += 1
                file_blocks.append((relative, line_number_width, line_matches, []))
            else:
                # Fallback when rendered-line matching is sparse but structured field match exists.
                files_with_matches += 1
                total_matches += len(structured_matches)
                file_blocks.append((relative, line_number_width, [], structured_matches))

        column_widths_by_length: dict[int, list[int]] = {}
        for row_length, rows in parsed_table_rows_by_length.items():
            column_widths: list[int] = []
            for cells in rows:
                for i, cell in enumerate(cells):
                    if i >= len(column_widths):
                        column_widths.append(len(cell))
                    else:
                        column_widths[i] = max(column_widths[i], len(cell))
            column_widths_by_length[row_length] = column_widths

        for relative, line_number_width, line_matches, structured_matches in file_blocks:
            if result_lines:
                result_lines.append('')
            result_lines.append(f'── {relative} ──')
            if line_matches:
                result_lines.extend(
                    self._render_aligned_line_matches(
                        line_matches=line_matches,
                        line_number_width=line_number_width,
                        column_widths_by_length=column_widths_by_length,
                    ),
                )
            else:
                result_lines.extend(structured_matches)

        if not result_lines:
            result_lines = [f'No matches found for "{text}" in any session JSON file.']

        return result_lines, total_matches, files_with_matches

    def _poll_global_search_result(self) -> None:
        latest_result: tuple[int, list[str], int, int] | None = None
        while True:
            try:
                queued = self._global_search_results_queue.get_nowait()
            except queue.Empty:
                break
            if queued[0] == self._global_search_generation:
                latest_result = queued

        if latest_result is None:
            if self._global_search_thread is not None and self._global_search_thread.is_alive():
                return
            if self._loading_label.isVisible() and self._global_search_thread is not None:
                self._stop_loading_animation()
                self._match_label.setText('Search failed')
                if not self._viewer.toPlainText():
                    self._viewer.setPlainText('Global search did not return results. Please try again.')
            return

        generation, result_lines, total_matches, files_with_matches = latest_result

        if generation != self._global_search_generation:
            return

        self._stop_loading_animation()
        self._viewer.setPlainText('\n'.join(result_lines))
        self._match_label.setText(f'{total_matches} match(es)' if total_matches else 'No matches')
        self._file_info_label.setText(
            f'Global search  |  {files_with_matches} file(s) matched' if total_matches else '',
        )

    def _build_loading_text(self) -> str:
        return f'{SPINNER_FRAMES[self._loading_spinner_index]} Searching...'

    def _animate_search_spinner(self) -> None:
        if not self._loading_label.isVisible():
            return
        self._loading_spinner_index = (self._loading_spinner_index + 1) % len(SPINNER_FRAMES)
        self._loading_label.setText(self._build_loading_text())

    def _stop_loading_animation(self) -> None:
        self._search_spinner_timer.stop()
        self._search_poll_timer.stop()
        self._loading_label.setVisible(False)

    @staticmethod
    def _normalize_search_value(value: object) -> str:
        if isinstance(value, list):
            values = cast('list[object]', value)
            return ', '.join(str(v) for v in values)
        if value is None:
            return ''
        return str(value)

    @staticmethod
    def _try_parse_prettytable_row(line: str) -> list[str] | None:
        stripped = line.strip()
        if not stripped.startswith('│') or not stripped.endswith('│'):
            return None
        raw_cells = stripped.split('│')[1:-1]
        if not raw_cells:
            return None
        return [cell.strip() for cell in raw_cells]

    @staticmethod
    def _format_prettytable_row(cells: list[str], column_widths: list[int]) -> str:
        padded = [cell.ljust(column_widths[i]) if i < len(column_widths) else cell for i, cell in enumerate(cells)]
        return f'│ {" │ ".join(padded)} │'

    @staticmethod
    def _build_effective_column_widths(base_widths: list[int], header_cells: list[str]) -> list[int]:
        effective_widths = list(base_widths)
        for i, header_cell in enumerate(header_cells):
            header_len = len(header_cell)
            if i >= len(effective_widths):
                effective_widths.append(header_len)
            else:
                effective_widths[i] = max(effective_widths[i], header_len)
        return effective_widths

    @staticmethod
    def _format_prettytable_separator(column_widths: list[int], column_count: int) -> str:
        if column_count <= 0:
            return ''
        widths = [column_widths[i] if i < len(column_widths) else 0 for i in range(column_count)]
        return f'├─{"─┼─".join("─" * width for width in widths)}─┤'

    @staticmethod
    def _column_headers_for_row_length(row_length: int) -> list[str] | None:
        connected_columns = list(Settings.GUI_ALL_CONNECTED_COLUMNS)
        disconnected_columns = list(Settings.GUI_ALL_DISCONNECTED_COLUMNS)

        if row_length == len(connected_columns):
            return connected_columns
        if row_length == len(disconnected_columns):
            return disconnected_columns
        return None

    def _render_aligned_line_matches(
        self,
        *,
        line_matches: list[tuple[int, str, list[str] | None]],
        line_number_width: int,
        column_widths_by_length: dict[int, list[int]],
    ) -> list[str]:
        rendered_lines: list[str] = []
        active_row_length = -1
        active_column_widths: list[int] = []
        has_rendered_schema_header = False

        for line_num, line, parsed_cells in line_matches:
            rendered_line = line
            if parsed_cells is not None:
                row_length = len(parsed_cells)
                if row_length != active_row_length:
                    if has_rendered_schema_header:
                        rendered_lines.append('')
                    active_row_length = row_length
                    active_column_widths = list(column_widths_by_length.get(row_length, []))
                    header_cells = self._column_headers_for_row_length(row_length)
                    if header_cells is not None:
                        schema_label = self._schema_label_for_row_length(row_length)
                        if schema_label:
                            rendered_lines.append(f'  {" " * line_number_width}  ── {schema_label} ──')
                        active_column_widths = self._build_effective_column_widths(active_column_widths, header_cells)
                        header_row = self._format_prettytable_row(header_cells, active_column_widths)
                        separator_row = self._format_prettytable_separator(active_column_widths, len(header_cells))
                        rendered_lines.append(f'  {" " * line_number_width}  {header_row}')
                        rendered_lines.append(f'  {" " * line_number_width}  {separator_row}')
                        has_rendered_schema_header = True
                rendered_line = self._format_prettytable_row(parsed_cells, active_column_widths)
            rendered_lines.append(f'  {line_num:>{line_number_width}}: {rendered_line}')

        return rendered_lines

    @staticmethod
    def _schema_label_for_row_length(row_length: int) -> str | None:
        if row_length == len(Settings.GUI_ALL_CONNECTED_COLUMNS):
            return 'Connected Columns'
        if row_length == len(Settings.GUI_ALL_DISCONNECTED_COLUMNS):
            return 'Disconnected Columns'
        return None

    @classmethod
    def _build_player_search_fields(cls, ip: str, info: dict[str, Any]) -> dict[str, str]:
        return {
            _SEARCH_COLUMN_USERNAMES: cls._normalize_search_value(info.get('Usernames')),
            _SEARCH_COLUMN_IP: ip,
            _SEARCH_COLUMN_HOSTNAME: cls._normalize_search_value(info.get('Hostname')),
            _SEARCH_COLUMN_COUNTRY: cls._normalize_search_value(info.get('Country')),
            _SEARCH_COLUMN_CITY: cls._normalize_search_value(info.get('City')),
            _SEARCH_COLUMN_ISP: cls._normalize_search_value(info.get('ISP')),
            _SEARCH_COLUMN_ASN: cls._normalize_search_value(info.get('ASN')),
            _SEARCH_COLUMN_LAST_PORT: cls._normalize_search_value(info.get('Last Port')),
            _SEARCH_COLUMN_MIDDLE_PORTS: cls._normalize_search_value(info.get('Middle Ports')),
            _SEARCH_COLUMN_FIRST_PORT: cls._normalize_search_value(info.get('First Port')),
        }

    @classmethod
    def _iter_json_text_values(cls, value: object) -> list[str]:
        if isinstance(value, dict):
            mapping = cast('dict[object, object]', value)
            texts: list[str] = []
            for item in mapping.values():
                texts.extend(cls._iter_json_text_values(item))
            return texts
        if isinstance(value, list):
            values = cast('list[object]', value)
            texts = []
            for item in values:
                texts.extend(cls._iter_json_text_values(item))
            return texts
        if value is None:
            return []
        return [str(value)]

    @staticmethod
    def _load_session_log_file(file_path: Path) -> SessionLogFile:
        return SessionLogFile.model_validate_json(file_path.read_text(encoding='utf-8', errors='replace'))

    def _collect_structured_search_matches(self, file_path: Path, search_lower: str, selected_column: str) -> list[str]:
        try:
            session_log = self._load_session_log_file(file_path)
        except OSError, ValidationError:
            return []

        matches: list[str] = []

        for section_name, players in (('connected', session_log.connected), ('disconnected', session_log.disconnected)):
            for ip, info in players.items():
                fields = self._build_player_search_fields(ip, info)
                if selected_column == _SEARCH_ALL:
                    matched_columns = []
                    all_text = ' '.join(self._iter_json_text_values(info))
                    if search_lower in all_text.lower():
                        matched_columns = list(fields)
                else:
                    selected_value = fields.get(selected_column, '')
                    matched_columns = [selected_column] if search_lower in selected_value.lower() else []

                if matched_columns:
                    preview = ', '.join(f'{column}: {fields[column]}' for column in matched_columns)
                    matches.append(f'  [{section_name}] {ip}  |  {preview}')

        return matches

    def _file_has_search_match(self, file_path: Path, text: str, selected_column: str) -> bool:
        return bool(self._collect_structured_search_matches(file_path, text.lower(), selected_column))

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _copy_all(self) -> None:
        copy_viewer_text_to_clipboard(self, self._viewer, success_label='contents')

    def _save_as(self) -> None:
        if self._current_file is None:
            QMessageBox.information(self, TITLE, 'No file selected.')
            return
        default_name = str(self._current_file.with_suffix('.export.log'))
        path, _ = QFileDialog.getSaveFileName(
            self,
            'Save Session Log As',
            default_name,
            'Log Files (*.log);;Text Files (*.txt);;All Files (*)',
        )
        if not path:
            return
        Path(path).write_text(self._current_rendered_text or self._viewer.toPlainText(), encoding='utf-8')
        QMessageBox.information(self, TITLE, f'Saved to {path}')

    # ------------------------------------------------------------------
    # Session rendering
    # ------------------------------------------------------------------

    @staticmethod
    def _format_session_datetime(value: object) -> str:
        if not isinstance(value, str) or not value:
            return 'N/A'
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            return value
        return parsed.strftime('%H:%M:%S.%f')[:-3]

    @staticmethod
    def _format_bool(value: object) -> str:
        if isinstance(value, bool):
            return 'Yes' if value else 'No'
        return '...'

    @staticmethod
    def _format_table_value(value: object) -> str:
        if value is None:
            return 'N/A'
        if isinstance(value, bool):
            return 'Yes' if value else 'No'
        if isinstance(value, list):
            items = cast('list[object]', value)
            return ', '.join(str(item) for item in items)
        return str(value)

    @staticmethod
    def _get_column_snapshot(player_info: dict[str, Any]) -> dict[str, Any]:
        columns_raw = player_info.get('columns')
        if isinstance(columns_raw, dict):
            return cast('dict[str, Any]', columns_raw)
        return player_info

    @classmethod
    def _build_session_table(
        cls,
        *,
        players: dict[str, dict[str, Any]],
        column_names: tuple[str, ...],
        config: _SessionTableRenderConfig,
    ) -> PrettyTable:
        table = PrettyTable()
        table.set_style(TableStyle.SINGLE_BORDER)
        table.title = config.title
        table.field_names = [
            f'{column} ↓' if column == config.sort_column and config.descending else f'{column} ↑' if column == config.sort_column else column for column in column_names
        ]
        table.align = 'l'

        sorted_players = sorted(
            players.items(),
            key=lambda item: cls._get_column_snapshot(item[1]).get(config.sort_column, ''),
            reverse=config.descending,
        )
        for ip, info in sorted_players:
            columns = cls._get_column_snapshot(info)
            row = [
                cls._format_session_datetime(columns.get(column_name, info.get(column_name, 'N/A')))
                if column_name in DATETIME_TRACKING_COLUMNS
                else cls._format_table_value(columns.get(column_name, info.get(column_name, 'N/A')))
                if column_name != 'IP Address'
                else cls._format_table_value(ip)
                for column_name in column_names
            ]
            table.add_row(row)

        return table

    @classmethod
    def _build_connected_table(cls, players: dict[str, dict[str, Any]]) -> PrettyTable:
        return cls._build_session_table(
            players=players,
            column_names=Settings.GUI_ALL_CONNECTED_COLUMNS,
            config=_SessionTableRenderConfig(
                title=f'Players connected in your session ({len(players)}):',
                sort_column='Last Rejoin',
                descending=True,
            ),
        )

    @classmethod
    def _build_disconnected_table(cls, players: dict[str, dict[str, Any]]) -> PrettyTable:
        return cls._build_session_table(
            players=players,
            column_names=Settings.GUI_ALL_DISCONNECTED_COLUMNS,
            config=_SessionTableRenderConfig(
                title=f"Players who've left your session ({len(players)}):",
                sort_column='Last Seen',
                descending=False,
            ),
        )

    def _render_session_file(self, file_path: Path) -> str:
        try:
            session_log = self._load_session_log_file(file_path)
        except (OSError, ValidationError) as e:
            return f'[Failed to parse JSON session file: {file_path.name}]\n{e}'

        connected_table = self._build_connected_table(session_log.connected)
        disconnected_table = self._build_disconnected_table(session_log.disconnected)
        return f'{connected_table.get_string()}\n{disconnected_table.get_string()}'

    def _delete_selected(self) -> None:
        target = self._selected_path
        if target is None or not target.exists():
            QMessageBox.information(self, TITLE, 'No file or folder selected.')
            return

        is_dir = target.is_dir()
        kind = 'folder' if is_dir else 'file'
        extra = '\n\nAll contents within the folder will be removed.' if is_dir else ''
        reply = QMessageBox.warning(
            self,
            TITLE,
            f'Delete {kind} "{target.name}"?{extra}\n\nThis cannot be undone.',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        if is_dir:
            shutil.rmtree(target)
        else:
            target.unlink()
        self._viewer.clear()
        self._file_info_label.setText('')
        self._current_file = None
        self._selected_path = None
        self._current_rendered_text = ''
        self.update_dir_metadata()
        self._delete_button.setText(' Delete')
        self._delete_button.setToolTip('Delete the currently selected file or folder')
        self._open_location_button.setText(' Open Folder Location')
        self._open_file_button.setEnabled(False)

    def _open_location(self) -> None:
        if self._selected_path and self._selected_path.exists():
            if self._selected_path.is_dir():
                QDesktopServices.openUrl(QUrl.fromLocalFile(str(self._selected_path)))
            else:
                open_file_location(self._selected_path)
        elif self._sessions_dir.exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(self._sessions_dir)))

    def _open_file(self) -> None:
        if self._selected_path and self._selected_path.is_file():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(self._selected_path)))
