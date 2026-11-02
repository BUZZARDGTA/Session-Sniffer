"""Sessions logging tab — folder tree + file viewer."""

import logging
import os
import queue
import shutil
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, cast

from pydantic import ValidationError
from PySide6.QtCore import QItemSelectionModel, QModelIndex, QPoint, QSignalBlocker, Qt, QTimer, QUrl
from PySide6.QtGui import QDesktopServices, QIcon
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
    QTreeView,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.local import RESOURCES_DIR_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.constants.standard import LOCAL_TZ
from session_sniffer.constants.tables import DATETIME_TRACKING_COLUMNS, SEARCHABLE_COLUMN_EXCLUSIONS
from session_sniffer.guis.delegates import ElidedTextTooltipDelegate
from session_sniffer.guis.file_watch import DebouncedFileWatcher
from session_sniffer.guis.logs_manager._helpers import (
    copy_viewer_text_to_clipboard,
    create_log_viewer,
    create_search_input,
    find_and_highlight_matches,
    prepare_search,
    setup_copy_save_button_row,
    setup_metadata_label,
)
from session_sniffer.guis.stylesheets import DIALOG_BUTTON_STYLESHEET, DIALOG_DANGER_BUTTON_STYLESHEET, SVG_ICON_CONTEXT_MENU_STYLESHEET
from session_sniffer.guis.userip_manager_helpers import human_readable_size
from session_sniffer.guis.utils import SPINNER_FRAMES, open_file_location
from session_sniffer.models import SessionLogFile
from session_sniffer.settings import Settings
from session_sniffer.text_utils import format_single_border_table, pluralize

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from typing import Any

_SEARCH_ALL = 'All Searchable Columns'
_SINGLE_FILE_VIEWER_PLACEHOLDER = 'Select a session JSON file from the tree to view its contents.'
_GLOBAL_SEARCH_VIEWER_PLACEHOLDER = 'Press Enter to search across all session JSON files.'


def _build_searchable_columns() -> tuple[str, ...]:
    columns: list[str] = []
    seen: set[str] = set()
    for source_columns in (Settings.GUI_ALL_CONNECTED_COLUMNS, Settings.GUI_ALL_DISCONNECTED_COLUMNS):
        for column in source_columns:
            if column not in SEARCHABLE_COLUMN_EXCLUSIONS and column not in seen:
                seen.add(column)
                columns.append(column)
    return (_SEARCH_ALL, *columns)


_SEARCHABLE_COLUMNS: tuple[str, ...] = _build_searchable_columns()
_GLOBAL_SEARCH_WORKERS = 16


@dataclass(frozen=True, slots=True)
class _SessionTableRenderConfig:
    title: str
    sort_column: str
    descending: bool


@dataclass(frozen=True, slots=True)
class _CachedPlayerSearchEntry:
    section_name: str
    ip: str
    fields: dict[str, str]
    fields_lower: dict[str, str]
    all_fields_lower: str
    fallback_all_text_lower: str
    non_empty_columns: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _CachedTableRow:
    line_num: int
    line: str
    parsed_cells: list[str]
    cells_by_col_lower: dict[str, str]
    all_cells_lower: str
    has_headers: bool


@dataclass(slots=True)
class _CachedSessionFile:
    mtime_ns: int
    size: int
    session_log: SessionLogFile
    player_entries: tuple[_CachedPlayerSearchEntry, ...]
    combined_haystack_lower: str
    rendered_text: str | None = None
    line_number_width: int = 0
    table_rows: tuple[_CachedTableRow, ...] | None = None


class SessionsLogTab(QWidget):
    """Browse and view session JSON files in a YYYY/MM/DD folder hierarchy."""

    def __init__(self, sessions_dir: Path, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._sessions_dir = sessions_dir
        self._current_file: Path | None = None
        self._saved_file_before_global_search: Path | None = None
        self._selected_path: Path | None = None
        self._global_search_active = False
        self._current_rendered_text = ''
        self._global_search_generation = 0
        self._global_search_thread: threading.Thread | None = None
        self._global_search_results_queue: queue.SimpleQueue[tuple[int, list[str], int, int]] = queue.SimpleQueue()
        self._loading_spinner_index = 0
        self._cache_lock = threading.Lock()
        self._session_file_cache: dict[Path, _CachedSessionFile] = {}

        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)

        top_bar = QHBoxLayout()
        self._search_input = create_search_input(top_bar, 'Search in displayed file…', self._on_search_changed, debounce_ms=60)
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

        splitter = QSplitter(Qt.Orientation.Horizontal)
        self._sessions_dir.mkdir(parents=True, exist_ok=True)

        self._tree_container = QWidget()
        tree_container_layout = QVBoxLayout(self._tree_container)
        tree_container_layout.setContentsMargins(0, 0, 0, 0)
        tree_container_layout.setSpacing(0)

        self._fs_model = QFileSystemModel(self)
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
            self._tree.hideColumn(column)
        self._tree.clicked.connect(self._on_tree_clicked)
        self._tree.activated.connect(self._on_tree_activated)
        if selection_model := self._tree.selectionModel():
            selection_model.currentChanged.connect(self._on_tree_current_changed)
        self._tree.setMinimumWidth(200)

        tree_container_layout.addWidget(self._tree)
        splitter.addWidget(self._tree_container)

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

        self._metadata_label = setup_metadata_label(layout)
        button_row, self._copy_button, self._save_button = setup_copy_save_button_row(
            layout, self._copy_all, self._save_as, save_tooltip='Save the displayed file to a new location',
        )
        button_row.addStretch()

        self._delete_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'remove.svg')), ' Delete')
        self._delete_button.setStyleSheet(DIALOG_DANGER_BUTTON_STYLESHEET)
        self._delete_button.setToolTip('Delete the currently selected file or folder')
        self._delete_button.setEnabled(False)
        self._delete_button.clicked.connect(self._delete_selected)
        button_row.addWidget(self._delete_button)

        self._open_location_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'folder.svg')), ' Open Folder Location')
        self._open_location_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        self._open_location_button.setToolTip('Open the containing folder in Windows Explorer')
        self._open_location_button.clicked.connect(self._open_location)
        button_row.addWidget(self._open_location_button)

        self._open_file_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'file-text.svg')), ' Open File')
        self._open_file_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        self._open_file_button.setToolTip('Open the selected log file in the default text editor')
        self._open_file_button.clicked.connect(self._open_file)
        self._open_file_button.setEnabled(False)
        button_row.addWidget(self._open_file_button)

        self._watching_stopped: bool = False
        self._file_watcher = DebouncedFileWatcher(self, self._on_current_file_changed)
        self.update_dir_metadata()

    def start_watching(self) -> None:
        """Resume watching the currently selected session file."""
        if self._watching_stopped:
            self._watching_stopped = False
            self.update_dir_metadata()
            if self._selected_path is not None and self._selected_path.is_file():
                self._file_watcher.watch(files=[self._selected_path])
                self._on_current_file_changed()

    def stop_watching(self) -> None:
        """Stop watching session files."""
        self._watching_stopped = True
        self._file_watcher.stop()

    @classmethod
    def _count_json_files_and_size(cls, directory: Path) -> tuple[int, int]:
        """Return `(total_bytes, file_count)` for all `.json` files under *directory*."""
        files = cls._collect_session_json_files(directory)
        return sum(size for _, _, size in files), len(files)

    @staticmethod
    def _collect_session_json_files(directory: Path) -> list[tuple[Path, int, int]]:
        """Return sorted `(file_path, mtime_ns, size)` tuples for all `.json` files under *directory*."""
        if not directory.is_dir():
            return []
        collected: list[tuple[Path, int, int]] = []
        stack = [str(directory)]
        while stack:
            try:
                with os.scandir(stack.pop()) as it:
                    for entry in it:
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(entry.path)
                        elif entry.name.endswith('.json') and entry.is_file(follow_symlinks=False):
                            st = entry.stat(follow_symlinks=False)
                            collected.append((Path(entry.path), st.st_mtime_ns, st.st_size))
            except OSError:
                continue
        collected.sort(key=lambda item: item[0])
        return collected

    def update_dir_metadata(self) -> None:
        """Update the metadata label with total size and file count of the sessions directory."""
        if self._selected_path is not None:
            if not self._selected_path.exists():
                self._clear_tree_selection()
            elif self._selected_path.is_dir() and not self._global_search_active:
                folder_size, folder_count = self._count_json_files_and_size(self._selected_path)
                size_str = human_readable_size(folder_size)
                self._file_info_label.setText(f'{self._selected_path.name}  (folder)  |  {size_str}  |  {folder_count} json file{pluralize(folder_count)}')
        if not self._sessions_dir.exists():
            self._metadata_label.setText(f'{self._sessions_dir.name}  —  Directory not found')
            return
        total_size, file_count = self._count_json_files_and_size(self._sessions_dir)
        self._metadata_label.setText(f'{self._sessions_dir.name}  |  {human_readable_size(total_size)}  |  {file_count} json file{pluralize(file_count)}')

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

        if not is_dir and (open_action := menu.addAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'file-text.svg')), 'Open File')):
            open_action.triggered.connect(self._open_file)

        location_text = 'Open Folder Location' if is_dir else 'Open File Location'
        if location_action := menu.addAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'folder.svg')), location_text):
            location_action.triggered.connect(self._open_location)

        menu.addSeparator()
        if delete_action := menu.addAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'remove.svg')), 'Delete'):
            delete_action.triggered.connect(self._delete_selected)

        if viewport := self._tree.viewport():
            menu.exec(viewport.mapToGlobal(pos))

    def _on_tree_current_changed(self, current: QModelIndex, _previous: QModelIndex) -> None:
        self._handle_tree_selection(current)

    def _handle_tree_selection(self, index: QModelIndex) -> None:
        if not index.isValid():
            self._file_watcher.stop()
            self._reset_selection_display()
            return
        selected = Path(self._fs_model.filePath(index))
        if selected == self._selected_path:
            return
        if selected.is_file():
            self._apply_file_selection(selected)
        elif selected.is_dir():
            self._apply_folder_selection(selected)

    def _set_viewer_content(self, text: str, placeholder_text: str) -> None:
        """Update the viewer content, placeholder text, and Copy/Save button states."""
        self._current_rendered_text = text
        self._viewer.setPlaceholderText(placeholder_text)
        self._viewer.setPlainText(text)
        if not text:
            self._viewer.setExtraSelections([])
        has_text = bool(text)
        self._copy_button.setEnabled(has_text)
        self._save_button.setEnabled(has_text)

    def _reset_selection_display(self) -> None:
        """Clear the selected path, viewer state, and disable file/folder action buttons."""
        self._selected_path = None
        self._current_file = None
        self._file_info_label.setText('')
        self._match_label.setText('')
        self._set_viewer_content('', _GLOBAL_SEARCH_VIEWER_PLACEHOLDER if self._global_search_active else _SINGLE_FILE_VIEWER_PLACEHOLDER)
        self._delete_button.setText(' Delete')
        self._delete_button.setToolTip('Delete the currently selected file or folder')
        self._delete_button.setEnabled(False)
        self._open_location_button.setText(' Open Folder Location')
        self._open_file_button.setEnabled(False)

    def _apply_file_selection(self, file_path: Path) -> None:
        """Select *file_path*, render its contents, and enable file action buttons."""
        self._selected_path = file_path
        self._load_file(file_path)
        self._delete_button.setText(' Delete File')
        self._delete_button.setToolTip('Delete the currently selected session JSON file')
        self._delete_button.setEnabled(True)
        self._open_location_button.setText(' Open File Location')
        self._open_file_button.setEnabled(file_path.is_file())

    def _apply_folder_selection(self, folder_path: Path) -> None:
        """Select *folder_path*, display its folder summary, and update folder action buttons."""
        self._selected_path = folder_path
        self._file_watcher.stop()
        self._current_file = None
        self._set_viewer_content('', _SINGLE_FILE_VIEWER_PLACEHOLDER)
        total_size, file_count = self._count_json_files_and_size(folder_path)
        self._file_info_label.setText(f'{folder_path.name}  (folder)  |  {human_readable_size(total_size)}  |  {file_count} json file{pluralize(file_count)}')
        self._match_label.setText('')
        self._delete_button.setText(' Delete Folder')
        self._delete_button.setToolTip('Delete the currently selected folder and all its contents')
        self._delete_button.setEnabled(True)
        self._open_location_button.setText(' Open Folder Location')
        self._open_file_button.setEnabled(False)

    def _load_file(self, file_path: Path) -> None:
        self._current_file = file_path
        self._file_watcher.watch(files=[file_path])
        text = self._render_session_file(file_path)
        if text is None:
            self._current_file = None
            self._set_viewer_content('', f'[Failed to parse JSON session file: {file_path.name}]')
            self._file_info_label.setText(f'{file_path.name}  |  Failed to parse')
            self._match_label.setText('')
            return
        self._set_viewer_content(text, _SINGLE_FILE_VIEWER_PLACEHOLDER)
        line_count = text.count('\n') + (1 if text and not text.endswith('\n') else 0)
        self._file_info_label.setText(f'{file_path.name}  |  {human_readable_size(file_path.stat().st_size)}  |  {line_count:,} rendered lines')
        if self._search_input.text():
            self._on_search_changed(self._search_input.text())
        else:
            self._match_label.setText('')
            self._viewer.setExtraSelections([])

    def _on_current_file_changed(self) -> None:
        """Re-render the displayed session file after it changes on disk."""
        target_file = self._current_file or (self._selected_path if self._selected_path is not None and not self._selected_path.is_dir() else None)
        if self._global_search_active or target_file is None:
            return
        if not target_file.is_file():
            self._clear_tree_selection()
            self.update_dir_metadata()
            return
        scrollbar = self._viewer.verticalScrollBar()
        previous_scroll = scrollbar.value() if scrollbar else 0
        at_bottom = scrollbar and previous_scroll >= scrollbar.maximum() - 5
        self._load_file(target_file)
        if scrollbar:
            scrollbar.setValue(scrollbar.maximum() if at_bottom else min(previous_scroll, scrollbar.maximum()))

    def _on_search_column_changed(self, _value: str) -> None:
        if self._global_search_active:
            self._start_global_search(self._search_input.text())
            return
        self._on_search_changed(self._search_input.text())

    def _on_search_changed(self, text: str) -> None:
        if self._global_search_active:
            if not text:
                self._start_global_search('')
            return
        if self._current_file is None:
            self._viewer.setExtraSelections([])
            self._match_label.setText('')
            return
        selected_column = self._search_column_combo.currentText()
        if text and not self._file_has_search_match(self._current_file, text, selected_column):
            self._viewer.setExtraSelections([])
            self._match_label.setText('No matches')
            return
        if (document := prepare_search(text, self._match_label, self._viewer)) is None:
            return
        matched_cursors = find_and_highlight_matches(document, text, self._viewer)
        if matched_cursors:
            self._viewer.setTextCursor(matched_cursors[0])
            self._viewer.centerCursor()
        self._match_label.setText(f'{len(matched_cursors)} match{pluralize(len(matched_cursors), "", "es")}' if matched_cursors else 'No matches')

    def set_search_global(self, text: str) -> None:
        """Programmatically activate global search mode with the given text and start the search."""
        with QSignalBlocker(self._search_input):
            self._search_input.setText(text)
        if self._global_search_checkbox.isChecked():
            self._start_global_search(text)
        else:
            self._global_search_checkbox.setChecked(True)

    def _on_search_return_pressed(self) -> None:
        """Run global search on Enter. Activates global mode if not already active."""
        if self._global_search_active:
            self._start_global_search(self._search_input.text())
        else:
            self._global_search_checkbox.setChecked(True)

    def _on_global_search_toggled(self) -> None:
        """Switch between single-file view mode and global search mode."""
        if self._global_search_checkbox.isChecked():
            self._file_watcher.stop()
            self._saved_file_before_global_search = self._selected_path
            self._global_search_active = True
            self._clear_tree_selection()
            self._tree_container.setVisible(False)
            self._search_input.setPlaceholderText('Search across all session JSON files (press Enter)…')
            self._viewer.setPlaceholderText(_GLOBAL_SEARCH_VIEWER_PLACEHOLDER)
            self._tree.setEnabled(False)
            self._start_global_search(self._search_input.text())
        else:
            self._global_search_active = False
            self._global_search_generation += 1
            self._stop_loading_animation()
            self._tree_container.setVisible(True)
            self._search_input.setPlaceholderText('Search in displayed file…')
            self._viewer.setPlaceholderText(_SINGLE_FILE_VIEWER_PLACEHOLDER)
            self._tree.setEnabled(True)
            self._viewer.setExtraSelections([])
            restored_path, self._saved_file_before_global_search = self._saved_file_before_global_search, None
            if isinstance(restored_path, Path) and restored_path.exists():
                if (index := self._fs_model.index(str(restored_path))).isValid():
                    self._tree.setCurrentIndex(index)
                if self._selected_path != restored_path:
                    if restored_path.is_file():
                        self._apply_file_selection(restored_path)
                    elif restored_path.is_dir():
                        self._apply_folder_selection(restored_path)
            else:
                self._reset_selection_display()

    def _clear_tree_selection(self) -> None:
        if selection_model := self._tree.selectionModel():
            selection_model.clearSelection()
            selection_model.setCurrentIndex(QModelIndex(), QItemSelectionModel.SelectionFlag.Clear)
        self._tree.setCurrentIndex(QModelIndex())
        self._file_watcher.stop()
        self._reset_selection_display()

    def _start_global_search(self, text: str) -> None:
        """Clear the display and start an animated background search across all JSON files."""
        self._global_search_generation += 1
        self._reset_selection_display()
        if not text:
            self._loading_label.setVisible(False)
            self._search_spinner_timer.stop()
            self._search_poll_timer.stop()
            return

        generation = self._global_search_generation
        selected_column = self._search_column_combo.currentText()
        self._loading_spinner_index = 0
        self._loading_label.setText(self._build_loading_text())
        self._loading_label.setVisible(True)
        self._search_spinner_timer.start()
        self._search_poll_timer.start()

        def worker() -> None:
            try:
                result_lines, total_matches, files_with_matches = self._build_global_search_result(text, selected_column, generation=generation)
            except (OSError, ValidationError) as e:
                logger.warning('Global session search failed: %s', e)
                result_lines, total_matches, files_with_matches = ['Search failed unexpectedly. Please try again.'], 0, 0
            self._global_search_results_queue.put((generation, result_lines, total_matches, files_with_matches))

        self._global_search_thread = threading.Thread(target=worker, name=f'SessionsGlobalSearch-{generation}', daemon=True)
        self._global_search_thread.start()

    def _build_global_search_result(self, text: str, selected_column: str, *, generation: int = 0) -> tuple[list[str], int, int]:
        """Build the rendered output for a global JSON session search."""
        if not self._sessions_dir.exists():
            return ['[Sessions directory not found]'], 0, 0

        search_lower = text.lower()
        result_lines: list[str] = []
        file_blocks: list[tuple[Path, int, list[tuple[int, str, list[str] | None]], list[str]]] = []
        parsed_table_rows_by_length: dict[int, list[list[str]]] = {}
        total_matches, files_with_matches = 0, 0

        all_files = self._collect_session_json_files(self._sessions_dir)
        if generation and generation != self._global_search_generation:
            return [], 0, 0

        active_paths = {item[0] for item in all_files}
        to_load: list[tuple[Path, int, int]] = []
        with self._cache_lock:
            for stale_path in set(self._session_file_cache) - active_paths:
                self._session_file_cache.pop(stale_path, None)
            for json_path, mtime_ns, size in all_files:
                cached = self._session_file_cache.get(json_path)
                if cached is None or cached.mtime_ns != mtime_ns or cached.size != size:
                    to_load.append((json_path, mtime_ns, size))

        if to_load:
            def _load_task(item: tuple[Path, int, int]) -> tuple[Path, _CachedSessionFile | None]:
                if generation and generation != self._global_search_generation:
                    return item[0], None
                return item[0], self._build_cached_session_file(item[0], item[1], item[2])

            if len(to_load) == 1:
                loaded_items = [_load_task(to_load[0])]
            else:
                workers = min(_GLOBAL_SEARCH_WORKERS, len(to_load))
                with ThreadPoolExecutor(max_workers=workers) as executor:
                    loaded_items = list(executor.map(_load_task, to_load, chunksize=max(1, len(to_load) // (workers * 2))))

            with self._cache_lock:
                for path_key, built in loaded_items:
                    if built is not None:
                        self._session_file_cache[path_key] = built

        for file_index, (json_path, mtime_ns, size) in enumerate(all_files, start=1):
            if generation and generation != self._global_search_generation:
                return [], 0, 0
            if not file_index % 25:
                time.sleep(0)

            cached = self._get_or_load_cached_file(json_path, (mtime_ns, size))
            if cached is None or search_lower not in cached.combined_haystack_lower:
                continue
            structured_matches = self._collect_structured_matches_from_cached(cached, search_lower, selected_column)
            if not structured_matches:
                continue

            _, line_number_width, table_rows = self._ensure_rendered(cached)
            relative = json_path.relative_to(self._sessions_dir)
            line_matches: list[tuple[int, str, list[str] | None]] = []
            is_search_all = selected_column == _SEARCH_ALL
            for row in table_rows:
                matched = search_lower in row.all_cells_lower if is_search_all else (row.has_headers and search_lower in row.cells_by_col_lower.get(selected_column, ''))
                if matched:
                    parsed_table_rows_by_length.setdefault(len(row.parsed_cells), []).append(row.parsed_cells)
                    line_matches.append((row.line_num, row.line, row.parsed_cells))
                    total_matches += 1

            files_with_matches += 1
            if line_matches:
                file_blocks.append((relative, line_number_width, line_matches, []))
            else:
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
                    self._render_aligned_line_matches(line_matches=line_matches, line_number_width=line_number_width, column_widths_by_length=column_widths_by_length),
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
                    self._set_viewer_content('', 'Search did not return results. Please try again.')
            return

        generation, result_lines, total_matches, files_with_matches = latest_result
        if generation != self._global_search_generation:
            return

        self._stop_loading_animation()
        rendered_text = '\n'.join(result_lines)
        if total_matches > 0:
            self._set_viewer_content(rendered_text, _GLOBAL_SEARCH_VIEWER_PLACEHOLDER)
            if search_text := self._search_input.text():
                find_and_highlight_matches(self._viewer.document(), search_text, self._viewer)
        else:
            self._set_viewer_content('', rendered_text or _GLOBAL_SEARCH_VIEWER_PLACEHOLDER)
        self._match_label.setText(f'{total_matches} match{pluralize(total_matches, "", "es")}' if total_matches else 'No matches')
        self._file_info_label.setText(f'Search across all files  |  {files_with_matches} file{pluralize(files_with_matches)} matched' if total_matches else '')

    def _build_loading_text(self) -> str:
        return f'{SPINNER_FRAMES[self._loading_spinner_index]} Searching...'

    def _animate_search_spinner(self) -> None:
        if self._loading_label.isVisible():
            self._loading_spinner_index = (self._loading_spinner_index + 1) % len(SPINNER_FRAMES)
            self._loading_label.setText(self._build_loading_text())

    def _stop_loading_animation(self) -> None:
        self._search_spinner_timer.stop()
        self._search_poll_timer.stop()
        self._loading_label.setVisible(False)

    @staticmethod
    def _normalize_search_value(value: object) -> str:
        if isinstance(value, list):
            return ', '.join(str(item) for item in cast('list[object]', value))
        if value is None:
            return ''
        text = str(value)
        return '' if text in {'N/A', '...'} else text

    @staticmethod
    def _try_parse_table_row(line: str) -> list[str] | None:
        stripped = line.strip()
        if not (stripped.startswith('│') and stripped.endswith('│')):
            return None
        raw_cells = stripped.split('│')[1:-1]
        return [cell.strip() for cell in raw_cells] if raw_cells else None

    @staticmethod
    def _format_table_row(cells: list[str], column_widths: list[int]) -> str:
        padded = [cell.ljust(column_widths[i]) if i < len(column_widths) else cell for i, cell in enumerate(cells)]
        return f'│ {" │ ".join(padded)} │'

    @staticmethod
    def _build_effective_column_widths(base_widths: list[int], header_cells: list[str]) -> list[int]:
        effective_widths = list(base_widths)
        for i, header_cell in enumerate(header_cells):
            if i >= len(effective_widths):
                effective_widths.append(len(header_cell))
            else:
                effective_widths[i] = max(effective_widths[i], len(header_cell))
        return effective_widths

    @staticmethod
    def _format_table_separator(column_widths: list[int], column_count: int) -> str:
        if column_count <= 0:
            return ''
        widths = [column_widths[i] if i < len(column_widths) else 0 for i in range(column_count)]
        return f'├─{"─┼─".join("─" * width for width in widths)}─┤'

    @staticmethod
    def _column_headers_for_row_length(row_length: int) -> list[str] | None:
        if row_length == len(Settings.GUI_ALL_CONNECTED_COLUMNS):
            return list(Settings.GUI_ALL_CONNECTED_COLUMNS)
        if row_length == len(Settings.GUI_ALL_DISCONNECTED_COLUMNS):
            return list(Settings.GUI_ALL_DISCONNECTED_COLUMNS)
        return None

    def _render_aligned_line_matches(
        self, *, line_matches: list[tuple[int, str, list[str] | None]], line_number_width: int, column_widths_by_length: dict[int, list[int]],
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
                    if (header_cells := self._column_headers_for_row_length(row_length)) is not None:
                        if (schema_label := self._schema_label_for_row_length(row_length)) is not None:
                            rendered_lines.append(f'  {" " * line_number_width}  ── {schema_label} ──')
                        active_column_widths = self._build_effective_column_widths(active_column_widths, header_cells)
                        rendered_lines.append(f'  {" " * line_number_width}  {self._format_table_row(header_cells, active_column_widths)}')
                        rendered_lines.append(f'  {" " * line_number_width}  {self._format_table_separator(active_column_widths, len(header_cells))}')
                        has_rendered_schema_header = True
                rendered_line = self._format_table_row(parsed_cells, active_column_widths)
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
        columns = cls._get_column_snapshot(info)
        return {column: ip if column == 'IP Address' else cls._normalize_search_value(columns.get(column, info.get(column))) for column in _SEARCHABLE_COLUMNS[1:]}

    @classmethod
    def _iter_json_text_values(cls, value: object) -> list[str]:
        if isinstance(value, dict):
            return [text for k, v in cast('dict[object, object]', value).items() if k not in SEARCHABLE_COLUMN_EXCLUSIONS for text in cls._iter_json_text_values(v)]
        if isinstance(value, list):
            return [text for item in cast('list[object]', value) for text in cls._iter_json_text_values(item)]
        return [normalized] if (normalized := cls._normalize_search_value(value)) else []

    @staticmethod
    def _load_session_log_file(file_path: Path) -> SessionLogFile:
        return SessionLogFile.model_validate_json(file_path.read_text(encoding='utf-8', errors='replace'))

    @classmethod
    def _build_cached_session_file(cls, file_path: Path, mtime_ns: int, size: int) -> _CachedSessionFile | None:
        try:
            session_log = cls._load_session_log_file(file_path)
        except (OSError, ValidationError) as e:
            logger.warning('Failed to load session log from %s: %s', file_path, e)
            return None

        player_entries: list[_CachedPlayerSearchEntry] = []
        haystack_parts: list[str] = []
        for section_name, players in (('connected', session_log.connected), ('disconnected', session_log.disconnected)):
            for ip, info in players.items():
                fields = cls._build_player_search_fields(ip, info)
                fields_lower = {column: value.lower() for column, value in fields.items()}
                all_fields_lower = '\x00'.join(fields_lower.values())
                fallback_all_text_lower = ' '.join((ip, *cls._iter_json_text_values(info))).lower()
                non_empty_columns = tuple(column for column, value in fields.items() if value)
                haystack_parts.extend((all_fields_lower, fallback_all_text_lower))
                player_entries.append(_CachedPlayerSearchEntry(section_name, ip, fields, fields_lower, all_fields_lower, fallback_all_text_lower, non_empty_columns))
        return _CachedSessionFile(mtime_ns, size, session_log, tuple(player_entries), '\x00'.join(haystack_parts))

    def _get_or_load_cached_file(self, file_path: Path, stat_sig: tuple[int, int] | None = None) -> _CachedSessionFile | None:
        if stat_sig is None:
            try:
                st = file_path.stat()
                stat_sig = (st.st_mtime_ns, st.st_size)
            except OSError as e:
                logger.warning('Failed to stat session log from %s: %s', file_path, e)
                return None
        mtime_ns, size = stat_sig
        with self._cache_lock:
            if (cached := self._session_file_cache.get(file_path)) is not None and cached.mtime_ns == mtime_ns and cached.size == size:
                return cached
        if (built := self._build_cached_session_file(file_path, mtime_ns, size)) is not None:
            with self._cache_lock:
                self._session_file_cache[file_path] = built
        return built

    def _ensure_rendered(self, cached: _CachedSessionFile) -> tuple[str, int, tuple[_CachedTableRow, ...]]:
        if cached.rendered_text is not None and cached.table_rows is not None:
            return cached.rendered_text, cached.line_number_width, cached.table_rows
        rendered = f'{self._build_connected_table(cached.session_log.connected)}\n{self._build_disconnected_table(cached.session_log.disconnected)}'
        lines = rendered.splitlines()
        line_number_width = max(len(str(len(lines))), 1)
        table_rows: list[_CachedTableRow] = []
        for line_num, line in enumerate(lines, start=1):
            if (parsed_cells := self._try_parse_table_row(line)) is None:
                continue
            header_cells = self._column_headers_for_row_length(len(parsed_cells))
            if header_cells is not None and parsed_cells[0] == header_cells[0]:
                continue
            if header_cells is None:
                cells_by_col_lower, all_cells_lower, has_headers = {}, line.lower(), False
            else:
                cells_by_col_lower = {
                    col: cell.lower() for col, cell in zip(header_cells, parsed_cells, strict=False) if col not in SEARCHABLE_COLUMN_EXCLUSIONS and cell not in {'N/A', '...'}
                }
                all_cells_lower, has_headers = '\x00'.join(cells_by_col_lower.values()), True
            table_rows.append(_CachedTableRow(line_num, line, parsed_cells, cells_by_col_lower, all_cells_lower, has_headers))
        rows_tuple = tuple(table_rows)
        with self._cache_lock:
            cached.rendered_text, cached.line_number_width, cached.table_rows = rendered, line_number_width, rows_tuple
        return rendered, line_number_width, rows_tuple

    @staticmethod
    def _collect_structured_matches_from_cached(cached: _CachedSessionFile, search_lower: str, selected_column: str) -> list[str]:
        if search_lower not in cached.combined_haystack_lower:
            return []
        matches: list[str] = []
        is_search_all = selected_column == _SEARCH_ALL
        for entry in cached.player_entries:
            if is_search_all:
                if search_lower in entry.all_fields_lower:
                    matched_columns = [column for column, val_lower in entry.fields_lower.items() if search_lower in val_lower]
                else:
                    matched_columns = list(entry.non_empty_columns) if search_lower in entry.fallback_all_text_lower else []
            else:
                matched_columns = [selected_column] if search_lower in entry.fields_lower.get(selected_column, '') else []
            if matched_columns:
                matches.append(f'  [{entry.section_name}] {entry.ip}  |  {", ".join(f"{column}: {entry.fields[column]}" for column in matched_columns)}')
        return matches

    def _collect_structured_search_matches(self, file_path: Path, search_lower: str, selected_column: str) -> list[str]:
        cached = self._get_or_load_cached_file(file_path)
        return self._collect_structured_matches_from_cached(cached, search_lower, selected_column) if cached is not None else []

    def _file_has_search_match(self, file_path: Path, text: str, selected_column: str) -> bool:
        return bool(self._collect_structured_search_matches(file_path, text.lower(), selected_column))

    def _copy_all(self) -> bool:
        return copy_viewer_text_to_clipboard(self._viewer)

    def _save_as(self) -> None:
        if self._current_file is None and not (self._global_search_active and self._current_rendered_text):
            QMessageBox.information(self, TITLE, 'No file selected.')
            return
        default_name = str(self._current_file.with_suffix('.export.log')) if self._current_file is not None else str(self._sessions_dir / 'global_search.export.log')
        path, _ = QFileDialog.getSaveFileName(self, 'Save Session Log As', default_name, 'Log Files (*.log);;Text Files (*.txt);;All Files (*)')
        if path:
            Path(path).write_text(self._current_rendered_text or self._viewer.toPlainText(), encoding='utf-8')
            QMessageBox.information(self, TITLE, f'Saved to {path}')

    @staticmethod
    def _format_session_datetime(value: object) -> str:
        if not isinstance(value, str) or not value:
            return 'N/A'
        try:
            return datetime.fromisoformat(value).strftime('%H:%M:%S.%f')[:-3]
        except ValueError:
            return value

    @staticmethod
    def _format_table_value(value: object) -> str:
        if value is None:
            return 'N/A'
        if isinstance(value, bool):
            return 'Yes' if value else 'No'
        return ', '.join(str(item) for item in cast('list[object]', value)) if isinstance(value, list) else str(value)

    @staticmethod
    def _get_column_snapshot(player_info: dict[str, Any]) -> dict[str, Any]:
        columns_raw = player_info.get('columns')
        return cast('dict[str, Any]', columns_raw) if isinstance(columns_raw, dict) else player_info

    @classmethod
    def _player_datetime_sort_key(cls, player_info: dict[str, Any], sort_column: str) -> datetime:
        for candidate in (player_info.get(sort_column), cls._get_column_snapshot(player_info).get(sort_column)):
            if not isinstance(candidate, str) or not candidate:
                continue
            try:
                parsed = datetime.fromisoformat(candidate)
                return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=LOCAL_TZ)
            except ValueError:
                try:
                    return datetime.strptime(candidate, '%m/%d/%Y %H:%M:%S.%f').replace(tzinfo=LOCAL_TZ)
                except ValueError:
                    continue
        return datetime.min.replace(tzinfo=LOCAL_TZ)

    @classmethod
    def _build_session_table(cls, *, players: dict[str, dict[str, Any]], column_names: tuple[str, ...], config: _SessionTableRenderConfig) -> str:
        headers = [f'{col} ↓' if col == config.sort_column and config.descending else f'{col} ↑' if col == config.sort_column else col for col in column_names]
        sorted_players = sorted(players.items(), key=lambda item: cls._player_datetime_sort_key(item[1], config.sort_column), reverse=not config.descending)
        rows = [
            [
                cls._format_session_datetime(columns.get(col, info.get(col, 'N/A')))
                if col in DATETIME_TRACKING_COLUMNS
                else cls._format_table_value(columns.get(col, info.get(col, 'N/A')) if col != 'IP Address' else ip)
                for col in column_names
            ]
            for ip, info in sorted_players
            for columns in (cls._get_column_snapshot(info),)
        ]
        return format_single_border_table(headers, rows, title=config.title)

    @classmethod
    def _build_connected_table(cls, players: dict[str, dict[str, Any]]) -> str:
        config = _SessionTableRenderConfig(f'Players connected in your session ({len(players)}):', 'Last Rejoin', descending=True)
        return cls._build_session_table(players=players, column_names=Settings.GUI_ALL_CONNECTED_COLUMNS, config=config)

    @classmethod
    def _build_disconnected_table(cls, players: dict[str, dict[str, Any]]) -> str:
        config = _SessionTableRenderConfig(f"Players who've left your session ({len(players)}):", 'Last Seen', descending=False)
        return cls._build_session_table(players=players, column_names=Settings.GUI_ALL_DISCONNECTED_COLUMNS, config=config)

    def _render_session_file(self, file_path: Path) -> str | None:
        cached = self._get_or_load_cached_file(file_path)
        return self._ensure_rendered(cached)[0] if cached is not None else None

    def _delete_selected(self) -> None:
        if self._selected_path is None or not self._selected_path.exists():
            QMessageBox.information(self, TITLE, 'No file or folder selected.')
            return
        is_dir = self._selected_path.is_dir()
        kind = 'folder' if is_dir else 'file'
        extra = '\n\nAll contents within the folder will be removed.' if is_dir else ''
        msg = f'Delete {kind} "{self._selected_path.name}"?{extra}\n\nThis cannot be undone.'
        if QMessageBox.warning(self, TITLE, msg, QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
            return
        deleted_path = self._selected_path
        if is_dir:
            shutil.rmtree(deleted_path)
            with self._cache_lock:
                for cached_path in [p for p in self._session_file_cache if deleted_path in p.parents]:
                    self._session_file_cache.pop(cached_path, None)
        else:
            deleted_path.unlink()
            with self._cache_lock:
                self._session_file_cache.pop(deleted_path, None)
        self._clear_tree_selection()
        self.update_dir_metadata()

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
