"""Sessions logging tab — folder tree + file viewer."""

import logging
import queue
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from pydantic import ValidationError
from PySide6.QtCore import QItemSelectionModel, QModelIndex, QPoint, QSignalBlocker, Qt, QTimer, QUrl
from PySide6.QtGui import QDesktopServices, QIcon, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QAbstractItemView,
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

from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis.delegates import ElidedTextTooltipDelegate
from session_sniffer.guis.file_watch import DebouncedFileWatcher
from session_sniffer.guis.live_language import register_language_refresh, set_i18n_colon_label
from session_sniffer.guis.loading_overlay import run_blocking_with_loading
from session_sniffer.guis.logs_manager._helpers import (
    copy_viewer_text_to_clipboard,
    create_log_viewer,
    create_search_input,
    find_and_highlight_matches,
    prepare_search,
    setup_copy_save_button_row,
    setup_metadata_label,
)
from session_sniffer.guis.logs_manager._sessions_render import (
    SEARCH_ALL,
    SEARCHABLE_COLUMNS,
    CachedSessionFile,
    build_cached_session_file,
    collect_session_json_files,
    collect_structured_matches_from_cached,
    count_json_files_and_size,
    delete_session_paths,
    ensure_cached_session_rendered,
    normalize_fs_path,
    prune_nested_paths,
    render_aligned_line_matches,
)
from session_sniffer.guis.stylesheets import DIALOG_BUTTON_STYLESHEET, DIALOG_DANGER_BUTTON_STYLESHEET, SVG_ICON_CONTEXT_MENU_STYLESHEET
from session_sniffer.guis.theming import ICONS_DIR_PATH
from session_sniffer.guis.userip_manager_helpers import human_readable_size
from session_sniffer.guis.utils import SPINNER_FRAMES, open_file_location
from session_sniffer.i18n import tr, tr_plural
from session_sniffer.rendering_core.renderer import SESSIONS_LOGGING_PATH
from session_sniffer.settings import Settings

logger = logging.getLogger(__name__)

_SINGLE_FILE_VIEWER_PLACEHOLDER = 'Select a session JSON file from the tree to view its contents.'
_GLOBAL_SEARCH_VIEWER_PLACEHOLDER = 'Press Enter to search across all session JSON files.'
_GLOBAL_SEARCH_WORKERS = 16


class SessionsLogTab(QWidget):
    """Browse and view session JSON files in a YYYY/MM/DD folder hierarchy."""

    def __init__(self, sessions_dir: Path, parent: QWidget | None = None) -> None:
        """Initialize the sessions log tab for *sessions_dir*."""
        super().__init__(parent)
        self._sessions_dir = sessions_dir
        self._current_file: Path | None = None
        self._saved_file_before_global_search: Path | None = None
        self._selected_path: Path | None = None
        self._multi_selected: bool = False
        self._global_search_active = False
        self._current_rendered_text = ''
        self._global_search_generation = 0
        self._global_search_thread: threading.Thread | None = None
        self._global_search_results_queue: queue.SimpleQueue[tuple[int, list[str], int, int]] = queue.SimpleQueue()
        self._loading_spinner_index = 0
        self._cache_lock = threading.Lock()
        self._session_file_cache: dict[Path, CachedSessionFile] = {}

        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)

        top_bar = QHBoxLayout()
        self._search_input = create_search_input(top_bar, tr('Search in displayed file\u2026'), self._on_search_changed, debounce_ms=60)
        self._search_input.returnPressed.connect(self._on_search_return_pressed)

        self._search_column_combo = QComboBox()
        for column_name in SEARCHABLE_COLUMNS:
            self._search_column_combo.addItem(tr(column_name), column_name)
        self._search_column_combo.setToolTip(tr('Select which session fields to search'))
        self._search_column_combo.currentIndexChanged.connect(self._on_search_column_changed)
        column_label = QLabel()
        set_i18n_colon_label(column_label, 'Column')
        top_bar.addWidget(column_label)
        top_bar.addWidget(self._search_column_combo)

        self._global_search_checkbox = QCheckBox(tr('Search All Files'))
        self._global_search_checkbox.setToolTip(tr('Search across all session JSON files (read-only)'))
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
        self._tree.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self._tree.setItemDelegate(ElidedTextTooltipDelegate(self._tree))
        self._tree.setWordWrap(False)
        self._tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._tree.customContextMenuRequested.connect(self._on_tree_context_menu)
        for column in (1, 2, 3):
            self._tree.hideColumn(column)
        self._tree.clicked.connect(self._on_tree_clicked)
        self._tree.activated.connect(self._on_tree_activated)
        if selection_model := self._tree.selectionModel():
            selection_model.selectionChanged.connect(self._on_tree_selection_changed)
            selection_model.currentChanged.connect(self._on_tree_current_changed)
        QShortcut(QKeySequence('Delete'), self._tree, context=Qt.ShortcutContext.WidgetShortcut).activated.connect(self._delete_selected)
        self._tree.setMinimumWidth(200)

        tree_container_layout.addWidget(self._tree)
        splitter.addWidget(self._tree_container)

        self._viewer = create_log_viewer()
        self._viewer.setPlaceholderText(tr(_SINGLE_FILE_VIEWER_PLACEHOLDER))
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
            layout, self._copy_all, self._save_as, save_tooltip=tr('Save the displayed file to a new location'),
        )
        button_row.addStretch()

        self._delete_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'remove.svg')), f" {tr('Delete')}")
        self._delete_button.setStyleSheet(DIALOG_DANGER_BUTTON_STYLESHEET)
        self._delete_button.setToolTip(tr('Delete the currently selected file or folder'))
        self._delete_button.setEnabled(False)
        self._delete_button.clicked.connect(self._delete_selected)
        button_row.addWidget(self._delete_button)

        self._open_location_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'folder.svg')), f" {tr('Open Folder Location')}")
        self._open_location_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        self._open_location_button.setToolTip(tr('Open the containing folder in your file manager'))
        self._open_location_button.clicked.connect(self._open_location)
        button_row.addWidget(self._open_location_button)

        self._open_file_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'file-text.svg')), f" {tr('Open File')}")
        self._open_file_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        self._open_file_button.setToolTip(tr('Open the selected log file in the default text editor'))
        self._open_file_button.clicked.connect(self._open_file)
        self._open_file_button.setEnabled(False)
        button_row.addWidget(self._open_file_button)

        self._watching_stopped: bool = False
        self._file_watcher = DebouncedFileWatcher(self, self._on_current_file_changed)
        self.update_dir_metadata()
        register_language_refresh(self, self._retranslate)

    def _invalidate_rendered_cache(self) -> None:
        """Clear cached rendered text and parsed rows so previews re-render in the active language."""
        with self._cache_lock:
            for cached in self._session_file_cache.values():
                cached.rendered_text = None
                cached.table_rows = None

    def _retranslate(self) -> None:
        """Refresh UI strings and cached session previews after a live language change."""
        self._invalidate_rendered_cache()
        self._search_input.setPlaceholderText(
            tr('Search across all session JSON files (press Enter)\u2026')
            if self._global_search_active
            else tr('Search in displayed file\u2026'),
        )
        with QSignalBlocker(self._search_column_combo):
            for idx in range(self._search_column_combo.count()):
                column_name = str(self._search_column_combo.itemData(idx) or '')
                if column_name:
                    self._search_column_combo.setItemText(idx, tr(column_name))
        self._search_column_combo.setToolTip(tr('Select which session fields to search'))
        self._global_search_checkbox.setText(tr('Search All Files'))
        self._global_search_checkbox.setToolTip(tr('Search across all session JSON files (read-only)'))
        self._copy_button.setText(f" {tr('Copy All')}")
        self._save_button.setText(f" {tr('Save As...')}")
        self._save_button.setToolTip(tr('Save the displayed file to a new location'))
        self._open_location_button.setToolTip(tr('Open the containing folder in your file manager'))
        self._open_file_button.setText(f" {tr('Open File')}")
        self._open_file_button.setToolTip(tr('Open the selected log file in the default text editor'))

        self.update_dir_metadata()
        if self._global_search_active:
            if self._loading_label.isVisible():
                self._loading_label.setText(self._build_loading_text())
            elif search_text := self._search_input.text():
                self._start_global_search(search_text)
            else:
                self._reset_selection_display()
            return

        if self._multi_selected:
            selected_paths = self._get_selected_tree_paths()
            if len(selected_paths) > 1:
                self._apply_multi_selection_ui(selected_paths)
            else:
                self._reset_selection_display()
        elif self._selected_path is not None and self._selected_path.exists():
            if self._selected_path.is_file():
                self._apply_file_selection(self._selected_path)
            elif self._selected_path.is_dir():
                self._apply_folder_selection(self._selected_path)
        else:
            self._reset_selection_display()

    def start_watching(self) -> None:
        """Resume watching the currently selected session file."""
        if self._watching_stopped:
            self._watching_stopped = False
            self.update_dir_metadata()
            if self._global_search_active and self._search_input.text() and not self._viewer.toPlainText():
                self._start_global_search(self._search_input.text())
            elif not self._global_search_active and not self._multi_selected and self._selected_path is not None and self._selected_path.is_file():
                self._file_watcher.watch(files=[self._selected_path])
                self._on_current_file_changed()

    def stop_watching(self) -> None:
        """Stop watching session files and cancel any in-flight global search."""
        self._watching_stopped = True
        self._file_watcher.stop()
        self._global_search_generation += 1
        self._stop_loading_animation()

    def _get_selected_tree_paths(self) -> list[Path]:
        """Return existing filesystem paths for all currently selected rows in the tree."""
        selection_model = self._tree.selectionModel()
        indexes = selection_model.selectedRows(0)
        if not indexes:
            current = selection_model.currentIndex()
            if current.isValid():
                indexes = [current.siblingAtColumn(0)]
        paths: list[Path] = []
        seen: set[str] = set()
        for index in indexes:
            if not index.isValid():
                continue
            raw_path = self._fs_model.filePath(index)
            if not raw_path:
                continue
            path = Path(raw_path)
            norm = normalize_fs_path(path)
            if norm not in seen and path.exists():
                seen.add(norm)
                paths.append(path)
        return paths

    def update_dir_metadata(self) -> None:
        """Update the metadata label with total size and file count of the sessions directory."""
        if not self._multi_selected and self._selected_path is not None:
            if not self._selected_path.exists():
                self._clear_tree_selection()
            elif self._selected_path.is_dir() and not self._global_search_active:
                folder_size, folder_count = count_json_files_and_size(self._selected_path)
                size_str = human_readable_size(folder_size)
                self._file_info_label.setText(
                    tr_plural(
                        '{name}  (folder)  |  {size}  |  {count} json file',
                        '{name}  (folder)  |  {size}  |  {count} json files',
                        folder_count,
                        name=self._selected_path.name,
                        size=size_str,
                    ),
                )
        if not self._sessions_dir.exists():
            self._metadata_label.setText(tr('{name}  \u2014  Directory not found', name=self._sessions_dir.name))
            return
        total_size, file_count = count_json_files_and_size(self._sessions_dir)
        self._metadata_label.setText(
            tr_plural(
                '{name}  |  {size}  |  {count} json file',
                '{name}  |  {size}  |  {count} json files',
                file_count,
                name=self._sessions_dir.name,
                size=human_readable_size(total_size),
            ),
        )

    def _on_tree_clicked(self, _index: QModelIndex) -> None:
        self._sync_tree_selection()

    def _on_tree_activated(self, _index: QModelIndex) -> None:
        self._sync_tree_selection()

    def _on_tree_selection_changed(self, *_args: object) -> None:
        self._sync_tree_selection()

    def _on_tree_current_changed(self, current: QModelIndex, _previous: QModelIndex) -> None:
        if self._tree.selectionModel().selectedRows(0):
            return
        if not current.isValid():
            self._file_watcher.stop()
            self._reset_selection_display()

    def _sync_tree_selection(self) -> None:
        """Synchronize viewer content and action buttons with single or multi-item tree selection."""
        selected_paths = self._get_selected_tree_paths()
        if not selected_paths:
            self._file_watcher.stop()
            self._reset_selection_display()
            return
        if len(selected_paths) == 1:
            only = selected_paths[0]
            if only == self._selected_path and not self._multi_selected:
                return
            self._multi_selected = False
            if only.is_file():
                self._apply_file_selection(only)
            elif only.is_dir():
                self._apply_folder_selection(only)
            return

        self._apply_multi_selection_ui(selected_paths)

    def _apply_multi_selection_ui(self, selected_paths: list[Path]) -> None:
        """Update the viewer placeholder, summary label, and buttons for multi-item selection."""
        self._multi_selected = True
        self._selected_path = selected_paths[0]
        self._file_watcher.stop()
        self._current_file = None
        sel_count = len(selected_paths)
        file_sel = sum(1 for p in selected_paths if p.is_file())
        dir_sel = sel_count - file_sel
        parts: list[str] = []
        if file_sel:
            parts.append(tr_plural('{count} file', '{count} files', file_sel))
        if dir_sel:
            parts.append(tr_plural('{count} folder', '{count} folders', dir_sel))
        breakdown = ', '.join(parts)
        self._set_viewer_content('', tr('{count} items selected ({breakdown}).', count=sel_count, breakdown=breakdown))
        self._file_info_label.setText(tr('{count} items selected  ({breakdown})', count=sel_count, breakdown=breakdown))
        self._match_label.setText('')
        self._delete_button.setText(f" {tr('Delete ({count})', count=sel_count)}")
        self._delete_button.setToolTip(tr('Delete all selected files and folders'))
        self._delete_button.setEnabled(True)
        self._open_location_button.setText(f" {tr('Open Folder Location')}")
        self._open_file_button.setEnabled(False)

    def _on_tree_context_menu(self, pos: QPoint) -> None:
        index = self._tree.indexAt(pos)
        if not index.isValid():
            return
        selection_model = self._tree.selectionModel()
        if not selection_model.isSelected(index):
            selection_model.select(index, QItemSelectionModel.SelectionFlag.ClearAndSelect | QItemSelectionModel.SelectionFlag.Rows)
            selection_model.setCurrentIndex(index, QItemSelectionModel.SelectionFlag.NoUpdate)
        selected_paths = self._get_selected_tree_paths()
        if not selected_paths:
            return
        sel_count = len(selected_paths)
        menu = QMenu(self)
        menu.setStyleSheet(SVG_ICON_CONTEXT_MENU_STYLESHEET)

        if sel_count == 1:
            is_dir = selected_paths[0].is_dir()
            if not is_dir and (open_action := menu.addAction(QIcon(str(ICONS_DIR_PATH / 'file-text.svg')), tr('Open File'))):
                open_action.triggered.connect(self._open_file)
            loc_label = tr('Open Folder Location') if is_dir else tr('Open File Location')
            if location_action := menu.addAction(QIcon(str(ICONS_DIR_PATH / 'folder.svg')), loc_label):
                location_action.triggered.connect(self._open_location)
            menu.addSeparator()

        if select_all_action := menu.addAction(QIcon(str(ICONS_DIR_PATH / 'square-check.svg')), tr('Select All')):
            select_all_action.setShortcut('Ctrl+A')
            select_all_action.triggered.connect(self._tree.selectAll)

        menu.addSeparator()
        delete_label = tr('Delete ({count})', count=sel_count) if sel_count > 1 else tr('Delete')
        if delete_action := menu.addAction(QIcon(str(ICONS_DIR_PATH / 'remove.svg')), delete_label):
            delete_action.setShortcut('Delete')
            delete_action.triggered.connect(self._delete_selected)

        if viewport := self._tree.viewport():
            menu.exec(viewport.mapToGlobal(pos))

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
        self._multi_selected = False
        self._current_file = None
        self._file_info_label.setText('')
        self._match_label.setText('')
        placeholder = tr(_GLOBAL_SEARCH_VIEWER_PLACEHOLDER if self._global_search_active else _SINGLE_FILE_VIEWER_PLACEHOLDER)
        self._set_viewer_content('', placeholder)
        self._delete_button.setText(f" {tr('Delete')}")
        self._delete_button.setToolTip(tr('Delete the currently selected file or folder'))
        self._delete_button.setEnabled(False)
        self._open_location_button.setText(f" {tr('Open Folder Location')}")
        self._open_file_button.setEnabled(False)

    def _apply_file_selection(self, file_path: Path) -> None:
        """Select *file_path*, render its contents, and enable file action buttons."""
        self._selected_path = file_path
        self._load_file(file_path)
        self._delete_button.setText(f" {tr('Delete File')}")
        self._delete_button.setToolTip(tr('Delete the currently selected session JSON file'))
        self._delete_button.setEnabled(True)
        self._open_location_button.setText(f" {tr('Open File Location')}")
        self._open_file_button.setEnabled(file_path.is_file())

    def _apply_folder_selection(self, folder_path: Path) -> None:
        """Select *folder_path*, display its folder summary, and update folder action buttons."""
        self._selected_path = folder_path
        self._file_watcher.stop()
        self._current_file = None
        self._set_viewer_content('', tr(_SINGLE_FILE_VIEWER_PLACEHOLDER))
        total_size, file_count = count_json_files_and_size(folder_path)
        self._file_info_label.setText(
            tr_plural(
                '{name}  (folder)  |  {size}  |  {count} json file',
                '{name}  (folder)  |  {size}  |  {count} json files',
                file_count,
                name=folder_path.name,
                size=human_readable_size(total_size),
            ),
        )
        self._match_label.setText('')
        self._delete_button.setText(f" {tr('Delete Folder')}")
        self._delete_button.setToolTip(tr('Delete the currently selected folder and all its contents'))
        self._delete_button.setEnabled(True)
        self._open_location_button.setText(f" {tr('Open Folder Location')}")
        self._open_file_button.setEnabled(False)

    def _load_file(self, file_path: Path) -> None:
        self._current_file = file_path
        self._file_watcher.watch(files=[file_path])
        text = self._render_session_file(file_path)
        if text is None:
            self._current_file = None
            self._set_viewer_content('', tr('[Failed to parse JSON session file: {filename}]', filename=file_path.name))
            self._file_info_label.setText(tr('{filename}  |  Failed to parse', filename=file_path.name))
            self._match_label.setText('')
            return
        self._set_viewer_content(text, tr(_SINGLE_FILE_VIEWER_PLACEHOLDER))
        line_count = text.count('\n') + (1 if text and not text.endswith('\n') else 0)
        self._file_info_label.setText(
            tr_plural(
                '{filename}  |  {size}  |  {count:,} rendered line',
                '{filename}  |  {size}  |  {count:,} rendered lines',
                line_count,
                filename=file_path.name,
                size=human_readable_size(file_path.stat().st_size),
            ),
        )
        if self._search_input.text():
            self._on_search_changed(self._search_input.text())
        else:
            self._match_label.setText('')
            self._viewer.setExtraSelections([])

    def _on_current_file_changed(self) -> None:
        """Re-render the displayed session file after it changes on disk."""
        target_file = self._current_file or (self._selected_path if self._selected_path is not None and not self._selected_path.is_dir() else None)
        if self._global_search_active or self._multi_selected or target_file is None:
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

    def _on_search_column_changed(self, _index: int = 0) -> None:
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
        selected_column = str(self._search_column_combo.currentData() or SEARCH_ALL)
        if text and not self._file_has_search_match(self._current_file, text, selected_column):
            self._viewer.setExtraSelections([])
            self._match_label.setText(tr('No matches'))
            return
        if (document := prepare_search(text, self._match_label, self._viewer)) is None:
            return
        matched_cursors = find_and_highlight_matches(document, text, self._viewer)
        if matched_cursors:
            self._viewer.setTextCursor(matched_cursors[0])
            self._viewer.centerCursor()
        self._match_label.setText(tr_plural('{count} match', '{count} matches', len(matched_cursors)) if matched_cursors else tr('No matches'))

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
            self._saved_file_before_global_search = self._selected_path if not self._multi_selected else None
            self._global_search_active = True
            self._clear_tree_selection()
            self._tree_container.setVisible(False)
            self._search_input.setPlaceholderText(tr('Search across all session JSON files (press Enter)\u2026'))
            self._viewer.setPlaceholderText(tr(_GLOBAL_SEARCH_VIEWER_PLACEHOLDER))
            self._tree.setEnabled(False)
            self._start_global_search(self._search_input.text())
        else:
            self._global_search_active = False
            self._global_search_generation += 1
            self._stop_loading_animation()
            self._tree_container.setVisible(True)
            self._search_input.setPlaceholderText(tr('Search in displayed file\u2026'))
            self._viewer.setPlaceholderText(tr(_SINGLE_FILE_VIEWER_PLACEHOLDER))
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
            self._stop_loading_animation()
            return

        generation = self._global_search_generation
        selected_column = str(self._search_column_combo.currentData() or SEARCH_ALL)
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
                result_lines, total_matches, files_with_matches = [tr('Search failed unexpectedly. Please try again.')], 0, 0
            self._global_search_results_queue.put((generation, result_lines, total_matches, files_with_matches))

        self._global_search_thread = threading.Thread(target=worker, name=f'SessionsGlobalSearch-{generation}', daemon=True)
        self._global_search_thread.start()

    def _build_global_search_result(self, text: str, selected_column: str, *, generation: int = 0) -> tuple[list[str], int, int]:
        """Build the rendered output for a global JSON session search."""
        if not self._sessions_dir.exists():
            return [tr('[Sessions directory not found]')], 0, 0

        search_lower = text.lower()
        result_lines: list[str] = []
        file_blocks: list[tuple[Path, int, list[tuple[int, str, list[str] | None]], list[str]]] = []
        parsed_table_rows_by_length: dict[int, list[list[str]]] = {}
        total_matches, files_with_matches = 0, 0

        all_files = collect_session_json_files(self._sessions_dir)
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
            def _load_task(item: tuple[Path, int, int]) -> tuple[Path, CachedSessionFile | None]:
                if generation and generation != self._global_search_generation:
                    return item[0], None
                return item[0], build_cached_session_file(item[0], item[1], item[2])

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
            structured_matches = collect_structured_matches_from_cached(cached, search_lower, selected_column)
            if not structured_matches:
                continue

            _, line_number_width, table_rows = ensure_cached_session_rendered(cached, self._cache_lock)
            relative = json_path.relative_to(self._sessions_dir)
            line_matches: list[tuple[int, str, list[str] | None]] = []
            is_search_all = selected_column == SEARCH_ALL
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
                    render_aligned_line_matches(line_matches=line_matches, line_number_width=line_number_width, column_widths_by_length=column_widths_by_length),
                )
            else:
                result_lines.extend(structured_matches)

        if not result_lines:
            result_lines = [tr('No matches found for "{query}" in any session JSON file.', query=text)]
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
                self._match_label.setText(tr('Search failed'))
                if not self._viewer.toPlainText():
                    self._set_viewer_content('', tr('Search did not return results. Please try again.'))
            return

        generation, result_lines, total_matches, files_with_matches = latest_result
        if generation != self._global_search_generation:
            return

        self._stop_loading_animation()
        rendered_text = '\n'.join(result_lines)
        global_placeholder = tr(_GLOBAL_SEARCH_VIEWER_PLACEHOLDER)
        if total_matches > 0:
            self._set_viewer_content(rendered_text, global_placeholder)
            if search_text := self._search_input.text():
                find_and_highlight_matches(self._viewer.document(), search_text, self._viewer)
        else:
            self._set_viewer_content('', rendered_text or global_placeholder)
        self._match_label.setText(tr_plural('{count} match', '{count} matches', total_matches) if total_matches else tr('No matches'))
        self._file_info_label.setText(
            tr_plural(
                'Search across all files  |  {count} file matched',
                'Search across all files  |  {count} files matched',
                files_with_matches,
            )
            if total_matches
            else '',
        )

    def _build_loading_text(self) -> str:
        return tr('{spinner} Searching...', spinner=SPINNER_FRAMES[self._loading_spinner_index])

    def _animate_search_spinner(self) -> None:
        if self._loading_label.isVisible():
            self._loading_spinner_index = (self._loading_spinner_index + 1) % len(SPINNER_FRAMES)
            self._loading_label.setText(self._build_loading_text())

    def _stop_loading_animation(self) -> None:
        self._search_spinner_timer.stop()
        self._search_poll_timer.stop()
        self._loading_label.setVisible(False)

    def _get_or_load_cached_file(self, file_path: Path, stat_sig: tuple[int, int] | None = None) -> CachedSessionFile | None:
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
        if (built := build_cached_session_file(file_path, mtime_ns, size)) is not None:
            with self._cache_lock:
                self._session_file_cache[file_path] = built
        return built

    def _collect_structured_search_matches(self, file_path: Path, search_lower: str, selected_column: str) -> list[str]:
        cached = self._get_or_load_cached_file(file_path)
        return collect_structured_matches_from_cached(cached, search_lower, selected_column) if cached is not None else []

    def _file_has_search_match(self, file_path: Path, text: str, selected_column: str) -> bool:
        return bool(self._collect_structured_search_matches(file_path, text.lower(), selected_column))

    def _copy_all(self) -> bool:
        return copy_viewer_text_to_clipboard(self._viewer)

    def _save_as(self) -> None:
        if self._current_file is None and not (self._global_search_active and self._current_rendered_text):
            QMessageBox.information(self, TITLE, tr('No file selected.'))
            return
        default_name = str(self._current_file.with_suffix('.export.log')) if self._current_file is not None else str(self._sessions_dir / 'global_search.export.log')
        path, _ = QFileDialog.getSaveFileName(
            self,
            tr('Save Session Log As'),
            default_name,
            f"{tr('Log Files')} (*.log);;{tr('Text Files')} (*.txt);;{tr('All Files')} (*)",
        )
        if path:
            export_name = self._current_file.name if self._current_file is not None else Path(path).name
            try:
                Path(path).write_text(self._current_rendered_text or self._viewer.toPlainText(), encoding='utf-8')
            except OSError as e:
                logger.warning('Failed to export session log to "%s": %s', path, e)
                QMessageBox.critical(self, tr('Export Error'), tr('Failed to export "{name}":\n{error}', name=export_name, error=e))
                return
            QMessageBox.information(self, TITLE, tr('Saved to {path}', path=path))

    def _render_session_file(self, file_path: Path) -> str | None:
        cached = self._get_or_load_cached_file(file_path)
        return ensure_cached_session_rendered(cached, self._cache_lock)[0] if cached is not None else None

    def _delete_selected(self) -> None:
        selected_paths = self._get_selected_tree_paths()
        if not selected_paths and self._selected_path is not None and self._selected_path.exists():
            selected_paths = [self._selected_path]
        if not selected_paths:
            return

        top_paths = prune_nested_paths(selected_paths)
        protected_active = SESSIONS_LOGGING_PATH if Settings.gui_sessions_logging else None
        if (
            len(top_paths) == 1
            and top_paths[0].is_file()
            and protected_active is not None
            and normalize_fs_path(top_paths[0]) == normalize_fs_path(protected_active)
        ):
            QMessageBox.warning(
                self,
                TITLE,
                tr('Cannot delete the active session log file while GUI session logging is enabled.'),
            )
            return

        if len(selected_paths) == 1:
            only = selected_paths[0]
            if only.is_dir():
                confirm_text = tr('Delete folder "{name}"?\n\nAll contents within the folder will be removed.\n\nThis cannot be undone.', name=only.name)
            else:
                confirm_text = tr('Delete file "{name}"?\n\nThis cannot be undone.', name=only.name)
        else:
            file_sel = sum(1 for p in selected_paths if p.is_file())
            dir_sel = len(selected_paths) - file_sel
            if file_sel and dir_sel:
                confirm_text = tr(
                    'Delete {files_part}, {folders_part}?\n\nThis cannot be undone.',
                    files_part=tr_plural('{count} file', '{count} files', file_sel),
                    folders_part=tr_plural('{count} folder (and all their contents)', '{count} folders (and all their contents)', dir_sel),
                )
            elif file_sel:
                confirm_text = tr_plural('Delete {count} file?\n\nThis cannot be undone.', 'Delete {count} files?\n\nThis cannot be undone.', file_sel)
            else:
                confirm_text = tr_plural(
                    'Delete {count} folder (and all their contents)?\n\nThis cannot be undone.',
                    'Delete {count} folders (and all their contents)?\n\nThis cannot be undone.',
                    dir_sel,
                )

        if QMessageBox.warning(self, TITLE, confirm_text, QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
            return

        self._file_watcher.stop()

        def _do_delete() -> tuple[int, int, bool]:
            return delete_session_paths(top_paths, protected_active_file=protected_active)

        _, _, skipped_active = (
            run_blocking_with_loading(
                self.window(),
                tr('Deleting Session Logs\u2026'),
                tr('Removing selected session files and folders\u2026'),
                _do_delete,
            )
            if self.isVisible()
            else _do_delete()
        )

        with self._cache_lock:
            stale = [p for p in self._session_file_cache if not p.exists()]
            for cached_path in stale:
                self._session_file_cache.pop(cached_path, None)

        self._clear_tree_selection()
        self.update_dir_metadata()
        if skipped_active:
            QMessageBox.information(
                self,
                TITLE,
                tr('The active session log file was kept because GUI session logging is currently enabled.'),
            )

    def _open_location(self) -> None:
        if self._selected_path and self._selected_path.exists():
            if self._selected_path.is_dir():
                QDesktopServices.openUrl(QUrl.fromLocalFile(str(self._selected_path)))
            else:
                open_file_location(self._selected_path)
        elif self._sessions_dir.exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(self._sessions_dir)))

    def _open_file(self) -> None:
        if not self._multi_selected and self._selected_path and self._selected_path.is_file():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(self._selected_path)))
