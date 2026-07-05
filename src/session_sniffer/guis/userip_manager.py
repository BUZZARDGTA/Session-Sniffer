"""UserIP Databases Manager dialog for browsing, editing, and managing UserIP database files and entries."""

from collections import defaultdict
from datetime import UTC, datetime
from ipaddress import IPv4Address
from pathlib import Path
from typing import override

from PyQt6.QtCore import QFileSystemWatcher, QItemSelectionModel, QModelIndex, Qt, QTimer, QUrl
from PyQt6.QtGui import QBrush, QColor, QDesktopServices, QFileSystemModel, QShowEvent, QStandardItem, QStandardItemModel
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTreeView,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.local import USERIP_DATABASES_DIR_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis._dialog_mixins import UnsavedChangesMixin
from session_sniffer.guis.logs_manager._helpers import human_readable_timestamp
from session_sniffer.guis.stylesheets import DIALOG_BUTTON_STYLESHEET, DIALOG_DANGER_BUTTON_STYLESHEET, DIALOG_PRIMARY_BUTTON_STYLESHEET
from session_sniffer.guis.userip_manager_context_menu_mixin import EntriesContextMenuMixin
from session_sniffer.guis.userip_manager_fs_sync_mixin import FileSyncMixin
from session_sniffer.guis.userip_manager_helpers import (
    DATABASE_COLUMN,
    DUPLICATE_HIGHLIGHT_BRUSH,
    INDEX_COLUMN,
    IP_COLUMN,
    RANGE_COLUMN,
    SETTINGS_DEFAULTS,
    SETTINGS_KEYS_ORDER,
    USERNAME_COLUMN,
    ElidedTooltipFilter,
    EntriesSortProxy,
    IPRangeBuilderDialog,
    human_readable_size,
    iter_userip_databases,
    iter_userip_entries_with_metadata,
    parse_settings_from_lines,
    read_preserved_sections,
    rewrite_db_without_entries,
)
from session_sniffer.guis.userip_manager_settings_mixin import SettingsPanelMixin
from session_sniffer.guis.userip_manager_tree_ops import TreeOperationsMixin
from session_sniffer.guis.utils import apply_search_icon, get_screen_size, resize_window_for_screen, set_dialog_window_flags
from session_sniffer.networking.ip_range import is_valid_ip_range_entry
from session_sniffer.text_utils import pluralize


class UserIPDatabasesManager(EntriesContextMenuMixin, FileSyncMixin, SettingsPanelMixin, TreeOperationsMixin, UnsavedChangesMixin, QDialog):
    """Non-modal dialog for managing UserIP database files and their entries."""

    def __init__(self, parent: QWidget | None) -> None:
        """Build the UserIP Databases Manager dialog."""
        super().__init__(parent)
        self.setWindowTitle(f'UserIP Databases Manager - {TITLE}')
        set_dialog_window_flags(self)
        self.setMinimumSize(1100, 660)
        screen_size = get_screen_size()
        resize_window_for_screen(self, screen_size)

        self._current_path: Path | None = None
        self._dirty = False
        self._entries_dirty = False
        self._settings_dirty = False
        self._settings_snapshot: dict[str, str] = {}
        self._global_search_active = False
        self._next_index = 1
        self._disk_snapshot: str = ''

        root_layout = QVBoxLayout(self)

        # === Main splitter: file tree (left) | entries editor (right) ===
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)

        # ------ LEFT PANEL: file tree ------
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 10, 0)

        # Tree toolbar buttons
        tree_buttons = QHBoxLayout()

        new_db_button = QPushButton('📄 New DB')
        new_db_button.setAutoDefault(False)
        new_db_button.setToolTip('Create a new UserIP database file')
        new_db_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        new_db_button.clicked.connect(self._new_database)
        tree_buttons.addWidget(new_db_button)

        new_folder_button = QPushButton('📁 New Folder')
        new_folder_button.setAutoDefault(False)
        new_folder_button.setToolTip('Create a new folder to organize databases')
        new_folder_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        new_folder_button.clicked.connect(self._new_folder)
        tree_buttons.addWidget(new_folder_button)

        self._delete_tree_button = QPushButton('🗑️ Delete')
        self._delete_tree_button.setAutoDefault(False)
        self._delete_tree_button.setToolTip('Delete the selected database or folder')
        self._delete_tree_button.setStyleSheet(DIALOG_DANGER_BUTTON_STYLESHEET)
        self._delete_tree_button.setEnabled(False)
        self._delete_tree_button.clicked.connect(self._delete_tree_item)  # reconnected dynamically in _on_tree_selection_changed
        tree_buttons.addWidget(self._delete_tree_button)

        reset_button = QPushButton('🗑️ Reset all…')
        reset_button.setAutoDefault(False)
        reset_button.setToolTip('Permanently delete all user databases and restore defaults')
        reset_button.setStyleSheet(DIALOG_DANGER_BUTTON_STYLESHEET)
        reset_button.clicked.connect(self._reset_all_databases)
        tree_buttons.addWidget(reset_button)

        left_layout.addLayout(tree_buttons)

        # Filesystem-backed tree view
        USERIP_DATABASES_DIR_PATH.mkdir(parents=True, exist_ok=True)

        self._fs_model = QFileSystemModel()
        self._fs_model.setRootPath(str(USERIP_DATABASES_DIR_PATH))
        self._fs_model.setReadOnly(False)
        self._fs_model.setNameFilters(['*.ini'])
        self._fs_model.setNameFilterDisables(False)

        self._tree = QTreeView()
        self._tree.setModel(self._fs_model)
        self._tree.setRootIndex(self._fs_model.index(str(USERIP_DATABASES_DIR_PATH)))
        self._tree.setHeaderHidden(True)
        self._tree.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)

        # Enable drag-and-drop to move files/folders within the tree
        self._tree.setDragEnabled(True)
        self._tree.setAcceptDrops(True)
        self._tree.setDropIndicatorShown(True)
        self._tree.setDragDropMode(QAbstractItemView.DragDropMode.InternalMove)

        # Hide size / type / date-modified columns — keep only the name
        for column in range(1, self._fs_model.columnCount()):
            self._tree.setColumnHidden(column, True)  # noqa: FBT003

        self._tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._tree.customContextMenuRequested.connect(self._show_tree_context_menu)

        tree_selection = self._tree.selectionModel()
        if tree_selection is not None:
            tree_selection.selectionChanged.connect(self._on_tree_selection_changed)

        left_layout.addWidget(self._tree, stretch=1)

        # Import / Export buttons (below the tree, above stats)
        transfer_buttons = QHBoxLayout()

        import_menu = QMenu(self)
        import_files_action = import_menu.addAction('📂 Import .ini file(s)…')
        if import_files_action is not None:
            import_files_action.triggered.connect(self._import_database_files)
        import_zip_action = import_menu.addAction('📦 Import from ZIP…')
        if import_zip_action is not None:
            import_zip_action.triggered.connect(self._import_from_zip)

        import_button = QPushButton('📥 Import…')
        import_button.setAutoDefault(False)
        import_button.setMaximumWidth(130)
        import_button.setToolTip('Import database files into the databases directory')
        import_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        import_button.setMenu(import_menu)
        transfer_buttons.addWidget(import_button)

        export_menu = QMenu(self)
        self._export_selected_action = export_menu.addAction('📤 Export selected database…')
        if self._export_selected_action is not None:
            self._export_selected_action.triggered.connect(self._export_selected_database)
            self._export_selected_action.setEnabled(False)
        export_zip_action = export_menu.addAction('📦 Export all as ZIP…')
        if export_zip_action is not None:
            export_zip_action.triggered.connect(self._export_all_as_zip)

        export_button = QPushButton('📤 Export…')
        export_button.setAutoDefault(False)
        export_button.setMaximumWidth(130)
        export_button.setToolTip('Export databases to an external location')
        export_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        export_button.setMenu(export_menu)
        transfer_buttons.addWidget(export_button)

        left_layout.addLayout(transfer_buttons)

        # Stats summary
        self._stats_label = QLabel('')
        self._stats_label.setWordWrap(True)
        left_layout.addWidget(self._stats_label)

        splitter.addWidget(left_panel)

        # ------ RIGHT PANEL: entries editor ------
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(10, 0, 0, 0)

        # Search / filter bar
        search_bar = QHBoxLayout()
        search_bar.addWidget(QLabel('Search:'))

        self._search_input = QLineEdit()
        self._search_input.setPlaceholderText('Filter entries by username or IP…')
        self._search_input.textChanged.connect(self._on_search_changed)
        self._search_input.returnPressed.connect(self._on_search_return_pressed)
        apply_search_icon(self._search_input)
        search_bar.addWidget(self._search_input)

        self._global_search_checkbox = QCheckBox('Search All Databases')
        self._global_search_checkbox.setToolTip('Search across all UserIP database files (read-only)')
        self._global_search_checkbox.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self._global_search_checkbox.toggled.connect(self._on_global_search_toggled)
        search_bar.addWidget(self._global_search_checkbox)

        right_layout.addLayout(search_bar)

        # ------ Settings panel (collapsible, built by mixin) ------
        self.build_settings_panel(right_layout)

        # Entries table
        self._model = QStandardItemModel(0, 5)
        self._model.setHorizontalHeaderLabels(['#', 'Username', 'IP', 'Range', 'Database'])
        self._model.dataChanged.connect(self._on_data_changed)

        self._proxy = EntriesSortProxy()
        self._proxy.setSourceModel(self._model)
        self._proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self._proxy.setFilterKeyColumn(-1)

        self._entries_table = QTreeView()
        self._entries_table.setModel(self._proxy)
        self._entries_table.setRootIsDecorated(False)
        self._entries_table.setAlternatingRowColors(True)
        self._entries_table.setSortingEnabled(True)
        self._entries_table.sortByColumn(INDEX_COLUMN, Qt.SortOrder.AscendingOrder)
        self._entries_table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self._entries_table.setEditTriggers(
            QAbstractItemView.EditTrigger.DoubleClicked | QAbstractItemView.EditTrigger.EditKeyPressed,
        )

        header = self._entries_table.header()
        if header is not None:
            header.setStretchLastSection(False)
            for column, width in ((INDEX_COLUMN, 50), (IP_COLUMN, 160), (RANGE_COLUMN, 180), (DATABASE_COLUMN, 120)):
                header.setSectionResizeMode(column, QHeaderView.ResizeMode.Interactive)
                header.resizeSection(column, width)
            header.setSectionResizeMode(USERNAME_COLUMN, QHeaderView.ResizeMode.Stretch)

        self._entries_table.setColumnHidden(DATABASE_COLUMN, True)  # noqa: FBT003

        self._entries_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._entries_table.customContextMenuRequested.connect(self.show_entries_context_menu)
        self._entries_table.doubleClicked.connect(self.on_entry_double_clicked)

        entries_selection = self._entries_table.selectionModel()
        if entries_selection is not None:
            entries_selection.selectionChanged.connect(self._on_entries_selection_changed)

        self._tooltip_filter = ElidedTooltipFilter(self._entries_table)
        viewport = self._entries_table.viewport()
        if viewport is not None:
            viewport.installEventFilter(self._tooltip_filter)

        right_layout.addWidget(self._entries_table, stretch=1)

        # Entry action buttons
        entry_buttons = QHBoxLayout()

        self._add_button = QPushButton('➕ Add Entry')  # noqa: RUF001
        self._add_button.setAutoDefault(False)
        self._add_button.setToolTip('Add a new entry (single IP, IP range, or subnet) to the current database')
        self._add_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        self._add_button.setEnabled(False)
        self._add_button.clicked.connect(self._add_entry)
        entry_buttons.addWidget(self._add_button)

        self._edit_ip_button = QPushButton('🔧 Edit IP/Range…')
        self._edit_ip_button.setAutoDefault(False)
        self._edit_ip_button.setToolTip('Edit the IP or range of the selected entry using the builder')
        self._edit_ip_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        self._edit_ip_button.setEnabled(False)
        self._edit_ip_button.clicked.connect(self._edit_selected_entry_ip)
        entry_buttons.addWidget(self._edit_ip_button)

        self._delete_button = QPushButton('❌ Delete Selected')
        self._delete_button.setAutoDefault(False)
        self._delete_button.setToolTip('Delete the selected entries (with confirmation)')
        self._delete_button.setStyleSheet(DIALOG_DANGER_BUTTON_STYLESHEET)
        self._delete_button.setEnabled(False)
        self._delete_button.clicked.connect(self._delete_selected)
        entry_buttons.addWidget(self._delete_button)

        self._open_db_button = QPushButton('📝 Open DB')
        self._open_db_button.setAutoDefault(False)
        self._open_db_button.setToolTip('Open the current database file in the default text editor')
        self._open_db_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        self._open_db_button.setEnabled(False)
        self._open_db_button.clicked.connect(self._open_db_in_editor)
        entry_buttons.addWidget(self._open_db_button)

        entry_buttons.addStretch()

        self._save_button = QPushButton('💾 Save')
        self._save_button.setAutoDefault(False)
        self._save_button.setToolTip('Save all changes to the current database file')
        self._save_button.setStyleSheet(DIALOG_PRIMARY_BUTTON_STYLESHEET)
        self._save_button.setEnabled(False)
        self._save_button.clicked.connect(self._save_database)
        entry_buttons.addWidget(self._save_button)

        right_layout.addLayout(entry_buttons)

        # File metadata
        self._file_info_label = QLabel('')
        right_layout.addWidget(self._file_info_label)

        # Status bar
        self._status_label = QLabel('')
        right_layout.addWidget(self._status_label)

        splitter.addWidget(right_panel)
        splitter.setSizes([300, 700])
        splitter.setHandleWidth(1)

        handle = splitter.handle(1)
        if handle is not None:
            handle.setDisabled(True)

        root_layout.addWidget(splitter)

        # --- Real-time filesystem sync ---
        self._fs_watcher = QFileSystemWatcher(self)
        self._fs_watcher.fileChanged.connect(self._on_fs_changed)
        self._fs_watcher.directoryChanged.connect(self._on_fs_changed)
        self._fs_sync_timer = QTimer(self)
        self._fs_sync_timer.setSingleShot(True)
        self._fs_sync_timer.setInterval(250)
        self._fs_sync_timer.timeout.connect(self._sync_from_disk)
        self._rebuild_fs_watch()

        self._refresh_stats()

    @override
    def _clear_dirty_state(self) -> None:
        """Reset the aggregate dirty state and its underlying sources."""
        self._entries_dirty = False
        self._settings_dirty = False
        self._dirty = False

    def _sync_dirty_state(self) -> None:
        """Recompute the aggregate dirty flag from the tracked sources."""
        self._dirty = self._entries_dirty or self._settings_dirty

    @override
    def _mark_entries_dirty(self) -> None:
        """Mark entry edits as dirty and refresh the aggregate state."""
        self._entries_dirty = True
        self._sync_dirty_state()

    @override
    def _mark_settings_dirty(self) -> None:
        """Re-evaluate settings dirtiness against the loaded snapshot."""
        self._settings_dirty = self.read_settings_from_widgets() != self._settings_snapshot
        self._sync_dirty_state()

    def _capture_settings_snapshot(self) -> None:
        """Record the current serialized settings as the clean baseline."""
        self._settings_snapshot = self.read_settings_from_widgets()
        self._settings_dirty = False
        self._sync_dirty_state()

    # ------------------------------------------------------------------
    # Load / parse
    # ------------------------------------------------------------------

    def _open_db_in_editor(self) -> None:
        """Open the current (or selected row's) database file in the system's default text editor."""
        if self._global_search_active:
            selection = self._entries_table.selectionModel()
            selected_rows = selection.selectedRows() if selection is not None else []
            if len(selected_rows) == 1:
                source_row = self._proxy.mapToSource(selected_rows[0]).row()
                db_item = self._model.item(source_row, DATABASE_COLUMN)
                db_path_str = db_item.data(Qt.ItemDataRole.UserRole) if db_item else None
                if db_path_str:
                    QDesktopServices.openUrl(QUrl.fromLocalFile(db_path_str))
        elif self._current_path is not None and self._current_path.is_file():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(self._current_path)))

    @override
    def _load_database(self, path: Path) -> None:
        """Parse the INI file and populate the entries table model and settings panel."""
        self._model.removeRows(0, self._model.rowCount())
        self._clear_dirty_state()
        self._search_input.clear()

        if not path.is_file():
            self._set_status(f'File not found: {path.name}')
            self._settings_container.setVisible(False)
            self._disk_snapshot = ''
            self._rebuild_fs_watch()
            return

        content = path.read_text('utf-8')
        self._disk_snapshot = content

        # Load settings panel
        _, settings_lines = read_preserved_sections(path)
        settings_dict = parse_settings_from_lines(settings_lines)
        self.populate_settings_widgets(settings_dict)
        self._capture_settings_snapshot()
        self._settings_container.setVisible(True)

        entry_count = 0
        for entry_count, (username, ip, is_looky) in enumerate(iter_userip_entries_with_metadata(content), start=1):
            self._append_row(username, ip, index=entry_count, is_looky=is_looky)

        self._next_index = entry_count + 1
        self._update_file_info(path)
        duplicate_count = self._highlight_duplicates()
        status = f'Loaded {entry_count} entries from {path.name}'
        if duplicate_count > 0:
            status += f' ({duplicate_count} duplicate{"s" if duplicate_count != 1 else ""} found)'
        self._set_status(status)
        self._rebuild_fs_watch()

    @override
    def _append_row(self, username: str, ip: str, *, index: int = 0, database: tuple[str, Path] | None = None, is_looky: bool = False) -> None:
        """Add a single row to the entries model."""
        index_item = QStandardItem(str(index))
        index_item.setData(index, Qt.ItemDataRole.UserRole)
        index_item.setFlags(index_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
        username_item = QStandardItem(username)
        if is_looky:
            username_item.setForeground(QBrush(QColor('#a855f7')))
            username_item.setToolTip('Added automatically by Looky System')
            username_item.setData(True, Qt.ItemDataRole.UserRole)  # noqa: FBT003

        db_item = QStandardItem(database[0] if database else '')
        if database is not None:
            db_item.setData(str(database[1]), Qt.ItemDataRole.UserRole)

        # Determine whether the value is a single IP or a range
        is_single_ip = False
        try:
            IPv4Address(ip)
            is_single_ip = True
        except ValueError:
            pass

        if is_single_ip:
            ip_item = QStandardItem(ip)
            range_item = QStandardItem('')
        else:
            ip_item = QStandardItem('')
            range_item = QStandardItem(ip)

        self._model.appendRow([index_item, username_item, ip_item, range_item, db_item])

    # ------------------------------------------------------------------
    # Search / filter
    # ------------------------------------------------------------------

    def _on_entries_selection_changed(self) -> None:
        """Update action buttons based on the current entries-table selection."""
        selection = self._entries_table.selectionModel()
        selected_rows = selection.selectedRows() if selection is not None else []
        has_selection = bool(selected_rows)

        self._delete_button.setEnabled(has_selection)
        if not self._global_search_active:
            self._edit_ip_button.setEnabled(len(selected_rows) == 1)

        if self._global_search_active:
            # Enable Open DB only when a single row is selected (unambiguous DB target)
            if len(selected_rows) == 1:
                source_row = self._proxy.mapToSource(selected_rows[0]).row()
                db_item = self._model.item(source_row, DATABASE_COLUMN)
                db_path_str = db_item.data(Qt.ItemDataRole.UserRole) if db_item else None
                self._open_db_button.setEnabled(bool(db_path_str))
            else:
                self._open_db_button.setEnabled(False)

    def _on_search_changed(self, text: str) -> None:
        """Apply a case-insensitive filter across all columns."""
        if text and not self._global_search_active and self._current_path is None:
            self._global_search_checkbox.setChecked(True)
        self._proxy.setFilterFixedString(text)
        self._update_entry_counts()

    def _on_search_return_pressed(self) -> None:
        """Activate global search when the user presses Enter in the search field."""
        if not self._global_search_active:
            self._global_search_checkbox.setChecked(True)

    def _on_global_search_toggled(self, checked: bool) -> None:  # noqa: FBT001
        """Switch between single-database editing mode and read-only global search mode."""
        if checked:
            if self._dirty and not self._confirm_discard():
                self._global_search_checkbox.blockSignals(True)  # noqa: FBT003
                self._global_search_checkbox.setChecked(False)
                self._global_search_checkbox.blockSignals(False)  # noqa: FBT003
                return
            self._dirty = False
            self._global_search_active = True
            self._update_file_info(None)
            self._load_all_databases()
        else:
            self._global_search_active = False
            if self._current_path is not None:
                self._load_database(self._current_path)
            else:
                self._model.removeRows(0, self._model.rowCount())
                self._set_status('')

        db_available = not self._global_search_active and self._current_path is not None
        self._add_button.setVisible(not self._global_search_active)
        self._add_button.setEnabled(db_available)
        self._edit_ip_button.setVisible(not self._global_search_active)
        self._edit_ip_button.setEnabled(False)  # driven by selection
        self._delete_button.setEnabled(False)  # driven by selection
        self._save_button.setEnabled(db_available)
        self._open_db_button.setEnabled(not self._global_search_active and self._current_path is not None)
        if self._export_selected_action is not None:
            self._export_selected_action.setEnabled(db_available)
        self._entries_table.setColumnHidden(DATABASE_COLUMN, not self._global_search_active)
        self._settings_container.setVisible(not self._global_search_active and self._current_path is not None)

        editable = QAbstractItemView.EditTrigger.DoubleClicked | QAbstractItemView.EditTrigger.EditKeyPressed
        self._entries_table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers if self._global_search_active else editable,
        )
        self._rebuild_fs_watch()

    # ------------------------------------------------------------------
    # Import: merge entries
    # ------------------------------------------------------------------
    # Edit tracking
    # ------------------------------------------------------------------

    def _on_data_changed(self, _top_left: QModelIndex, _bottom_right: QModelIndex, _roles: list[int]) -> None:
        """Mark the current database as having unsaved changes."""
        self._mark_entries_dirty()
        self._highlight_duplicates()

    # ------------------------------------------------------------------
    # Add / delete entries
    # ------------------------------------------------------------------

    @override
    def _add_entry(self) -> None:
        """Open the IP Range Builder dialog and insert the result as a new entry."""
        if self._current_path is None:
            return

        dialog = IPRangeBuilderDialog(self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        ip_text = dialog.result_entry()
        if not ip_text:
            return

        self._append_row('', ip_text, index=self._next_index)
        self._next_index += 1
        self._mark_entries_dirty()

        # Scroll to the new row and start editing the Username column
        last_source_row = self._model.rowCount() - 1
        proxy_index = self._proxy.mapFromSource(self._model.index(last_source_row, USERNAME_COLUMN))
        if proxy_index.isValid():
            self._entries_table.scrollTo(proxy_index)
            self._entries_table.setCurrentIndex(proxy_index)
            self._entries_table.edit(proxy_index)

    def _edit_selected_entry_ip(self) -> None:
        """Edit the IP/range of the currently selected entry via the builder button."""
        selection = self._entries_table.selectionModel()
        if selection is None:
            return
        selected_rows = selection.selectedRows()
        if len(selected_rows) != 1:
            return
        source_row = self._proxy.mapToSource(selected_rows[0]).row()
        self._edit_entry_ip(source_row)

    @override
    def _edit_entry_ip(self, source_row: int) -> None:
        """Open the IP Range Builder dialog to edit the IP/range of an existing entry."""
        if self._current_path is None:
            return

        current_entry = self._get_row_entry_value(source_row)
        dialog = IPRangeBuilderDialog(self, initial_entry=current_entry or None)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        new_ip_text = dialog.result_entry()
        if not new_ip_text:
            return

        try:
            IPv4Address(new_ip_text)
            is_single = True
        except ValueError:
            is_single = False

        ip_item = self._model.item(source_row, IP_COLUMN)
        range_item = self._model.item(source_row, RANGE_COLUMN)
        if ip_item is not None:
            ip_item.setText(new_ip_text if is_single else '')
        if range_item is not None:
            range_item.setText('' if is_single else new_ip_text)

        self._mark_entries_dirty()
        self._highlight_duplicates()

    @override
    def _insert_entry_at(self, source_row: int) -> None:
        """Insert a blank row at a specific position in the source model."""
        if self._current_path is None:
            return

        index_item = QStandardItem('')
        index_item.setData(0, Qt.ItemDataRole.UserRole)
        index_item.setFlags(index_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
        username_item = QStandardItem('')
        db_item = QStandardItem('')
        self._model.insertRow(source_row, [index_item, username_item, QStandardItem(''), QStandardItem(''), db_item])

        self._renumber_indexes()
        self._mark_entries_dirty()

        proxy_index = self._proxy.mapFromSource(self._model.index(source_row, USERNAME_COLUMN))
        if proxy_index.isValid():
            self._entries_table.scrollTo(proxy_index)
            self._entries_table.setCurrentIndex(proxy_index)
            self._entries_table.edit(proxy_index)

    @override
    def _move_rows(self, proxy_index: QModelIndex, direction: int) -> None:
        """Move selected rows up (direction=-1) or down (direction=+1) in the source model."""
        selection = self._entries_table.selectionModel()
        if selection is None:
            return

        selected_proxy_rows = selection.selectedRows()
        if not selected_proxy_rows:
            selected_proxy_rows = [proxy_index]

        source_rows = sorted({self._proxy.mapToSource(i).row() for i in selected_proxy_rows})

        if direction < 0:
            if source_rows[0] <= 0:
                return
            for src_row in source_rows:
                items = self._model.takeRow(src_row)
                self._model.insertRow(src_row - 1, items)
        else:
            if source_rows[-1] >= self._model.rowCount() - 1:
                return
            for src_row in reversed(source_rows):
                items = self._model.takeRow(src_row)
                self._model.insertRow(src_row + 1, items)

        self._renumber_indexes()
        self._mark_entries_dirty()

        # Reselect the moved rows
        new_source_rows = [row + direction for row in source_rows]
        selection_model = self._entries_table.selectionModel()
        if selection_model is not None:
            selection_model.clearSelection()
            for src_row in new_source_rows:
                proxy_index = self._proxy.mapFromSource(self._model.index(src_row, 0))
                if proxy_index.isValid():
                    selection_model.select(
                        proxy_index,
                        QItemSelectionModel.SelectionFlag.Select | QItemSelectionModel.SelectionFlag.Rows,
                    )
            # Scroll to the first moved row
            first_proxy = self._proxy.mapFromSource(self._model.index(new_source_rows[0], 0))
            if first_proxy.isValid():
                self._entries_table.scrollTo(first_proxy)

    def _renumber_indexes(self) -> None:
        """Reassign sequential index numbers (1-based) to all rows in the source model."""
        for row in range(self._model.rowCount()):
            index_item = self._model.item(row, INDEX_COLUMN)
            if index_item is not None:
                index_item.setText(str(row + 1))
                index_item.setData(row + 1, Qt.ItemDataRole.UserRole)
        self._next_index = self._model.rowCount() + 1

    def _delete_selected(self) -> None:
        """Delete selected rows after confirmation."""
        selection = self._entries_table.selectionModel()
        if selection is None:
            return

        selected_indexes = selection.selectedRows()
        if not selected_indexes:
            QMessageBox.information(self, TITLE, 'No entries selected.')
            return

        count = len(selected_indexes)
        source_rows = sorted(
            {self._proxy.mapToSource(i).row() for i in selected_indexes},
            reverse=True,
        )

        consequence = 'This will immediately write the changes to the database files.' if self._global_search_active else 'This action cannot be undone after saving.'

        result = QMessageBox.warning(
            self,
            TITLE,
            f'Are you sure you want to delete {count} selected {"entry" if count == 1 else "entries"}?\n\n{consequence}',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if result != QMessageBox.StandardButton.Yes:
            return

        if self._global_search_active:
            self._delete_global_search_rows(count, source_rows)
        else:
            for row in source_rows:
                self._model.removeRow(row)
            self._renumber_indexes()
            self._mark_entries_dirty()
            self._set_status(f'Deleted {count} {"entry" if count == 1 else "entries"}. Remember to save.')

    def _delete_global_search_rows(self, count: int, source_rows: list[int]) -> None:
        """Write deletions directly to database files and remove rows from the global search model."""
        rows_by_db: dict[str, list[int]] = defaultdict(list)
        for row in source_rows:
            db_item = self._model.item(row, DATABASE_COLUMN)
            db_path_str = db_item.data(Qt.ItemDataRole.UserRole) if db_item else None
            if db_path_str:
                rows_by_db[db_path_str].append(row)

        for db_path_str, rows in rows_by_db.items():
            db_path = Path(db_path_str)
            if not db_path.is_file():
                continue
            to_remove: set[tuple[str, str]] = set()
            for row in rows:
                u_item = self._model.item(row, USERNAME_COLUMN)
                username = u_item.text() if u_item else ''
                ip = self._get_row_entry_value(row)
                if username and ip:
                    to_remove.add((username, ip))
            rewrite_db_without_entries(db_path, to_remove)

        for row in source_rows:
            self._model.removeRow(row)
        self._update_entry_counts()
        self._set_status(f'Deleted {count} {"entry" if count == 1 else "entries"} from database files.')

    # ------------------------------------------------------------------
    # Save
    # ------------------------------------------------------------------

    def _save_database(self) -> None:
        """Validate entries and write the database file back to disk."""
        if self._current_path is None:
            return

        # --- Validate all entries ---
        errors: list[str] = []
        entries: list[tuple[str, str, bool]] = []

        for row in range(self._model.rowCount()):
            username_item = self._model.item(row, USERNAME_COLUMN)
            if username_item is None:
                continue

            username = username_item.text().strip()
            ip = self._get_row_entry_value(row)

            if not username and not ip:
                continue  # skip completely empty rows

            if not username:
                errors.append(f'Row {row + 1}: Username is empty.')
            if not ip:
                errors.append(f'Row {row + 1}: IP or Range is empty.')
            elif not is_valid_ip_range_entry(ip):
                errors.append(f'Row {row + 1}: "{ip}" is not a valid IP address or range.')

            if username and ip:
                is_looky = bool(username_item.data(Qt.ItemDataRole.UserRole))
                entries.append((username, ip, is_looky))

        if errors:
            QMessageBox.critical(self, TITLE, '\n'.join(errors))
            return

        # --- Deduplicate exact (username, ip) pairs ---
        seen: set[tuple[str, str]] = set()
        unique_entries: list[tuple[str, str, bool]] = []
        duplicate_count = 0
        for entry in entries:
            base_entry = (entry[0], entry[1])
            if base_entry in seen:
                duplicate_count += 1
                continue
            seen.add(base_entry)
            unique_entries.append(entry)
        entries = unique_entries

        if duplicate_count > 0:
            QMessageBox.information(
                self,
                TITLE,
                f'{duplicate_count} exact duplicate entr{"y was" if duplicate_count == 1 else "ies were"} removed before saving.',
            )

        # --- Read existing file to preserve header ---
        header_lines, _ = read_preserved_sections(self._current_path)

        # --- Build settings from widgets ---
        settings_values = self.read_settings_from_widgets()

        # --- Validate COLOR ---
        color_value = settings_values.get('COLOR', '')
        if color_value and not QColor(color_value).isValid():
            QMessageBox.critical(self, TITLE, f'Invalid color value: "{color_value}"\n\nUse a Qt color name (e.g. RED, GREEN) or hex (e.g. #FF00FF).')
            return

        # --- Build new file content ---
        output_lines: list[str] = [*header_lines]

        output_lines.append('[Settings]')
        output_lines.extend(f'{key}={settings_values.get(key, SETTINGS_DEFAULTS[key])}' for key in SETTINGS_KEYS_ORDER)
        output_lines.append('')

        output_lines.append('[UserIP]')
        for username, ip, is_looky in entries:
            suffix = ' ; looky' if is_looky else ''
            output_lines.append(f'{username}={ip}{suffix}')
        output_lines.append('')  # trailing newline

        written = '\n'.join(output_lines)
        self._current_path.write_text(written, encoding='utf-8')
        self._disk_snapshot = written

        self._settings_snapshot = settings_values.copy()
        self._clear_dirty_state()
        self._update_file_info(self._current_path)
        self._set_status(f'Saved {len(entries)} entries to {self._current_path.name}')
        self._refresh_stats()
        self._rebuild_fs_watch()
        if duplicate_count > 0:
            self._load_database(self._current_path)

    # ------------------------------------------------------------------
    # Duplicate highlighting
    # ------------------------------------------------------------------

    @override
    def _highlight_duplicates(self) -> int:
        """Scan all rows for exact (username, ip) duplicates and highlight them.

        Returns:
            The number of duplicate rows found.
        """
        seen: dict[tuple[str, str], int] = {}
        duplicate_rows: set[int] = set()

        for row in range(self._model.rowCount()):
            username_item = self._model.item(row, USERNAME_COLUMN)
            if username_item is None:
                continue

            username = username_item.text().strip()
            ip = self._get_row_entry_value(row)
            if not username or not ip:
                continue

            key = (username, ip)
            if key in seen:
                duplicate_rows.add(row)
                duplicate_rows.add(seen[key])
            else:
                seen[key] = row

        self._model.blockSignals(True)  # noqa: FBT003
        try:
            for row in range(self._model.rowCount()):
                for column in range(DATABASE_COLUMN):
                    item = self._model.item(row, column)
                    if item is None:
                        continue
                    if row in duplicate_rows:
                        item.setBackground(DUPLICATE_HIGHLIGHT_BRUSH)
                    else:
                        item.setData(None, Qt.ItemDataRole.BackgroundRole)
        finally:
            self._model.blockSignals(False)  # noqa: FBT003

        return len(duplicate_rows)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @override
    def _get_row_entry_value(self, row: int) -> str:
        """Return the effective IP or Range value from a row (whichever is non-empty)."""
        ip_item = self._model.item(row, IP_COLUMN)
        ip_text = ip_item.text().strip() if ip_item else ''
        if ip_text:
            return ip_text
        range_item = self._model.item(row, RANGE_COLUMN)
        return range_item.text().strip() if range_item else ''

    @override
    def _set_status(self, text: str) -> None:
        """Update the status label at the bottom of the right panel."""
        self._status_label.setText(text)

    @override
    def _update_entry_counts(self) -> None:
        """Update the status label with visible/total entry counts."""
        total = self._model.rowCount()
        visible = self._proxy.rowCount()
        parts = [f'{total} entr{"y" if total == 1 else "ies"}']
        if visible != total:
            parts.append(f'{visible} visible')
        self._status_label.setText('  |  '.join(parts))

    @override
    def _update_file_info(self, path: Path | None) -> None:
        """Update the file metadata label for the given database file."""
        if path is None or not path.is_file():
            self._file_info_label.setText('')
            return
        stat = path.stat()
        size = human_readable_size(int(stat.st_size))
        modified = datetime.fromtimestamp(stat.st_mtime, tz=UTC).astimezone()
        self._file_info_label.setText(f'{path.name}  |  {size}  |  Last modified: {human_readable_timestamp(modified)}')

    @override
    def _refresh_stats(self) -> None:
        """Scan all UserIP databases and update the stats summary label."""
        total_files = 0
        total_entries = 0
        unique_ips: set[str] = set()
        unique_usernames: set[str] = set()

        for _ini_path, entries in iter_userip_databases():
            total_files += 1
            for username, ip in entries:
                total_entries += 1
                unique_ips.add(ip)
                unique_usernames.add(username)

        parts = [
            f'{total_files} database{pluralize(total_files)}',
            f'{total_entries} entr{"y" if total_entries == 1 else "ies"}',
            f'{len(unique_usernames)} unique user{pluralize(len(unique_usernames))}',
            f'{len(unique_ips)} unique IP{pluralize(len(unique_ips))}',
        ]
        self._stats_label.setText('\n'.join(parts))

    @override
    def _has_unsaved_changes_for_close(self) -> bool:
        """Return `True` if there are dirty (unsaved) changes."""
        return self._dirty

    @override
    def _save_on_close(self) -> bool:
        """Save the database; return `True` if the save succeeded (no longer dirty)."""
        self._save_database()
        return not self._dirty

    @override
    def showEvent(self, a0: QShowEvent | None) -> None:
        """Handle the window show event and maximize if required."""
        super().showEvent(a0)
        if self.property('_should_maximize_on_show') is True:
            self.setProperty('_should_maximize_on_show', False)  # noqa: FBT003
            self.showMaximized()
