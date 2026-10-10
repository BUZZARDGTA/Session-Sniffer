"""UserIP Databases Manager dialog for browsing, editing, and managing UserIP database files and entries."""

import logging
from datetime import UTC, datetime
from ipaddress import IPv4Address
from typing import TYPE_CHECKING, ClassVar, override

if TYPE_CHECKING:
    from pathlib import Path

from PySide6.QtCore import QByteArray, QModelIndex, QSignalBlocker, Qt, QUrl
from PySide6.QtGui import (
    QBrush,
    QCloseEvent,
    QColor,
    QDesktopServices,
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
    QCheckBox,
    QDialog,
    QFileSystemModel,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QPushButton,
    QSplitter,
    QTreeView,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.local import GUI_STATE_PATH, RESOURCES_DIR_PATH, USERIP_DATABASES_DIR_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis._dialog_mixins import prompt_unsaved_changes_close
from session_sniffer.guis.delegates import ElidedTextTooltipDelegate, SearchHighlightDelegate
from session_sniffer.guis.file_watch import DebouncedFileWatcher
from session_sniffer.guis.logs_manager._helpers import human_readable_timestamp
from session_sniffer.guis.stylesheets import DIALOG_BUTTON_STYLESHEET, DIALOG_DANGER_BUTTON_STYLESHEET, DIALOG_PRIMARY_BUTTON_STYLESHEET
from session_sniffer.guis.table_column_resizing import setup_table_header_context_menu
from session_sniffer.guis.userip_manager_context_menu_mixin import EntriesContextMenuMixin
from session_sniffer.guis.userip_manager_entries_ops_mixin import UserIPEntriesOperationsMixin
from session_sniffer.guis.userip_manager_helpers import (
    DATABASE_COLUMN,
    INDEX_COLUMN,
    IP_COLUMN,
    RANGE_COLUMN,
    USERNAME_COLUMN,
    EntriesSortProxy,
    human_readable_size,
    iter_userip_databases,
    iter_userip_entries_with_metadata,
    parse_settings_from_lines,
    read_preserved_sections,
)
from session_sniffer.guis.userip_manager_import_export_mixin import UserIPImportExportMixin
from session_sniffer.guis.userip_manager_settings_mixin import SettingsPanelMixin
from session_sniffer.guis.userip_manager_tree_ops import TreeOperationsMixin
from session_sniffer.guis.utils import (
    apply_search_icon,
    get_screen_size,
    resize_window_for_screen,
    scale_by_ui,
    set_dialog_window_flags,
)
from session_sniffer.models import GUIState
from session_sniffer.settings.settings import Settings

logger = logging.getLogger(__name__)


def _load_userip_manager_state() -> tuple[QByteArray | None, bool, QByteArray | None, dict[str, int] | None]:
    """Load saved window geometry, maximized state, splitter state, and table column widths from local app data."""
    gui_state = GUIState.load()
    userip_manager_geometry = gui_state.userip_manager_geometry
    geometry: QByteArray | None = (
        QByteArray.fromHex(userip_manager_geometry.encode('ascii')) if userip_manager_geometry is not None and userip_manager_geometry else None
    )
    maximized: bool = gui_state.userip_manager_maximized
    userip_manager_splitter = gui_state.userip_manager_splitter
    splitter: QByteArray | None = (
        QByteArray.fromHex(userip_manager_splitter.encode('ascii')) if userip_manager_splitter is not None and userip_manager_splitter else None
    )
    return geometry, maximized, splitter, gui_state.userip_manager_table_column_widths


def _save_userip_manager_state(
    geometry: QByteArray,
    splitter: QByteArray,
    *,
    maximized: bool,
    table_column_widths: dict[str, int] | None = None,
) -> None:
    """Save window geometry, maximized state, splitter state, and table column widths to local app data."""
    gui_state = GUIState.load()
    gui_state.userip_manager_geometry = geometry.toHex().toStdString()
    gui_state.userip_manager_maximized = maximized
    gui_state.userip_manager_splitter = splitter.toHex().toStdString()
    gui_state.userip_manager_table_column_widths = table_column_widths
    gui_state.save()


class UserIPDatabasesManager(
    UserIPEntriesOperationsMixin,
    UserIPImportExportMixin,
    EntriesContextMenuMixin,
    SettingsPanelMixin,
    TreeOperationsMixin,
    QDialog,
):
    """Non-modal dialog for managing UserIP database files and their entries."""

    _cached_geometry: ClassVar[QByteArray | None] = None
    _cached_maximized: ClassVar[bool] = False
    _cached_splitter: ClassVar[QByteArray | None] = None
    _cached_column_widths: ClassVar[dict[str, int] | None] = None

    def __init__(self, parent: QWidget | None = None) -> None:
        """Build the UserIP Databases Manager dialog."""
        super().__init__(parent)
        self.setWindowTitle(f'UserIP Databases Manager - {TITLE}')
        set_dialog_window_flags(self)
        self.setMinimumSize(scale_by_ui(1000), scale_by_ui(600))
        self._custom_column_widths: dict[str, int] | None = None
        self._is_programmatic_resizing: bool = False

        if Settings.gui_remember_window_layout:
            if UserIPDatabasesManager._cached_geometry is None and GUI_STATE_PATH.is_file():
                (
                    UserIPDatabasesManager._cached_geometry,
                    UserIPDatabasesManager._cached_maximized,
                    UserIPDatabasesManager._cached_splitter,
                    UserIPDatabasesManager._cached_column_widths,
                ) = _load_userip_manager_state()
        else:
            UserIPDatabasesManager._cached_geometry = None
            UserIPDatabasesManager._cached_maximized = False
            UserIPDatabasesManager._cached_splitter = None
            UserIPDatabasesManager._cached_column_widths = None

        if UserIPDatabasesManager._cached_geometry is not None:
            self.restoreGeometry(UserIPDatabasesManager._cached_geometry)
            if UserIPDatabasesManager._cached_maximized:
                self.setProperty('_should_maximize_on_show', True)  # noqa: FBT003
        else:
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
        self._saving = False
        self._looky_icon = QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'eye.svg'))

        root_layout = QVBoxLayout(self)

        # === Main splitter: file tree (left) | entries editor (right) ===
        self._splitter = QSplitter(Qt.Orientation.Horizontal)
        self._splitter.setChildrenCollapsible(False)

        # ------ LEFT PANEL: file tree ------
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 10, 0)

        # Tree toolbar buttons
        tree_buttons = QHBoxLayout()

        new_db_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'new_file.svg')), ' New DB')
        new_db_button.setAutoDefault(False)
        new_db_button.setToolTip('Create a new UserIP database file')
        new_db_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        new_db_button.clicked.connect(self._new_database)
        tree_buttons.addWidget(new_db_button)

        new_folder_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'folder.svg')), ' New Folder')
        new_folder_button.setAutoDefault(False)
        new_folder_button.setToolTip('Create a new folder to organize databases')
        new_folder_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        new_folder_button.clicked.connect(self._new_folder)
        tree_buttons.addWidget(new_folder_button)

        self._delete_tree_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'remove.svg')), ' Delete')
        self._delete_tree_button.setAutoDefault(False)
        self._delete_tree_button.setFixedWidth(115)
        self._delete_tree_button.setToolTip('Delete the selected database or folder')
        self._delete_tree_button.setStyleSheet(DIALOG_DANGER_BUTTON_STYLESHEET)
        self._delete_tree_button.setEnabled(False)
        self._delete_tree_button.clicked.connect(self._delete_tree_item)  # reconnected dynamically in _on_tree_selection_changed
        tree_buttons.addWidget(self._delete_tree_button)

        reset_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'reset.svg')), ' Reset all…')
        reset_button.setAutoDefault(False)
        reset_button.setFixedWidth(115)
        reset_button.setToolTip('Permanently delete all user databases and restore defaults')
        reset_button.setStyleSheet(DIALOG_DANGER_BUTTON_STYLESHEET)
        reset_button.clicked.connect(self._reset_all_databases)
        tree_buttons.addWidget(reset_button)

        left_layout.addLayout(tree_buttons)

        # Filesystem-backed tree view
        USERIP_DATABASES_DIR_PATH.mkdir(parents=True, exist_ok=True)

        self._fs_model = QFileSystemModel(self)
        self._fs_model.setRootPath(str(USERIP_DATABASES_DIR_PATH))
        self._fs_model.setReadOnly(False)
        self._fs_model.setNameFilters(['*.ini'])
        self._fs_model.setNameFilterDisables(False)

        self._tree = QTreeView()
        self._tree.setModel(self._fs_model)
        self._tree.setRootIndex(self._fs_model.index(str(USERIP_DATABASES_DIR_PATH)))
        self._tree.setHeaderHidden(True)
        self._tree.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._tree.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self._tree.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self._tree.setItemDelegate(ElidedTextTooltipDelegate(self._tree))
        self._tree.setWordWrap(False)

        # Enable drag-and-drop to move files/folders within the tree
        self._tree.setDragEnabled(True)
        self._tree.setAcceptDrops(True)
        self._tree.setDropIndicatorShown(True)
        self._tree.setDragDropMode(QAbstractItemView.DragDropMode.InternalMove)

        # Hide size / type / date-modified columns — keep only the name
        for column in range(1, self._fs_model.columnCount()):
            self._tree.hideColumn(column)

        self._tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._tree.customContextMenuRequested.connect(self._show_tree_context_menu)

        tree_selection = self._tree.selectionModel()
        if tree_selection:
            tree_selection.selectionChanged.connect(self._on_tree_selection_changed)

        left_layout.addWidget(self._tree, stretch=1)

        # Import / Export buttons (below the tree, above stats)
        transfer_buttons = QHBoxLayout()

        import_menu = QMenu(self)
        import_files_action = import_menu.addAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'folder.svg')), 'Import .ini file(s)…')
        if import_files_action:
            import_files_action.triggered.connect(self._import_database_files)
        import_zip_action = import_menu.addAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'import.svg')), 'Import from ZIP…')
        if import_zip_action:
            import_zip_action.triggered.connect(self._import_from_zip)

        import_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'import.svg')), ' Import…')
        import_button.setAutoDefault(False)
        import_button.setMaximumWidth(130)
        import_button.setToolTip('Import database files into the databases directory')
        import_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        import_button.setMenu(import_menu)
        transfer_buttons.addWidget(import_button)

        export_menu = QMenu(self)
        self._export_selected_action = export_menu.addAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'export.svg')), 'Export selected database…')
        if self._export_selected_action:
            self._export_selected_action.triggered.connect(self._export_selected_database)
            self._export_selected_action.setEnabled(False)
        export_zip_action = export_menu.addAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'export.svg')), 'Export all as ZIP…')
        if export_zip_action:
            export_zip_action.triggered.connect(self._export_all_as_zip)
        export_menu.addSeparator()
        backup_databases_action = export_menu.addAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'export.svg')), 'Backup databases now')
        if backup_databases_action:
            backup_databases_action.triggered.connect(self._backup_databases_now)
        open_backups_action = export_menu.addAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'folder.svg')), 'Open backups folder')
        if open_backups_action:
            open_backups_action.triggered.connect(self._open_backups_folder)

        export_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'export.svg')), ' Export…')
        export_button.setAutoDefault(False)
        export_button.setMaximumWidth(130)
        export_button.setToolTip('Export databases to an external location')
        export_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        export_button.setMenu(export_menu)
        transfer_buttons.addWidget(export_button)

        left_layout.addLayout(transfer_buttons)

        # Fancy Metadata Container
        self._metadata_container = QFrame()
        self._metadata_container.setStyleSheet("""
            QFrame {
                background-color: rgba(16, 20, 26, 0.85);
                border: 1px solid rgba(50, 65, 80, 0.7);
                border-radius: 6px;
            }
            QLabel {
                background: transparent;
                border: none;
                line-height: 1.4;
            }
        """)
        status_row = QHBoxLayout(self._metadata_container)
        status_row.setContentsMargins(12, 10, 12, 10)
        status_row.setSpacing(16)

        self._stats_label = QLabel('')
        self._stats_label.setWordWrap(True)
        status_row.addWidget(self._stats_label, stretch=1, alignment=Qt.AlignmentFlag.AlignTop)

        right_col = QVBoxLayout()
        right_col.setSpacing(6)

        self._file_info_label = QLabel('')
        self._file_info_label.setWordWrap(True)
        right_col.addWidget(self._file_info_label, alignment=Qt.AlignmentFlag.AlignTop)

        self._status_label = QLabel('')
        self._status_label.setWordWrap(True)
        right_col.addWidget(self._status_label, alignment=Qt.AlignmentFlag.AlignTop)

        right_col.addStretch()
        status_row.addLayout(right_col, stretch=2)

        left_layout.addWidget(self._metadata_container)

        self._splitter.addWidget(left_panel)

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
        self._model.setHorizontalHeaderLabels(['#', 'Usernames', 'IP', 'Range', 'Database'])
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
        self._entries_table.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self._entries_table.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self._entries_table.setItemDelegate(
            SearchHighlightDelegate(self._entries_table, self._search_input.text),
        )
        self._entries_table.setWordWrap(False)
        self._entries_table.sortByColumn(INDEX_COLUMN, Qt.SortOrder.AscendingOrder)
        self._entries_table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self._entries_table.setEditTriggers(
            QAbstractItemView.EditTrigger.DoubleClicked | QAbstractItemView.EditTrigger.EditKeyPressed,
        )

        header = self._entries_table.header()
        if header:
            header.setStretchLastSection(False)
            for column in range(self._model.columnCount()):
                header.setSectionResizeMode(column, QHeaderView.ResizeMode.Interactive)

        self._entries_table.hideColumn(DATABASE_COLUMN)
        self._reset_column_sizes()
        setup_table_header_context_menu(self._entries_table, on_reset=self._reset_column_sizes)
        if header:
            header.sectionResized.connect(self._on_section_resized)
        cached_column_widths = UserIPDatabasesManager._cached_column_widths
        if cached_column_widths is not None and cached_column_widths:
            self._apply_column_widths(cached_column_widths)

        self._entries_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._entries_table.customContextMenuRequested.connect(self.show_entries_context_menu)
        self._entries_table.doubleClicked.connect(self.on_entry_double_clicked)
        QShortcut(QKeySequence('Ctrl+C'), self._entries_table).activated.connect(self._copy_selected_entries)
        QShortcut(QKeySequence('Ctrl+A'), self._entries_table).activated.connect(self._entries_table.selectAll)
        QShortcut(QKeySequence('Delete'), self._entries_table).activated.connect(self._delete_selected)
        QShortcut(QKeySequence('F2'), self._entries_table).activated.connect(self._rename_selected)

        entries_selection = self._entries_table.selectionModel()
        if entries_selection:
            entries_selection.selectionChanged.connect(self._on_entries_selection_changed)

            def _on_entry_current_changed(_curr: QModelIndex, _prev: QModelIndex) -> None:
                viewport = self._entries_table.viewport()
                if viewport:
                    viewport.update()

            entries_selection.currentChanged.connect(_on_entry_current_changed)

        right_layout.addWidget(self._entries_table, stretch=1)

        # Entry action buttons
        entry_buttons = QHBoxLayout()

        self._add_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'add.svg')), ' Add Entry')
        self._add_button.setAutoDefault(False)
        self._add_button.setToolTip('Add a new entry (single IP, IP range, or subnet) to the current database')
        self._add_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        self._add_button.setEnabled(False)
        self._add_button.clicked.connect(self._add_entry)
        entry_buttons.addWidget(self._add_button)

        self._edit_ip_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'edit.svg')), ' Edit IP/Range…')
        self._edit_ip_button.setAutoDefault(False)
        self._edit_ip_button.setToolTip('Edit the IP or range of the selected entry using the builder')
        self._edit_ip_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        self._edit_ip_button.setEnabled(False)
        self._edit_ip_button.clicked.connect(self._edit_selected_entry_ip)
        entry_buttons.addWidget(self._edit_ip_button)

        self._rename_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'edit.svg')), ' Rename')
        self._rename_button.setAutoDefault(False)
        self._rename_button.setToolTip('Rename the username of the selected entry or entries')
        self._rename_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        self._rename_button.setEnabled(False)
        self._rename_button.clicked.connect(self._rename_selected)
        entry_buttons.addWidget(self._rename_button)

        self._open_db_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'text_editor.svg')), ' Open DB')
        self._open_db_button.setAutoDefault(False)
        self._open_db_button.setToolTip('Open the current database file in the default text editor')
        self._open_db_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        self._open_db_button.setEnabled(False)
        self._open_db_button.clicked.connect(self._open_db_in_editor)
        entry_buttons.addWidget(self._open_db_button)

        self._delete_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'remove.svg')), ' Delete Selected')
        self._delete_button.setAutoDefault(False)
        self._delete_button.setToolTip('Delete the selected entries (with confirmation)')
        self._delete_button.setStyleSheet(DIALOG_DANGER_BUTTON_STYLESHEET)
        self._delete_button.setEnabled(False)
        self._delete_button.clicked.connect(self._delete_selected)
        entry_buttons.addWidget(self._delete_button)

        entry_buttons.addStretch()

        self._save_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'save.svg')), ' Save')
        self._save_button.setAutoDefault(False)
        self._save_button.setMinimumWidth(120)
        self._save_button.setToolTip('Save all changes to the current database file')
        self._save_button.setStyleSheet(DIALOG_PRIMARY_BUTTON_STYLESHEET)
        self._save_button.setEnabled(False)
        self._save_button.clicked.connect(self._save_database)
        entry_buttons.addWidget(self._save_button)

        right_layout.addLayout(entry_buttons)

        self._splitter.addWidget(right_panel)
        self._splitter.setHandleWidth(scale_by_ui(4))
        self._splitter.handle(1).setEnabled(True)

        if UserIPDatabasesManager._cached_splitter is not None:
            self._splitter.restoreState(UserIPDatabasesManager._cached_splitter)
        else:
            self._splitter.setSizes([scale_by_ui(280), scale_by_ui(820)])

        def _on_splitter_moved(_pos: int, _index: int) -> None:
            self._adjust_username_column_width()

        self._splitter.splitterMoved.connect(_on_splitter_moved)
        root_layout.addWidget(self._splitter)

        # --- Real-time filesystem sync ---
        self._fs_watcher = DebouncedFileWatcher(self, self._sync_from_disk, interval_ms=250, poll_interval_ms=250)
        self._rebuild_fs_watch()

        self._refresh_stats()

    @override
    def _clear_dirty_state(self) -> None:
        """Reset the aggregate dirty state and its underlying sources."""
        self._entries_dirty = False
        self._settings_dirty = False
        self._dirty = False
        self._sync_dirty_state()

    def _sync_dirty_state(self) -> None:
        """Recompute the aggregate dirty flag from the tracked sources and update the Save button."""
        self._dirty = (self._entries_dirty or self._settings_dirty) and self._current_path is not None and not self._global_search_active
        self._save_button.setEnabled(self._dirty)

    @override
    def _mark_entries_dirty(self) -> None:
        """Mark entry edits as dirty and refresh the aggregate state."""
        if self._global_search_active or self._current_path is None:
            return
        self._entries_dirty = True
        self._sync_dirty_state()

    @override
    def _mark_settings_dirty(self) -> None:
        """Re-evaluate settings dirtiness against the loaded snapshot."""
        if self._global_search_active or self._current_path is None:
            return
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
            selected_rows = selection.selectedRows() if selection else []
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
            username_item.setIcon(self._looky_icon)
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
        selected_rows = selection.selectedRows() if selection else []
        has_selection = bool(selected_rows)

        self._delete_button.setEnabled(has_selection)
        self._rename_button.setEnabled(has_selection)
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
        self._entries_table.viewport().update()

    def _on_search_return_pressed(self) -> None:
        """Activate global search when the user presses Enter in the search field."""
        if not self._global_search_active:
            self._global_search_checkbox.setChecked(True)

    def _on_global_search_toggled(self, checked: bool) -> None:  # noqa: FBT001
        """Switch between single-database editing mode and read-only global search mode."""
        if checked:
            if self._dirty and not self._confirm_discard():
                with QSignalBlocker(self._global_search_checkbox):
                    self._global_search_checkbox.setChecked(False)
                return
            self._clear_dirty_state()
            self._global_search_active = True
            self._update_file_info(None)
            self._load_all_databases()
        else:
            self._clear_dirty_state()
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
        self._rename_button.setEnabled(False)  # driven by selection
        self._delete_button.setEnabled(False)  # driven by selection
        self._save_button.setEnabled(self._dirty)
        self._open_db_button.setEnabled(not self._global_search_active and self._current_path is not None)
        if self._export_selected_action is not None:
            self._export_selected_action.setEnabled(db_available)
        self._entries_table.setColumnHidden(DATABASE_COLUMN, not self._global_search_active)
        self._reset_column_sizes()
        self._settings_container.setVisible(not self._global_search_active and self._current_path is not None)

        editable = QAbstractItemView.EditTrigger.DoubleClicked | QAbstractItemView.EditTrigger.EditKeyPressed
        self._entries_table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers if self._global_search_active else editable,
        )
        self._rebuild_fs_watch()

    def search_global(self, text: str) -> None:
        """Programmatically activate global search mode with the given text."""
        self._search_input.setText(text)
        if not self._global_search_active:
            self._global_search_checkbox.setChecked(True)

    # ------------------------------------------------------------------
    # Import: merge entries
    # ------------------------------------------------------------------
    # Edit tracking
    # ------------------------------------------------------------------

    def _on_data_changed(self, top_left: QModelIndex, bottom_right: QModelIndex, roles: list[int]) -> None:
        """Mark the current database as having unsaved changes."""
        if self._global_search_active or self._current_path is None or self._saving:
            return
        if roles and Qt.ItemDataRole.EditRole not in roles and Qt.ItemDataRole.DisplayRole not in roles:
            return
        if top_left.column() <= USERNAME_COLUMN <= bottom_right.column():
            for row in range(top_left.row(), bottom_right.row() + 1):
                item = self._model.item(row, USERNAME_COLUMN)
                if item and item.data(Qt.ItemDataRole.UserRole):
                    item.setData(False, Qt.ItemDataRole.UserRole)  # noqa: FBT003
                    item.setIcon(QIcon())
                    item.setForeground(QBrush())
                    item.setToolTip('')
        self._mark_entries_dirty()
        self._highlight_duplicates()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @override
    def _set_status(self, text: str) -> None:
        """Update the status label at the bottom of the right panel."""
        self._status_label.setText(f'<i style="color:#50c878;">{text}</i>')

    @override
    def _update_entry_counts(self) -> None:
        """Update the status label with visible/total entry counts."""
        total = self._model.rowCount()
        visible = self._proxy.rowCount()

        # In global search without filters, the total table rows match the global stats block exactly
        if self._global_search_active and visible == total:
            self._status_label.setText('<span style="color:#a0b0c0;"><i>Showing all databases</i></span>')
            return

        text = f'<span style="color:#8a9bad;">Table Entries:</span> <b style="color:#e0e0e0;">{total}</b>'
        if visible != total:
            text += f'<br><span style="color:#8a9bad;">Visible (Filtered):</span> <b style="color:#6db3f2;">{visible}</b>'

        self._status_label.setText(text)

    @override
    def _update_file_info(self, path: Path | None) -> None:
        """Update the file metadata label for the given database file."""
        if path is None or not path.is_file():
            self._file_info_label.setText('<span style="color:#607080;"><i>No database selected</i></span>')
            return
        stat = path.stat()
        size = human_readable_size(stat.st_size)
        modified = datetime.fromtimestamp(stat.st_mtime, tz=UTC).astimezone()

        self._file_info_label.setText(
            f'<span style="color:#8a9bad;">File:</span> <b style="color:#6db3f2;">{path.name}</b><br>'
            f'<span style="color:#8a9bad;">Size:</span> <b style="color:#e0e0e0;">{size}</b><br>'
            f'<span style="color:#8a9bad;">Modified:</span> <span style="color:#a0b0c0;">{human_readable_timestamp(modified)}</span>'
        )

    @override
    def _refresh_stats(self) -> None:
        """Scan all UserIP databases and update the stats summary label."""
        total_files = 0
        total_entries = 0
        unique_ips: set[str] = set()
        unique_usernames: set[str] = set()

        for _ini_path, entries in iter_userip_databases():
            total_files += 1
            for username, ip, _is_looky in entries:
                total_entries += 1
                unique_ips.add(ip)
                unique_usernames.add(username)

        parts = [
            f'<span style="color:#8a9bad;">Databases:</span> <b style="color:#e0e0e0;">{total_files}</b>',
            f'<span style="color:#8a9bad;">Entries:</span> <b style="color:#e0e0e0;">{total_entries}</b>',
            f'<span style="color:#8a9bad;">Unique Users:</span> <b style="color:#e0e0e0;">{len(unique_usernames)}</b>',
            f'<span style="color:#8a9bad;">Unique IPs:</span> <b style="color:#e0e0e0;">{len(unique_ips)}</b>',
        ]
        self._stats_label.setText('<br>'.join(parts))

    def _has_unsaved_changes_for_close(self) -> bool:
        """Return `True` if there are dirty (unsaved) changes."""
        return self._dirty and self._current_path is not None and not self._global_search_active

    @override
    def _save_on_close(self) -> bool:
        """Save the database; return `True` if the save succeeded (no longer dirty)."""
        if self._current_path is None or self._global_search_active:
            return True
        self._save_database()
        return not self._dirty

    @override
    def closeEvent(self, event: QCloseEvent) -> None:
        """Prompt to save unsaved changes and persist window layout on close."""
        if not prompt_unsaved_changes_close(
            self,
            self._has_unsaved_changes_for_close,
            self._save_on_close,
            event,
        ):
            return

        self._fs_watcher.stop()
        super().closeEvent(event)
        if event.isAccepted() and Settings.gui_remember_window_layout:
            geometry = self.saveGeometry()
            maximized = self.isMaximized()
            splitter_state = self._splitter.saveState()
            UserIPDatabasesManager._cached_geometry = geometry
            UserIPDatabasesManager._cached_maximized = maximized
            UserIPDatabasesManager._cached_splitter = splitter_state
            UserIPDatabasesManager._cached_column_widths = self._custom_column_widths
            _save_userip_manager_state(
                geometry,
                splitter_state,
                maximized=maximized,
                table_column_widths=self._custom_column_widths,
            )

    @override
    def showEvent(self, a0: QShowEvent) -> None:
        """Handle the window show event and maximize if required."""
        super().showEvent(a0)
        if self.property('_should_maximize_on_show') is True:
            self.setProperty('_should_maximize_on_show', False)  # noqa: FBT003
            self.showMaximized()
        self._adjust_username_column_width()

    @override
    def resizeEvent(self, a0: QResizeEvent) -> None:
        """Adjust column widths when the dialog is resized."""
        super().resizeEvent(a0)
        self._adjust_username_column_width()

    def _on_section_resized(self, logical_index: int, _old_size: int, new_size: int) -> None:
        """Track user-driven column resizing in the entries table."""
        if self._is_programmatic_resizing:
            return
        header_label = str(self._model.headerData(logical_index, Qt.Orientation.Horizontal) or '')
        if header_label:
            if self._custom_column_widths is None:
                self._custom_column_widths = self._get_column_widths()
            self._custom_column_widths[header_label] = new_size

    def _get_column_widths(self) -> dict[str, int]:
        """Return a mapping of column header names to their current section widths."""
        widths: dict[str, int] = {}
        for column in range(self._model.columnCount()):
            header_label = str(self._model.headerData(column, Qt.Orientation.Horizontal) or '')
            if header_label:
                widths[header_label] = self._entries_table.columnWidth(column)
        return widths

    def _apply_column_widths(self, widths: dict[str, int]) -> None:
        """Apply saved column widths to matching entries table header sections."""
        header = self._entries_table.header()
        if not header:
            return
        self._is_programmatic_resizing = True
        try:
            for column in range(self._model.columnCount()):
                header_label = str(self._model.headerData(column, Qt.Orientation.Horizontal) or '')
                if header_label in widths and widths[header_label] > 0:
                    header.setSectionResizeMode(column, QHeaderView.ResizeMode.Interactive)
                    self._entries_table.setColumnWidth(column, widths[header_label])
            self._custom_column_widths = dict(widths)
        finally:
            self._is_programmatic_resizing = False

    def _adjust_username_column_width(self) -> None:
        """Adjust the Username column width so all entries columns fit the viewport without trailing blank space."""
        if self._custom_column_widths is not None:
            return
        viewport = self._entries_table.viewport()
        available_width = viewport.width() if viewport and viewport.width() > 0 else self._entries_table.width()
        other_widths = sum(
            self._entries_table.columnWidth(column)
            for column in range(self._model.columnCount())
            if column != USERNAME_COLUMN and not self._entries_table.isColumnHidden(column)
        )
        self._entries_table.setColumnWidth(USERNAME_COLUMN, max(180, available_width - other_widths))

    @override
    def _reset_column_sizes(self) -> None:
        """Reset column widths back to their initial default layout."""
        self._custom_column_widths = None
        UserIPDatabasesManager._cached_column_widths = None
        self._is_programmatic_resizing = True
        try:
            header = self._entries_table.header()
            if not header:
                return
            header.setStretchLastSection(False)
            for column in range(self._model.columnCount()):
                header.setSectionResizeMode(column, QHeaderView.ResizeMode.Interactive)

            self._entries_table.setColumnWidth(INDEX_COLUMN, 50)
            self._entries_table.setColumnWidth(IP_COLUMN, 125)
            self._entries_table.setColumnWidth(RANGE_COLUMN, 210)
            self._entries_table.setColumnWidth(DATABASE_COLUMN, 180)
            self._adjust_username_column_width()
        finally:
            self._is_programmatic_resizing = False

        if Settings.gui_remember_window_layout:
            gui_state = GUIState.load()
            gui_state.userip_manager_table_column_widths = None
            gui_state.save()
