"""UserIP Databases Manager dialog for browsing, editing, and managing UserIP database files and entries."""

import html
from datetime import UTC, datetime
from typing import TYPE_CHECKING, ClassVar, override

from PySide6.QtCore import QByteArray, QModelIndex, QSignalBlocker, QSize, Qt, QUrl
from PySide6.QtGui import QCloseEvent, QDesktopServices, QIcon, QKeySequence, QResizeEvent, QShortcut, QShowEvent, QStandardItemModel
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
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
from session_sniffer.guis.select_usernames_dialog import configure_username_cell_editor
from session_sniffer.guis.stylesheets import USERIP_METADATA_CONTAINER_STYLESHEET, userip_dialog_button_stylesheet, userip_dialog_danger_button_stylesheet
from session_sniffer.guis.table_column_resizing import adjust_last_visible_column_to_viewport, setup_table_header_context_menu
from session_sniffer.guis.userip_conflict_resolver import open_userip_conflict_resolver
from session_sniffer.guis.userip_manager_context_menu_mixin import EntriesContextMenuMixin
from session_sniffer.guis.userip_manager_entries_ops_mixin import UserIPEntriesOperationsMixin
from session_sniffer.guis.userip_manager_helpers import (
    ADDED_AT_COLUMN,
    DATABASE_COLUMN,
    ENTRY_TABLE_HEADERS,
    INDEX_COLUMN,
    NEW_DATABASE_SETTINGS,
    RANGE_COLUMN,
    USERIP_METADATA_HEADER_TOOLTIPS,
    USERNAME_COLUMN,
    EntriesSortProxy,
    append_entry_rows,
    build_entry_row_items,
    clear_row_looky_badge,
    human_readable_size,
    is_row_persisted,
    iter_userip_databases,
    load_userip_database_model,
    set_row_updated_at,
)
from session_sniffer.guis.userip_manager_import_export_mixin import UserIPImportExportMixin
from session_sniffer.guis.userip_manager_settings_mixin import SettingsPanelMixin
from session_sniffer.guis.userip_manager_tree_ops import TreeOperationsMixin
from session_sniffer.guis.utils import (
    apply_search_icon,
    consume_maximize_on_show,
    get_screen_size,
    resize_window_for_screen,
    scale_by_ui,
    set_dialog_window_flags,
    set_maximize_on_show,
)
from session_sniffer.models import GUIState
from session_sniffer.player.userip import UserIPDatabases
from session_sniffer.settings.settings import Settings
from session_sniffer.text_utils import pluralize

if TYPE_CHECKING:
    from pathlib import Path

    from session_sniffer.models.userip_settings_model import UserIPEntryModel, UserIPSettingsModel

_ENTRY_TABLE_HEADER_TOOLTIPS: dict[str, str] = {
    '#': 'The sequential row number of the entry in the database.',
    'Username': 'The username associated with this entry.\nPurple entries with a Looky icon were automatically added or confirmed via Looky System.',
    'IP': 'The single IPv4 address matched by this entry.',
    'Range': 'The IPv4 address range or CIDR subnet matched by this entry.',
    'Database': 'The UserIP database file that contains this entry (shown when searching across all databases).',
    'Notes': 'Optional user notes or comments attached to this entry.',
    **USERIP_METADATA_HEADER_TOOLTIPS,
}

_DEFAULT_ENTRY_COLUMN_WIDTHS: dict[str, int] = {
    '#': 50,
    'Username': 180,
    'IP': 120,
    'Range': 180,
    'Database': 160,
    'Notes': 180,
    'Source': 85,
    'Detections': 85,
    'Added': 145,
    'Updated': 145,
    'First Seen': 145,
    'Last Seen': 145,
}


def _load_userip_manager_state() -> tuple[QByteArray | None, bool, QByteArray | None, dict[str, int] | None, str, int, Qt.SortOrder]:
    """Load saved window geometry, maximized state, splitter state, table column widths, and sort state from local app data."""
    gui_state = GUIState.load()
    geom_hex, split_hex = gui_state.userip_manager_geometry, gui_state.userip_manager_splitter
    geometry = QByteArray.fromHex(geom_hex.encode('ascii')) if geom_hex is not None and geom_hex else None
    splitter = QByteArray.fromHex(split_hex.encode('ascii')) if split_hex is not None and split_hex else None
    sort_mode = gui_state.userip_manager_sort_mode if gui_state.userip_manager_sort_mode in ('Groups', 'Date Added', 'Entry Order (#)') else 'Groups'
    sort_col = gui_state.userip_manager_sort_column if 0 <= gui_state.userip_manager_sort_column < len(ENTRY_TABLE_HEADERS) else INDEX_COLUMN
    sort_order = Qt.SortOrder.DescendingOrder if gui_state.userip_manager_sort_order == 1 else Qt.SortOrder.AscendingOrder
    return geometry, gui_state.userip_manager_maximized, splitter, gui_state.userip_manager_table_column_widths, sort_mode, sort_col, sort_order


def _save_userip_manager_sort_state(sort_mode: str, sort_column: int, sort_order: Qt.SortOrder) -> None:
    """Persist the active sort mode, sort column, and sort order to local app data."""
    if not Settings.gui_remember_window_layout:
        return
    gui_state = GUIState.load()
    gui_state.userip_manager_sort_mode = sort_mode
    gui_state.userip_manager_sort_column = sort_column
    gui_state.userip_manager_sort_order = 1 if sort_order == Qt.SortOrder.DescendingOrder else 0
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
    _cached_sort_mode: ClassVar[str] = 'Groups'
    _cached_sort_column: ClassVar[int] = INDEX_COLUMN
    _cached_sort_order: ClassVar[Qt.SortOrder] = Qt.SortOrder.AscendingOrder

    def __init__(self, parent: QWidget | None = None) -> None:
        """Build the UserIP Databases Manager dialog."""
        super().__init__(parent)
        self.setWindowTitle(f'UserIP Databases Manager - {TITLE}')
        set_dialog_window_flags(self)
        self.setMinimumSize(scale_by_ui(1000), scale_by_ui(600))
        self._custom_column_widths: dict[str, int] | None = None
        self._is_programmatic_resizing: bool = False
        self._syncing_sort_mode: bool = False

        if Settings.gui_remember_window_layout and UserIPDatabasesManager._cached_geometry is None and GUI_STATE_PATH.is_file():
            (
                UserIPDatabasesManager._cached_geometry, UserIPDatabasesManager._cached_maximized,
                UserIPDatabasesManager._cached_splitter, UserIPDatabasesManager._cached_column_widths,
                UserIPDatabasesManager._cached_sort_mode, UserIPDatabasesManager._cached_sort_column,
                UserIPDatabasesManager._cached_sort_order,
            ) = _load_userip_manager_state()
        elif not Settings.gui_remember_window_layout:
            UserIPDatabasesManager._cached_geometry, UserIPDatabasesManager._cached_maximized = None, False
            UserIPDatabasesManager._cached_splitter, UserIPDatabasesManager._cached_column_widths = None, None
            UserIPDatabasesManager._cached_sort_mode, UserIPDatabasesManager._cached_sort_column = 'Groups', INDEX_COLUMN
            UserIPDatabasesManager._cached_sort_order = Qt.SortOrder.AscendingOrder

        if UserIPDatabasesManager._cached_geometry is not None:
            self.restoreGeometry(UserIPDatabasesManager._cached_geometry)
            if UserIPDatabasesManager._cached_maximized:
                set_maximize_on_show(self, maximize=True)
        else:
            screen_size = get_screen_size()
            resize_window_for_screen(self, screen_size)

        self._current_path: Path | None = None
        self._dirty = False
        self._entries_dirty = False
        self._settings_dirty = False
        self._settings_snapshot: UserIPSettingsModel = NEW_DATABASE_SETTINGS.model_copy()
        self._global_search_active = False
        self._next_index = 1
        self._disk_snapshot: str = ''
        self._saving = False
        self._looky_icon = QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'eye.svg'))

        root_layout = QVBoxLayout(self)
        root_margin = scale_by_ui(6)
        root_layout.setContentsMargins(root_margin, root_margin, root_margin, root_margin)
        root_layout.setSpacing(scale_by_ui(6))

        btn_style = userip_dialog_button_stylesheet(scale_by_ui)
        danger_btn_style = userip_dialog_danger_button_stylesheet(scale_by_ui)
        btn_icon_size = QSize(scale_by_ui(14), scale_by_ui(14))
        btn_row_spacing = scale_by_ui(4)

        # === Main splitter: file tree (left) | entries editor (right) ===
        self._splitter = QSplitter(Qt.Orientation.Horizontal)
        self._splitter.setChildrenCollapsible(False)

        # ------ LEFT PANEL: file tree ------
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, scale_by_ui(6), 0)
        left_layout.setSpacing(scale_by_ui(6))

        # Tree toolbar buttons
        tree_buttons = QHBoxLayout()
        tree_buttons.setSpacing(btn_row_spacing)

        new_db_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'file-plus.svg')), ' New DB')
        new_db_button.setToolTip('Create a new UserIP database file')
        new_db_button.setStyleSheet(btn_style)
        new_db_button.clicked.connect(self._new_database)
        tree_buttons.addWidget(new_db_button)

        new_folder_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'folder.svg')), ' New Folder')
        new_folder_button.setToolTip('Create a new folder to organize databases')
        new_folder_button.setStyleSheet(btn_style)
        new_folder_button.clicked.connect(self._new_folder)
        tree_buttons.addWidget(new_folder_button)

        self._delete_tree_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'remove.svg')), ' Delete')
        self._delete_tree_button.setIconSize(btn_icon_size)
        self._delete_tree_button.setToolTip('Delete the selected database or folder')
        self._delete_tree_button.setStyleSheet(danger_btn_style)
        self._delete_tree_button.setMinimumWidth(self._delete_tree_button.sizeHint().width())
        self._delete_tree_button.setEnabled(False)
        self._delete_tree_button.clicked.connect(self._delete_tree_item)  # reconnected dynamically in _on_tree_selection_changed
        tree_buttons.addWidget(self._delete_tree_button)

        reset_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'rotate-ccw.svg')), ' Reset all…')
        reset_button.setToolTip('Permanently delete all user databases and restore defaults')
        reset_button.setStyleSheet(danger_btn_style)
        reset_button.clicked.connect(self._reset_all_databases)
        tree_buttons.addWidget(reset_button)

        left_layout.addLayout(tree_buttons)

        # Filesystem-backed tree view
        USERIP_DATABASES_DIR_PATH.mkdir(parents=True, exist_ok=True)

        self._fs_model = QFileSystemModel(self)
        self._fs_model.setRootPath(str(USERIP_DATABASES_DIR_PATH))
        self._fs_model.setReadOnly(False)
        self._fs_model.setNameFilters(['*.json'])
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
        transfer_buttons.setSpacing(btn_row_spacing)

        import_menu = QMenu(self)
        for icon_name, label, slot in (('folder.svg', 'Import .json file(s)…', self._import_database_files), ('import.svg', 'Import from ZIP…', self._import_from_zip)):
            if act := import_menu.addAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / icon_name)), label):
                act.triggered.connect(slot)

        import_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'import.svg')), ' Import…')
        import_button.setMaximumWidth(scale_by_ui(130))
        import_button.setToolTip('Import database files into the databases directory')
        import_button.setStyleSheet(btn_style)
        import_button.setMenu(import_menu)
        transfer_buttons.addWidget(import_button)

        export_menu = QMenu(self)
        self._export_selected_action = export_menu.addAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'upload.svg')), 'Export selected database…')
        if self._export_selected_action:
            self._export_selected_action.triggered.connect(self._export_selected_database)
            self._export_selected_action.setEnabled(False)
        if export_zip_action := export_menu.addAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'upload.svg')), 'Export all as ZIP…'):
            export_zip_action.triggered.connect(self._export_all_as_zip)
        export_menu.addSeparator()
        for icon_name, label, slot in (('upload.svg', 'Backup databases now', self._backup_databases_now), ('folder.svg', 'Open backups folder', self._open_backups_folder)):
            if act := export_menu.addAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / icon_name)), label):
                act.triggered.connect(slot)

        export_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'upload.svg')), ' Export…')
        export_button.setMaximumWidth(scale_by_ui(130))
        export_button.setToolTip('Export databases to an external location')
        export_button.setStyleSheet(btn_style)
        export_button.setMenu(export_menu)
        transfer_buttons.addWidget(export_button)

        resolve_conflicts_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'scale.svg')), ' Resolve Conflicts…')
        resolve_conflicts_button.setToolTip('Open the UserIP Conflict Resolver to fix IPs or ranges claimed by multiple databases')
        resolve_conflicts_button.setStyleSheet(btn_style)
        resolve_conflicts_button.clicked.connect(lambda: open_userip_conflict_resolver(None))
        transfer_buttons.addWidget(resolve_conflicts_button)

        left_layout.addLayout(transfer_buttons)

        # Fancy Metadata Container
        self._metadata_container = QFrame()
        self._metadata_container.setStyleSheet(USERIP_METADATA_CONTAINER_STYLESHEET)
        status_row = QHBoxLayout(self._metadata_container)
        status_margin_h = scale_by_ui(10)
        status_margin_v = scale_by_ui(8)
        status_row.setContentsMargins(status_margin_h, status_margin_v, status_margin_h, status_margin_v)
        status_row.setSpacing(scale_by_ui(12))

        self._stats_label = QLabel('', wordWrap=True)
        status_row.addWidget(self._stats_label, stretch=1, alignment=Qt.AlignmentFlag.AlignTop)

        right_col = QVBoxLayout()
        right_col.setSpacing(scale_by_ui(4))
        self._file_info_label, self._status_label = QLabel('', wordWrap=True), QLabel('', wordWrap=True)
        right_col.addWidget(self._file_info_label, alignment=Qt.AlignmentFlag.AlignTop)
        right_col.addWidget(self._status_label, alignment=Qt.AlignmentFlag.AlignTop)
        right_col.addStretch()
        status_row.addLayout(right_col, stretch=2)
        left_layout.addWidget(self._metadata_container)
        self._splitter.addWidget(left_panel)

        # ------ RIGHT PANEL: entries editor ------
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(scale_by_ui(6), 0, 0, 0)
        right_layout.setSpacing(scale_by_ui(6))

        # Search / filter bar
        search_bar = QHBoxLayout()
        search_bar.setSpacing(scale_by_ui(6))
        search_bar.addWidget(QLabel('Search:'))

        self._search_input = QLineEdit()
        self._search_input.setPlaceholderText('Filter entries by username, IP, or notes…')
        self._search_input.textChanged.connect(self._on_search_changed)
        self._search_input.returnPressed.connect(self._on_search_return_pressed)
        apply_search_icon(self._search_input)
        search_bar.addWidget(self._search_input)

        self._global_search_checkbox = QCheckBox('Search All Databases')
        self._global_search_checkbox.setToolTip('Search across all UserIP database files (read-only)')
        self._global_search_checkbox.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self._global_search_checkbox.toggled.connect(self._on_global_search_toggled)
        search_bar.addWidget(self._global_search_checkbox)

        search_bar.addWidget(QLabel('Sort by:'))
        self._sort_mode_combo = QComboBox()
        self._sort_mode_combo.addItems(['Groups', 'Date Added', 'Entry Order (#)'])
        self._sort_mode_combo.setToolTip(
            'Choose how database entries are ordered:\n'
            '• Groups: Keep linked accounts together in consecutive blocks separated by alternating background shades.\n'
            '• Date Added: Sort entries by when they were added to the database.\n'
            '• Entry Order (#): Sort entries by their sequential row number in the file.',
        )
        self._sort_mode_combo.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        initial_sort_mode = UserIPDatabasesManager._cached_sort_mode
        if initial_sort_mode in ('Groups', 'Date Added', 'Entry Order (#)'):
            self._sort_mode_combo.setCurrentText(initial_sort_mode)
        self._sort_mode_combo.currentTextChanged.connect(self._on_sort_mode_changed)
        search_bar.addWidget(self._sort_mode_combo)

        right_layout.addLayout(search_bar)

        # ------ Settings panel (collapsible, built by mixin) ------
        self.build_settings_panel(right_layout)

        # Entries table
        self._model = QStandardItemModel(0, len(ENTRY_TABLE_HEADERS))
        self._model.setHorizontalHeaderLabels(ENTRY_TABLE_HEADERS)
        for column, header_label in enumerate(ENTRY_TABLE_HEADERS):
            if (tooltip := _ENTRY_TABLE_HEADER_TOOLTIPS.get(header_label)) is not None:
                self._model.setHeaderData(column, Qt.Orientation.Horizontal, tooltip, Qt.ItemDataRole.ToolTipRole)
        self._model.dataChanged.connect(self._on_data_changed)

        self._proxy = EntriesSortProxy()
        self._proxy.setSourceModel(self._model)
        self._proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self._proxy.setFilterKeyColumn(INDEX_COLUMN)

        self._entries_table = QTreeView()
        self._entries_table.setModel(self._proxy)
        self._entries_table.setRootIsDecorated(False)
        self._entries_table.setUniformRowHeights(True)
        self._entries_table.setAlternatingRowColors(False)
        self._entries_table.setSortingEnabled(True)
        self._entries_table.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self._entries_table.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self._entries_table.setItemDelegate(
            SearchHighlightDelegate(self._entries_table, self._search_input.text, configure_editor=configure_username_cell_editor),
        )
        self._entries_table.setWordWrap(False)
        self._apply_sort_mode(self._sort_mode_combo.currentText(), restore_saved_column=True)
        self._entries_table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self._entries_table.setEditTriggers(
            QAbstractItemView.EditTrigger.DoubleClicked | QAbstractItemView.EditTrigger.EditKeyPressed,
        )

        header = self._entries_table.header()
        self._entries_table.hideColumn(DATABASE_COLUMN)
        self._reset_column_sizes()
        setup_table_header_context_menu(self._entries_table, on_reset=self._reset_column_sizes)
        if header:
            header.sectionResized.connect(self._on_section_resized)
            header.sortIndicatorChanged.connect(self._on_header_sort_indicator_changed)
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
        entry_buttons.setSpacing(btn_row_spacing)

        self._add_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'plus.svg')), ' Add Entry')
        self._add_button.setToolTip('Add a new entry (single IP, IP range, or subnet) to the current database')
        self._add_button.setStyleSheet(btn_style)
        self._add_button.setEnabled(False)
        self._add_button.clicked.connect(self._add_entry)
        entry_buttons.addWidget(self._add_button)

        self._edit_ip_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'square-pen.svg')), ' Edit IP/Range…')
        self._edit_ip_button.setToolTip('Edit the IP or range of the selected entry using the builder')
        self._edit_ip_button.setStyleSheet(btn_style)
        self._edit_ip_button.setEnabled(False)
        self._edit_ip_button.clicked.connect(self._edit_selected_entry_ip)
        entry_buttons.addWidget(self._edit_ip_button)

        self._rename_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'square-pen.svg')), ' Rename')
        self._rename_button.setToolTip('Rename the username of the selected entry or entries')
        self._rename_button.setStyleSheet(btn_style)
        self._rename_button.setEnabled(False)
        self._rename_button.clicked.connect(self._rename_selected)
        entry_buttons.addWidget(self._rename_button)

        self._open_db_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'file-text.svg')), ' Open DB')
        self._open_db_button.setToolTip('Open the current database file in the default text editor')
        self._open_db_button.setStyleSheet(btn_style)
        self._open_db_button.setEnabled(False)
        self._open_db_button.clicked.connect(self._open_db_in_editor)
        entry_buttons.addWidget(self._open_db_button)

        entry_buttons.addStretch()

        self._delete_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'remove.svg')), ' Delete Selected')
        self._delete_button.setToolTip('Delete the selected entries (with confirmation)')
        self._delete_button.setStyleSheet(danger_btn_style)
        self._delete_button.setEnabled(False)
        self._delete_button.clicked.connect(self._delete_selected)
        entry_buttons.addWidget(self._delete_button)

        close_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'x.svg')), ' Close')
        close_button.setToolTip('Close the UserIP Databases Manager')
        close_button.setStyleSheet(btn_style)
        close_button.clicked.connect(self.close)
        entry_buttons.addWidget(close_button)

        for action_button in (
            new_db_button,
            new_folder_button,
            self._delete_tree_button,
            reset_button,
            import_button,
            export_button,
            resolve_conflicts_button,
            self._add_button,
            self._edit_ip_button,
            self._rename_button,
            self._open_db_button,
            self._delete_button,
            close_button,
        ):
            action_button.setAutoDefault(False)
            action_button.setIconSize(btn_icon_size)

        right_layout.addLayout(entry_buttons)

        self._splitter.addWidget(right_panel)
        self._splitter.setStretchFactor(0, 1)
        self._splitter.setStretchFactor(1, 2)
        self._splitter.setHandleWidth(scale_by_ui(4))
        self._splitter.handle(1).setEnabled(True)

        if UserIPDatabasesManager._cached_splitter is not None:
            self._splitter.restoreState(UserIPDatabasesManager._cached_splitter)
        else:
            self._splitter.setSizes([scale_by_ui(350), scale_by_ui(750)])

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
        """Recompute the aggregate dirty flag from the tracked sources."""
        self._dirty = (self._entries_dirty or self._settings_dirty) and self._current_path is not None and not self._global_search_active

    @override
    def _mark_entries_dirty(self) -> None:
        """Mark entry edits as dirty and refresh the aggregate state."""
        if self._global_search_active or self._current_path is None:
            return
        self._entries_dirty = True
        self._sync_dirty_state()

    @override
    def _mark_settings_dirty(self) -> None:
        """Re-evaluate settings dirtiness against the loaded snapshot and auto-save."""
        if self._global_search_active or self._current_path is None:
            return
        self._settings_dirty = self.read_settings_from_widgets() != self._settings_snapshot
        self._sync_dirty_state()
        if self._settings_dirty:
            self._save_database(show_errors=False)

    def _capture_settings_snapshot(self) -> None:
        """Record the current serialized settings as the clean baseline."""
        self._settings_snapshot = self.read_settings_from_widgets().model_copy()
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
        """Parse the JSON database file and populate the entries table model and settings panel."""
        self._model.removeRows(0, self._model.rowCount())
        self._clear_dirty_state()
        self._search_input.clear()

        if not path.is_file():
            self._set_status(f'File not found: {path.name}')
            self._settings_container.setVisible(False)
            self._disk_snapshot = ''
            self._rebuild_fs_watch()
            return

        self._disk_snapshot = path.read_text('utf-8')
        db_model = load_userip_database_model(path)

        # Load settings panel
        self.populate_settings_widgets(db_model.settings)
        self._capture_settings_snapshot()
        self._settings_container.setVisible(True)

        rows = [build_entry_row_items(entry, index=entry_count, looky_icon=self._looky_icon) for entry_count, entry in enumerate(db_model.entries, start=1)]
        dynamic_sort_filter = self._proxy.dynamicSortFilter()
        self._proxy.setDynamicSortFilter(False)
        try:
            append_entry_rows(self._model, rows)
        finally:
            self._proxy.setDynamicSortFilter(dynamic_sort_filter)
            self._proxy.prepare_sort_and_invalidate()
        entry_count = len(rows)

        self._next_index = entry_count + 1
        self._update_file_info(path)
        duplicate_count = self._highlight_duplicates()
        status = f'Loaded {entry_count} entries from {path.name}'
        if duplicate_count > 0:
            status += f' ({duplicate_count} duplicate{pluralize(duplicate_count)} found)'
        self._set_status(status)
        self._rebuild_fs_watch()

    @override
    def _append_row(self, entry: UserIPEntryModel, *, index: int = 0, persisted: bool = True) -> None:
        """Add a single row to the entries model."""
        self._model.appendRow(build_entry_row_items(entry, index=index, looky_icon=self._looky_icon, persisted=persisted))

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
        if len(selected_rows) == 1 and (self._global_search_active or self._current_path is not None):
            source_row = self._proxy.mapToSource(selected_rows[0]).row()
            range_item = self._model.item(source_row, RANGE_COLUMN)
            is_range = bool(range_item and range_item.text().strip())
            self._edit_ip_button.setText(' Edit Range…' if is_range else ' Edit IP…')
            self._edit_ip_button.setEnabled(True)
        else:
            self._edit_ip_button.setText(' Edit IP/Range…')
            self._edit_ip_button.setEnabled(False)

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

    def _apply_sort_mode(self, mode: str, *, restore_saved_column: bool = False) -> None:
        """Apply `'Groups'`, `'Date Added'`, or `'Entry Order (#)'` sorting to the entries table."""
        self._syncing_sort_mode = True
        try:
            self._proxy.set_group_sort_enabled(enabled=mode == 'Groups')
            if restore_saved_column:
                target_col, target_order = UserIPDatabasesManager._cached_sort_column, UserIPDatabasesManager._cached_sort_order
            elif mode == 'Date Added':
                target_col, target_order = ADDED_AT_COLUMN, Qt.SortOrder.DescendingOrder
            else:
                target_col = INDEX_COLUMN
                target_order = UserIPDatabasesManager._cached_sort_order if UserIPDatabasesManager._cached_sort_column == INDEX_COLUMN else Qt.SortOrder.AscendingOrder
            UserIPDatabasesManager._cached_sort_column, UserIPDatabasesManager._cached_sort_order = target_col, target_order
            self._entries_table.sortByColumn(target_col, target_order)
            if viewport := self._entries_table.viewport():
                viewport.update()
        finally:
            self._syncing_sort_mode = False

    def _on_sort_mode_changed(self, mode: str) -> None:
        """Handle user changes to the Sort by combo box."""
        if self._syncing_sort_mode:
            return
        UserIPDatabasesManager._cached_sort_mode = mode
        self._apply_sort_mode(mode)
        _save_userip_manager_sort_state(mode, UserIPDatabasesManager._cached_sort_column, UserIPDatabasesManager._cached_sort_order)

    def _on_header_sort_indicator_changed(self, logical_index: int, order: Qt.SortOrder) -> None:
        """Keep the Sort by combo box and group sort mode synchronized when the user clicks a column header."""
        if self._syncing_sort_mode:
            return
        self._syncing_sort_mode = True
        try:
            UserIPDatabasesManager._cached_sort_column = logical_index
            UserIPDatabasesManager._cached_sort_order = order
            if logical_index == ADDED_AT_COLUMN:
                self._proxy.set_group_sort_enabled(enabled=False)
                self._sort_mode_combo.setCurrentText('Date Added')
                UserIPDatabasesManager._cached_sort_mode = 'Date Added'
            elif logical_index == INDEX_COLUMN and self._sort_mode_combo.currentText() == 'Date Added':
                self._proxy.set_group_sort_enabled(enabled=True)
                self._sort_mode_combo.setCurrentText('Groups')
                UserIPDatabasesManager._cached_sort_mode = 'Groups'
            _save_userip_manager_sort_state(UserIPDatabasesManager._cached_sort_mode, logical_index, order)
            if viewport := self._entries_table.viewport():
                viewport.update()
        finally:
            self._syncing_sort_mode = False

    def _on_global_search_toggled(self) -> None:
        """Switch between single-database editing mode and read-only global search mode."""
        checked = self._global_search_checkbox.isChecked()
        if checked and self._dirty and not self._confirm_discard():
            with QSignalBlocker(self._global_search_checkbox):
                self._global_search_checkbox.setChecked(False)
            return

        self._clear_dirty_state()
        self._global_search_active = checked
        db_available = not checked and self._current_path is not None
        self._add_button.setVisible(not checked)
        self._add_button.setEnabled(db_available)
        self._edit_ip_button.setVisible(True)
        self._edit_ip_button.setEnabled(False)  # driven by selection
        self._rename_button.setEnabled(False)  # driven by selection
        self._delete_button.setEnabled(False)  # driven by selection
        self._open_db_button.setEnabled(db_available)
        if self._export_selected_action is not None:
            self._export_selected_action.setEnabled(db_available)
        self._entries_table.setColumnHidden(DATABASE_COLUMN, not checked)
        self._reset_column_sizes()
        self._settings_container.setVisible(db_available)

        editable = QAbstractItemView.EditTrigger.DoubleClicked | QAbstractItemView.EditTrigger.EditKeyPressed
        self._entries_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers if checked else editable)
        self._rebuild_fs_watch()

        if checked:
            self._update_file_info(None)
            self._load_all_databases()
        elif self._current_path is not None:
            self._load_database(self._current_path)
        else:
            self._model.removeRows(0, self._model.rowCount())
            self._set_status('')

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
        """Mark the current database as dirty and auto-save when valid."""
        if self._global_search_active or self._current_path is None or self._saving:
            return
        if roles and Qt.ItemDataRole.EditRole not in roles and Qt.ItemDataRole.DisplayRole not in roles:
            return
        is_identity_edit = top_left.column() <= RANGE_COLUMN and bottom_right.column() >= USERNAME_COLUMN
        modified_entries: list[str] = []
        with QSignalBlocker(self._model):
            for row in range(top_left.row(), bottom_right.row() + 1):
                if is_identity_edit:
                    clear_row_looky_badge(self._model, row)
                    if entry_val := self._get_row_entry_value(row):
                        modified_entries.append(entry_val)
                if is_row_persisted(self._model, row):
                    set_row_updated_at(self._model, row)
        self._proxy.refresh_rows(range(top_left.row(), bottom_right.row() + 1))
        self._highlight_duplicates()
        self._mark_entries_dirty()
        self._save_database(show_errors=False)
        if is_identity_edit and not self._dirty and modified_entries:
            UserIPDatabases.renotify_if_conflicting(modified_entries)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @override
    def _set_status(self, text: str) -> None:
        """Update the status label at the bottom of the right panel."""
        self._status_label.setText(f'<i style="color:#50c878;">{html.escape(text)}</i>')

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
            f'<span style="color:#8a9bad;">File:</span> <b style="color:#6db3f2;">{html.escape(path.name)}</b><br>'
            f'<span style="color:#8a9bad;">Size:</span> <b style="color:#e0e0e0;">{size}</b><br>'
            f'<span style="color:#8a9bad;">Modified:</span> <span style="color:#a0b0c0;">{human_readable_timestamp(modified)}</span>',
        )

    @override
    def _refresh_stats(self) -> None:
        """Scan all UserIP databases and update the stats summary label."""
        total_files = 0
        total_entries = 0
        unique_ips: set[str] = set()
        unique_usernames: set[str] = set()

        for _json_path, entries in iter_userip_databases():
            total_files += 1
            for entry in entries:
                total_entries += 1
                unique_ips.add(entry.ip)
                unique_usernames.add(entry.username.casefold())

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
        if not prompt_unsaved_changes_close(self, self._has_unsaved_changes_for_close, self._save_on_close, event):
            return

        self._fs_watcher.stop()
        super().closeEvent(event)
        if event.isAccepted() and Settings.gui_remember_window_layout:
            geometry, maximized, splitter_state = self.saveGeometry(), self.isMaximized(), self._splitter.saveState()
            UserIPDatabasesManager._cached_geometry, UserIPDatabasesManager._cached_maximized = geometry, maximized
            UserIPDatabasesManager._cached_splitter, UserIPDatabasesManager._cached_column_widths = splitter_state, self._custom_column_widths
            UserIPDatabasesManager._cached_sort_mode = self._sort_mode_combo.currentText()
            gui_state = GUIState.load()
            gui_state.userip_manager_geometry, gui_state.userip_manager_maximized = geometry.toHex().toStdString(), maximized
            gui_state.userip_manager_splitter, gui_state.userip_manager_table_column_widths = splitter_state.toHex().toStdString(), self._custom_column_widths
            gui_state.userip_manager_sort_mode = UserIPDatabasesManager._cached_sort_mode
            gui_state.userip_manager_sort_column = UserIPDatabasesManager._cached_sort_column
            gui_state.userip_manager_sort_order = 1 if UserIPDatabasesManager._cached_sort_order == Qt.SortOrder.DescendingOrder else 0
            gui_state.save()

    @override
    def showEvent(self, a0: QShowEvent) -> None:
        """Handle the window show event and maximize if required."""
        super().showEvent(a0)
        if consume_maximize_on_show(self):
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
        if header_label := str(self._model.headerData(logical_index, Qt.Orientation.Horizontal) or ''):
            if self._custom_column_widths is None:
                self._custom_column_widths = self._get_column_widths()
            self._custom_column_widths[header_label] = new_size
            self._is_programmatic_resizing = True
            try:
                adjust_last_visible_column_to_viewport(
                    self._entries_table, resized_column=logical_index, min_column_widths=_DEFAULT_ENTRY_COLUMN_WIDTHS, custom_widths=self._custom_column_widths,
                )
            finally:
                self._is_programmatic_resizing = False

    def _get_column_widths(self) -> dict[str, int]:
        """Return a mapping of column header names to their current section widths."""
        return {
            header_label: self._entries_table.columnWidth(column)
            for column in range(self._model.columnCount())
            if (header_label := str(self._model.headerData(column, Qt.Orientation.Horizontal) or ''))
        }

    def _apply_column_widths(self, widths: dict[str, int]) -> None:
        """Apply saved column widths to matching entries table header sections."""
        if not (header := self._entries_table.header()):
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
        """Adjust the last visible column width so the entries table fits the viewport without trailing blank space."""
        self._is_programmatic_resizing = True
        try:
            adjust_last_visible_column_to_viewport(self._entries_table, min_column_widths=_DEFAULT_ENTRY_COLUMN_WIDTHS, custom_widths=self._custom_column_widths)
        finally:
            self._is_programmatic_resizing = False

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
            for column, header_label in enumerate(ENTRY_TABLE_HEADERS):
                header.setSectionResizeMode(column, QHeaderView.ResizeMode.Interactive)
                self._entries_table.setColumnWidth(column, scale_by_ui(_DEFAULT_ENTRY_COLUMN_WIDTHS[header_label]))
            self._adjust_username_column_width()
        finally:
            self._is_programmatic_resizing = False

        if Settings.gui_remember_window_layout:
            gui_state = GUIState.load()
            gui_state.userip_manager_table_column_widths = None
            gui_state.save()
