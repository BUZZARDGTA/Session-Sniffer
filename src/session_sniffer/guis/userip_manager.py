"""UserIP Databases Manager dialog for browsing, editing, and managing UserIP database files and entries."""

from typing import TYPE_CHECKING, ClassVar, override

from PySide6.QtCore import QByteArray, QModelIndex, QSignalBlocker, QSize, Qt, QUrl
from PySide6.QtGui import QAction, QCloseEvent, QColor, QDesktopServices, QIcon, QKeySequence, QResizeEvent, QShortcut, QShowEvent, QStandardItemModel
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QDialog,
    QFileSystemModel,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMenu,
    QPushButton,
    QSplitter,
    QTreeView,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.local import GUI_STATE_PATH, USERIP_DATABASES_DIR_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis._dialog_mixins import prompt_unsaved_changes_close
from session_sniffer.guis._userip_tree_batch_ops import format_multi_tree_selection_info, is_default_userip_db
from session_sniffer.guis.delegates import SearchHighlightDelegate
from session_sniffer.guis.file_watch import DebouncedFileWatcher
from session_sniffer.guis.live_language import CANONICAL_HEADER_ROLE, register_language_refresh, set_i18n_colon_label
from session_sniffer.guis.loading_overlay import loading_overlay_scope
from session_sniffer.guis.select_usernames_dialog import configure_username_cell_editor
from session_sniffer.guis.stylesheets import USERIP_METADATA_CONTAINER_STYLESHEET, userip_dialog_button_stylesheet, userip_dialog_danger_button_stylesheet
from session_sniffer.guis.table_column_resizing import setup_table_header_context_menu
from session_sniffer.guis.theming import ICONS_DIR_PATH, get_themed_icon
from session_sniffer.guis.userip_conflict_resolver import open_userip_conflict_resolver
from session_sniffer.guis.userip_manager_context_menu_mixin import EntriesContextMenuMixin
from session_sniffer.guis.userip_manager_entries_ops_mixin import UserIPEntriesOperationsMixin
from session_sniffer.guis.userip_manager_helpers import (
    DATABASE_COLUMN,
    ENTRY_TABLE_HEADERS,
    INDEX_COLUMN,
    NEW_DATABASE_SETTINGS,
    RANGE_COLUMN,
    USERNAME_COLUMN,
    EntriesSortProxy,
    append_entry_rows,
    build_entry_row_items,
    clear_row_looky_badge,
    get_userip_metadata_header_tooltips,
    is_row_persisted,
    load_userip_database_model,
    retranslate_entry_rows,
    set_row_updated_at,
)
from session_sniffer.guis.userip_manager_import_export_mixin import UserIPImportExportMixin
from session_sniffer.guis.userip_manager_settings_mixin import SettingsPanelMixin
from session_sniffer.guis.userip_manager_tree_ops import TreeOperationsMixin, UserIPDatabaseTreeDelegate, UserIPDatabaseTreeSortProxy
from session_sniffer.guis.utils import (
    apply_search_icon,
    consume_maximize_on_show,
    get_screen_size,
    resize_window_for_screen,
    scale_by_ui,
    set_dialog_window_flags,
    set_maximize_on_show,
)
from session_sniffer.i18n import tr, tr_plural
from session_sniffer.models import GUIState
from session_sniffer.player.userip import UserIPDatabases
from session_sniffer.settings.settings import Settings

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from PySide6.QtGui import QStandardItem

    from session_sniffer.models.userip_settings_model import UserIPEntryModel, UserIPSettingsModel


def _get_entry_table_header_tooltips() -> dict[str, str]:
    """Return localized header tooltips keyed by canonical entry table column name."""
    return {
        '#': tr('The sequential row number of the entry in the database.'),
        'Username': tr('The username associated with this entry.\nPurple entries with a Looky icon were automatically added or confirmed via Looky System.'),
        'IP': tr('The single IPv4 address matched by this entry.'),
        'Range': tr('The IPv4 address range or CIDR subnet matched by this entry.'),
        'Database': tr('The UserIP database file that contains this entry (shown when searching across all databases).'),
        'Notes': tr('Optional user notes or comments attached to this entry.'),
        **get_userip_metadata_header_tooltips(),
    }


def _load_userip_manager_state() -> tuple[QByteArray | None, bool, QByteArray | None, dict[str, int] | None, bool, int, Qt.SortOrder]:
    """Load saved window geometry, maximized state, splitter state, table column widths, and sort state from local app data."""
    gui_state = GUIState.load()
    geom_hex, split_hex = gui_state.userip_manager_geometry, gui_state.userip_manager_splitter
    geometry = QByteArray.fromHex(geom_hex.encode('ascii')) if geom_hex is not None and geom_hex else None
    splitter = QByteArray.fromHex(split_hex.encode('ascii')) if split_hex is not None and split_hex else None
    sort_col = gui_state.userip_manager_sort_column if 0 <= gui_state.userip_manager_sort_column < len(ENTRY_TABLE_HEADERS) else INDEX_COLUMN
    sort_order = Qt.SortOrder.DescendingOrder if gui_state.userip_manager_sort_order == 1 else Qt.SortOrder.AscendingOrder
    return geometry, gui_state.userip_manager_maximized, splitter, gui_state.userip_manager_table_column_widths, gui_state.userip_manager_group_accounts, sort_col, sort_order


def _save_userip_manager_sort_state(*, group_accounts: bool, sort_column: int, sort_order: Qt.SortOrder) -> None:
    """Persist the account-grouping toggle, sort column, and sort order to local app data."""
    if not Settings.gui_remember_window_layout:
        return
    gui_state = GUIState.load()
    gui_state.userip_manager_group_accounts = group_accounts
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
    _cached_group_accounts: ClassVar[bool] = True
    _cached_sort_column: ClassVar[int] = INDEX_COLUMN
    _cached_sort_order: ClassVar[Qt.SortOrder] = Qt.SortOrder.AscendingOrder

    def __init__(self, parent: QWidget | None = None) -> None:
        """Build the UserIP Databases Manager dialog."""
        super().__init__(parent)
        self.setWindowTitle(tr('UserIP Databases Manager - {title}', title=TITLE))
        set_dialog_window_flags(self)
        self.setMinimumSize(scale_by_ui(1000), scale_by_ui(600))
        self._custom_column_widths: dict[str, int] | None = None
        self._is_programmatic_resizing: bool = False
        self._syncing_sort_state: bool = False
        self._static_menu_actions: list[tuple[QAction, str]] = []

        if Settings.gui_remember_window_layout and UserIPDatabasesManager._cached_geometry is None and GUI_STATE_PATH.is_file():
            (
                UserIPDatabasesManager._cached_geometry,
                UserIPDatabasesManager._cached_maximized,
                UserIPDatabasesManager._cached_splitter,
                UserIPDatabasesManager._cached_column_widths,
                UserIPDatabasesManager._cached_group_accounts,
                UserIPDatabasesManager._cached_sort_column,
                UserIPDatabasesManager._cached_sort_order,
            ) = _load_userip_manager_state()
        elif not Settings.gui_remember_window_layout:
            UserIPDatabasesManager._cached_geometry, UserIPDatabasesManager._cached_maximized = None, False
            UserIPDatabasesManager._cached_splitter, UserIPDatabasesManager._cached_column_widths = None, None
            UserIPDatabasesManager._cached_group_accounts, UserIPDatabasesManager._cached_sort_column = True, INDEX_COLUMN
            UserIPDatabasesManager._cached_sort_order = Qt.SortOrder.AscendingOrder

        if UserIPDatabasesManager._cached_geometry is not None:
            self.restoreGeometry(UserIPDatabasesManager._cached_geometry)
            if UserIPDatabasesManager._cached_maximized:
                set_maximize_on_show(self, maximize=True)
        else:
            resize_window_for_screen(self, get_screen_size())

        self._current_path: Path | None = None
        self._dirty, self._entries_dirty, self._settings_dirty = False, False, False
        self._settings_snapshot: UserIPSettingsModel = NEW_DATABASE_SETTINGS.model_copy()
        self._global_search_active, self._saving = False, False
        self._next_index, self._last_seen_build_version = 1, UserIPDatabases.build_version
        self._disk_snapshot: str = ''
        self._db_visual_cache: dict[Path, tuple[int, bool, QColor]] = {}
        self._entries_scroll_db_path: Path | None = None
        self._entries_scroll_positions: dict[Path, int] = {}

        root_layout = QVBoxLayout(self)
        root_margin = scale_by_ui(6)
        root_layout.setContentsMargins(root_margin, root_margin, root_margin, root_margin)
        root_layout.setSpacing(scale_by_ui(6))

        btn_style = userip_dialog_button_stylesheet(scale_by_ui)
        danger_btn_style = userip_dialog_danger_button_stylesheet(scale_by_ui)
        btn_icon_size = QSize(scale_by_ui(14), scale_by_ui(14))
        btn_row_spacing = scale_by_ui(4)

        def make_button(icon_name: str, text: str, tooltip: str, slot: Callable[[], object] | None = None, *, danger: bool = False) -> QPushButton:
            button = QPushButton(QIcon(str(ICONS_DIR_PATH / icon_name)), text)
            button.setToolTip(tooltip)
            button.setStyleSheet(danger_btn_style if danger else btn_style)
            button.setAutoDefault(False)
            button.setIconSize(btn_icon_size)
            if slot is not None:
                button.clicked.connect(slot)
            return button

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
        self._new_db_button = make_button('file-plus.svg', f" {tr('New DB')}", tr('Create a new UserIP database file'), self._new_database)
        tree_buttons.addWidget(self._new_db_button)
        self._new_folder_button = make_button('folder.svg', f" {tr('New Folder')}", tr('Create a new folder to organize databases'), self._new_folder)
        tree_buttons.addWidget(self._new_folder_button)
        # Delete slot is reconnected dynamically in _on_tree_selection_changed
        self._delete_tree_button = make_button('trash.svg', f" {tr('Delete')}", tr('Delete the selected database or folder'), self._delete_tree_item, danger=True)
        self._delete_tree_button.setMinimumWidth(self._delete_tree_button.sizeHint().width())
        self._delete_tree_button.setEnabled(False)
        tree_buttons.addWidget(self._delete_tree_button)
        left_layout.addLayout(tree_buttons)

        self._resolve_conflicts_button = make_button('scale.svg', f" {tr('Resolve Conflicts\u2026')}", '', lambda: open_userip_conflict_resolver(None))
        left_layout.addWidget(self._resolve_conflicts_button)

        # Filesystem-backed tree view
        USERIP_DATABASES_DIR_PATH.mkdir(parents=True, exist_ok=True)

        self._fs_model = QFileSystemModel(self)
        root_source_index = self._fs_model.setRootPath(str(USERIP_DATABASES_DIR_PATH))
        self._fs_model.setReadOnly(False)
        self._fs_model.setNameFilters(['*.json'])
        self._fs_model.setNameFilterDisables(False)
        self._tree_proxy = UserIPDatabaseTreeSortProxy(self, self._fs_model, self._is_database_path_enabled)

        self._tree = QTreeView()
        self._tree.setModel(self._tree_proxy)
        self._tree.setRootIndex(self._tree_proxy.mapFromSource(root_source_index))
        self._tree.setHeaderHidden(True)
        self._tree.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self._tree.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        QShortcut(QKeySequence('Delete'), self._tree, context=Qt.ShortcutContext.WidgetShortcut).activated.connect(self._delete_tree_button.click)
        self._tree.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self._tree.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self._tree.setItemDelegate(UserIPDatabaseTreeDelegate(self._tree, self._get_tree_index_db_visual, self._toggle_tree_index_db))
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

        # Import / Export / Reset buttons (below the tree, above stats)
        transfer_buttons = QHBoxLayout()
        transfer_buttons.setSpacing(btn_row_spacing)

        import_menu = QMenu(self)
        for icon_name, canonical_label, slot in (
            ('folder.svg', 'Import .json file(s)\u2026', self._import_database_files),
            ('import.svg', 'Import from ZIP\u2026', self._import_from_zip),
        ):
            if act := import_menu.addAction(QIcon(str(ICONS_DIR_PATH / icon_name)), tr(canonical_label)):
                act.triggered.connect(slot)
                self._static_menu_actions.append((act, canonical_label))

        self._import_button = make_button('import.svg', f" {tr('Import\u2026')}", tr('Import database files into the databases directory'))
        self._import_button.setMenu(import_menu)
        transfer_buttons.addWidget(self._import_button)

        export_menu = QMenu(self)
        self._export_selected_action = export_menu.addAction(QIcon(str(ICONS_DIR_PATH / 'upload.svg')), tr('Export selected database\u2026'))
        if self._export_selected_action:
            self._export_selected_action.triggered.connect(self._export_selected_database)
            self._export_selected_action.setEnabled(False)
        if export_zip_action := export_menu.addAction(QIcon(str(ICONS_DIR_PATH / 'upload.svg')), tr('Export all as ZIP\u2026')):
            export_zip_action.triggered.connect(self._export_all_as_zip)
            self._static_menu_actions.append((export_zip_action, 'Export all as ZIP\u2026'))
        export_menu.addSeparator()
        for icon_name, canonical_label, slot in (
            ('upload.svg', 'Backup databases now', self._backup_databases_now),
            ('folder.svg', 'Open backups folder', self._open_backups_folder),
        ):
            if act := export_menu.addAction(QIcon(str(ICONS_DIR_PATH / icon_name)), tr(canonical_label)):
                act.triggered.connect(slot)
                self._static_menu_actions.append((act, canonical_label))

        self._export_button = make_button('upload.svg', f" {tr('Export\u2026')}", tr('Export databases to an external location'))
        self._export_button.setMenu(export_menu)
        transfer_buttons.addWidget(self._export_button)

        self._reset_all_button = make_button(
            'rotate-ccw.svg',
            f" {tr('Reset all\u2026')}",
            tr('Permanently delete all user databases and restore defaults'),
            self._reset_all_databases,
            danger=True,
        )
        transfer_buttons.addWidget(self._reset_all_button)

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
        search_label = QLabel()
        set_i18n_colon_label(search_label, 'Search')
        search_bar.addWidget(search_label)

        self._search_input = QLineEdit()
        self._search_input.setPlaceholderText(tr('Filter entries by username, IP, or notes\u2026'))
        self._search_input.textChanged.connect(self._on_search_changed)
        self._search_input.returnPressed.connect(self._on_search_return_pressed)
        apply_search_icon(self._search_input)
        search_bar.addWidget(self._search_input)

        self._global_search_checkbox = QCheckBox(tr('Search All Databases'))
        self._global_search_checkbox.setToolTip(tr('Search across all UserIP database files (read-only)'))
        self._global_search_checkbox.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self._global_search_checkbox.toggled.connect(self._on_global_search_toggled)
        search_bar.addWidget(self._global_search_checkbox)

        self._group_accounts_checkbox = QCheckBox(tr('Group Accounts'))
        self._group_accounts_checkbox.setToolTip(tr('Keep linked accounts together in consecutive blocks separated by alternating background shades'))
        self._group_accounts_checkbox.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self._group_accounts_checkbox.setChecked(UserIPDatabasesManager._cached_group_accounts)
        self._group_accounts_checkbox.toggled.connect(self._on_group_accounts_toggled)
        search_bar.addWidget(self._group_accounts_checkbox)

        right_layout.addLayout(search_bar)

        # ------ Settings panel (collapsible, built by mixin) ------
        self.build_settings_panel(right_layout)

        # Entries table
        self._model = QStandardItemModel(0, len(ENTRY_TABLE_HEADERS))
        self._apply_entry_table_headers()
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
        header = self._entries_table.header()
        if header:
            header.sectionResized.connect(self._on_section_resized)
            header.sortIndicatorChanged.connect(self._on_header_sort_indicator_changed)
        self._entries_table.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self._entries_table.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self._entries_table.setItemDelegate(
            SearchHighlightDelegate(self._entries_table, self._search_input.text, configure_editor=configure_username_cell_editor),
        )
        self._entries_table.setWordWrap(False)
        self._apply_sort_state(UserIPDatabasesManager._cached_sort_column, UserIPDatabasesManager._cached_sort_order)
        self._entries_table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self._entries_table.setEditTriggers(
            QAbstractItemView.EditTrigger.DoubleClicked | QAbstractItemView.EditTrigger.EditKeyPressed,
        )

        self._entries_table.hideColumn(DATABASE_COLUMN)
        self._reset_column_sizes()
        setup_table_header_context_menu(self._entries_table, on_reset=self._reset_column_sizes)
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
        self._add_button = make_button('plus.svg', f" {tr('Add Entry')}", tr('Add a new entry (single IP, IP range, or subnet) to the current database'), self._add_entry)
        self._edit_ip_button = make_button(
            'square-pen.svg',
            f" {tr('Edit IP/Range\u2026')}",
            tr('Edit the IP or range of the selected entry using the builder'),
            self._edit_selected_entry_ip,
        )
        self._rename_button = make_button('square-pen.svg', f" {tr('Rename')}", tr('Rename the username of the selected entry or entries'), self._rename_selected)
        self._open_db_button = make_button('file-text.svg', f" {tr('Open DB')}", tr('Open the current database file in the default text editor'), self._open_db_in_editor)
        self._delete_button = make_button('trash.svg', f" {tr('Delete Selected')}", tr('Delete the selected entries (with confirmation)'), self._delete_selected, danger=True)
        for entry_button in (self._add_button, self._edit_ip_button, self._rename_button, self._open_db_button):
            entry_button.setEnabled(False)
            entry_buttons.addWidget(entry_button)
        entry_buttons.addStretch()
        self._delete_button.setEnabled(False)
        entry_buttons.addWidget(self._delete_button)
        self._close_button = make_button('x.svg', f" {tr('Close')}", tr('Close the UserIP Databases Manager'), self.close)
        entry_buttons.addWidget(self._close_button)
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
        register_language_refresh(self, self._retranslate)

    def _apply_entry_table_headers(self) -> None:
        """Apply localized column titles, canonical keys, and tooltips on the entry table model."""
        tooltips = _get_entry_table_header_tooltips()
        with QSignalBlocker(self._model):
            self._model.setHorizontalHeaderLabels([tr(header) for header in ENTRY_TABLE_HEADERS])
            for column, canonical_label in enumerate(ENTRY_TABLE_HEADERS):
                self._model.setHeaderData(column, Qt.Orientation.Horizontal, canonical_label, CANONICAL_HEADER_ROLE)
                if (tooltip := tooltips.get(canonical_label)) is not None:
                    self._model.setHeaderData(column, Qt.Orientation.Horizontal, tooltip, Qt.ItemDataRole.ToolTipRole)

    @override
    def _canonical_entry_header(self, column: int) -> str:
        """Return the canonical English header name for entry table *column*."""
        raw = self._model.headerData(column, Qt.Orientation.Horizontal, CANONICAL_HEADER_ROLE)
        if isinstance(raw, str) and raw:
            return raw
        return str(self._model.headerData(column, Qt.Orientation.Horizontal) or '')

    def _refresh_tree_selection_labels(self) -> None:
        """Refresh tree toolbar buttons, export action text, and multi-selection summary after a language change."""
        selected_paths = self._selected_tree_paths()
        if not selected_paths:
            self._configure_delete_tree_button(enabled=False)
            self._delete_tree_button.setMinimumWidth(self._delete_tree_button.sizeHint().width())
            return

        if len(selected_paths) > 1:
            self._apply_multi_selection_tree_controls(selected_paths)
        else:
            if self._export_selected_action is not None:
                self._export_selected_action.setText(tr('Export selected database\u2026'))
            self._configure_delete_tree_button(enabled=True, is_reset=is_default_userip_db(selected_paths[0]))
        self._delete_tree_button.setMinimumWidth(self._delete_tree_button.sizeHint().width())

    def _retranslate(self) -> None:
        """Refresh dialog title, controls, headers, rows, settings panel, and metadata on live language change."""
        self.setWindowTitle(tr('UserIP Databases Manager - {title}', title=TITLE))
        self._new_db_button.setText(f" {tr('New DB')}")
        self._new_db_button.setToolTip(tr('Create a new UserIP database file'))
        self._new_folder_button.setText(f" {tr('New Folder')}")
        self._new_folder_button.setToolTip(tr('Create a new folder to organize databases'))
        self._reset_all_button.setText(f" {tr('Reset all\u2026')}")
        self._reset_all_button.setToolTip(tr('Permanently delete all user databases and restore defaults'))
        self._import_button.setText(f" {tr('Import\u2026')}")
        self._import_button.setToolTip(tr('Import database files into the databases directory'))
        self._export_button.setText(f" {tr('Export\u2026')}")
        self._export_button.setToolTip(tr('Export databases to an external location'))
        for action, canonical_label in self._static_menu_actions:
            action.setText(tr(canonical_label))

        self._search_input.setPlaceholderText(tr('Filter entries by username, IP, or notes\u2026'))
        self._global_search_checkbox.setText(tr('Search All Databases'))
        self._global_search_checkbox.setToolTip(tr('Search across all UserIP database files (read-only)'))
        self._group_accounts_checkbox.setText(tr('Group Accounts'))
        self._group_accounts_checkbox.setToolTip(tr('Keep linked accounts together in consecutive blocks separated by alternating background shades'))

        self._add_button.setText(f" {tr('Add Entry')}")
        self._add_button.setToolTip(tr('Add a new entry (single IP, IP range, or subnet) to the current database'))
        self._edit_ip_button.setToolTip(tr('Edit the IP or range of the selected entry using the builder'))
        self._rename_button.setText(f" {tr('Rename')}")
        self._rename_button.setToolTip(tr('Rename the username of the selected entry or entries'))
        self._open_db_button.setText(f" {tr('Open DB')}")
        self._open_db_button.setToolTip(tr('Open the current database file in the default text editor'))
        self._delete_button.setText(f" {tr('Delete Selected')}")
        self._delete_button.setToolTip(tr('Delete the selected entries (with confirmation)'))
        self._close_button.setText(f" {tr('Close')}")
        self._close_button.setToolTip(tr('Close the UserIP Databases Manager'))

        self.retranslate_settings_panel()
        self._apply_entry_table_headers()
        retranslate_entry_rows(self._model)
        self._on_entries_selection_changed()
        self._refresh_tree_selection_labels()
        self._refresh_stats()

        selected_paths = self._selected_tree_paths()
        if len(selected_paths) > 1 and not self._global_search_active:
            info_html, status_html = format_multi_tree_selection_info(selected_paths)
            self._file_info_label.setText(info_html)
            self._status_label.setText(status_html)
        else:
            self._update_file_info(None if self._global_search_active else self._current_path)
            if self._global_search_active or self._current_path is not None:
                self._update_entry_counts()
        if viewport := self._tree.viewport():
            viewport.update()

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
        prev_enabled = self._settings_snapshot.ENABLED
        self._settings_dirty = self.read_settings_from_widgets() != self._settings_snapshot
        self._sync_dirty_state()
        if self._settings_dirty:
            self._save_database(show_errors=False)
        self._refresh_tree_item_visual(self._current_path, resort=self._setting_enabled.isChecked() != prev_enabled)

    @override
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
        self._remember_entries_scroll()
        self._model.removeRows(0, self._model.rowCount())
        self._clear_dirty_state()
        self._search_input.clear()

        if not path.is_file():
            self._set_status(tr('File not found: {name}', name=path.name))
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

        built_rows: list[list[QStandardItem]] = [
            build_entry_row_items(entry, index=entry_count, looky_icon=get_themed_icon('eye.svg'))
            for entry_count, entry in enumerate(db_model.entries, start=1)
        ]
        dynamic_sort_filter = self._proxy.dynamicSortFilter()
        self._proxy.setDynamicSortFilter(False)
        try:
            append_entry_rows(self._model, built_rows)
        finally:
            self._proxy.prepare_sort_and_invalidate()
            self._proxy.setDynamicSortFilter(dynamic_sort_filter)
        entry_count = len(built_rows)
        self._last_seen_build_version = UserIPDatabases.build_version

        self._next_index = entry_count + 1
        self._update_file_info(path)
        duplicate_count = self._highlight_duplicates()
        loaded_text = tr_plural('Loaded {count} entry from {name}', 'Loaded {count} entries from {name}', entry_count, name=path.name)
        if duplicate_count > 0:
            dup_text = tr_plural('{count} duplicate found', '{count} duplicates found', duplicate_count)
            status = tr('{loaded} ({duplicates})', loaded=loaded_text, duplicates=dup_text)
        else:
            status = loaded_text
        self._set_status(status)
        self._rebuild_fs_watch()
        self._restore_entries_scroll(path)

    @override
    def _remember_entries_scroll(self) -> None:
        """Store the entries table scroll position of the currently displayed database for this manager session."""
        if self._entries_scroll_db_path is not None and (scrollbar := self._entries_table.verticalScrollBar()):
            self._entries_scroll_positions[self._entries_scroll_db_path] = scrollbar.value()
        self._entries_scroll_db_path = None

    def _restore_entries_scroll(self, path: Path) -> None:
        """Scroll the entries table to the position last seen for *path* in this manager session, or to the top."""
        self._entries_scroll_db_path = path
        self._entries_table.doItemsLayout()
        if scrollbar := self._entries_table.verticalScrollBar():
            scrollbar.setValue(self._entries_scroll_positions.get(path, 0))

    @override
    def _append_row(self, entry: UserIPEntryModel, *, index: int = 0, persisted: bool = True) -> None:
        """Add a single row to the entries model."""
        self._model.appendRow(build_entry_row_items(entry, index=index, looky_icon=get_themed_icon('eye.svg'), persisted=persisted))

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
            self._edit_ip_button.setText(f" {tr('Edit Range\u2026')}" if is_range else f" {tr('Edit IP\u2026')}")
            self._edit_ip_button.setEnabled(True)
        else:
            self._edit_ip_button.setText(f" {tr('Edit IP/Range\u2026')}")
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

    def _apply_sort_state(self, column: int, order: Qt.SortOrder) -> None:
        """Apply *column* and *order* sorting alongside the cached account-grouping state."""
        self._syncing_sort_state = True
        try:
            self._proxy.set_group_sort_enabled(enabled=UserIPDatabasesManager._cached_group_accounts, invalidate=False)
            target_col = INDEX_COLUMN if not self._global_search_active and column == DATABASE_COLUMN else column
            UserIPDatabasesManager._cached_sort_column, UserIPDatabasesManager._cached_sort_order = target_col, order
            if not self._entries_table.isSortingEnabled():
                self._entries_table.setSortingEnabled(True)
            self._entries_table.sortByColumn(target_col, order)
            if viewport := self._entries_table.viewport():
                viewport.update()
        finally:
            self._syncing_sort_state = False

    def _on_group_accounts_toggled(self) -> None:
        """Enable or disable account grouping while preserving the active sort column and order."""
        checked = self._group_accounts_checkbox.isChecked()
        UserIPDatabasesManager._cached_group_accounts = checked
        self._proxy.set_group_sort_enabled(enabled=checked)
        _save_userip_manager_sort_state(
            group_accounts=checked,
            sort_column=UserIPDatabasesManager._cached_sort_column,
            sort_order=UserIPDatabasesManager._cached_sort_order,
        )
        if viewport := self._entries_table.viewport():
            viewport.update()

    def _on_header_sort_indicator_changed(self, logical_index: int, order: Qt.SortOrder) -> None:
        """Persist the active sort column and order when the user clicks a column header."""
        if self._syncing_sort_state:
            return
        UserIPDatabasesManager._cached_sort_column = logical_index
        UserIPDatabasesManager._cached_sort_order = order
        _save_userip_manager_sort_state(
            group_accounts=UserIPDatabasesManager._cached_group_accounts,
            sort_column=logical_index,
            sort_order=order,
        )
        if viewport := self._entries_table.viewport():
            viewport.update()

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
        if not checked and UserIPDatabasesManager._cached_sort_column == DATABASE_COLUMN:
            self._apply_sort_state(INDEX_COLUMN, Qt.SortOrder.AscendingOrder)
        self._reset_column_sizes()
        self._settings_container.setVisible(db_available)

        editable = QAbstractItemView.EditTrigger.DoubleClicked | QAbstractItemView.EditTrigger.EditKeyPressed
        self._entries_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers if checked else editable)
        self._rebuild_fs_watch()

        if checked:
            self._remember_entries_scroll()
            self._update_file_info(None)
            if self.isVisible():
                with loading_overlay_scope(self, tr('Loading Databases\u2026'), tr('Scanning all UserIP databases\u2026')):
                    self._load_all_databases()
            else:
                self._load_all_databases()
        elif self._current_path is not None:
            self._load_database(self._current_path)
        else:
            self._remember_entries_scroll()
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
            UserIPDatabasesManager._cached_group_accounts = self._group_accounts_checkbox.isChecked()
            gui_state = GUIState.load()
            gui_state.userip_manager_geometry, gui_state.userip_manager_maximized = geometry.toHex().toStdString(), maximized
            gui_state.userip_manager_splitter, gui_state.userip_manager_table_column_widths = splitter_state.toHex().toStdString(), self._custom_column_widths
            gui_state.userip_manager_group_accounts = UserIPDatabasesManager._cached_group_accounts
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
