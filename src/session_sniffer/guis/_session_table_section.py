"""Session status bar and collapsible session table section widgets."""

from typing import TYPE_CHECKING, cast, override

from PySide6.QtCore import QEvent, QObject, QSize, Qt, Signal
from PySide6.QtGui import QIcon, QStandardItem, QStandardItemModel
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QSpinBox,
    QStatusBar,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.local import RESOURCES_DIR_PATH
from session_sniffer.constants.tables import COLUMN_FORMAT_SETTING_TO_COLUMNS
from session_sniffer.guis.delegates import SearchHighlightDelegate
from session_sniffer.guis.stylesheets import (
    CONNECTED_EXPAND_BUTTON_STYLESHEET,
    DISCONNECTED_EXPAND_BUTTON_STYLESHEET,
    SECTION_CLEAR_BUTTON_STYLESHEET,
    SECTION_HEADER_SEPARATOR_STYLESHEET,
    STATUS_BAR_CAPTURE_LABEL_STYLESHEET,
    STATUS_BAR_CONFIG_LABEL_STYLESHEET,
    STATUS_BAR_ISSUES_LABEL_STYLESHEET,
    STATUS_BAR_PERFORMANCE_LABEL_STYLESHEET,
    STATUS_BAR_STYLESHEET,
    section_bar_qss,
)
from session_sniffer.guis.table_model import SessionTableModel
from session_sniffer.guis.tables import SessionTableView
from session_sniffer.guis.utils import make_padded_icon, render_svg_pixmap_from_resource, scale_by_ui
from session_sniffer.player.registry import PlayersRegistry, SessionTracker
from session_sniffer.rendering_core.types import PaginationState, SearchState, SessionFilterState
from session_sniffer.settings import Settings
from session_sniffer.text_utils import pluralize

if TYPE_CHECKING:
    from collections.abc import Callable


class SessionStatusBar(QStatusBar):
    """Status bar with dedicated labels for capture, config, issues, and performance info."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Create the status bar and add the four section labels."""
        super().__init__(parent)
        self.setSizeGripEnabled(False)
        self.setStyleSheet(STATUS_BAR_STYLESHEET)

        self._capture_label = QLabel()
        self._capture_label.setTextFormat(Qt.TextFormat.RichText)
        self._capture_label.setStyleSheet(STATUS_BAR_CAPTURE_LABEL_STYLESHEET)

        self._config_label = QLabel()
        self._config_label.setTextFormat(Qt.TextFormat.RichText)
        self._config_label.setStyleSheet(STATUS_BAR_CONFIG_LABEL_STYLESHEET)

        self._issues_label = QLabel()
        self._issues_label.setTextFormat(Qt.TextFormat.RichText)
        self._issues_label.setStyleSheet(STATUS_BAR_ISSUES_LABEL_STYLESHEET)

        self._performance_label = QLabel()
        self._performance_label.setTextFormat(Qt.TextFormat.RichText)
        self._performance_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self._performance_label.setStyleSheet(STATUS_BAR_PERFORMANCE_LABEL_STYLESHEET)

        self.addWidget(self._capture_label)
        self.addWidget(self._config_label)
        self.addWidget(self._issues_label)
        self.addPermanentWidget(self._performance_label)

    def set_texts(self, *, capture: str, config: str, issues: str, performance: str) -> None:
        """Update all four status label texts at once."""
        self._capture_label.setText(capture)
        self._config_label.setText(config)
        self._issues_label.setText(issues)
        self._issues_label.setVisible(bool(issues))
        self._performance_label.setText(performance)


class SessionTableSection(QWidget):
    """Self-contained collapsible widget containing a session table with header controls."""

    section_toggled = Signal()
    session_filter_changed = Signal(int)
    table_model: SessionTableModel
    table_view: SessionTableView
    expand_button: QPushButton
    collapse_button: QToolButton
    _clear_button: QPushButton
    _session_filter_combo: QComboBox | None
    _is_expanded: bool

    def __init__(
        self,
        *,
        is_connected: bool,
        column_names: list[str],
        clear_slot: Callable[[], None],
        parent: QWidget | None = None,
    ) -> None:
        """Build the header, table, and expand button for a collapsible session section."""
        super().__init__(parent)

        self._section_name = 'Connected' if is_connected else 'Disconnected'
        self.last_count: int = -1
        self._selected_count: int = 0
        self._is_expanded = True

        self._is_connected = is_connected
        self._rows_keyboard_editing = False
        self._session_filter_combo = None

        if is_connected:
            accent = '#22c55e'
            border_color = '#1c4f32'
            table_bg = '#101412'
            alt_bg = '#131915'
            grid_color = '#18241d'
            sel_bg = '#1a3826'
            header_bg = '#141d17'
            header_text = '#94a3b8'
            expand_button_stylesheet = CONNECTED_EXPAND_BUTTON_STYLESHEET
            collapse_tooltip = 'Hide the connected players table'
            clear_tooltip = 'Clear all connected players' if Settings.gui_disconnected_players_enabled else 'Clear all players'
            expand_tooltip = 'Show the connected players table'
            configured_column = Settings.gui_connected_table_sort_column
            sort_order = Qt.SortOrder.AscendingOrder if Settings.gui_connected_table_sort_order == 'Ascending' else Qt.SortOrder.DescendingOrder
            sort_column_name = (
                configured_column if configured_column in column_names else ('Last Rejoin' if 'Last Rejoin' in column_names else (column_names[0] if column_names else ''))
            )
        else:
            accent = '#ef4444'
            border_color = '#59282a'
            table_bg = '#141011'
            alt_bg = '#191315'
            grid_color = '#261719'
            sel_bg = '#3d1a1e'
            header_bg = '#1d1315'
            header_text = '#94a3b8'
            expand_button_stylesheet = DISCONNECTED_EXPAND_BUTTON_STYLESHEET
            collapse_tooltip = 'Hide the disconnected players table'
            clear_tooltip = 'Clear all disconnected players'
            expand_tooltip = 'Show the disconnected players table'
            configured_column = Settings.gui_disconnected_table_sort_column
            sort_order = Qt.SortOrder.AscendingOrder if Settings.gui_disconnected_table_sort_order == 'Ascending' else Qt.SortOrder.DescendingOrder
            sort_column_name = (
                configured_column if configured_column in column_names else ('Last Seen' if 'Last Seen' in column_names else (column_names[0] if column_names else ''))
            )

        # Header container
        header_container = QFrame()
        header_container.setObjectName('sectionBar')
        header_container.setStyleSheet(section_bar_qss(accent))
        header_container.setFixedHeight(scale_by_ui(42))
        header_layout = QHBoxLayout(header_container)
        header_layout.setContentsMargins(scale_by_ui(10), scale_by_ui(4), scale_by_ui(10), scale_by_ui(4))
        header_layout.setSpacing(scale_by_ui(8))

        icon_label = QLabel()
        icon_label.setFixedSize(scale_by_ui(26), scale_by_ui(26))
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_label.setPixmap(render_svg_pixmap_from_resource('player.svg', scale_by_ui(20), scale_by_ui(20), accent))

        self._header_label = QLabel(self._header_label_text())
        self._header_label.setObjectName('sectionTitle')
        self._header_label.setAutoFillBackground(False)

        clear_button = QPushButton('CLEAR')
        clear_button.setObjectName('sectionClearButton')
        clear_button.setStyleSheet(SECTION_CLEAR_BUTTON_STYLESHEET)
        clear_button.setToolTip(clear_tooltip)
        clear_button.clicked.connect(clear_slot)
        self._clear_button = clear_button

        collapse_button = QToolButton()
        collapse_button.setIcon(QIcon((RESOURCES_DIR_PATH / 'icons' / 'collapse_table.svg').as_posix()))
        collapse_button.setIconSize(QSize(16, 16))
        collapse_button.setToolTip(collapse_tooltip)
        collapse_button.clicked.connect(self.minimize)
        self.collapse_button = collapse_button

        icon_title_pair = QHBoxLayout()
        icon_title_pair.setSpacing(1)
        icon_title_pair.setContentsMargins(0, 0, 0, 0)
        icon_title_pair.addWidget(icon_label)
        icon_title_pair.addWidget(self._header_label)
        header_layout.addLayout(icon_title_pair)
        header_layout.addStretch(1)

        # Pagination controls — rows per page
        rows_label = QLabel('Rows:')
        rows_label.setToolTip('Rows per page (0 = show all)')

        initial_rpp = Settings.gui_connected_table_rows_per_page if is_connected else Settings.gui_disconnected_table_rows_per_page

        self._rows_per_page_spinbox = QSpinBox()
        self._rows_per_page_spinbox.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self._rows_per_page_spinbox.setRange(0, 5000)
        self._rows_per_page_spinbox.setMinimumWidth(95)
        self._rows_per_page_spinbox.setSpecialValueText('All')
        self._rows_per_page_spinbox.setValue(initial_rpp)
        self._rows_per_page_spinbox.setToolTip(
            f'Limit how many {self._rows_per_page_tooltip_noun()} are shown per page. Set 0 to show all.',
        )
        self._rows_per_page_spinbox.setKeyboardTracking(False)
        self._rows_per_page_spinbox.valueChanged.connect(self._handle_rows_per_page_changed)
        self._rows_per_page_spinbox.editingFinished.connect(self._finalize_rows_edit)
        self._install_spinbox_input_filter(self._rows_per_page_spinbox)

        rows_pair = QHBoxLayout()
        rows_pair.setSpacing(3)
        rows_pair.setContentsMargins(0, 0, 0, 0)
        rows_pair.addWidget(rows_label)
        rows_pair.addWidget(self._rows_per_page_spinbox)
        header_layout.addLayout(rows_pair)

        # Pagination controls — page number
        page_label = QLabel('Page:')
        page_label.setToolTip('Current page when rows are limited.')

        self._page_spinbox = QSpinBox()
        self._page_spinbox.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self._page_spinbox.setRange(1, 1)
        self._page_spinbox.setToolTip('Jump between pages when a row limit is set.')
        self._page_spinbox.setSuffix(' / 1')
        self._page_spinbox.valueChanged.connect(self._handle_page_changed)
        self._install_spinbox_input_filter(self._page_spinbox)

        page_pair = QHBoxLayout()
        page_pair.setSpacing(3)
        page_pair.setContentsMargins(0, 0, 0, 0)
        page_pair.addWidget(page_label)
        page_pair.addWidget(self._page_spinbox)
        header_layout.addLayout(page_pair)

        nav_separator = QFrame()
        nav_separator.setFrameShape(QFrame.Shape.VLine)
        nav_separator.setFrameShadow(QFrame.Shadow.Sunken)
        nav_separator.setStyleSheet(SECTION_HEADER_SEPARATOR_STYLESHEET)
        header_layout.addWidget(nav_separator)

        # Internal paging state
        self._rows_per_page: int = initial_rpp
        self._current_page: int = 1
        self._total_pages: int = 1

        # Seed PaginationState so the worker thread knows the initial values
        if is_connected:
            PaginationState.set_connected(rows_per_page=initial_rpp, page=1)
        else:
            PaginationState.set_disconnected(rows_per_page=initial_rpp, page=1)

        if not is_connected:
            session_label = QLabel('Session:')
            session_label.setToolTip('Filter disconnected players by session.')

            session_filter_combo = QComboBox()
            session_filter_combo.setObjectName('sectionSessionFilterCombo')
            session_filter_combo.setToolTip('Filter disconnected players by session.')
            session_filter_combo.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToContents)
            session_filter_combo.currentIndexChanged.connect(self._handle_session_filter_changed)
            self._session_filter_combo = session_filter_combo

            session_pair = QHBoxLayout()
            session_pair.setSpacing(3)
            session_pair.setContentsMargins(0, 0, 0, 0)
            session_pair.addWidget(session_label)
            session_pair.addWidget(session_filter_combo)
            header_layout.addLayout(session_pair)
            self._sync_session_filter_combo()
        else:
            self._session_filter_combo = None

        header_layout.addWidget(clear_button)
        header_layout.addWidget(collapse_button)

        # Table model and view
        self.table_model = SessionTableModel(column_names)
        self.table_view = SessionTableView(
            self.table_model,
            column_names.index(sort_column_name) if sort_column_name in column_names else 0,
            sort_order,
            is_connected_table=is_connected,
        )
        self.table_view.setItemDelegate(
            SearchHighlightDelegate(
                self.table_view,
                SearchState.get_text,
                self._get_highlight_search_column,
            ),
        )
        scrollbar_arrow_up_path = (RESOURCES_DIR_PATH / 'icons' / 'scrollbar_arrow_up.svg').as_posix()
        scrollbar_arrow_down_path = (RESOURCES_DIR_PATH / 'icons' / 'scrollbar_arrow_down.svg').as_posix()
        scrollbar_arrow_left_path = (RESOURCES_DIR_PATH / 'icons' / 'scrollbar_arrow_left.svg').as_posix()
        scrollbar_arrow_right_path = (RESOURCES_DIR_PATH / 'icons' / 'scrollbar_arrow_right.svg').as_posix()

        sb_track_bg = '#111215'
        sb_handle_bg = '#2a2d36'
        sb_handle_hover = '#3d4250'
        sb_handle_pressed = '#4b5163'

        self.table_view.setStyleSheet(f"""
            QTableView {{
                border-left: 1px solid {border_color};
                border-right: 1px solid {border_color};
                border-bottom: 1px solid {border_color};
                border-top: none;
                border-bottom-left-radius: 8px;
                border-bottom-right-radius: 8px;
                background-color: {table_bg};
                alternate-background-color: {alt_bg};
                color: #e0e0e0;
                gridline-color: {grid_color};
                selection-background-color: {sel_bg};
                selection-color: #ffffff;
            }}
            QTableView::viewport {{
                border-bottom-left-radius: 7px;
                border-bottom-right-radius: 7px;
                background-color: {table_bg};
            }}
            QTableView::item {{
                border-bottom: 1px solid {grid_color};
                background-color: transparent;
            }}
            QTableView::item:selected {{
                background-color: {sel_bg};
                color: #ffffff;
            }}
            QHeaderView {{
                background-color: {header_bg};
                border: none;
            }}
            QHeaderView::section {{
                background-color: {header_bg};
                color: {header_text};
                padding: 6px;
                border: none;
                border-right: 1px solid {grid_color};
                border-bottom: 1px solid {accent};
                font-weight: bold;
                font-size: 9.5pt;
            }}
            QHeaderView::section:hover {{
                background-color: {sel_bg};
            }}
            QScrollBar:vertical {{
                background-color: {sb_track_bg};
                width: 12px;
                margin: 16px 0px 16px 0px;
                border: none;
                border-radius: 6px;
            }}
            QScrollBar::handle:vertical {{
                background-color: {sb_handle_bg};
                min-height: 28px;
                border-radius: 4px;
                margin: 2px;
            }}
            QScrollBar::handle:vertical:hover {{
                background-color: {sb_handle_hover};
            }}
            QScrollBar::handle:vertical:pressed {{
                background-color: {sb_handle_pressed};
            }}
            QScrollBar::sub-line:vertical {{
                subcontrol-position: top;
                subcontrol-origin: margin;
                height: 14px;
                width: 12px;
                background-color: transparent;
                border: none;
            }}
            QScrollBar::sub-line:vertical:hover {{
                background-color: rgba(255, 255, 255, 0.08);
                border-radius: 3px;
            }}
            QScrollBar::sub-line:vertical:pressed {{
                background-color: rgba(255, 255, 255, 0.15);
                border-radius: 3px;
            }}
            QScrollBar::add-line:vertical {{
                subcontrol-position: bottom;
                subcontrol-origin: margin;
                height: 14px;
                width: 12px;
                background-color: transparent;
                border: none;
            }}
            QScrollBar::add-line:vertical:hover {{
                background-color: rgba(255, 255, 255, 0.08);
                border-radius: 3px;
            }}
            QScrollBar::add-line:vertical:pressed {{
                background-color: rgba(255, 255, 255, 0.15);
                border-radius: 3px;
            }}
            QScrollBar::up-arrow:vertical {{
                image: url("{scrollbar_arrow_up_path}");
                width: 8px;
                height: 8px;
            }}
            QScrollBar::down-arrow:vertical {{
                image: url("{scrollbar_arrow_down_path}");
                width: 8px;
                height: 8px;
            }}
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{
                background: none;
            }}
            QScrollBar:horizontal {{
                background-color: {sb_track_bg};
                height: 12px;
                margin: 0px 16px 0px 16px;
                border: none;
                border-radius: 6px;
            }}
            QScrollBar::handle:horizontal {{
                background-color: {sb_handle_bg};
                min-width: 28px;
                border-radius: 4px;
                margin: 2px;
            }}
            QScrollBar::handle:horizontal:hover {{
                background-color: {sb_handle_hover};
            }}
            QScrollBar::handle:horizontal:pressed {{
                background-color: {sb_handle_pressed};
            }}
            QScrollBar::sub-line:horizontal {{
                subcontrol-position: left;
                subcontrol-origin: margin;
                width: 14px;
                height: 12px;
                background-color: transparent;
                border: none;
            }}
            QScrollBar::sub-line:horizontal:hover {{
                background-color: rgba(255, 255, 255, 0.08);
                border-radius: 3px;
            }}
            QScrollBar::sub-line:horizontal:pressed {{
                background-color: rgba(255, 255, 255, 0.15);
                border-radius: 3px;
            }}
            QScrollBar::add-line:horizontal {{
                subcontrol-position: right;
                subcontrol-origin: margin;
                width: 14px;
                height: 12px;
                background-color: transparent;
                border: none;
            }}
            QScrollBar::add-line:horizontal:hover {{
                background-color: rgba(255, 255, 255, 0.08);
                border-radius: 3px;
            }}
            QScrollBar::add-line:horizontal:pressed {{
                background-color: rgba(255, 255, 255, 0.15);
                border-radius: 3px;
            }}
            QScrollBar::left-arrow:horizontal {{
                image: url("{scrollbar_arrow_left_path}");
                width: 8px;
                height: 8px;
            }}
            QScrollBar::right-arrow:horizontal {{
                image: url("{scrollbar_arrow_right_path}");
                width: 8px;
                height: 8px;
            }}
            QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {{
                background: none;
            }}
            QScrollBar::corner {{
                background-color: {table_bg};
                border: none;
            }}
        """)
        self.table_view.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Custom)
        self.table_view.setup_static_column_resizing()
        self.table_model.view = self.table_view

        # Expand button (shown when section is collapsed; laid out by MainWindow, not this section)
        self.expand_button = QPushButton(f'Show {self._expand_button_noun()} (0)')
        _expand_icon = QIcon((RESOURCES_DIR_PATH / 'icons' / 'expand_table.svg').as_posix())
        self.expand_button.setIcon(make_padded_icon(_expand_icon, (16, 16), 8))
        self.expand_button.setIconSize(QSize(16 + 8, 16))
        self.expand_button.setToolTip(expand_tooltip)
        self.expand_button.setStyleSheet(expand_button_stylesheet)
        self.expand_button.setVisible(False)
        self.expand_button.clicked.connect(self.expand)

        # Section layout
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(header_container)
        layout.addWidget(self.table_view, 1)

        self.setMinimumHeight(scale_by_ui(110))

        self.table_view.selectionModel().selectionChanged.connect(self._on_selection_changed)

    @property
    def _header_widget(self) -> QWidget:
        """The header container widget, accessed via the header label's parent."""
        return cast('QWidget', self._header_label.parentWidget())

    @property
    def is_expanded(self) -> bool:
        """True when the section content (header + table) is visible."""
        return self._is_expanded

    def expand(self) -> None:
        """Show section content and hide the expand button."""
        self._is_expanded = True
        self.expand_button.setVisible(False)
        self.setVisible(True)
        self.table_model.refresh_view()
        self.table_view.check_initial_data_column_sizing()
        self.section_toggled.emit()

    def minimize(self) -> None:
        """Collapse section to just an expand button."""
        self._is_expanded = False
        self.setVisible(False)
        self.expand_button.setText(
            f'Show {self._expand_button_noun()} ({max(self.last_count, 0)})',
        )
        self.expand_button.setVisible(True)
        self.section_toggled.emit()

    def update_current_count(self, count: int) -> None:
        """Update the player count, refresh the header, and sync the expand button text."""
        self.last_count = count
        self._update_header_label()
        if not self.is_expanded:
            self.expand_button.setText(
                f'Show {self._expand_button_noun()} ({count})',
            )

    def clear_table(self) -> None:
        """Clear all table data and reset selection count."""
        self.table_model.reset_columns()
        self._selected_count = 0
        self._sync_session_filter_combo()
        self._update_header_label()
        self.table_view.reset_initial_data_sizing()
        self.table_view.setup_static_column_resizing()

    def update_columns(self, column_names: list[str]) -> None:
        """Replace the column set at runtime and reconfigure the view."""
        if self._section_name == 'Connected':
            configured_column = Settings.gui_connected_table_sort_column
            sort_order = Qt.SortOrder.AscendingOrder if Settings.gui_connected_table_sort_order == 'Ascending' else Qt.SortOrder.DescendingOrder
            fallback = 'Last Rejoin'
        else:
            configured_column = Settings.gui_disconnected_table_sort_column
            sort_order = Qt.SortOrder.AscendingOrder if Settings.gui_disconnected_table_sort_order == 'Ascending' else Qt.SortOrder.DescendingOrder
            fallback = 'Last Seen'

        if configured_column in column_names:
            sort_column_name = configured_column
        elif fallback in column_names:
            sort_column_name = fallback
        elif column_names:
            sort_column_name = column_names[0]
        else:
            sort_column_name = None

        old_columns = set(self.table_model.column_names)
        new_columns = set(column_names)
        added_columns = new_columns - old_columns
        if added_columns:
            self.table_view.clear_custom_column_widths(added_columns)

        self.table_model.reset_columns(column_names)
        if sort_column_name is not None:
            self.table_view.apply_sort(sort_column_name, sort_order)
        self.table_view.request_column_recalculation()
        self.table_view.setup_static_column_resizing()

    def apply_sort_from_settings(self) -> None:
        """Apply sort column and order from current Settings."""
        if self._section_name == 'Connected':
            target_column = Settings.gui_connected_table_sort_column
            target_order = Qt.SortOrder.AscendingOrder if Settings.gui_connected_table_sort_order == 'Ascending' else Qt.SortOrder.DescendingOrder
        else:
            target_column = Settings.gui_disconnected_table_sort_column
            target_order = Qt.SortOrder.AscendingOrder if Settings.gui_disconnected_table_sort_order == 'Ascending' else Qt.SortOrder.DescendingOrder
        self.table_view.apply_sort(target_column, target_order)

    def set_all_enabled(self, *, enabled: bool) -> None:
        """Enable or disable all interactive child widgets."""
        self._header_widget.setEnabled(enabled)
        self.table_view.setEnabled(enabled)
        self.expand_button.setEnabled(enabled)

    def update_disconnected_players_state(self) -> None:
        """Update header label and tooltips when the disconnected players setting changes."""
        self._update_header_label()
        if self._is_connected:
            disconnected_enabled = Settings.gui_disconnected_players_enabled
            self._clear_button.setToolTip('Clear all connected players' if disconnected_enabled else 'Clear all players')
            self._rows_per_page_spinbox.setToolTip(f'Limit how many {self._rows_per_page_tooltip_noun()} are shown per page. Set 0 to show all.')
            self.table_view.viewport().update()

    def _expand_button_noun(self) -> str:
        """Return the player label for the expand button, respecting the disconnected players setting."""
        if self._is_connected:
            return 'Connected Players' if Settings.gui_disconnected_players_enabled else 'Players'
        return 'Disconnected Players'

    def _rows_per_page_tooltip_noun(self) -> str:
        """Return the player noun used in the rows-per-page tooltip, respecting the disconnected players setting."""
        if self._is_connected:
            return 'connected players' if Settings.gui_disconnected_players_enabled else 'players'
        return 'disconnected players'

    def _header_label_text(self) -> str:
        selected_session = SessionFilterState.get_selected_session()
        if not self._is_connected and 0 < selected_session < SessionTracker.get_current_session_id():
            display_name = SessionTracker.get_session_display_name(selected_session)
            intro = f"Session '{display_name}' Players"
        elif self._is_connected:
            intro = 'Connected Players' if Settings.gui_disconnected_players_enabled else 'Players'
        else:
            intro = 'Disconnected Players'

        base = f'{intro} ({max(0, self.last_count)})'
        if self._selected_count > 0:
            noun = f'player{pluralize(self._selected_count)}'
            return f'{base} ({self._selected_count} {noun} selected)'
        return base

    def _update_header_label(self) -> None:
        self._header_label.setText(self._header_label_text())

    def refresh_selection_count(self) -> None:
        """Recompute the selected-row count and update the header label."""
        self._on_selection_changed()

    def _on_selection_changed(self) -> None:
        self._selected_count = len({i.row() for i in self.table_view.selectionModel().selectedIndexes()})
        self._update_header_label()

    # -- Pagination handlers --------------------------------------------------

    def _handle_rows_per_page_changed(self, value: int) -> None:
        self._rows_per_page = max(value, 0)
        self._current_page, self._total_pages = self._sync_paging_controls(
            total_rows=max(self.last_count, 0),
            rows_per_page=self._rows_per_page,
            requested_page=1,
        )
        self._push_pagination_state()
        self._update_header_label()

    def apply_pagination_from_settings(self) -> None:
        """Apply configured rows per page from Settings to this table section."""
        configured_rows = Settings.gui_connected_table_rows_per_page if self._is_connected else Settings.gui_disconnected_table_rows_per_page
        if self._rows_per_page == configured_rows:
            return
        self._rows_per_page = max(configured_rows, 0)
        self._rows_per_page_spinbox.blockSignals(True)  # noqa: FBT003
        self._rows_per_page_spinbox.setValue(self._rows_per_page)
        self._rows_per_page_spinbox.blockSignals(False)  # noqa: FBT003
        self._current_page, self._total_pages = self._sync_paging_controls(
            total_rows=max(self.last_count, 0),
            rows_per_page=self._rows_per_page,
            requested_page=1,
        )
        self._push_pagination_state()
        self._update_header_label()

    def apply_columns_from_settings(self, changed: set[str] | None = None) -> None:
        """Handle column formatting and visibility settings changes saved from SettingsDialog."""
        shown_setting = 'gui_columns_connected_shown' if self._is_connected else 'gui_columns_disconnected_shown'
        affected_columns: set[str] = {
            column_name for setting_key, column_names in COLUMN_FORMAT_SETTING_TO_COLUMNS.items() if changed is None or setting_key in changed for column_name in column_names
        }
        if affected_columns:
            self.table_view.clear_custom_column_widths(affected_columns)
            self.table_view.request_column_recalculation()
        if changed is None or shown_setting in changed:
            self.table_view.request_column_recalculation()

    def _handle_page_changed(self, value: int) -> None:
        self._current_page = max(value, 1)
        self._push_pagination_state()
        self._update_header_label()

    def _finalize_rows_edit(self) -> None:
        self._handle_rows_per_page_changed(self._rows_per_page_spinbox.value())
        self._rows_per_page_spinbox.clearFocus()

    def sync_session_filter(self) -> None:
        """Synchronize the session filter combobox and section header."""
        if self._session_filter_combo is not None:
            self._sync_session_filter_combo()
        self._update_header_label()

    def set_selected_session_filter(self, session_id: int) -> None:
        """Set the active session filter and synchronize the combobox."""
        self._current_page = 1
        PaginationState.set_disconnected_page(1)
        SessionFilterState.set_selected_session(session_id=session_id)
        if self._session_filter_combo is not None:
            self._sync_session_filter_combo()
        self._update_header_label()
        self.session_filter_changed.emit(session_id)

    def _handle_session_filter_changed(self, index: int) -> None:
        """Handle session filter combobox selection changes."""
        if self._session_filter_combo is None or index < 0:
            return
        selected_session = self._session_filter_combo.itemData(index)
        if selected_session is None:
            selected_session = SessionFilterState.FILTER_ALL

        self._current_page = 1
        PaginationState.set_disconnected_page(1)
        SessionFilterState.set_selected_session(session_id=selected_session)
        self._sync_session_filter_combo()
        self._update_header_label()
        self.session_filter_changed.emit(selected_session)

    def _push_pagination_state(self) -> None:
        """Write current pagination state to the shared PaginationState."""
        if self._is_connected:
            PaginationState.set_connected(rows_per_page=self._rows_per_page, page=self._current_page)
        else:
            PaginationState.set_disconnected(rows_per_page=self._rows_per_page, page=self._current_page)

    def _sync_paging_controls(
        self,
        *,
        total_rows: int,
        rows_per_page: int,
        requested_page: int,
    ) -> tuple[int, int]:
        """Update the page spinbox range/value and return (clamped_page, total_pages)."""
        if not rows_per_page:
            total_pages = 1
            page = 1
        else:
            total_pages = max(1, (total_rows + rows_per_page - 1) // rows_per_page)
            page = min(max(1, requested_page), total_pages)

        self._page_spinbox.blockSignals(True)  # noqa: FBT003
        self._page_spinbox.setMinimum(1)
        self._page_spinbox.setMaximum(total_pages)
        self._page_spinbox.setEnabled(0 < rows_per_page < total_rows)
        self._page_spinbox.setValue(page)
        self._page_spinbox.blockSignals(False)  # noqa: FBT003

        return page, total_pages

    def sync_paging_from_payload(
        self,
        *,
        total_count: int,
        rows_per_page: int,
        page: int,
    ) -> None:
        """Called from _update_gui to keep spinbox decorations in sync."""
        self._rows_per_page = rows_per_page

        if not self._rows_keyboard_editing:
            self._rows_per_page_spinbox.setRange(0, 5000)
            if self._rows_per_page_spinbox.value() != self._rows_per_page:
                self._rows_per_page_spinbox.blockSignals(True)  # noqa: FBT003
                self._rows_per_page_spinbox.setValue(self._rows_per_page)
                self._rows_per_page_spinbox.blockSignals(False)  # noqa: FBT003
            if self._rows_per_page > 0:
                self._rows_per_page_spinbox.setPrefix(f'{total_count} / ')
                self._rows_per_page_spinbox.setSuffix('')
                self._rows_per_page_spinbox.setSpecialValueText('')
            else:
                self._rows_per_page_spinbox.setPrefix('')
                self._rows_per_page_spinbox.setSuffix('')
                self._rows_per_page_spinbox.setSpecialValueText(f'All ({total_count})')

        self._current_page, self._total_pages = self._sync_paging_controls(
            total_rows=max(self.last_count, 0),
            rows_per_page=self._rows_per_page,
            requested_page=page,
        )
        if self._current_page != page:
            self._push_pagination_state()

        if not self._rows_keyboard_editing:
            self._page_spinbox.setSuffix(f' / {self._total_pages}')

        self._sync_session_filter_combo()

    def _install_spinbox_input_filter(self, spinbox: QSpinBox) -> None:
        """Attach an event filter that tracks keyboard vs. wheel editing and ignores unfocused wheels."""
        line_edit = spinbox.lineEdit()
        if not line_edit:
            return

        section = self

        class _SpinboxInputGuard(QObject):
            @override
            def eventFilter(self, a0: QObject | None, a1: QEvent | None) -> bool:
                """Track input method to distinguish keyboard edits from wheel/spin changes."""
                _ = a0
                if a1 is None:
                    return False
                event_type = a1.type()
                if event_type == QEvent.Type.KeyPress:
                    section.set_keyboard_editing(is_editing=True)
                elif event_type in (QEvent.Type.FocusOut, QEvent.Type.Hide):
                    section.set_keyboard_editing(is_editing=False)
                elif event_type == QEvent.Type.Wheel:
                    section.set_keyboard_editing(is_editing=False)
                    if not spinbox.hasFocus():
                        return True
                return False

        guard = _SpinboxInputGuard(self)
        spinbox.installEventFilter(guard)
        line_edit.installEventFilter(guard)
        if not hasattr(self, '_spinbox_guards'):
            self._spinbox_guards: list[QObject] = []
        self._spinbox_guards.append(guard)

    def set_keyboard_editing(self, *, is_editing: bool) -> None:
        """Set the keyboard editing state for the rows-per-page spinbox."""
        self._rows_keyboard_editing = is_editing

    def get_search_column_index(self, column_name: str) -> int:
        """Return the column index for `column_name`, or -1 if 'All Columns' or not found."""
        if not column_name or column_name == 'All Columns':
            return -1
        try:
            return self.table_model.column_names.index(column_name)
        except ValueError:
            return -1

    def _get_highlight_search_column(self) -> int:
        return self.get_search_column_index(SearchState.get_column_name())

    def _has_past_disconnected_players(self) -> bool:
        """Check if any disconnected player belongs to a past session."""
        current_session_id = SessionTracker.get_current_session_id()
        if len(SessionTracker.get_all_session_ids()) <= 1:
            return False
        return any(player.session_id < current_session_id for player in PlayersRegistry.get_disconnected_players())

    @staticmethod
    def _set_combo_item_enabled(item: QStandardItem | None, *, enabled: bool) -> None:
        if item is None:
            return
        flags = item.flags()
        if enabled:
            flags |= Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable
        else:
            flags &= ~(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
        item.setFlags(flags)

    def _sync_session_filter_combo(self) -> None:
        """Synchronize the session filter combobox enabled state, item list, and active selection."""
        if self._session_filter_combo is None:
            return

        selected_session = SessionFilterState.get_selected_session()
        current_session_id = SessionTracker.get_current_session_id()
        all_session_ids = SessionTracker.get_all_session_ids()
        past_session_ids = [session_id for session_id in all_session_ids if session_id < current_session_id]
        has_past_disconnected = self._has_past_disconnected_players()
        is_past_session = 0 < selected_session < current_session_id

        desired_items: list[tuple[str, int, str]] = [
            ('All', SessionFilterState.FILTER_ALL, 'Show disconnected players from all recorded sessions'),
            ('Current', SessionFilterState.FILTER_CURRENT, 'Show disconnected players from the current active session'),
        ]
        for past_id in reversed(past_session_ids):
            display_name = SessionTracker.get_session_display_name(past_id)
            player_count = SessionTracker.get_session_player_count(past_id)
            player_noun = f'player{pluralize(player_count)}'
            time_label = SessionTracker.get_session_time_label(past_id)
            tooltip_parts = [f'{player_count} {player_noun} recorded in {display_name}']
            if time_label:
                tooltip_parts.append(time_label)
            desired_items.append((display_name, past_id, '  |  '.join(tooltip_parts)))

        current_items = [
            (
                self._session_filter_combo.itemText(i),
                self._session_filter_combo.itemData(i),
                self._session_filter_combo.itemData(i, Qt.ItemDataRole.ToolTipRole) or '',
            )
            for i in range(self._session_filter_combo.count())
        ]

        if current_items != desired_items:
            self._session_filter_combo.blockSignals(True)  # noqa: FBT003
            self._session_filter_combo.clear()
            for text, data, tooltip in desired_items:
                self._session_filter_combo.addItem(text, data)
                self._session_filter_combo.setItemData(self._session_filter_combo.count() - 1, tooltip, Qt.ItemDataRole.ToolTipRole)
            self._session_filter_combo.blockSignals(False)  # noqa: FBT003

        target_index = -1
        for i in range(self._session_filter_combo.count()):
            if self._session_filter_combo.itemData(i) == selected_session:
                target_index = i
                break

        if target_index >= 0:
            if self._session_filter_combo.currentIndex() != target_index:
                self._session_filter_combo.blockSignals(True)  # noqa: FBT003
                self._session_filter_combo.setCurrentIndex(target_index)
                self._session_filter_combo.blockSignals(False)  # noqa: FBT003
        else:
            self._session_filter_combo.blockSignals(True)  # noqa: FBT003
            self._session_filter_combo.setCurrentIndex(0)
            self._session_filter_combo.blockSignals(False)  # noqa: FBT003
            SessionFilterState.set_selected_session(session_id=SessionFilterState.FILTER_ALL)
            selected_session = SessionFilterState.FILTER_ALL
            is_past_session = False

        can_change_filter = is_past_session or has_past_disconnected or bool(past_session_ids)
        self._session_filter_combo.setEnabled(can_change_filter)

        if len(all_session_ids) <= 1:
            self._session_filter_combo.setToolTip('Filter disconnected players by session (only one session recorded).')
        elif not has_past_disconnected and not is_past_session and not past_session_ids:
            self._session_filter_combo.setToolTip('Filter disconnected players by session (no disconnected players from other sessions).')
        else:
            self._session_filter_combo.setToolTip('Filter disconnected players by session.')

        model = self._session_filter_combo.model()
        if isinstance(model, QStandardItemModel):
            for i in range(self._session_filter_combo.count()):
                item = model.item(i)
                item_data = self._session_filter_combo.itemData(i)
                self._set_combo_item_enabled(item, enabled=selected_session != item_data)
