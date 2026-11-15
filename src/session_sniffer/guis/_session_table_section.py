"""Session status bar and collapsible session table section widgets."""

from typing import TYPE_CHECKING, cast, override

from PySide6.QtCore import QEvent, QObject, QSignalBlocker, QSize, Qt, Signal
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
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
from shiboken6 import isValid

from session_sniffer.constants.tables import COLUMN_FORMAT_SETTING_TO_COLUMNS
from session_sniffer.guis.delegates import SearchHighlightDelegate
from session_sniffer.guis.live_language import register_language_refresh
from session_sniffer.guis.stylesheets import (
    CONNECTED_EXPAND_BUTTON_STYLESHEET,
    DISCONNECTED_EXPAND_BUTTON_STYLESHEET,
    SECTION_HEADER_SEPARATOR_STYLESHEET,
    STATUS_BAR_LABEL_STYLESHEET,
    STATUS_BAR_PERFORMANCE_LABEL_STYLESHEET,
    section_bar_qss,
)
from session_sniffer.guis.table_model import SessionTableModel
from session_sniffer.guis.tables import SessionTableView
from session_sniffer.guis.theming import ICONS_DIR_PATH, themed_qss
from session_sniffer.guis.utils import make_padded_icon, render_svg_icon_from_resource, render_svg_pixmap_from_resource, scale_by_ui
from session_sniffer.i18n import tr, tr_plural
from session_sniffer.player.registry import SessionTracker
from session_sniffer.rendering_core.types import PaginationState, SearchState, SessionFilterState, TableMergeState
from session_sniffer.settings import Settings

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence


class SessionStatusBar(QStatusBar):
    """Status bar with dedicated labels for capture, config, issues, and performance info."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Create the status bar and add the four section labels."""
        super().__init__(parent)
        self.setSizeGripEnabled(False)

        self._capture_label = QLabel()
        self._capture_label.setTextFormat(Qt.TextFormat.RichText)
        self._capture_label.setStyleSheet(STATUS_BAR_LABEL_STYLESHEET)

        self._config_label = QLabel()
        self._config_label.setTextFormat(Qt.TextFormat.RichText)
        self._config_label.setStyleSheet(STATUS_BAR_LABEL_STYLESHEET)

        self._issues_label = QLabel()
        self._issues_label.setTextFormat(Qt.TextFormat.RichText)
        self._issues_label.setStyleSheet(STATUS_BAR_LABEL_STYLESHEET)

        self._performance_label = QLabel()
        self._performance_label.setTextFormat(Qt.TextFormat.RichText)
        self._performance_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self._performance_label.setStyleSheet(STATUS_BAR_PERFORMANCE_LABEL_STYLESHEET)
        self._refresh_language_texts()

        self.addWidget(self._capture_label)
        self.addWidget(self._config_label)
        self.addWidget(self._issues_label)
        self.addPermanentWidget(self._performance_label)
        register_language_refresh(self, self._refresh_language_texts)

    def _refresh_language_texts(self) -> None:
        self._performance_label.setToolTip(
            tr(
                'Packet capture performance metrics:\n\n'
                '• Latency: Processing delay between packet arrival at the network driver and capture analysis (not network ping).\n'
                '  If this value steadily increments, the capture engine is falling behind real-time traffic (see Capture Overflow Timer setting).\n\n'
                '• Restarts: Number of times packet capture was automatically restarted.',
            ),
        )

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
    _merge_button: QPushButton | None
    _is_expanded: bool

    def __init__(
        self,
        *,
        is_connected: bool,
        column_names: list[str],
        clear_slot: Callable[[], None],
        merge_slot: Callable[[], None] | None = None,
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
        self._has_synced_paging = False
        self._last_total_count = 0
        self._spinbox_guards: list[QObject] = []

        if is_connected:
            role_key = 'success'
            accent = '@success[#22c55e]'
            border_color = '@border~success[#1c4f32]'
            table_bg = '@table~success[#101412]'
            alt_bg = '@table_alt~success[#131915]'
            grid_color = '@border~success[#18241d]'
            sel_bg = '@selection~success[#1a3826]'
            header_bg = '@table_header~success[#141d17]'
            expand_button_stylesheet = CONNECTED_EXPAND_BUTTON_STYLESHEET
            collapse_tooltip = tr('Hide the connected players table')
            expand_tooltip = tr('Show the connected players table')
        else:
            role_key = 'danger'
            accent = '@danger[#ef4444]'
            border_color = '@border~danger[#59282a]'
            table_bg = '@table~danger[#180e11]'
            alt_bg = '@table_alt~danger[#241317]'
            grid_color = '@border~danger[#2d181c]'
            sel_bg = '@selection~danger[#3d1a1e]'
            header_bg = '@table_header~danger[#1d1315]'
            expand_button_stylesheet = DISCONNECTED_EXPAND_BUTTON_STYLESHEET
            collapse_tooltip = tr('Hide the disconnected players table')
            expand_tooltip = tr('Show the disconnected players table')

        header_text = '@text_muted[#94a3b8]'

        sort_column_name, sort_order = self._resolve_sort_from_settings(column_names)

        # Header container
        header_container = QFrame()
        header_container.setObjectName('sectionBar')
        header_container.setStyleSheet(section_bar_qss(role_key))
        header_container.setFixedHeight(max(scale_by_ui(42), 38))
        header_layout = QHBoxLayout(header_container)
        header_layout.setContentsMargins(scale_by_ui(10), 3, scale_by_ui(10), 3)
        header_layout.setSpacing(scale_by_ui(8))
        header_layout.setAlignment(Qt.AlignmentFlag.AlignVCenter)

        icon_label = QLabel()
        icon_label.setFixedSize(scale_by_ui(26), scale_by_ui(26))
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_label.setPixmap(render_svg_pixmap_from_resource('user-round.svg', scale_by_ui(20), scale_by_ui(20), accent))

        self._header_label = QLabel(self._header_label_text())
        self._header_label.setObjectName('sectionTitle')
        self._header_label.setAutoFillBackground(False)

        self._clear_button = QPushButton(tr('CLEAR'))
        self._clear_button.setObjectName('sectionClearButton')
        self._clear_button.setEnabled(False)
        self._update_clear_button_tooltip()
        self._clear_button.clicked.connect(clear_slot)

        self.collapse_button = QToolButton()
        self.collapse_button.setObjectName('sectionCollapseButton')
        self.collapse_button.setIcon(QIcon((ICONS_DIR_PATH / 'arrow-down-to-line.svg').as_posix()))
        self.collapse_button.setIconSize(QSize(16, 16))
        self.collapse_button.setToolTip(collapse_tooltip)
        self.collapse_button.clicked.connect(self.minimize)

        icon_title_pair = QHBoxLayout()
        icon_title_pair.setSpacing(1)
        icon_title_pair.setContentsMargins(0, 0, 0, 0)
        icon_title_pair.setAlignment(Qt.AlignmentFlag.AlignVCenter)
        icon_title_pair.addWidget(icon_label)
        icon_title_pair.addWidget(self._header_label)
        header_layout.addLayout(icon_title_pair)
        header_layout.addStretch(1)

        # Pagination controls — rows per page
        self._rows_label = QLabel(tr('Rows:'))
        self._rows_label.setAlignment(Qt.AlignmentFlag.AlignVCenter)
        self._rows_label.setToolTip(tr('Rows per page (0 = show all)'))

        initial_rpp = Settings.gui_connected_table_rows_per_page if is_connected else Settings.gui_disconnected_table_rows_per_page

        self._rows_per_page_spinbox = QSpinBox()
        self._rows_per_page_spinbox.setObjectName('sectionRowsSpinBox')
        self._rows_per_page_spinbox.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self._rows_per_page_spinbox.setRange(0, 5000)
        self._rows_per_page_spinbox.setSpecialValueText(tr('All'))
        self._rows_per_page_spinbox.setValue(initial_rpp)
        self._rows_per_page_spinbox.setToolTip(self._rows_per_page_tooltip())
        self._rows_per_page_spinbox.setKeyboardTracking(False)
        self._rows_per_page_spinbox.valueChanged.connect(self._handle_rows_per_page_changed)
        self._rows_per_page_spinbox.editingFinished.connect(self._finalize_rows_edit)
        self._install_spinbox_input_filter(self._rows_per_page_spinbox)

        rows_pair = QHBoxLayout()
        rows_pair.setSpacing(scale_by_ui(4))
        rows_pair.setContentsMargins(0, 0, 0, 0)
        rows_pair.setAlignment(Qt.AlignmentFlag.AlignVCenter)
        rows_pair.addWidget(self._rows_label)
        rows_pair.addWidget(self._rows_per_page_spinbox)
        header_layout.addLayout(rows_pair)

        # Pagination controls — page number
        self._page_label = QLabel(tr('Page:'))
        self._page_label.setAlignment(Qt.AlignmentFlag.AlignVCenter)
        self._page_label.setToolTip(tr('Current page when rows are limited.'))

        self._page_spinbox = QSpinBox()
        self._page_spinbox.setObjectName('sectionPageSpinBox')
        self._page_spinbox.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self._page_spinbox.setRange(1, 1)
        self._page_spinbox.setToolTip(tr('Jump between pages when a row limit is set.'))
        self._page_spinbox.setSuffix(' / 1')
        self._page_spinbox.valueChanged.connect(self._handle_page_changed)
        self._install_spinbox_input_filter(self._page_spinbox)

        page_pair = QHBoxLayout()
        page_pair.setSpacing(scale_by_ui(4))
        page_pair.setContentsMargins(0, 0, 0, 0)
        page_pair.setAlignment(Qt.AlignmentFlag.AlignVCenter)
        page_pair.addWidget(self._page_label)
        page_pair.addWidget(self._page_spinbox)
        header_layout.addLayout(page_pair)

        nav_separator = QFrame()
        nav_separator.setFrameShape(QFrame.Shape.VLine)
        nav_separator.setFrameShadow(QFrame.Shadow.Sunken)
        nav_separator.setStyleSheet(SECTION_HEADER_SEPARATOR_STYLESHEET)
        header_layout.addWidget(nav_separator, alignment=Qt.AlignmentFlag.AlignVCenter)

        # Internal paging state
        self._rows_per_page: int = initial_rpp
        self._current_page: int = 1
        self._total_pages: int = 1

        # Seed PaginationState so the worker thread knows the initial values
        if is_connected:
            PaginationState.set_connected(rows_per_page=initial_rpp, page=1)
        else:
            PaginationState.set_disconnected(rows_per_page=initial_rpp, page=1)

        if merge_slot is not None:
            self._merge_button = QPushButton()
            self._merge_button.setObjectName('sectionMergeButton')
            self._merge_button.clicked.connect(merge_slot)
            self.update_merge_button_state()
            header_layout.addWidget(self._merge_button, alignment=Qt.AlignmentFlag.AlignVCenter)
        else:
            self._merge_button = None

        header_layout.addWidget(self._clear_button, alignment=Qt.AlignmentFlag.AlignVCenter)
        header_layout.addWidget(self.collapse_button, alignment=Qt.AlignmentFlag.AlignVCenter)

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
        scrollbar_arrow_up_path = (ICONS_DIR_PATH / 'scrollbar_arrow_up.svg').as_posix()
        scrollbar_arrow_down_path = (ICONS_DIR_PATH / 'scrollbar_arrow_down.svg').as_posix()
        scrollbar_arrow_left_path = (ICONS_DIR_PATH / 'scrollbar_arrow_left.svg').as_posix()
        scrollbar_arrow_right_path = (ICONS_DIR_PATH / 'scrollbar_arrow_right.svg').as_posix()

        sb_track_bg = '@table[#111215]'
        sb_handle_bg = '@scrollbar[#2a2d36]'
        sb_handle_hover = '@scrollbar[#3d4250]'
        sb_handle_pressed = '@scrollbar[#4b5163]'

        self.table_view.setStyleSheet(
            themed_qss(f"""
            QTableView {{
                border-left: 1px solid {border_color};
                border-right: 1px solid {border_color};
                border-bottom: 1px solid {border_color};
                border-top: none;
                border-bottom-left-radius: 8px;
                border-bottom-right-radius: 8px;
                background-color: {table_bg};
                alternate-background-color: {alt_bg};
                color: @text[#e0e0e0];
                gridline-color: {grid_color};
                selection-background-color: {sel_bg};
                selection-color: @text_strong[#ffffff];
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
                color: @text_strong[#ffffff];
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
                background-color: @scrollbar[rgba(255, 255, 255, 0.08)];
                border-radius: 3px;
            }}
            QScrollBar::sub-line:vertical:pressed {{
                background-color: @scrollbar[rgba(255, 255, 255, 0.15)];
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
                background-color: @scrollbar[rgba(255, 255, 255, 0.08)];
                border-radius: 3px;
            }}
            QScrollBar::add-line:vertical:pressed {{
                background-color: @scrollbar[rgba(255, 255, 255, 0.15)];
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
                background-color: @scrollbar[rgba(255, 255, 255, 0.08)];
                border-radius: 3px;
            }}
            QScrollBar::sub-line:horizontal:pressed {{
                background-color: @scrollbar[rgba(255, 255, 255, 0.15)];
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
                background-color: @scrollbar[rgba(255, 255, 255, 0.08)];
                border-radius: 3px;
            }}
            QScrollBar::add-line:horizontal:pressed {{
                background-color: @scrollbar[rgba(255, 255, 255, 0.15)];
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
        """),
        )
        self.table_view.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Custom)
        self.table_view.setup_static_column_resizing()
        self.table_model.view = self.table_view

        # Expand button (shown when section is collapsed; laid out by MainWindow, not this section)
        self.expand_button = QPushButton(self._expand_button_text(0))
        _expand_icon = render_svg_icon_from_resource('arrow-up-from-line.svg', 16, 16)
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
        register_language_refresh(self, self._refresh_language_texts)

    def _refresh_language_texts(self) -> None:
        """Re-translate section labels, buttons, spinboxes, and tooltips on language change."""
        self._clear_button.setText(tr('CLEAR'))
        self.collapse_button.setToolTip(tr('Hide the connected players table') if self._is_connected else tr('Hide the disconnected players table'))
        self.expand_button.setToolTip(tr('Show the connected players table') if self._is_connected else tr('Show the disconnected players table'))
        self._rows_label.setText(tr('Rows:'))
        self._rows_label.setToolTip(tr('Rows per page (0 = show all)'))
        self._rows_per_page_spinbox.setToolTip(self._rows_per_page_tooltip())
        if self._rows_per_page <= 0:
            self._rows_per_page_spinbox.setSpecialValueText(
                tr('All ({count})', count=self._last_total_count) if self._has_synced_paging else tr('All'),
            )
        self._page_label.setText(tr('Page:'))
        self._page_label.setToolTip(tr('Current page when rows are limited.'))
        self._page_spinbox.setToolTip(tr('Jump between pages when a row limit is set.'))
        self._update_header_label()
        self.update_merge_button_state()
        if not self.is_expanded:
            self.expand_button.setText(self._expand_button_text(max(self.last_count, 0)))

    @property
    def _header_widget(self) -> QWidget:
        """The header container widget, accessed via the header label's parent."""
        return cast('QWidget', self._header_label.parentWidget())

    @property
    def is_expanded(self) -> bool:
        """True when the section content (header + table) is visible."""
        return self._is_expanded

    @property
    def is_clear_enabled(self) -> bool:
        """Return `True` when the section clear button is currently enabled."""
        return self._clear_button.isEnabled()

    def refresh_shortcut_tooltips(self) -> None:
        """Refresh merge and clear button tooltips to reflect configured shortcuts."""
        self.update_merge_button_state()
        self._update_clear_button_tooltip()

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
        self.expand_button.setText(self._expand_button_text(max(self.last_count, 0)))
        self.expand_button.setVisible(True)
        self.section_toggled.emit()

    def update_current_count(self, count: int) -> None:
        """Update the player count, refresh the header, and sync the expand button text."""
        self.last_count = count
        self._clear_button.setEnabled(count > 0)
        self._update_header_label()
        if not self.is_expanded:
            self.expand_button.setText(self._expand_button_text(count))

    def clear_table(self) -> None:
        """Clear all table data and reset selection count."""
        self.table_model.reset_columns()
        self._selected_count = 0
        self.last_count = 0
        self._clear_button.setEnabled(False)
        self._update_header_label()
        self.table_view.reset_initial_data_sizing()
        self.table_view.setup_static_column_resizing()

    def _resolve_sort_from_settings(self, column_names: Sequence[str] | None = None) -> tuple[str | None, Qt.SortOrder]:
        """Resolve the configured sort column and order for this section."""
        is_connected = self._section_name == 'Connected'
        configured_column = Settings.gui_connected_table_sort_column if is_connected else Settings.gui_disconnected_table_sort_column
        sort_setting = Settings.gui_connected_table_sort_order if is_connected else Settings.gui_disconnected_table_sort_order
        sort_order = Qt.SortOrder.AscendingOrder if sort_setting == 'Ascending' else Qt.SortOrder.DescendingOrder
        if column_names is None:
            return configured_column, sort_order
        fallback_column = 'Last Rejoin' if is_connected else 'Last Seen'
        if configured_column in column_names:
            return configured_column, sort_order
        if fallback_column in column_names:
            return fallback_column, sort_order
        return (column_names[0] if column_names else None), sort_order

    def update_columns(self, column_names: list[str]) -> None:
        """Replace the column set at runtime and reconfigure the view."""
        sort_column_name, sort_order = self._resolve_sort_from_settings(column_names)

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
        target_column, target_order = self._resolve_sort_from_settings()
        if target_column is not None:
            self.table_view.apply_sort(target_column, target_order)

    def set_all_enabled(self, *, enabled: bool) -> None:
        """Enable or disable all interactive child widgets."""
        self._header_widget.setEnabled(enabled)
        self.table_view.setEnabled(enabled)
        self.expand_button.setEnabled(enabled)

    def update_merge_button_state(self) -> None:
        """Update the merge button text, tooltip, and visibility according to the current merge state."""
        if self._merge_button is None:
            return
        selected_session = SessionFilterState.get_selected_session()
        is_past_session = 0 < selected_session < SessionTracker.get_current_session_id()
        self._merge_button.setVisible(not is_past_session)
        is_merged = TableMergeState.is_merged()
        self._merge_button.setText(tr('SPLIT') if is_merged else tr('MERGE'))
        shortcut = Settings.shortcut_merge_tables
        if shortcut == 'Ctrl+M':
            tooltip = tr('Split into connected and disconnected tables (Ctrl+M)') if is_merged else tr('Merge connected and disconnected tables into one (Ctrl+M)')
        else:
            base_tooltip = tr('Split into connected and disconnected tables') if is_merged else tr('Merge connected and disconnected tables into one')
            tooltip = f'{base_tooltip} ({shortcut})' if bool(shortcut) else base_tooltip
        self._merge_button.setToolTip(tooltip)

    def update_disconnected_players_state(self) -> None:
        """Update header label and tooltips when the disconnected players setting changes."""
        self._update_header_label()
        if not self.is_expanded:
            self.expand_button.setText(self._expand_button_text(max(self.last_count, 0)))
        self.update_merge_button_state()
        if self._is_connected:
            self._rows_per_page_spinbox.setToolTip(self._rows_per_page_tooltip())
            self.table_view.viewport().update()

    def _expand_button_text(self, count: int) -> str:
        """Return localized text for the collapsed expand button."""
        if self._is_connected:
            return tr('Show Players ({count})', count=count) if TableMergeState.is_merged() else tr('Show Connected Players ({count})', count=count)
        return tr('Show Disconnected Players ({count})', count=count)

    def _rows_per_page_tooltip(self) -> str:
        """Return the localized tooltip for the rows-per-page spinbox."""
        if self._is_connected:
            return (
                tr('Limit how many players are shown per page. Set 0 to show all.')
                if TableMergeState.is_merged()
                else tr('Limit how many connected players are shown per page. Set 0 to show all.')
            )
        return tr('Limit how many disconnected players are shown per page. Set 0 to show all.')

    def _header_label_text(self) -> str:
        selected_session = SessionFilterState.get_selected_session()
        count = max(0, self.last_count)
        if not self._is_connected and 0 < selected_session < SessionTracker.get_current_session_id():
            display_name = SessionTracker.get_session_display_name(selected_session)
            base = tr("Session '{name}' Players ({count})", name=display_name, count=count)
        elif self._is_connected:
            base = tr('Players ({count})', count=count) if TableMergeState.is_merged() else tr('Connected Players ({count})', count=count)
        else:
            base = tr('Disconnected Players ({count})', count=count)

        if self._selected_count > 0:
            return tr_plural(
                '{base} ({count} player selected)',
                '{base} ({count} players selected)',
                self._selected_count,
                base=base,
            )
        return base

    def _update_clear_button_tooltip(self) -> None:
        if self._is_connected:
            is_merged = TableMergeState.is_merged()
            base_tooltip = tr('Clear all players') if is_merged else tr('Clear all connected players')
            shortcut = Settings.shortcut_clear_connected
        else:
            selected_session = SessionFilterState.get_selected_session()
            current_session_id = SessionTracker.get_current_session_id()
            if 0 < selected_session < current_session_id:
                display_name = SessionTracker.get_session_display_name(selected_session)
                base_tooltip = tr("Clear all players from session '{name}'", name=display_name)
            else:
                base_tooltip = tr('Clear all disconnected players')
            shortcut = Settings.shortcut_clear_disconnected
        self._clear_button.setToolTip(f'{base_tooltip} ({shortcut})' if bool(shortcut) else base_tooltip)

    def _update_header_label(self) -> None:
        if not isValid(self._header_label):
            return
        self._header_label.setText(self._header_label_text())
        self._update_clear_button_tooltip()

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
        with QSignalBlocker(self._rows_per_page_spinbox):
            self._rows_per_page_spinbox.setValue(self._rows_per_page)
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
        """Synchronize the section header label and clear button tooltip."""
        self._update_header_label()

    def reset_page_to_first(self) -> None:
        """Reset this section's pagination to the first page."""
        self._current_page = 1
        self._push_pagination_state()

    def set_selected_session_filter(self, session_id: int) -> None:
        """Set the active session filter and update header state."""
        self.reset_page_to_first()
        SessionFilterState.set_selected_session(session_id=session_id)
        self._update_header_label()
        self.session_filter_changed.emit(session_id)

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

        with QSignalBlocker(self._page_spinbox):
            self._page_spinbox.setMinimum(1)
            self._page_spinbox.setMaximum(total_pages)
            self._page_spinbox.setEnabled(0 < rows_per_page < total_rows)
            self._page_spinbox.setValue(page)

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
        self._has_synced_paging = True
        self._last_total_count = total_count

        if not self._rows_keyboard_editing:
            self._rows_per_page_spinbox.setRange(0, 5000)
            if self._rows_per_page_spinbox.value() != self._rows_per_page:
                with QSignalBlocker(self._rows_per_page_spinbox):
                    self._rows_per_page_spinbox.setValue(self._rows_per_page)
            if self._rows_per_page > 0:
                self._rows_per_page_spinbox.setPrefix(f'{total_count} / ')
                self._rows_per_page_spinbox.setSuffix('')
                self._rows_per_page_spinbox.setSpecialValueText('')
            else:
                self._rows_per_page_spinbox.setPrefix('')
                self._rows_per_page_spinbox.setSuffix('')
                self._rows_per_page_spinbox.setSpecialValueText(tr('All ({count})', count=total_count))

        self._current_page, self._total_pages = self._sync_paging_controls(
            total_rows=max(self.last_count, 0),
            rows_per_page=self._rows_per_page,
            requested_page=page,
        )
        if self._current_page != page:
            self._push_pagination_state()

        if not self._rows_keyboard_editing:
            self._page_spinbox.setSuffix(f' / {self._total_pages}')

    def _install_spinbox_input_filter(self, spinbox: QSpinBox) -> None:
        """Attach an event filter that tracks keyboard vs. wheel editing and ignores unfocused wheels."""
        line_edit = spinbox.lineEdit()
        if not line_edit:
            return

        line_edit.setTextMargins(scale_by_ui(9), 0, 0, 0)

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
        self._spinbox_guards.append(guard)

    def set_keyboard_editing(self, *, is_editing: bool) -> None:
        """Set the keyboard editing state for the rows-per-page spinbox."""
        self._rows_keyboard_editing = is_editing

    def _get_highlight_search_column(self) -> int:
        """Return the active search column index for highlighting, or -1 if 'All Columns' or not found."""
        column_name = SearchState.get_column_name()
        if not column_name or column_name == 'All Columns':
            return -1
        try:
            return self.table_model.column_names.index(column_name)
        except ValueError:
            return -1
