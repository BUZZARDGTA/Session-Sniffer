"""Session status bar and collapsible session table section widgets."""
from typing import TYPE_CHECKING, cast

from PyQt6.QtCore import QEvent, QObject, Qt, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QSpinBox,
    QStatusBar,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.guis.stylesheets import (
    COMMON_COLLAPSE_BUTTON_STYLESHEET,
    CONNECTED_CLEAR_BUTTON_STYLESHEET,
    CONNECTED_EXPAND_BUTTON_STYLESHEET,
    CONNECTED_HEADER_CONTAINER_STYLESHEET,
    CONNECTED_HEADER_TEXT_STYLESHEET,
    DISCONNECTED_CLEAR_BUTTON_STYLESHEET,
    DISCONNECTED_EXPAND_BUTTON_STYLESHEET,
    DISCONNECTED_HEADER_CONTAINER_STYLESHEET,
    DISCONNECTED_HEADER_TEXT_STYLESHEET,
    STATUS_BAR_CAPTURE_LABEL_STYLESHEET,
    STATUS_BAR_CONFIG_LABEL_STYLESHEET,
    STATUS_BAR_ISSUES_LABEL_STYLESHEET,
    STATUS_BAR_PERFORMANCE_LABEL_STYLESHEET,
    STATUS_BAR_STYLESHEET,
)
from session_sniffer.guis.table_model import SessionTableModel
from session_sniffer.guis.tables import SessionTableView
from session_sniffer.rendering_core.types import PaginationState
from session_sniffer.settings import Settings

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

    section_toggled = pyqtSignal()
    table_model: SessionTableModel
    table_view: SessionTableView

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

        self._is_connected = is_connected
        self._rows_keyboard_editing = False

        if is_connected:
            header_container_stylesheet = CONNECTED_HEADER_CONTAINER_STYLESHEET
            header_text_stylesheet = CONNECTED_HEADER_TEXT_STYLESHEET
            clear_button_stylesheet = CONNECTED_CLEAR_BUTTON_STYLESHEET
            expand_button_stylesheet = CONNECTED_EXPAND_BUTTON_STYLESHEET
            collapse_tooltip = 'Hide the connected players table'
            clear_tooltip = 'Clear all connected players'
            expand_tooltip = 'Show the connected players table'
            sort_column_name = 'Last Rejoin'
            sort_order = Qt.SortOrder.DescendingOrder
        else:
            header_container_stylesheet = DISCONNECTED_HEADER_CONTAINER_STYLESHEET
            header_text_stylesheet = DISCONNECTED_HEADER_TEXT_STYLESHEET
            clear_button_stylesheet = DISCONNECTED_CLEAR_BUTTON_STYLESHEET
            expand_button_stylesheet = DISCONNECTED_EXPAND_BUTTON_STYLESHEET
            collapse_tooltip = 'Hide the disconnected players table'
            clear_tooltip = 'Clear all disconnected players'
            expand_tooltip = 'Show the disconnected players table'
            sort_column_name = 'Last Seen'
            sort_order = Qt.SortOrder.AscendingOrder

        # Header container
        header_container = QWidget()
        header_container.setStyleSheet(header_container_stylesheet)
        header_layout = QHBoxLayout(header_container)
        header_layout.setContentsMargins(0, 0, 0, 0)

        self._header_label = QLabel(self._header_label_text())
        self._header_label.setTextFormat(Qt.TextFormat.RichText)
        self._header_label.setStyleSheet(header_text_stylesheet)
        self._header_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._header_label.setFont(QFont('Courier', 9, QFont.Weight.Bold))

        clear_button = QPushButton('CLEAR')
        clear_button.setToolTip(clear_tooltip)
        clear_button.setStyleSheet(clear_button_stylesheet)
        clear_button.clicked.connect(clear_slot)

        collapse_button = QPushButton('▼')
        collapse_button.setToolTip(collapse_tooltip)
        collapse_button.setStyleSheet(COMMON_COLLAPSE_BUTTON_STYLESHEET)
        collapse_button.clicked.connect(self.minimize)

        header_layout.addWidget(self._header_label, 1)

        # Pagination controls — rows per page
        rows_label = QLabel('Rows:')
        rows_label.setToolTip('Rows per page (0 = show all)')
        header_layout.addWidget(rows_label)

        initial_rpp = (
            Settings.gui_connected_table_rows_per_page
            if is_connected
            else Settings.gui_disconnected_table_rows_per_page
        )

        self._rows_per_page_spinbox = QSpinBox()
        self._rows_per_page_spinbox.setRange(0, 5000)
        self._rows_per_page_spinbox.setSpecialValueText('All')
        self._rows_per_page_spinbox.setSuffix(' rows/page')
        self._rows_per_page_spinbox.setValue(initial_rpp)
        self._rows_per_page_spinbox.setToolTip(
            f'Limit how many {self._section_name.lower()} players are shown per page. Set 0 to show all.',
        )
        self._rows_per_page_spinbox.setKeyboardTracking(False)
        self._rows_per_page_spinbox.valueChanged.connect(self._handle_rows_per_page_changed)
        self._rows_per_page_spinbox.editingFinished.connect(self._finalize_rows_edit)
        header_layout.addWidget(self._rows_per_page_spinbox)
        self._install_spinbox_input_filter(self._rows_per_page_spinbox)

        # Pagination controls — page number
        page_label = QLabel('Page:')
        page_label.setToolTip('Current page when rows are limited.')
        header_layout.addWidget(page_label)

        self._page_spinbox = QSpinBox()
        self._page_spinbox.setRange(1, 1)
        self._page_spinbox.setToolTip('Jump between pages when a row limit is set.')
        self._page_spinbox.setSuffix(' / 1')
        self._page_spinbox.valueChanged.connect(self._handle_page_changed)
        header_layout.addWidget(self._page_spinbox)

        nav_separator = QFrame()
        nav_separator.setFrameShape(QFrame.Shape.VLine)
        nav_separator.setFrameShadow(QFrame.Shadow.Sunken)
        nav_separator.setStyleSheet(
            'background-color: rgba(128,128,128,0.55); max-width: 0.5px; min-width: 0.5px; margin: 30% 14px; height: 18px;',
        )
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

        header_layout.addWidget(clear_button)
        header_layout.addWidget(collapse_button)

        # Table model and view
        self.table_model = SessionTableModel(column_names)
        self.table_view = SessionTableView(
            self.table_model,
            column_names.index(sort_column_name),
            sort_order,
            is_connected_table=is_connected,
        )
        self.table_view.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Custom)
        self.table_view.setup_static_column_resizing()
        self.table_model.view = self.table_view

        # Expand button (shown when section is collapsed; laid out by MainWindow, not this section)
        self.expand_button = QPushButton(f'▲  Show {self._section_name} Players (0)')
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

        self.table_view.selectionModel().selectionChanged.connect(self._on_selection_changed)

    @property
    def _header_widget(self) -> QWidget:
        """The header container widget, accessed via the header label's parent."""
        return cast('QWidget', self._header_label.parentWidget())

    @property
    def is_expanded(self) -> bool:
        """True when the section content (header + table) is visible."""
        return self.isVisible()

    def expand(self) -> None:
        """Show section content and hide the expand button."""
        self.expand_button.setVisible(False)
        self.setVisible(True)
        self.table_model.refresh_view()
        self.section_toggled.emit()

    def minimize(self) -> None:
        """Collapse section to just an expand button."""
        self.setVisible(False)
        self.expand_button.setText(
            f'▲  Show {self._section_name} Players ({max(self.last_count, 0)})',
        )
        self.expand_button.setVisible(True)
        self.section_toggled.emit()

    def update_current_count(self, count: int) -> None:
        """Update the player count, refresh the header, and sync the expand button text."""
        self.last_count = count
        self._update_header_label()
        if not self.is_expanded:
            self.expand_button.setText(
                f'▲  Show {self._section_name} Players ({count})',
            )

    def clear_table(self) -> None:
        """Clear all table data and reset selection count."""
        self.table_model.reset_columns()
        self._selected_count = 0
        self._update_header_label()

    def update_columns(self, column_names: list[str]) -> None:
        """Replace the column set at runtime and reconfigure the view."""
        sort_col_name = 'Last Rejoin' if self._section_name == 'Connected' else 'Last Seen'
        self.table_model.reset_columns(column_names)
        sort_index = column_names.index(sort_col_name)
        header = self.table_view.horizontalHeader()
        header.setSortIndicator(sort_index, header.sortIndicatorOrder())
        self.table_view.setup_static_column_resizing()

    def set_all_enabled(self, *, enabled: bool) -> None:
        """Enable or disable all interactive child widgets."""
        self._header_widget.setEnabled(enabled)
        self.table_view.setEnabled(enabled)
        self.expand_button.setEnabled(enabled)

    def _header_label_text(self) -> str:
        intro = 'Connected players' if self._section_name == 'Connected' else 'Disconnected Players'
        base = f'{intro} ({max(0, self.last_count)})'
        if self._selected_count > 0:
            noun = 'player' if self._selected_count == 1 else 'players'
            return f'{base} ({self._selected_count} {noun} selected)'
        return base

    def _update_header_label(self) -> None:
        self._header_label.setText(self._header_label_text())

    def refresh_selection_count(self) -> None:
        """Recompute the selected-row count and update the header label."""
        self._on_selection_changed()

    def _on_selection_changed(self) -> None:
        self._selected_count = len({idx.row() for idx in self.table_view.selectionModel().selectedIndexes()})
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

    def _handle_page_changed(self, value: int) -> None:
        self._current_page = max(value, 1)
        self._push_pagination_state()
        self._update_header_label()

    def _finalize_rows_edit(self) -> None:
        val = self._rows_per_page_spinbox.value()
        self._handle_rows_per_page_changed(val)
        self._rows_per_page_spinbox.clearFocus()

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
        self._push_pagination_state()

        if not self._rows_keyboard_editing:
            self._page_spinbox.setSuffix(f' / {self._total_pages}')

    def _install_spinbox_input_filter(self, spinbox: QSpinBox) -> None:
        """Attach an event filter that tracks keyboard vs. wheel editing."""
        line_edit = spinbox.lineEdit()
        if line_edit is None:
            return

        section = self

        class _SpinboxInputGuard(QObject):
            def eventFilter(self, a0: QObject | None, a1: QEvent | None) -> bool:  # noqa: N802
                """Track input method to distinguish keyboard edits from wheel/spin changes."""
                _ = a0
                if a1 is None:
                    return False
                et = a1.type()
                if et == QEvent.Type.KeyPress:
                    section.set_keyboard_editing(is_editing=True)
                elif et in (QEvent.Type.FocusOut, QEvent.Type.Hide, QEvent.Type.Wheel):
                    section.set_keyboard_editing(is_editing=False)
                return False

        guard = _SpinboxInputGuard(self)
        spinbox.installEventFilter(guard)
        line_edit.installEventFilter(guard)
        # prevent GC
        self._spinbox_guard = guard

    def set_keyboard_editing(self, *, is_editing: bool) -> None:
        """Set the keyboard editing state for the rows-per-page spinbox."""
        self._rows_keyboard_editing = is_editing
