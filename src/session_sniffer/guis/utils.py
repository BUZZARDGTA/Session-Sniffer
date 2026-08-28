"""Utility functions for GUI-related operations."""

from dataclasses import dataclass
from typing import TYPE_CHECKING, cast, override

from PySide6.QtCore import QByteArray, QEvent, QModelIndex, QPersistentModelIndex, QPoint, QRectF, Qt
from PySide6.QtGui import QBrush, QColor, QFontMetrics, QHelpEvent, QIcon, QLinearGradient, QPainter, QPalette, QPixmap
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QBoxLayout,
    QCheckBox,
    QComboBox,
    QDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QStyle,
    QStyledItemDelegate,
    QStyleOptionViewItem,
    QTableView,
    QTableWidget,
    QTableWidgetItem,
    QToolTip,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.local import RESOURCES_DIR_PATH
from session_sniffer.constants.standalone import FLEXIBLE_STRETCH_COLUMNS, TITLE
from session_sniffer.settings.settings import Settings

from .app import app
from .exceptions import PrimaryScreenNotFoundError, UnsupportedScreenResolutionError

if TYPE_CHECKING:
    from collections.abc import Callable

    from PySide6.QtCore import QRect
    from PySide6.QtGui import QFont, QMouseEvent

SPINNER_FRAMES: tuple[str, ...] = ('⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏')

_MIN_SCREEN_HEIGHT_WARNING = 768
_LARGE_WINDOW_MIN_HEIGHT = 500

_BREAKPOINT_2K_WIDTH = 2560
_BREAKPOINT_2K_HEIGHT = 1400
_TARGET_2K_WIDTH = 1300
_TARGET_2K_HEIGHT = 820

_BREAKPOINT_FHD_WIDTH = 1920
_BREAKPOINT_FHD_HEIGHT = 1040
_TARGET_FHD_WIDTH = 1100
_TARGET_FHD_HEIGHT = 660

_BREAKPOINT_HD_WIDTH = 1024
_BREAKPOINT_HD_HEIGHT = 720
_TARGET_HD_WIDTH = 860
_TARGET_HD_HEIGHT = 620

_FALLBACK_MARGIN = 80

MINIMUM_VIEWPORT_WIDTH_THRESHOLD: int = 100
HEADER_SORT_PADDING: int = 40


# ---------------------------------------------------------------------------
# UI scale — computed once at startup from the available screen resolution.
# Call `initialize_ui_scale` early in main() after `get_screen_size` succeeds.
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class _UIState:
    scale: float = 1.0


_UI_STATE = _UIState()


def initialize_ui_scale(screen_size: tuple[int, int]) -> None:
    """Set the module-level UI scale factor from the given screen resolution.

    Must be called once, early in startup (after `get_screen_size` returns),
    before any dialog or window is constructed.
    """
    _UI_STATE.scale = compute_ui_scale(screen_size)


def scale_by_ui(value: int) -> int:
    """Scale *value* by the current UI scale factor, returning at least 1.

    Use this for every hardcoded pixel dimension (minimum sizes, fixed sizes,
    initial resize values) so the layout shrinks on small/low-DPI screens and
    expands naturally on high-resolution displays.
    """
    return max(1, round(value * _UI_STATE.scale))


class PersistentMenu(QMenu):
    """QMenu that stays open when a checkable action is clicked."""

    @override
    def mouseReleaseEvent(self, a0: QMouseEvent) -> None:
        """Prevent auto-closing when a checkable action is triggered."""
        action = self.actionAt(a0.pos())
        if action and action.isCheckable():
            action.trigger()
            a0.accept()
            return
        super().mouseReleaseEvent(a0)


# ---------------------------------------------------------------------------
# Suspend-mode tooltip strings — shared between detections_manager and
# userip_manager_settings_mixin.
# ---------------------------------------------------------------------------

SUSPEND_TOOLTIP_DISABLED = 'Suspension is disabled — no process will be suspended when this detection triggers.'
SUSPEND_TOOLTIP_AUTO = (
    'Resume when the hostile player fully disconnects.\n'
    '• Robustness: High - game stays frozen until the threat is gone.\n'
    '• Freeze time: Moderate - depends on how long the player stays.'
)
SUSPEND_TOOLTIP_MANUAL = (
    'Suspend for a fixed number of seconds without smart resume behavior.\n• Robustness: High - no idle detection.\n• Freeze time: Fixed - exactly the duration you set.'
)


def format_player_display(ip: str, usernames: list[str]) -> str:
    """Return a human-readable player identifier combining usernames and IP.

    Returns `'username1, username2 (ip)'` when usernames are known,
    or just `'ip'` when no usernames are available.
    """
    if usernames:
        names = ', '.join(usernames)
        return f'{names} ({ip})'
    return ip


def create_section_separator(title: str) -> QWidget:
    """Create a professional section separator with a label centered between two expanding horizontal lines."""
    widget = QWidget()
    layout = QHBoxLayout(widget)
    layout.setContentsMargins(0, 10, 0, 5)

    left_line = QFrame()
    left_line.setFrameShape(QFrame.Shape.HLine)
    left_line.setFrameShadow(QFrame.Shadow.Sunken)
    left_line.setStyleSheet('background-color: transparent; border-top: 1px solid #3b5064; border-bottom: 1px solid #11161d;')
    layout.addWidget(left_line, 1)

    label = QLabel(title)
    label.setStyleSheet('color: #88c0d0; font-weight: bold; font-size: 10pt; padding: 0 5px;')
    layout.addWidget(label)

    right_line = QFrame()
    right_line.setFrameShape(QFrame.Shape.HLine)
    right_line.setFrameShadow(QFrame.Shadow.Sunken)
    right_line.setStyleSheet('background-color: transparent; border-top: 1px solid #3b5064; border-bottom: 1px solid #11161d;')
    layout.addWidget(right_line, 1)

    return widget


def get_screen_size() -> tuple[int, int]:
    """Get the available logical screen size and validate minimum resolution requirements.

    Uses `availableSize()` (which excludes the taskbar) rather than `size()` so
    the reported dimensions reflect the actual usable area.  Qt 6 returns logical
    pixels here — i.e. the physical pixel count already divided by the display's
    device-pixel ratio — so the values are directly comparable to widget sizes
    expressed in logical pixels.

    Returns:
        Available screen width and height in logical pixels.

    Raises:
        PrimaryScreenNotFoundError: If no primary screen is detected.
        UnsupportedScreenResolutionError: If the available resolution is below the minimum.
    """
    min_screen_width = 1024
    min_screen_height = 768

    screen = app.primaryScreen()
    if not screen:
        raise PrimaryScreenNotFoundError

    available_size = screen.availableSize()
    screen_width = available_size.width()
    screen_height = available_size.height()

    if (screen_width < min_screen_width or screen_height < min_screen_height) and not getattr(Settings, 'gui_ignore_screen_resolution_warning', False):
        raise UnsupportedScreenResolutionError(screen_width, screen_height, min_screen_width, min_screen_height)

    return screen_width, screen_height


def resize_window_for_screen(window: QWidget, screen_size: tuple[int, int]) -> None:
    """Resize a window based on the screen resolution.

    Args:
        window: The window to resize.
        screen_size: Screen dimensions as (width, height) in pixels.
    """
    screen = window.screen() or QApplication.primaryScreen()
    if screen:
        avail = screen.availableGeometry()
        avail_width = avail.width()
        avail_height = avail.height()
    else:
        avail_width, avail_height = screen_size

    min_size = window.minimumSize()
    pad_width = 40

    if (
        (min_size.width() + pad_width) > avail_width
        or min_size.height() > avail_height
        or (avail_height < _MIN_SCREEN_HEIGHT_WARNING and min_size.height() >= _LARGE_WINDOW_MIN_HEIGHT)
    ):
        window.setWindowState(Qt.WindowState.WindowMaximized)
        window.setProperty('_should_maximize_on_show', True)  # noqa: FBT003
        return

    if avail_width >= _BREAKPOINT_2K_WIDTH and avail_height >= _BREAKPOINT_2K_HEIGHT:
        window.resize(max(_TARGET_2K_WIDTH, min_size.width()), max(_TARGET_2K_HEIGHT, min_size.height()))
    elif avail_width >= _BREAKPOINT_FHD_WIDTH and avail_height >= _BREAKPOINT_FHD_HEIGHT:
        window.resize(max(_TARGET_FHD_WIDTH, min_size.width()), max(_TARGET_FHD_HEIGHT, min_size.height()))
    elif avail_width >= _BREAKPOINT_HD_WIDTH and avail_height >= _BREAKPOINT_HD_HEIGHT:
        window.resize(max(_TARGET_HD_WIDTH, min_size.width()), max(_TARGET_HD_HEIGHT, min_size.height()))
    else:
        fallback_width = min(avail_width - _FALLBACK_MARGIN, _TARGET_HD_WIDTH)
        fallback_height = min(avail_height - _FALLBACK_MARGIN, _TARGET_HD_HEIGHT)
        window.resize(max(fallback_width, min_size.width()), max(fallback_height, min_size.height()))


def compute_ui_scale(screen_size: tuple[int, int]) -> float:
    """Return a UI scale factor for the given available screen resolution.

    Uses the same breakpoints as `resize_window_for_screen` so that window
    dimensions and element sizes stay in sync.  2560x1440 is the design
    baseline (scale 1.0); smaller screens receive proportionally reduced values.
    1920x1080 (FHD) yields 0.85, which keeps the UI comfortable without feeling
    cramped.  Screens below 1280x800 (common laptops at 1366x768) use 0.70.

    Args:
        screen_size: Available screen dimensions as (width, height) in logical pixels.

    Returns:
        A float in the range [0.65, 1.00].
    """
    if screen_size >= (2560, 1440):
        return 1.00
    if screen_size >= (1920, 1080):
        return 0.85
    if screen_size >= (1280, 800):
        return 0.75
    return 0.65  # ≥ 1024x768 (minimum supported resolution)


# ---------------------------------------------------------------------------
# Shared GUI helpers
# ---------------------------------------------------------------------------


class NumericTableWidgetItem(QTableWidgetItem):
    """QTableWidgetItem that sorts numerically."""

    def __init__(self, value: float | str) -> None:
        """Create an item displaying *str(value)*; store numeric values as UserRole data for sorting."""
        super().__init__(str(value))
        if isinstance(value, (int, float)):
            self.setData(Qt.ItemDataRole.UserRole, value)

    def numeric_value(self) -> float | None:
        """Return the item's value as a float for sorting, or `None` if it cannot be parsed as a number."""
        stored_value = self.data(Qt.ItemDataRole.UserRole)
        if isinstance(stored_value, (int, float)):
            return float(stored_value)
        try:
            return float(self.text())
        except ValueError:
            return None

    @override
    def __lt__(self, other: QTableWidgetItem) -> bool:
        """Compare numerically using UserRole data if available, falling back to text then string comparison."""
        self_numeric_value = self.numeric_value()
        other_raw = other.data(Qt.ItemDataRole.UserRole)
        if isinstance(other_raw, (int, float)):
            other_numeric_value: float | None = float(other_raw)
        else:
            try:
                other_numeric_value = float(other.text())
            except ValueError:
                other_numeric_value = None
        if self_numeric_value is not None and other_numeric_value is not None:
            return self_numeric_value < other_numeric_value
        return super().__lt__(other)


class ToggleAlwaysOnTopMixin(QWidget):
    """Mixin providing an always-on-top toggle and window-layout helpers for QWidget subclasses."""

    def setup_window_layout(
        self,
        *,
        always_on_top: bool,
        margins: tuple[int, int, int, int] = (8, 8, 8, 8),
        spacing: int = 4,
    ) -> QVBoxLayout:
        """Set always-on-top flag, WA_DeleteOnClose, and return a configured QVBoxLayout."""
        if always_on_top:
            self.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(*margins)
        layout.setSpacing(spacing)
        return layout

    def add_always_on_top_checkbox(self, layout: QBoxLayout, *, always_on_top: bool) -> None:
        """Create and add the standard 'Always on Top' checkbox to *layout*."""
        checkbox = QCheckBox('Always on Top')
        checkbox.setToolTip('Keep this window above all other windows.\nThis toggle does not change the saved default.')
        checkbox.setChecked(always_on_top)
        checkbox.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        checkbox.toggled.connect(self.toggle_always_on_top)
        layout.addWidget(checkbox)

    def toggle_always_on_top(self, checked: bool) -> None:  # noqa: FBT001
        """Apply or remove the always-on-top window flag based on *checked*."""
        apply_always_on_top(self, checked)


class RateGraphWindowMixin(ToggleAlwaysOnTopMixin):
    """Mixin for graph windows providing a unified bottom control bar."""

    def add_rate_graph_controls(self, layout: QBoxLayout, history_options: dict[str, int]) -> None:
        """Add the bottom controls bar (Always on Top, Max History)."""
        controls_layout = QHBoxLayout()
        controls_layout.setContentsMargins(8, 6, 8, 8)
        self.add_always_on_top_checkbox(controls_layout, always_on_top=True)

        controls_layout.addStretch()

        controls_layout.addWidget(QLabel('Max History:'))
        history_combo = QComboBox()
        history_combo.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        for text, seconds in history_options.items():
            history_combo.addItem(text, seconds)
        history_combo.setCurrentText('1 Hour')

        def on_history_changed(index: int) -> None:
            self._on_max_history_changed(int(history_combo.itemData(index)))

        history_combo.currentIndexChanged.connect(on_history_changed)
        controls_layout.addWidget(history_combo)

        layout.addLayout(controls_layout)

    def _on_max_history_changed(self, new_max_history: int) -> None:
        """Handle max history changes. Must be overridden by subclasses if add_rate_graph_controls is used."""
        raise NotImplementedError


def apply_always_on_top(window: QWidget, checked: bool) -> None:  # noqa: FBT001
    """Apply or remove the always-on-top window flag, preserving native decorations.

    Uses `setWindowFlag` (single-flag toggle) instead of a full `setWindowFlags`
    rewrite: on Windows the latter destroys and recreates the native HWND, which under
    PySide6 can leave the system menu's Close (X) button rendered as greyed/disabled.
    Only re-show the window if it was already visible, so this never forces an early
    show during `__init__` (the reveal is orchestrated separately in `main.py`).
    """
    was_visible = window.isVisible()
    window.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint, on=checked)
    if was_visible:
        window.show()


def set_dialog_window_flags(dialog: QDialog, *, keep_on_top: bool = False) -> None:
    """Apply the standard non-modal resizable window flags to *dialog*.

    Use *keep_on_top* for transient notification dialogs that must stay above other windows.
    """
    dialog.setWindowModality(Qt.WindowModality.NonModal)
    window_flags = Qt.WindowType.Window | Qt.WindowType.WindowCloseButtonHint | Qt.WindowType.WindowMinimizeButtonHint | Qt.WindowType.WindowMaximizeButtonHint
    if keep_on_top:
        window_flags |= Qt.WindowType.WindowStaysOnTopHint
    dialog.setWindowFlags(window_flags)


class ElidedTextTooltipDelegate(QStyledItemDelegate):
    """Custom delegate that reliably shows a tooltip only if the text is horizontally truncated."""

    @override
    def helpEvent(
        self,
        event: QHelpEvent,
        view: QAbstractItemView,
        option: QStyleOptionViewItem,
        index: QModelIndex | QPersistentModelIndex,
    ) -> bool:
        """Show tooltip for elided cells, let the default handle the rest."""
        if event and event.type() == QEvent.Type.ToolTip:
            if index.data(Qt.ItemDataRole.ToolTipRole):
                return super().helpEvent(event, view, option, index)

            text = index.data(Qt.ItemDataRole.DisplayRole)
            if isinstance(text, str) and text:
                opt = QStyleOptionViewItem(option)
                self.initStyleOption(opt, index)
                if QFontMetrics(cast('QFont', opt.font)).horizontalAdvance(text) > view.visualRect(index).width() - 6:  # type: ignore[redundant-cast]
                    QToolTip.showText(event.globalPos(), text, view)
                    return True

        return super().helpEvent(event, view, option, index)

    @override
    def paint(self, painter: QPainter, option: QStyleOptionViewItem, index: QModelIndex | QPersistentModelIndex) -> None:
        """Paint table cell with hover gradient and preserve custom ForegroundRole/BackgroundRole."""
        if painter:
            is_hovered = bool(option.state & QStyle.StateFlag.State_MouseOver)
            is_selected = bool(option.state & QStyle.StateFlag.State_Selected)

            if is_hovered:
                is_connected: bool | None = None
                view = self.parent()
                if view is not None and hasattr(view, 'is_connected_table'):
                    raw_is_connected = getattr(view, 'is_connected_table', None)
                    if isinstance(raw_is_connected, bool):
                        is_connected = raw_is_connected

                painter.save()
                rect = cast('QRect', option.rect)  # type: ignore[redundant-cast]

                if is_connected is True:
                    grad = QLinearGradient(rect.topLeft(), rect.bottomLeft())
                    if is_selected:
                        grad.setColorAt(0, QColor(42, 110, 85, 160))
                        grad.setColorAt(1, QColor(28, 75, 58, 160))
                    else:
                        grad.setColorAt(0, QColor(42, 110, 85, 100))
                        grad.setColorAt(1, QColor(28, 75, 58, 100))
                elif is_connected is False:
                    grad = QLinearGradient(rect.topLeft(), rect.bottomLeft())
                    if is_selected:
                        grad.setColorAt(0, QColor(130, 45, 45, 160))
                        grad.setColorAt(1, QColor(85, 28, 28, 160))
                    else:
                        grad.setColorAt(0, QColor(130, 45, 45, 100))
                        grad.setColorAt(1, QColor(85, 28, 28, 100))
                else:
                    grad = QLinearGradient(rect.topLeft(), rect.bottomLeft())
                    if is_selected:
                        grad.setColorAt(0, QColor('#2f4f64'))
                        grad.setColorAt(1, QColor('#2f4f64'))
                    else:
                        grad.setColorAt(0, QColor('#2d2d30'))
                        grad.setColorAt(1, QColor('#2d2d30'))

                painter.fillRect(rect, grad)
                painter.restore()
            else:
                bg_brush = index.data(Qt.ItemDataRole.BackgroundRole)
                if isinstance(bg_brush, QBrush) and not is_selected:
                    painter.save()
                    painter.fillRect(cast('QRect', option.rect), bg_brush)  # type: ignore[redundant-cast]
                    painter.restore()

        opt = QStyleOptionViewItem(option)
        self.initStyleOption(opt, index)
        # Clear HasFocus so that global stylesheet focus rules do not force white text onto unselected cells
        opt.state &= ~QStyle.StateFlag.State_HasFocus
        if not bool(opt.state & QStyle.StateFlag.State_Selected):
            fg_brush = index.data(Qt.ItemDataRole.ForegroundRole)
            if isinstance(fg_brush, QBrush):
                opt.palette.setBrush(QPalette.ColorRole.Text, fg_brush)
                opt.palette.setBrush(QPalette.ColorRole.WindowText, fg_brush)
        else:
            opt.palette.setColor(QPalette.ColorRole.Text, QColor('#ffffff'))
            opt.palette.setColor(QPalette.ColorRole.HighlightedText, QColor('#ffffff'))

        super().paint(painter, opt, index)


def setup_table_view_headers(table: QTableView) -> QHeaderView:
    """Hide the vertical header of *table* and return the horizontal header.

    Raises:
        RuntimeError: If either header is None.
    """
    v_header = table.verticalHeader()
    if not v_header:
        message = 'Failed to get vertical header'
        raise RuntimeError(message)
    v_header.setVisible(False)
    h_header = table.horizontalHeader()
    if not h_header:
        message = 'Failed to get horizontal header'
        raise RuntimeError(message)

    table.setItemDelegate(ElidedTextTooltipDelegate(table))
    table.setWordWrap(False)

    return h_header


def setup_static_table_column_resizing(
    table: QTableView,
    compute_base_width: Callable[[QFontMetrics, str], int] | None = None,
) -> None:
    """Set up initial column resizing for a QTableView, fitting columns and distributing extra space to flexible columns."""
    table_model = table.model()
    if not table_model:
        return

    horizontal_header = table.horizontalHeader()
    if not horizontal_header:
        return

    font_metrics = horizontal_header.fontMetrics()
    viewport = table.viewport()
    viewport_width = viewport.width() if viewport and viewport.width() > MINIMUM_VIEWPORT_WIDTH_THRESHOLD else table.width()

    total_base_width = 0
    flex_count = 0

    for column in range(table_model.columnCount()):
        if horizontal_header.isSectionHidden(column):
            continue
        header_label = str(table_model.headerData(column, Qt.Orientation.Horizontal) or '')
        base_width = (
            compute_base_width(font_metrics, header_label)
            if compute_base_width is not None
            else font_metrics.horizontalAdvance(header_label) + HEADER_SORT_PADDING
        )
        total_base_width += base_width
        if header_label in FLEXIBLE_STRETCH_COLUMNS:
            flex_count += 1

    extra_space = max(0, viewport_width - total_base_width)
    extra_per_flex = extra_space // flex_count if flex_count > 0 else 0
    remainder = extra_space % flex_count if flex_count > 0 else 0

    current_flex_index = 0
    for column in range(table_model.columnCount()):
        if horizontal_header.isSectionHidden(column):
            continue
        header_label = str(table_model.headerData(column, Qt.Orientation.Horizontal) or '')
        horizontal_header.setSectionResizeMode(column, QHeaderView.ResizeMode.Interactive)

        base_width = (
            compute_base_width(font_metrics, header_label)
            if compute_base_width is not None
            else font_metrics.horizontalAdvance(header_label) + HEADER_SORT_PADDING
        )

        if header_label in FLEXIBLE_STRETCH_COLUMNS:
            current_flex_index += 1
            add_pixels = extra_per_flex + (remainder if current_flex_index == flex_count else 0)
            final_width = base_width + add_pixels
        else:
            final_width = base_width

        if horizontal_header.sectionSize(column) != final_width:
            horizontal_header.resizeSection(column, final_width)


def find_main_window() -> QMainWindow | None:
    """Return the first visible top-level QMainWindow, or None."""
    return next(
        (widget for widget in QApplication.topLevelWidgets() if isinstance(widget, QMainWindow) and widget.isVisible()),
        None,
    )


def create_nonmodal_warning(parent: QWidget | None, text: str) -> QMessageBox:
    """Create a pre-configured non-modal warning QMessageBox without showing it."""
    dlg = QMessageBox(parent)
    dlg.setWindowModality(Qt.WindowModality.NonModal)
    dlg.setWindowTitle(TITLE)
    dlg.setText(text)
    dlg.setIcon(QMessageBox.Icon.Warning)
    dlg.setStandardButtons(QMessageBox.StandardButton.Ok)
    return dlg


def setup_stat_table(table: QTableWidget, layout: QVBoxLayout, *, sorting: bool = True) -> None:
    """Configure *table* with standard stat-window settings and add it to *layout*.

    Raises:
        RuntimeError: If either header is None.
    """
    h_header = table.horizontalHeader()
    if not h_header:
        message = 'Failed to get horizontal header'
        raise RuntimeError(message)
    h_header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
    h_header.setStretchLastSection(True)
    table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
    table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
    table.setSelectionMode(QTableWidget.SelectionMode.ExtendedSelection)
    table.setSortingEnabled(sorting)
    v_header = table.verticalHeader()
    if not v_header:
        message = 'Failed to get vertical header'
        raise RuntimeError(message)
    v_header.setVisible(False)

    table.setVerticalScrollMode(QTableWidget.ScrollMode.ScrollPerPixel)
    table.setHorizontalScrollMode(QTableWidget.ScrollMode.ScrollPerPixel)
    table.setItemDelegate(ElidedTextTooltipDelegate(table))
    table.setWordWrap(False)

    layout.addWidget(table)


def setup_stat_table_with_header(table: QTableWidget, layout: QVBoxLayout, *, sorting: bool = True) -> QHeaderView:
    """Configure *table* and return its horizontal header for further customisation.

    Calls `setup_stat_table` then retrieves the header; raises `RuntimeError` if unavailable.
    """
    setup_stat_table(table, layout, sorting=sorting)
    h_header = table.horizontalHeader()
    if not h_header:
        message = 'Failed to get horizontal header'
        raise RuntimeError(message)
    return h_header


def popup_menu_at_table(menu: QMenu, table: QTableView, pos: QPoint) -> None:
    """Pop up *menu* at the viewport-relative position *pos* of *table*.

    Raises `RuntimeError` if the table viewport cannot be obtained.
    """
    viewport = table.viewport()
    if not viewport:
        message = 'Failed to get table viewport'
        raise RuntimeError(message)
    menu.popup(viewport.mapToGlobal(pos))


def copy_table_widget_selection(table: QTableWidget) -> None:
    """Copy the selected rows from *table* to the system clipboard as tab-separated values.

    Each selected row is collected once (deduplication by row index) and its columns are
    joined with a tab character. Rows are separated by newlines so the result pastes cleanly
    into spreadsheets and plain-text editors alike.
    """
    selection_model = table.selectionModel()
    if not selection_model:
        return
    selected_indexes = selection_model.selectedIndexes()
    if not selected_indexes:
        return

    rows: dict[int, dict[int, str]] = {}
    for index in selected_indexes:
        row = index.row()
        column = index.column()
        item = table.item(row, column)
        rows.setdefault(row, {})[column] = item.text() if item else ''

    lines: list[str] = []
    for row in sorted(rows):
        column_map = rows[row]
        lines.append('\t'.join(column_map[column] for column in sorted(column_map)))

    set_clipboard_text('\n'.join(lines))


def set_clipboard_text(text: str) -> None:
    """Copy *text* to the system clipboard.

    Raises:
        RuntimeError: If the clipboard instance cannot be obtained.
    """
    clipboard = QApplication.clipboard()
    if not clipboard:
        message = 'Failed to get clipboard'
        raise RuntimeError(message)
    clipboard.setText(text)


def popup_menu_at_table_widget(menu: QMenu, table: QTableWidget, pos: QPoint) -> None:
    """Pop up *menu* at the viewport-relative position *pos* of a `QTableWidget`.

    Raises `RuntimeError` if the table viewport cannot be obtained.
    """
    viewport = table.viewport()
    if not viewport:
        message = 'Failed to get table viewport'
        raise RuntimeError(message)
    menu.popup(viewport.mapToGlobal(pos))


_SEARCH_ICON_SVG = (
    b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16">'
    b'<g opacity="0.65">'
    b'<circle cx="6.5" cy="6.5" r="4" fill="none" stroke="white" stroke-width="1.5"/>'
    b'<line x1="9.5" y1="9.5" x2="13.5" y2="13.5" stroke="white" stroke-width="1.5" stroke-linecap="round"/>'
    b'</g></svg>'
)

_CLEAR_ICON_SVG = (
    b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16">'
    b'<g opacity="0.65">'
    b'<line x1="4" y1="4" x2="12" y2="12" stroke="white" stroke-width="1.5" stroke-linecap="round"/>'
    b'<line x1="12" y1="4" x2="4" y2="12" stroke="white" stroke-width="1.5" stroke-linecap="round"/>'
    b'</g></svg>'
)


def _svg_to_icon(svg: bytes) -> QIcon:
    renderer = QSvgRenderer(QByteArray(svg))
    pixmap = QPixmap(16, 16)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    renderer.render(painter)
    painter.end()
    return QIcon(pixmap)


def apply_search_icon(line_edit: QLineEdit) -> None:
    """Add a trailing icon to *line_edit*: magnifying glass when empty, x to clear when filled."""
    line_edit.setClearButtonEnabled(False)
    search_icon = _svg_to_icon(_SEARCH_ICON_SVG)
    clear_icon = _svg_to_icon(_CLEAR_ICON_SVG)
    action = line_edit.addAction(search_icon, QLineEdit.ActionPosition.TrailingPosition)
    if not action:
        return

    def _update(text: str) -> None:
        action.setIcon(clear_icon if text else search_icon)

    action.triggered.connect(line_edit.clear)
    line_edit.textChanged.connect(_update)


def make_padded_icon(source: QIcon, icon_size: tuple[int, int], right_padding: int) -> QIcon:
    """Return a QIcon with `right_padding` transparent pixels appended to the right of *source*.

    Used to add space between a button's icon and its text label, since
    PySide6 no longer exposes `PM_ButtonIconSpacing`.
    """
    width, height = icon_size
    pixmap = QPixmap(width + right_padding, height)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    source.paint(painter, 0, 0, width, height)
    painter.end()
    return QIcon(pixmap)


def render_svg_pixmap_from_resource(filename: str, width: int, height: int) -> QPixmap:
    """Render an SVG icon from `resources/icons/` to a transparent QPixmap with smooth scaling."""
    renderer = QSvgRenderer(str(RESOURCES_DIR_PATH / 'icons' / filename))
    pixmap = QPixmap(width, height)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
    renderer.render(painter, QRectF(0, 0, width, height))
    painter.end()
    return pixmap


def center_window_on_screen(window: QWidget) -> None:
    """Center *window* on its current screen (or the primary screen as fallback)."""
    screen = window.screen() or QApplication.primaryScreen()
    if not screen:
        return
    available_geometry = screen.availableGeometry()
    x_position = available_geometry.x() + (available_geometry.width() - window.width()) // 2
    y_position = available_geometry.y() + (available_geometry.height() - window.height()) // 2
    window.move(x_position, y_position)


def format_duration(total_seconds: float) -> str:
    """Format a duration in seconds as a human-readable string."""
    duration_seconds = int(total_seconds)
    hours, remaining_seconds = divmod(duration_seconds, 3600)
    minutes, seconds = divmod(remaining_seconds, 60)
    if hours:
        return f'{hours}h {minutes}m {seconds}s'
    if minutes:
        return f'{minutes}m {seconds}s'
    return f'{seconds}s'
