"""Utility functions for GUI-related operations."""

from contextlib import contextmanager
from dataclasses import dataclass
from functools import cache
from typing import TYPE_CHECKING, cast, override

from PySide6.QtCore import QByteArray, QFileInfo, QPoint, QRectF, Qt, QTimer
from PySide6.QtGui import (
    QColor,
    QIcon,
    QPainter,
    QPixmap,
)
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QBoxLayout,
    QCheckBox,
    QComboBox,
    QDialog,
    QFileIconProvider,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QPushButton,
    QTableView,
    QTableWidget,
    QTableWidgetItem,
    QTreeView,
    QVBoxLayout,
    QWidget,
)
from shiboken6 import isValid

from session_sniffer.constants.local import RESOURCES_DIR_PATH
from session_sniffer.guis.delegates import ElidedTextTooltipDelegate
from session_sniffer.rendering_core.country_flags import get_country_flag
from session_sniffer.settings.settings import Settings

from .app import app
from .exceptions import PrimaryScreenNotFoundError, UnsupportedScreenResolutionError

if TYPE_CHECKING:
    from collections.abc import Callable, Generator

    from PySide6.QtGui import QMouseEvent

SPINNER_FRAMES: tuple[str, ...] = ('⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏')

_MIN_SCREEN_HEIGHT_WARNING = 768
_LARGE_WINDOW_MIN_HEIGHT = 500

_BREAKPOINT_2K_WIDTH = 2560
_BREAKPOINT_2K_HEIGHT = 1350
_TARGET_2K_WIDTH = 1300
_TARGET_2K_HEIGHT = 820

_BREAKPOINT_FHD_WIDTH = 1920
_BREAKPOINT_FHD_HEIGHT = 1000
_TARGET_FHD_WIDTH = 1100
_TARGET_FHD_HEIGHT = 660

_BREAKPOINT_HD_WIDTH = 1024
_BREAKPOINT_HD_HEIGHT = 720
_TARGET_HD_WIDTH = 860
_TARGET_HD_HEIGHT = 620

_FALLBACK_MARGIN = 80


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


def resize_window_for_screen(window: QWidget, screen_size: tuple[int, int] | None = None) -> None:
    """Resize a window based on the screen resolution.

    Args:
        window: The window to resize.
        screen_size: Screen dimensions as (width, height) in pixels. Defaults to `get_screen_size()`.
    """
    screen = window.screen() or QApplication.primaryScreen()
    if screen:
        avail = screen.availableGeometry()
        avail_width = avail.width()
        avail_height = avail.height()
    else:
        avail_width, avail_height = screen_size if screen_size is not None else get_screen_size()

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
    if screen_size[0] >= _BREAKPOINT_2K_WIDTH and screen_size[1] >= _BREAKPOINT_2K_HEIGHT:
        return 1.00
    if screen_size[0] >= _BREAKPOINT_FHD_WIDTH and screen_size[1] >= _BREAKPOINT_FHD_HEIGHT:
        return 0.85
    if screen_size[0] >= _BREAKPOINT_HD_WIDTH and screen_size[1] >= _BREAKPOINT_HD_HEIGHT:
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
        """Set window flags, WA_DeleteOnClose, and return a configured QVBoxLayout."""
        self.setWindowFlag(Qt.WindowType.Window)
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
        checkbox.setToolTip('Keep this window visible on top of all other applications and games.')
        checkbox.setChecked(always_on_top)
        checkbox.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        checkbox.toggled.connect(self.toggle_always_on_top)
        layout.addWidget(checkbox)

    def toggle_always_on_top(self, checked: bool) -> None:  # noqa: FBT001
        """Apply or remove the always-on-top window flag based on *checked*."""
        apply_always_on_top(self, checked=checked)


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


def apply_always_on_top(window: QWidget, *, checked: bool) -> None:
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
    dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
    window_flags = Qt.WindowType.Window | Qt.WindowType.WindowCloseButtonHint | Qt.WindowType.WindowMinimizeButtonHint | Qt.WindowType.WindowMaximizeButtonHint
    if keep_on_top:
        window_flags |= Qt.WindowType.WindowStaysOnTopHint
    dialog.setWindowFlags(window_flags)


def activate_window(widget: QWidget) -> None:
    """Restore if minimized, raise, and activate *widget*."""
    if not isValid(widget):
        return
    if widget.isMinimized():
        widget.showNormal()
    else:
        widget.show()
    widget.raise_()
    widget.activateWindow()


def apply_adaptive_window_size(
    window: QWidget,
    *,
    min_size: tuple[int, int],
    size_1080p: tuple[int, int],
    size_720p: tuple[int, int],
) -> None:
    """Apply a scaled minimum size and an adaptive resize based on the available screen resolution."""
    min_w = scale_by_ui(min_size[0])
    min_h = scale_by_ui(min_size[1])
    window.setMinimumSize(min_w, min_h)

    screen_size = get_screen_size()
    if screen_size >= (1920, 1080):
        window.resize(scale_by_ui(size_1080p[0]), scale_by_ui(size_1080p[1]))
    elif screen_size >= (1280, 720):
        window.resize(scale_by_ui(size_720p[0]), scale_by_ui(size_720p[1]))
    else:
        resize_window_for_screen(window, screen_size)
        window.resize(
            min(window.width(), max(min_w, screen_size[0] - 80)),
            min(window.height(), max(min_h, screen_size[1] - 80)),
        )


def show_or_focus_window[T: QWidget](
    owner: object,
    attr_name: str,
    factory: Callable[[], T],
    *,
    show_fn: Callable[[T], None] = activate_window,
) -> T:
    """Focus an existing window referenced by `getattr(owner, attr_name)`, or instantiate, track, and show a new one."""
    current = getattr(owner, attr_name, None)
    if current is not None:
        if isValid(current):
            activate_window(current)
            return cast('T', current)
        setattr(owner, attr_name, None)

    window = factory()
    window.destroyed.connect(lambda: setattr(owner, attr_name, None) if getattr(owner, attr_name, None) is window else None)
    setattr(owner, attr_name, window)
    show_fn(window)
    return window


class ActiveDialogRegistry[K, V: QWidget]:
    """Registry retaining open secondary dialogs by key and focusing existing instances."""

    def __init__(self) -> None:
        """Initialize an empty dialog registry."""
        self._dialogs: dict[K, V] = {}

    def get(self, key: K) -> V | None:
        """Return the active dialog for *key*, if one exists and is valid."""
        existing = self._dialogs.get(key)
        if existing is not None:
            if not isValid(existing):
                self._dialogs.pop(key, None)
                return None
            return existing
        return None

    def focus(self, key: K) -> bool:
        """Focus the active dialog for *key* if one exists. Return True if focused, False otherwise."""
        existing = self.get(key)
        if existing is not None:
            activate_window(existing)
            return True
        return False

    def close_all(self) -> None:
        """Close all tracked dialogs."""
        for dialog in list(self._dialogs.values()):
            if isValid(dialog):
                dialog.close()
        self._dialogs.clear()

    def show_or_focus(self, key: K, factory: Callable[[], V]) -> V:
        """Focus the active dialog for *key*, or instantiate, retain, and show a new one."""
        existing = self.get(key)
        if existing is not None:
            activate_window(existing)
            return existing

        dialog = factory()
        dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self._dialogs[key] = dialog
        dialog.destroyed.connect(lambda: self._dialogs.pop(key, None))
        activate_window(dialog)
        return dialog


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


def find_main_window() -> QMainWindow | None:
    """Return the first visible top-level QMainWindow, or None."""
    return next(
        (widget for widget in QApplication.topLevelWidgets() if isinstance(widget, QMainWindow) and widget.isVisible()),
        None,
    )


def setup_stat_table(table: QTableWidget, layout: QVBoxLayout, *, sorting: bool = True) -> None:
    """Configure *table* with standard stat-window settings and add it to *layout*.

    Raises:
        RuntimeError: If either header is None.
    """
    h_header = table.horizontalHeader()
    if not h_header:
        message = 'Failed to get horizontal header'
        raise RuntimeError(message)
    h_header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
    h_header.setStretchLastSection(False)
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


def copy_table_selection(table: QTableView | QTreeView) -> None:
    """Copy the selected rows from *table* to the system clipboard as tab-separated values.

    Each selected row is collected once (deduplication by row index) and its columns are
    joined with a tab character. Hidden columns are excluded. Rows are separated by newlines
    so the result pastes cleanly into spreadsheets and plain-text editors alike.
    """
    selection_model = table.selectionModel()
    if not selection_model:
        return
    selected_indexes = selection_model.selectedIndexes()
    if not selected_indexes:
        return

    rows: dict[int, dict[int, str]] = {}
    for model_index in selected_indexes:
        column = model_index.column()
        if table.isColumnHidden(column):
            continue
        row = model_index.row()
        cell_data = model_index.data(Qt.ItemDataRole.DisplayRole)
        rows.setdefault(row, {})[column] = str(cell_data) if cell_data is not None else ''

    lines: list[str] = []
    for row in sorted(rows):
        column_map = rows[row]
        lines.append('\t'.join(column_map[column] for column in sorted(column_map)))

    if not lines:
        return

    set_clipboard_text('\n'.join(lines))


def copy_table_all_rows(table: QTableView | QTreeView) -> None:
    """Copy all rows from *table* model to the system clipboard as tab-separated values.

    Hidden columns are excluded. Rows are separated by newlines so the result pastes cleanly
    into spreadsheets and plain-text editors alike.
    """
    model = table.model()
    if not model:
        return
    column_count = model.columnCount()
    row_count = model.rowCount()
    lines: list[str] = []
    for row_index in range(row_count):
        cells: list[str] = []
        for column_index in range(column_count):
            if table.isColumnHidden(column_index):
                continue
            index = model.index(row_index, column_index)
            cell_data = model.data(index, Qt.ItemDataRole.DisplayRole)
            cells.append(str(cell_data) if cell_data is not None else '')
        lines.append('\t'.join(cells))

    if not lines:
        return

    set_clipboard_text('\n'.join(lines))


@contextmanager
def paused_timer(timer: QTimer, interval_ms: int | None = None) -> Generator[None]:
    """Temporarily pause a running QTimer and resume it on exit."""
    was_active = timer.isActive()
    if was_active:
        timer.stop()
    try:
        yield
    finally:
        if was_active:
            if interval_ms is not None:
                timer.start(interval_ms)
            else:
                timer.start()


def copy_table_cells(table: QAbstractItemView) -> None:
    """Copy selected cells from *table* to the clipboard.

    - Single cell: plain text.
    - Single column: newline-separated values.
    - Single row: tab-separated values.
    - Multiple rows and columns: tab-separated rows with newline breaks.
    """
    selection_model = table.selectionModel()
    if not selection_model:
        return
    selected_indexes = selection_model.selectedIndexes()
    if not selected_indexes:
        return

    if len(selected_indexes) == 1:
        cell_data = selected_indexes[0].data(Qt.ItemDataRole.DisplayRole)
        set_clipboard_text(str(cell_data) if cell_data is not None else '')
        return

    columns = {index.column() for index in selected_indexes}
    if len(columns) == 1:
        sorted_indexes = sorted(selected_indexes, key=lambda item_index: item_index.row())
        texts = [str(item_index.data(Qt.ItemDataRole.DisplayRole) or '') for item_index in sorted_indexes]
        set_clipboard_text('\n'.join(texts))
        return

    rows: dict[int, dict[int, str]] = {}
    for index in selected_indexes:
        row = index.row()
        column = index.column()
        cell_data = index.data(Qt.ItemDataRole.DisplayRole)
        rows.setdefault(row, {})[column] = str(cell_data) if cell_data is not None else ''

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


def animate_button_feedback(
    button: QPushButton,
    *,
    feedback_text: str = ' Copied!',
    feedback_tooltip: str = 'Copied to clipboard!',
    duration_milliseconds: int = 1500,
) -> None:
    """Temporarily update a button's icon, text, and tooltip to show confirmation feedback."""
    raw_timer = button.property('_feedback_timer')
    existing_timer = raw_timer if isinstance(raw_timer, QTimer) else None
    if existing_timer is not None and existing_timer.isActive():
        existing_timer.stop()

    if button.property('_feedback_orig_text') is None:
        button.setProperty('_feedback_orig_text', button.text())
        button.setProperty('_feedback_orig_icon', button.icon())
        button.setProperty('_feedback_orig_tooltip', button.toolTip())
        button.setProperty('_feedback_orig_min_width', button.minimumWidth())

    orig_text = str(button.property('_feedback_orig_text') or '')
    prefix = ' ' if orig_text.startswith(' ') else ''
    display_text = f'{prefix}{feedback_text.lstrip()}'

    button.setMinimumWidth(max(button.minimumWidth(), button.width()))
    button.setText(display_text)
    button.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'check.svg')))
    button.setToolTip(feedback_tooltip)

    def _reset() -> None:
        try:
            saved_text = button.property('_feedback_orig_text')
            saved_icon = button.property('_feedback_orig_icon')
            saved_tooltip = button.property('_feedback_orig_tooltip')
            saved_min_width = button.property('_feedback_orig_min_width')

            if saved_text is not None:
                button.setText(str(saved_text))
            if isinstance(saved_icon, QIcon):
                button.setIcon(saved_icon)
            if saved_tooltip is not None:
                button.setToolTip(str(saved_tooltip))
            if isinstance(saved_min_width, int):
                button.setMinimumWidth(saved_min_width)

            button.setProperty('_feedback_orig_text', None)
            button.setProperty('_feedback_orig_icon', None)
            button.setProperty('_feedback_orig_tooltip', None)
            button.setProperty('_feedback_orig_min_width', None)
            button.setProperty('_feedback_timer', None)
        except RuntimeError:
            pass

    timer = QTimer(button)
    timer.setSingleShot(True)
    timer.timeout.connect(_reset)
    button.setProperty('_feedback_timer', timer)
    timer.start(duration_milliseconds)


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
    try:
        renderer.render(painter)
    finally:
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
    try:
        source.paint(painter, 0, 0, width, height)
    finally:
        painter.end()
    return QIcon(pixmap)


def render_svg_pixmap_from_resource(filename: str, width: int, height: int, tint_color: str | None = None) -> QPixmap:
    """Render an SVG icon from `resources/icons/` to a transparent QPixmap with smooth scaling and optional tint color."""
    renderer = QSvgRenderer(str(RESOURCES_DIR_PATH / 'icons' / filename))
    pixmap = QPixmap(width, height)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    try:
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        renderer.render(painter, QRectF(0, 0, width, height))
        if tint_color is not None:
            painter.setCompositionMode(QPainter.CompositionMode.CompositionMode_SourceIn)
            painter.fillRect(pixmap.rect(), QColor(tint_color))
    finally:
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


def load_country_flag_icon(country_code: str) -> QIcon | None:
    """Load and return a cached country flag QIcon."""
    flag = get_country_flag(country_code)
    return flag.icon if flag is not None else None


@cache
def _get_icon_provider() -> QFileIconProvider:
    return QFileIconProvider()


_process_icon_cache: dict[str, QIcon] = {}


def get_process_icon(exe_path: str) -> QIcon:
    """Retrieve and cache the executable icon for a process."""
    provider = _get_icon_provider()
    if not exe_path:
        return provider.icon(QFileIconProvider.IconType.File)

    icon = _process_icon_cache.get(exe_path)
    if icon is not None:
        return icon

    file_info = QFileInfo(exe_path)
    if file_info.exists():
        icon = provider.icon(file_info)
        if icon.isNull():
            icon = provider.icon(QFileIconProvider.IconType.File)
    else:
        icon = provider.icon(QFileIconProvider.IconType.File)

    _process_icon_cache[exe_path] = icon
    return icon
