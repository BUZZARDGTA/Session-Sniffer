"""Utility functions for GUI-related operations.

This module provides helper functions to interact with GUI elements.
"""

from typing import TYPE_CHECKING, override

from PyQt6.QtCore import QByteArray, QPoint, QRectF, Qt
from PyQt6.QtGui import QIcon, QPainter, QPixmap
from PyQt6.QtSvg import QSvgRenderer
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QDialog,
    QHeaderView,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QTableView,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.local import RESOURCES_DIR_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.settings.settings import Settings

from .app import app
from .exceptions import PrimaryScreenNotFoundError, UnsupportedScreenResolutionError

if TYPE_CHECKING:
    from PyQt6.QtGui import QMouseEvent

SPINNER_FRAMES: tuple[str, ...] = ('⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏')

# Screen resolution resizing thresholds and breakpoints
_MIN_SCREEN_HEIGHT_WARNING = 768
_LARGE_WINDOW_MIN_HEIGHT = 500

_BREAKPOINT_2K_WIDTH = 2560
_BREAKPOINT_2K_HEIGHT = 1400
_TARGET_2K_WIDTH = 1400
_TARGET_2K_HEIGHT = 900

_BREAKPOINT_FHD_WIDTH = 1920
_BREAKPOINT_FHD_HEIGHT = 1040
_TARGET_FHD_WIDTH = 1200
_TARGET_FHD_HEIGHT = 720

_BREAKPOINT_HD_WIDTH = 1024
_BREAKPOINT_HD_HEIGHT = 720
_TARGET_HD_WIDTH = 940
_TARGET_HD_HEIGHT = 680

_FALLBACK_MARGIN = 80


class PersistentMenu(QMenu):
    """QMenu that stays open when a checkable action is clicked."""

    @override
    def mouseReleaseEvent(self, a0: QMouseEvent | None) -> None:
        """Prevent auto-closing when a checkable action is triggered."""
        if a0 is None:
            super().mouseReleaseEvent(a0)
            return
        action = self.actionAt(a0.pos())
        if action and action.isCheckable():
            action.trigger()
            a0.accept()
            return
        super().mouseReleaseEvent(a0)


# ---------------------------------------------------------------------------
# Suspend-mode tooltip strings — shared between detections_manager and
# userip_manager_settings_mixin so they stay in sync.
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


def get_screen_size() -> tuple[int, int]:
    """Get the current screen size and validate minimum resolution requirements.

    Returns:
        Screen width and height in pixels.

    Raises:
        PrimaryScreenNotFoundError: If no primary screen is detected.
        UnsupportedScreenResolutionError: If screen resolution is below minimum requirements.
    """
    min_screen_width = 1024
    min_screen_height = 768

    screen = app.primaryScreen()
    if screen is None:
        raise PrimaryScreenNotFoundError

    size = screen.size()
    screen_width = size.width()
    screen_height = size.height()

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
    if screen is not None:
        avail = screen.availableGeometry()
        avail_width = avail.width()
        avail_height = avail.height()
    else:
        avail_width, avail_height = screen_size

    min_size = window.minimumSize()
    pad_width = 40

    # Maximize if minimum size doesn't fit, or if screen height is low and window is relatively large
    if (
        (min_size.width() + pad_width) > avail_width
        or min_size.height() > avail_height
        or (avail_height < _MIN_SCREEN_HEIGHT_WARNING and min_size.height() >= _LARGE_WINDOW_MIN_HEIGHT)
    ):
        window.setWindowState(Qt.WindowState.WindowMaximized)
        window.setProperty('_should_maximize_on_show', value=True)
        return

    # Resize window to fit available geometry based on breakpoints
    if avail_width >= _BREAKPOINT_2K_WIDTH and avail_height >= _BREAKPOINT_2K_HEIGHT:
        window.resize(_TARGET_2K_WIDTH, _TARGET_2K_HEIGHT)
    elif avail_width >= _BREAKPOINT_FHD_WIDTH and avail_height >= _BREAKPOINT_FHD_HEIGHT:
        window.resize(_TARGET_FHD_WIDTH, _TARGET_FHD_HEIGHT)
    elif avail_width >= _BREAKPOINT_HD_WIDTH and avail_height >= _BREAKPOINT_HD_HEIGHT:
        window.resize(_TARGET_HD_WIDTH, _TARGET_HD_HEIGHT)
    else:
        # Fallback: resize to fit available geometry comfortably without going below minimum size
        w = min(avail_width - _FALLBACK_MARGIN, _TARGET_HD_WIDTH)
        h = min(avail_height - _FALLBACK_MARGIN, _TARGET_HD_HEIGHT)
        window.resize(max(w, min_size.width()), max(h, min_size.height()))


def compute_ui_scale(screen_size: tuple[int, int]) -> float:
    """Return a UI scale factor for the given screen resolution.

    Uses the same breakpoints as `resize_window_for_screen` so that window
    dimensions and element sizes stay in sync.  2560x1440 is the design
    baseline (scale 1.0); smaller screens receive proportionally reduced values.

    Args:
        screen_size: Screen dimensions as (width, height) in pixels.

    Returns:
        A float in the range [0.65, 1.00].
    """
    if screen_size >= (2560, 1440):
        return 1.00
    if screen_size >= (1920, 1080):
        return 0.80
    if screen_size >= (1280, 800):
        return 0.70
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
        val = self.data(Qt.ItemDataRole.UserRole)
        if isinstance(val, (int, float)):
            return float(val)
        try:
            return float(self.text())
        except ValueError:
            return None

    @override
    def __lt__(self, other: QTableWidgetItem) -> bool:
        """Compare numerically using UserRole data if available, falling back to text then string comparison."""
        self_val = self.numeric_value()
        other_raw = other.data(Qt.ItemDataRole.UserRole)
        if isinstance(other_raw, (int, float)):
            other_val: float | None = float(other_raw)
        else:
            try:
                other_val = float(other.text())
            except ValueError:
                other_val = None
        if self_val is not None and other_val is not None:
            return self_val < other_val
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

    def add_always_on_top_checkbox(self, layout: QVBoxLayout, *, always_on_top: bool) -> None:
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


def apply_always_on_top(window: QWidget, checked: bool) -> None:  # noqa: FBT001
    """Apply or remove the always-on-top window flag and re-show the window."""
    if checked:
        window.setWindowFlags(window.windowFlags() | Qt.WindowType.WindowStaysOnTopHint)
    else:
        window.setWindowFlags(window.windowFlags() & ~Qt.WindowType.WindowStaysOnTopHint)
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


def setup_table_view_headers(table: QTableView) -> QHeaderView:
    """Hide the vertical header of *table* and return the horizontal header.

    Raises:
        RuntimeError: If either header is None.
    """
    v_header = table.verticalHeader()
    if v_header is None:
        message = 'Failed to get vertical header'
        raise RuntimeError(message)
    v_header.setVisible(False)
    h_header = table.horizontalHeader()
    if h_header is None:
        message = 'Failed to get horizontal header'
        raise RuntimeError(message)
    return h_header


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
    if h_header is None:
        message = 'Failed to get horizontal header'
        raise RuntimeError(message)
    h_header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
    h_header.setStretchLastSection(True)
    table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
    table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
    table.setSortingEnabled(sorting)
    v_header = table.verticalHeader()
    if v_header is None:
        message = 'Failed to get vertical header'
        raise RuntimeError(message)
    v_header.setVisible(False)
    layout.addWidget(table)


def setup_stat_table_with_header(table: QTableWidget, layout: QVBoxLayout, *, sorting: bool = True) -> QHeaderView:
    """Configure *table* and return its horizontal header for further customisation.

    Calls `setup_stat_table` then retrieves the header; raises `RuntimeError` if unavailable.
    """
    setup_stat_table(table, layout, sorting=sorting)
    h_header = table.horizontalHeader()
    if h_header is None:
        message = 'Failed to get horizontal header'
        raise RuntimeError(message)
    return h_header


def popup_menu_at_table(menu: QMenu, table: QTableView, pos: QPoint) -> None:
    """Pop up *menu* at the viewport-relative position *pos* of *table*.

    Raises `RuntimeError` if the table viewport cannot be obtained.
    """
    viewport = table.viewport()
    if viewport is None:
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
    if action is None:
        return

    def _update(text: str) -> None:
        action.setIcon(clear_icon if text else search_icon)

    action.triggered.connect(line_edit.clear)
    line_edit.textChanged.connect(_update)


def make_padded_icon(source: QIcon, icon_size: tuple[int, int], right_padding: int) -> QIcon:
    """Return a QIcon with `right_padding` transparent pixels appended to the right of *source*.

    Used to add space between a button's icon and its text label, since
    PyQt6 no longer exposes `PM_ButtonIconSpacing`.
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
    if screen is None:
        return
    geo = screen.availableGeometry()
    x = geo.x() + (geo.width() - window.width()) // 2
    y = geo.y() + (geo.height() - window.height()) // 2
    window.move(x, y)


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
