"""Utility functions for GUI-related operations."""

import os
import sys
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import TYPE_CHECKING, cast, override

from PySide6.QtCore import QByteArray, QFileInfo, QModelIndex, QPoint, QRectF, Qt, QTimer, QUrl
from PySide6.QtGui import QAction, QDesktopServices, QIcon, QPainter, QPixmap
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

from session_sniffer.guis.delegates import ElidedTextTooltipDelegate
from session_sniffer.guis.live_language import register_language_refresh, set_i18n_colon_label
from session_sniffer.guis.stylesheets import SVG_ICON_CONTEXT_MENU_STYLESHEET
from session_sniffer.guis.theming import ICONS_DIR_PATH, resolve_canonical_tint_pair, themed_qss, themed_svg, themed_text_qcolor
from session_sniffer.guis.theming._icons import RenderedSvgSpec, lookup_rendered_svg_spec, record_rendered_svg_spec
from session_sniffer.i18n import tr, tr_plural
from session_sniffer.rendering_core.country_flags import get_country_flag
from session_sniffer.settings.settings import Settings

from .app import app
from .exceptions import PrimaryScreenNotFoundError, UnsupportedScreenResolutionError

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from PySide6.QtGui import QMouseEvent, QScreen

SPINNER_FRAMES: tuple[str, ...] = ('⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏')

_MIN_SCREEN_HEIGHT_WARNING = 720
_LARGE_WINDOW_MIN_HEIGHT = 500

_BREAKPOINT_FHD_WIDTH = 1920
_BREAKPOINT_FHD_HEIGHT = 1000
_BREAKPOINT_HD_WIDTH = 1024
_BREAKPOINT_HD_HEIGHT = 660
_TARGET_HD_WIDTH = 860
_TARGET_HD_HEIGHT = 620

# Breakpoints ordered high-to-low: min width, min height, target width, target height, UI scale.
_SCREEN_BREAKPOINTS: tuple[tuple[int, int, int, int, float], ...] = (
    (3200, 1700, 1500, 940, 1.15),  # 4K (3840x2160 @ 100%)
    (2560, 1350, 1300, 820, 1.00),  # 2K / QHD (2560x1440 @ 100%, 4K @ 125%/150%)
    (2048, 1080, 1200, 740, 0.92),  # QHD @ 125% (2048x1152 logical)
    (_BREAKPOINT_FHD_WIDTH, _BREAKPOINT_FHD_HEIGHT, 1100, 660, 0.85),  # FHD (1920x1080 @ 100%)
    (1440, 790, 1000, 640, 0.80),  # FHD @ 125% (1536x864), 1600x900, 1440x900
    (_BREAKPOINT_HD_WIDTH, _BREAKPOINT_HD_HEIGHT, _TARGET_HD_WIDTH, _TARGET_HD_HEIGHT, 0.75),  # HD (1366x768, 720p, FHD @ 150%)
)

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


def get_ui_scale() -> float:
    """Return the active UI scale factor."""
    return _UI_STATE.scale


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


def format_menu_usernames(usernames: Sequence[str] | None, *, placeholder: str = '') -> str:
    """Format a sequence of usernames for concise display in a menu item, eliding excess names."""
    if usernames is None or not usernames:
        return placeholder
    max_display = 3
    if len(usernames) <= max_display:
        return ', '.join(usernames)
    remaining_count = len(usernames) - max_display
    return tr_plural('{usernames} (+{count} other)', '{usernames} (+{count} others)', remaining_count, usernames=', '.join(usernames[:max_display]))


def format_player_action_tooltip(base_tooltip: str, usernames: Sequence[str] | None) -> str:
    """Return *base_tooltip* augmented with the full list of usernames if present."""
    if usernames is None or not usernames:
        return base_tooltip
    header_and_names = tr_plural('Username: {usernames}', 'Usernames: {usernames}', len(usernames), usernames=', '.join(usernames))
    return f'{base_tooltip}\n\n{header_and_names}'


def create_section_separator(title: str) -> QWidget:
    """Create a professional section separator with a label centered between two expanding horizontal lines."""
    widget = QWidget()
    layout = QHBoxLayout(widget)
    layout.setContentsMargins(0, 10, 0, 5)
    line_style = themed_qss('background-color: transparent; border-top: 1px solid @border[#3b5064]; border-bottom: 1px solid @background[#11161d];')
    for add_label in (True, False):
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setFrameShadow(QFrame.Shadow.Sunken)
        line.setStyleSheet(line_style)
        layout.addWidget(line, 1)
        if add_label:
            label = QLabel(title)
            label.setStyleSheet(themed_qss('color: @accent[#88c0d0]; font-weight: bold; font-size: 10pt; padding: 0 5px;'))
            layout.addWidget(label)
    return widget


def get_screen_size() -> tuple[int, int]:
    """Get the available logical screen size and validate minimum resolution requirements.

    Validates the minimum resolution against `size()` (full logical monitor
    resolution) so taskbars/docks do not cause false-positive warnings on
    1366x768 or 1024x768 displays, while returning `availableSize()` (which
    excludes the taskbar) so reported dimensions reflect the usable work area.

    Returns:
        Available screen width and height in logical pixels.

    Raises:
        PrimaryScreenNotFoundError: If no primary screen is detected.
        UnsupportedScreenResolutionError: If the logical resolution is below the minimum.
    """
    min_screen_width = 1024
    min_screen_height = 768

    screen = app.primaryScreen()
    if not screen:
        raise PrimaryScreenNotFoundError

    full_size = screen.size()
    if (full_size.width() < min_screen_width or full_size.height() < min_screen_height) and not Settings.gui_ignore_screen_resolution_warning:
        raise UnsupportedScreenResolutionError(full_size.width(), full_size.height(), min_screen_width, min_screen_height)

    available_size = screen.availableSize()
    return available_size.width(), available_size.height()


def _resolve_window_screen(window: QWidget) -> QScreen | None:
    """Return the target QScreen for *window*, preferring its parent or main window's monitor."""
    parent = window.parentWidget()
    if parent is not None:
        return parent.window().screen() or QApplication.primaryScreen()
    if not isinstance(window, QMainWindow) and (main_window := find_main_window()) is not None:
        return main_window.screen() or QApplication.primaryScreen()
    return window.screen() or QApplication.primaryScreen()


_MAXIMIZE_ON_SHOW_PROPERTY = '_should_maximize_on_show'


def set_maximize_on_show(window: QWidget, *, maximize: bool) -> None:
    """Mark whether *window* should be maximized the next time it is shown."""
    window.setProperty(_MAXIMIZE_ON_SHOW_PROPERTY, maximize)


def consume_maximize_on_show(window: QWidget) -> bool:
    """Return whether *window* was marked to be maximized on show, clearing the mark."""
    if window.property(_MAXIMIZE_ON_SHOW_PROPERTY) is not True:
        return False
    set_maximize_on_show(window, maximize=False)
    return True


def resize_window_for_screen(window: QWidget, screen_size: tuple[int, int] | None = None) -> None:
    """Resize a window based on the screen resolution.

    Args:
        window: The window to resize.
        screen_size: Screen dimensions as (width, height) in pixels. Defaults to `get_screen_size()`.
    """
    screen = _resolve_window_screen(window)
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
        set_maximize_on_show(window, maximize=True)
        return

    for bp_width, bp_height, target_width, target_height, _ in _SCREEN_BREAKPOINTS:
        if avail_width >= bp_width and avail_height >= bp_height:
            window.resize(max(target_width, min_size.width()), max(target_height, min_size.height()))
            return

    fallback_width = min(avail_width - _FALLBACK_MARGIN, _TARGET_HD_WIDTH)
    fallback_height = min(avail_height - _FALLBACK_MARGIN, _TARGET_HD_HEIGHT)
    window.resize(max(fallback_width, min_size.width()), max(fallback_height, min_size.height()))


def compute_ui_scale(screen_size: tuple[int, int]) -> float:
    """Return a UI scale factor for the given available screen resolution.

    Uses the same breakpoints as `resize_window_for_screen` so that window
    dimensions and element sizes stay in sync across 4K, 2K/QHD, FHD,
    fractional-DPI (125%/150%), and HD laptop displays.

    Args:
        screen_size: Available screen dimensions as (width, height) in logical pixels.

    Returns:
        A float in the range [0.65, 1.15].
    """
    for bp_width, bp_height, _, _, scale in _SCREEN_BREAKPOINTS:
        if screen_size[0] >= bp_width and screen_size[1] >= bp_height:
            return scale
    return 0.65  # ≥ 1024x768 (minimum supported resolution)

# ---------------------------------------------------------------------------
# Shared GUI helpers
# ---------------------------------------------------------------------------


class NumericTableWidgetItem(QTableWidgetItem):
    """QTableWidgetItem that sorts numerically."""

    def __init__(
        self,
        value: float | str,
        *,
        sort_value: float | None = None,
        align: Qt.AlignmentFlag | None = None,
    ) -> None:
        """Create an item displaying *str(value)*; store numeric values as UserRole data for sorting."""
        super().__init__(str(value))
        if sort_value is not None:
            self.setData(Qt.ItemDataRole.UserRole, sort_value)
        elif isinstance(value, (int, float)):
            self.setData(Qt.ItemDataRole.UserRole, value)
        if align is not None:
            self.setTextAlignment(align)

    @staticmethod
    def _extract_numeric_value(item: QTableWidgetItem) -> float | None:
        """Return *item*'s value as a float for sorting, or `None` if it cannot be parsed as a number."""
        stored_value = item.data(Qt.ItemDataRole.UserRole)
        if isinstance(stored_value, (int, float)):
            return float(stored_value)
        try:
            return float(item.text())
        except ValueError:
            return None

    @override
    def __lt__(self, other: QTableWidgetItem) -> bool:
        """Compare numerically using UserRole data if available, falling back to text then string comparison."""
        self_numeric_value = self._extract_numeric_value(self)
        other_numeric_value = self._extract_numeric_value(other)
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

    def add_always_on_top_checkbox(
        self,
        layout: QBoxLayout,
        *,
        always_on_top: bool,
        alignment: Qt.AlignmentFlag | None = None,
    ) -> None:
        """Create and add the standard 'Always on Top' checkbox to *layout*."""
        checkbox = QCheckBox()
        checkbox.setChecked(always_on_top)
        checkbox.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        checkbox.toggled.connect(self.toggle_always_on_top)

        def _apply_translations() -> None:
            checkbox.setText(tr('Always on Top'))
            checkbox.setToolTip(tr('Keep this window visible on top of all other applications and games.'))

        _apply_translations()
        register_language_refresh(checkbox, _apply_translations)

        if alignment is not None:
            layout.addWidget(checkbox, alignment=alignment)
        else:
            layout.addWidget(checkbox)

    def toggle_always_on_top(self, *, checked: bool | None = None) -> None:
        """Apply or remove the always-on-top window flag based on *checked*."""
        if checked is None:
            sender = self.sender()
            checked = sender.isChecked() if isinstance(sender, (QCheckBox, QAction)) else not bool(self.windowFlags() & Qt.WindowType.WindowStaysOnTopHint)
        apply_always_on_top(self, checked=checked)


class RateGraphWindowMixin(ToggleAlwaysOnTopMixin):
    """Mixin for graph windows providing a unified bottom control bar."""

    def add_rate_graph_controls(
        self, layout: QBoxLayout, history_options: dict[str, int], *, default_history: int = 3600, margins: tuple[int, int, int, int] = (8, 6, 8, 8),
    ) -> None:
        """Add the bottom controls bar (Always on Top, optional window controls, Max History)."""
        controls_layout = QHBoxLayout()
        controls_layout.setContentsMargins(*margins)
        controls_layout.setSpacing(scale_by_ui(8))
        self.add_always_on_top_checkbox(controls_layout, always_on_top=True)
        for extra_widget in self._create_extra_rate_graph_controls():
            controls_layout.addSpacing(scale_by_ui(4))
            controls_layout.addWidget(extra_widget)

        controls_layout.addStretch()

        max_history_label = QLabel()
        set_i18n_colon_label(max_history_label, 'Max History')
        controls_layout.addWidget(max_history_label)
        history_combo = QComboBox()
        history_combo.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        for text, seconds in history_options.items():
            history_combo.addItem(tr(text), seconds)
        if (default_index := history_combo.findData(default_history)) >= 0:
            history_combo.setCurrentIndex(default_index)

        def on_history_changed(index: int) -> None:
            self._on_max_history_changed(int(history_combo.itemData(index)))

        history_combo.currentIndexChanged.connect(on_history_changed)
        controls_layout.addWidget(history_combo)

        def _refresh_history_combo() -> None:
            for i, canonical_text in enumerate(history_options):
                if i < history_combo.count():
                    history_combo.setItemText(i, tr(canonical_text))

        register_language_refresh(history_combo, _refresh_history_combo)

        layout.addLayout(controls_layout)

    def _create_extra_rate_graph_controls(self) -> list[QWidget]:
        """Override to return extra widgets placed after the 'Always on Top' checkbox."""
        return []

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

    screen = _resolve_window_screen(window)
    if screen is not None:
        avail = screen.availableGeometry()
        avail_width, avail_height = avail.width(), avail.height()
    else:
        avail_width, avail_height = get_screen_size()

    if avail_width >= _BREAKPOINT_FHD_WIDTH and avail_height >= _BREAKPOINT_FHD_HEIGHT:
        window.resize(max(min_w, scale_by_ui(size_1080p[0])), max(min_h, scale_by_ui(size_1080p[1])))
    elif avail_width >= _BREAKPOINT_HD_WIDTH and avail_height >= _BREAKPOINT_HD_HEIGHT:
        window.resize(max(min_w, scale_by_ui(size_720p[0])), max(min_h, scale_by_ui(size_720p[1])))
    else:
        resize_window_for_screen(window, (avail_width, avail_height))
        window.resize(
            min(window.width(), max(min_w, avail_width - _FALLBACK_MARGIN)),
            min(window.height(), max(min_h, avail_height - _FALLBACK_MARGIN)),
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


def create_styled_context_menu(
    parent: QWidget | None = None,
    *,
    title: str = '',
    icon_name: str | None = None,
    persistent: bool = False,
) -> QMenu:
    """Create a context menu or submenu styled with `SVG_ICON_CONTEXT_MENU_STYLESHEET` and visible tooltips."""
    menu_cls = PersistentMenu if persistent else QMenu
    menu = menu_cls(title, parent) if title else menu_cls(parent)
    if icon_name is not None:
        menu.setIcon(QIcon(str(ICONS_DIR_PATH / icon_name)))
    menu.setStyleSheet(SVG_ICON_CONTEXT_MENU_STYLESHEET)
    menu.setToolTipsVisible(True)
    return menu


def add_icon_menu_action(
    menu: QMenu,
    icon_name: str,
    text: str,
    callback: Callable[[], object] | None = None,
    *,
    tooltip: str = '',
) -> QAction:
    """Create a `QAction` with an icon from `resources/icons/`, attach it to *menu*, and return it."""
    action = QAction(QIcon(str(ICONS_DIR_PATH / icon_name)), text, menu)
    if tooltip:
        action.setToolTip(tooltip)
    if callback is not None:
        action.triggered.connect(callback)
    menu.addAction(action)
    return action


def popup_menu_at_table(menu: QMenu, table: QTableView, pos: QPoint) -> None:
    """Pop up *menu* at the viewport-relative position *pos* of *table*.

    Raises `RuntimeError` if the table viewport cannot be obtained.
    """
    viewport = table.viewport()
    if not viewport:
        message = 'Failed to get table viewport'
        raise RuntimeError(message)
    menu.popup(viewport.mapToGlobal(pos))


def _format_selected_indexes_tsv(
    selected_indexes: Sequence[QModelIndex],
    *,
    skip_column: Callable[[int], bool] | None = None,
) -> list[str]:
    """Group `QModelIndex` items by `(row, column)` and return tab-separated lines ordered by row and column."""
    rows: dict[int, dict[int, str]] = {}
    for item_index in selected_indexes:
        column = item_index.column()
        if skip_column is not None and skip_column(column):
            continue
        cell_data = item_index.data(Qt.ItemDataRole.DisplayRole)
        rows.setdefault(item_index.row(), {})[column] = str(cell_data) if cell_data is not None else ''
    return ['\t'.join(rows[row][column] for column in sorted(rows[row])) for row in sorted(rows)]


def copy_table_selection(table: QTableView | QTreeView) -> None:
    """Copy the selected rows from *table* to the system clipboard as tab-separated values."""
    selection_model = table.selectionModel()
    if not selection_model or not (selected_indexes := selection_model.selectedIndexes()):
        return
    if lines := _format_selected_indexes_tsv(selected_indexes, skip_column=table.isColumnHidden):
        set_clipboard_text('\n'.join(lines))


def copy_table_all_rows(table: QTableView | QTreeView) -> None:
    """Copy all rows from *table* model to the system clipboard as tab-separated values."""
    model = table.model()
    if not model:
        return
    column_count = model.columnCount()
    row_count = model.rowCount()
    lines: list[str] = []
    for row_index in range(row_count):
        cells = [
            str(cell_data) if (cell_data := model.data(model.index(row_index, column_index), Qt.ItemDataRole.DisplayRole)) is not None else ''
            for column_index in range(column_count)
            if not table.isColumnHidden(column_index)
        ]
        lines.append('\t'.join(cells))
    if lines:
        set_clipboard_text('\n'.join(lines))


def copy_table_cells(table: QAbstractItemView) -> None:
    """Copy selected cells from *table* to the clipboard."""
    selection_model = table.selectionModel()
    if not selection_model or not (selected_indexes := selection_model.selectedIndexes()):
        return
    if len(selected_indexes) == 1:
        cell_data = selected_indexes[0].data(Qt.ItemDataRole.DisplayRole)
        set_clipboard_text(str(cell_data) if cell_data is not None else '')
        return
    if len({index.column() for index in selected_indexes}) == 1:
        sorted_indexes = sorted(selected_indexes, key=lambda item_index: item_index.row())
        set_clipboard_text('\n'.join(str(item_index.data(Qt.ItemDataRole.DisplayRole) or '') for item_index in sorted_indexes))
        return
    set_clipboard_text('\n'.join(_format_selected_indexes_tsv(selected_indexes)))


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
    feedback_text: str | None = None,
    feedback_tooltip: str | None = None,
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

    resolved_feedback_text = tr('Copied!') if feedback_text is None else feedback_text
    resolved_feedback_tooltip = tr('Copied to clipboard!') if feedback_tooltip is None else feedback_tooltip
    orig_text = str(button.property('_feedback_orig_text') or '')
    prefix = ' ' if orig_text.startswith(' ') else ''
    display_text = f'{prefix}{resolved_feedback_text.lstrip()}'

    button.setMinimumWidth(max(button.minimumWidth(), button.width()))
    button.setText(display_text)
    button.setIcon(QIcon(str(ICONS_DIR_PATH / 'check.svg')))
    button.setToolTip(resolved_feedback_tooltip)

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
    timer.start(1500)


_RAW_SEARCH_ICON_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16"><g opacity="0.65">'
    '<circle cx="6.5" cy="6.5" r="4" fill="none" stroke="white" stroke-width="1.5"/>'
    '<line x1="9.5" y1="9.5" x2="13.5" y2="13.5" stroke="white" stroke-width="1.5" stroke-linecap="round"/></g></svg>'
)
_RAW_CLEAR_ICON_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16"><g opacity="0.65">'
    '<line x1="4" y1="4" x2="12" y2="12" stroke="white" stroke-width="1.5" stroke-linecap="round"/>'
    '<line x1="12" y1="4" x2="4" y2="12" stroke="white" stroke-width="1.5" stroke-linecap="round"/></g></svg>'
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
    icons = [_svg_to_icon(themed_svg(_RAW_SEARCH_ICON_SVG).encode('utf-8')), _svg_to_icon(themed_svg(_RAW_CLEAR_ICON_SVG).encode('utf-8'))]
    action = line_edit.addAction(icons[0], QLineEdit.ActionPosition.TrailingPosition)
    if not action:
        return

    def _update(text: str) -> None:
        action.setIcon(icons[1] if text else icons[0])

    def _refresh_theme() -> None:
        icons[0] = _svg_to_icon(themed_svg(_RAW_SEARCH_ICON_SVG).encode('utf-8'))
        icons[1] = _svg_to_icon(themed_svg(_RAW_CLEAR_ICON_SVG).encode('utf-8'))
        _update(line_edit.text())

    line_edit.setProperty('_ss_refresh_search_icon', _refresh_theme)
    action.triggered.connect(line_edit.clear)
    line_edit.textChanged.connect(_update)


def make_padded_icon(source: QIcon, icon_size: tuple[int, int], right_padding: int) -> QIcon:
    """Return a QIcon with `right_padding` transparent pixels appended to the right of *source* (button icon spacing)."""
    width, height = icon_size
    source_spec = lookup_rendered_svg_spec(source.pixmap(width, height))
    pixmap = QPixmap(width + right_padding, height)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    try:
        source.paint(painter, 0, 0, width, height)
    finally:
        painter.end()
    if source_spec is not None:
        record_rendered_svg_spec(pixmap, RenderedSvgSpec(source_spec.filename, width, height, source_spec.tint_pair, right_padding))
    return QIcon(pixmap)


def render_svg_pixmap_with_pair(filename: str, width: int, height: int, tint_pair: tuple[str, str] | None) -> QPixmap:
    """Render an SVG icon from `ICONS_DIR_PATH` with an optional canonical `(fg, bg)` tint pair."""
    renderer = QSvgRenderer(str(ICONS_DIR_PATH / filename))
    pixmap = QPixmap(width, height)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    try:
        painter.setRenderHints(QPainter.RenderHint.Antialiasing | QPainter.RenderHint.SmoothPixmapTransform)
        renderer.render(painter, QRectF(0, 0, width, height))
        if tint_pair is not None:
            painter.setCompositionMode(QPainter.CompositionMode.CompositionMode_SourceIn)
            painter.fillRect(pixmap.rect(), themed_text_qcolor(tint_pair[0], tint_pair[1]))
    finally:
        painter.end()
    record_rendered_svg_spec(pixmap, RenderedSvgSpec(filename, width, height, tint_pair))
    return pixmap


def render_svg_pixmap_from_resource(filename: str, width: int, height: int, tint_color: str | None = None) -> QPixmap:
    """Render an SVG icon from `resources/icons/` to a transparent QPixmap with smooth scaling and optional tint color."""
    return render_svg_pixmap_with_pair(filename, width, height, resolve_canonical_tint_pair(tint_color) if tint_color is not None else None)


def render_svg_icon_from_resource(filename: str, width: int, height: int, tint_color: str | None = None) -> QIcon:
    """Render an SVG icon from `resources/icons/` to a QIcon with optional tint color."""
    return QIcon(render_svg_pixmap_from_resource(filename, width, height, tint_color))


def center_window_on_screen(window: QWidget) -> None:
    """Center *window* on its target screen (preferring parent/main window screen, or primary screen as fallback)."""
    screen = _resolve_window_screen(window)
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
        return tr('{hours}h {minutes}m {seconds}s', hours=hours, minutes=minutes, seconds=seconds)
    if minutes:
        return tr('{minutes}m {seconds}s', minutes=minutes, seconds=seconds)
    return tr('{seconds}s', seconds=seconds)


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


def open_file_location(file_path: Path) -> None:
    """Open the containing folder and select the file in the file manager."""
    if file_path.is_file():
        if sys.platform == 'win32':
            explorer_exe = Path(os.getenv('WINDIR', r'C:\Windows')) / 'explorer.exe'
            if explorer_exe.is_file():
                os.startfile(str(explorer_exe), arguments=f'/select,"{file_path}"')
                return
        if file_path.parent.exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(file_path.parent)))
            return

    if file_path.is_dir():
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(file_path)))
    elif file_path.parent.exists():
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(file_path.parent)))
