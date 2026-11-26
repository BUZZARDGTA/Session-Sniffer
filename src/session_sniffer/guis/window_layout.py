"""Centralized, multi-monitor-safe window, splitter, and table layout persistence helpers."""

from typing import TYPE_CHECKING, ClassVar, override

from PySide6.QtCore import QByteArray, QPoint, QRect, Qt
from PySide6.QtWidgets import QApplication, QHeaderView, QSplitter, QTableView, QTreeView, QWidget

from session_sniffer.guis.live_language import CANONICAL_HEADER_ROLE
from session_sniffer.guis.utils import (
    RateGraphWindowMixin,
    center_window_on_screen,
    consume_maximize_on_show,
    is_maximize_on_show,
    set_maximize_on_show,
)
from session_sniffer.models import GUIState
from session_sniffer.settings import Settings

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from PySide6.QtGui import QCloseEvent, QShowEvent

    from session_sniffer.guis.table_column_resizing import ColumnSizingMenuCallbacks, TableColumnLayoutController
    from session_sniffer.models.gui_state import TableLayoutState, WindowLayoutState

_MIN_VISIBLE_WINDOW_WIDTH = 100
_MIN_VISIBLE_WINDOW_HEIGHT = 60
_TITLEBAR_TOP_TOLERANCE = 40
_LAYOUT_GENERATION_PROP = '_ss_layout_generation'
_CASCADE_STEP_PX = 28
_WINDOW_SIZE_COMPONENTS = 2

_layout_reset_state: dict[str, int] = {'generation': 0}
_layout_cache_resetters: list[Callable[[], None]] = []


def stamp_window_layout_generation(window: QWidget) -> None:
    """Stamp *window* with the current layout-reset generation."""
    window.setProperty(_LAYOUT_GENERATION_PROP, _layout_reset_state['generation'])


def should_save_window_layout(window: QWidget) -> bool:
    """Return `True` when layout memory is enabled and *window* does not predate the last layout reset."""
    if not Settings.gui_remember_window_layout:
        return False
    stamped = window.property(_LAYOUT_GENERATION_PROP)
    return not (isinstance(stamped, int) and stamped < _layout_reset_state['generation'])


def _rect_is_usable_on_screen(window_rect: QRect, screen_available: QRect) -> bool:
    """Return `True` if *window_rect* overlaps *screen_available* with a reachable titlebar."""
    overlap = window_rect.intersected(screen_available)
    if overlap.isEmpty():
        return False
    min_width = min(_MIN_VISIBLE_WINDOW_WIDTH, max(1, window_rect.width()))
    min_height = min(_MIN_VISIBLE_WINDOW_HEIGHT, max(1, window_rect.height()))
    if overlap.width() < min_width or overlap.height() < min_height:
        return False
    return screen_available.top() - _TITLEBAR_TOP_TOLERANCE <= window_rect.top() <= screen_available.bottom() - min_height


def _header_for_view(view: QTableView | QTreeView) -> QHeaderView | None:
    """Return the horizontal header for a `QTableView` or `QTreeView`."""
    if isinstance(view, QTableView):
        return view.horizontalHeader()
    return view.header()


def _canonical_header_label(view: QTableView | QTreeView, logical_index: int) -> str:
    """Return the canonical column name for *logical_index* in *view*, falling back to display text."""
    model = view.model()
    if not model or not 0 <= logical_index < model.columnCount():
        return ''
    canonical = model.headerData(logical_index, Qt.Orientation.Horizontal, CANONICAL_HEADER_ROLE)
    if isinstance(canonical, str) and canonical:
        return canonical
    display = model.headerData(logical_index, Qt.Orientation.Horizontal, Qt.ItemDataRole.DisplayRole)
    return str(display) if display is not None else ''


def _find_logical_column_by_name(view: QTableView | QTreeView, column_name: str) -> int | None:
    """Return the logical column index matching canonical *column_name*, or `None` if absent."""
    model = view.model()
    if not model or not column_name:
        return None
    for column_index in range(model.columnCount()):
        if _canonical_header_label(view, column_index) == column_name:
            return column_index
    return None


def restore_window_geometry_safely(
    window: QWidget,
    geometry_hex: str | None,
    *,
    maximized: bool = False,
) -> bool:
    """Restore *window* from *geometry_hex*, clamping and recentering if its saved monitor is gone."""
    if geometry_hex is None or not geometry_hex:
        return False
    raw_bytes = QByteArray.fromHex(geometry_hex.encode('ascii'))
    if raw_bytes.isEmpty() or not window.restoreGeometry(raw_bytes):
        return False

    restored_rect = window.geometry()
    if restored_rect.width() <= 0 or restored_rect.height() <= 0:
        return False

    screens = QApplication.screens()
    if screens and not any(_rect_is_usable_on_screen(restored_rect, screen.availableGeometry()) for screen in screens):
        target_screen = QApplication.primaryScreen() or screens[0]
        available = target_screen.availableGeometry()
        clamped_width = min(max(restored_rect.width(), window.minimumWidth()), available.width())
        clamped_height = min(max(restored_rect.height(), window.minimumHeight()), available.height())
        window.setWindowState(window.windowState() & ~Qt.WindowState.WindowMaximized)
        window.resize(clamped_width, clamped_height)
        center_window_on_screen(window)

    if maximized:
        set_maximize_on_show(window, maximize=True)
    else:
        set_maximize_on_show(window, maximize=False)
        window.setWindowState(window.windowState() & ~Qt.WindowState.WindowMaximized)
    return True


def capture_window_geometry(window_state: WindowLayoutState, window: QWidget) -> None:
    """Record *window*'s serialized geometry and maximized state into *window_state*."""
    window_state.geometry = bytes(window.saveGeometry().toHex().data()).decode('ascii')
    window_state.maximized = bool(window.windowState() & Qt.WindowState.WindowMaximized)


def apply_maximize_on_show(window: QWidget) -> None:
    """Maximize *window* if it was marked for deferred maximization during layout restoration."""
    if consume_maximize_on_show(window):
        window.showMaximized()


def restore_window_layout(
    window: QWidget,
    window_key: str,
    *,
    fallback_resize: Callable[[], None] | None = None,
    gui_state: GUIState | None = None,
) -> WindowLayoutState | None:
    """Restore *window*'s saved geometry when layout memory is enabled, else invoke *fallback_resize*."""
    stamp_window_layout_generation(window)
    if not Settings.gui_remember_window_layout:
        if fallback_resize is not None:
            fallback_resize()
        return None

    state = gui_state if gui_state is not None else GUIState.load()
    window_state = state.get_window(window_key)
    if (window_state is None or not restore_window_geometry_safely(window, window_state.geometry, maximized=window_state.maximized)) and fallback_resize is not None:
        fallback_resize()
    return window_state


def save_window_layout(
    window: QWidget,
    window_key: str,
    *,
    gui_state: GUIState | None = None,
) -> WindowLayoutState | None:
    """Capture and save *window*'s geometry when layout memory is enabled."""
    if not should_save_window_layout(window):
        return None
    state = gui_state if gui_state is not None else GUIState.load()
    window_state = state.ensure_window(window_key)
    capture_window_geometry(window_state, window)
    if gui_state is None:
        state.save()
    return window_state


def restore_window_size_layout(
    window: QWidget,
    window_key: str,
    *,
    fallback_resize: Callable[[], None] | None = None,
    gui_state: GUIState | None = None,
) -> WindowLayoutState | None:
    """Restore only *window*'s saved width and height (without pinning position) for multi-instance windows."""
    stamp_window_layout_generation(window)
    if not Settings.gui_remember_window_layout:
        if fallback_resize is not None:
            fallback_resize()
        return None

    state = gui_state if gui_state is not None else GUIState.load()
    window_state = state.get_window(window_key)
    restored = False
    if window_state is not None and window_state.window_size is not None and len(window_state.window_size) == _WINDOW_SIZE_COMPONENTS:
        raw_width, raw_height = window_state.window_size
        if raw_width > 0 and raw_height > 0:
            screens = QApplication.screens()
            if screens:
                available = (QApplication.primaryScreen() or screens[0]).availableGeometry()
                clamped_width = min(max(raw_width, window.minimumWidth()), available.width())
                clamped_height = min(max(raw_height, window.minimumHeight()), available.height())
            else:
                clamped_width = max(raw_width, window.minimumWidth())
                clamped_height = max(raw_height, window.minimumHeight())
            window.resize(clamped_width, clamped_height)
            restored = True
    if not restored and fallback_resize is not None:
        fallback_resize()
    return window_state


def save_window_size_layout(
    window: QWidget,
    window_key: str,
    *,
    gui_state: GUIState | None = None,
) -> WindowLayoutState | None:
    """Capture and save only *window*'s width and height when layout memory is enabled."""
    if not should_save_window_layout(window):
        return None
    state = gui_state if gui_state is not None else GUIState.load()
    window_state = state.ensure_window(window_key)
    size = window.normalGeometry().size() if (window.windowState() & Qt.WindowState.WindowMaximized) else window.size()
    if size.width() > 0 and size.height() > 0:
        window_state.window_size = [size.width(), size.height()]
    if gui_state is None:
        state.save()
    return window_state


def cascade_window_if_overlapping(
    window: QWidget,
    other_windows: Sequence[QWidget],
    *,
    step: int = _CASCADE_STEP_PX,
) -> None:
    """Shift *window* diagonally when its top-left position overlaps another live instance in *other_windows*."""
    if (window.windowState() & Qt.WindowState.WindowMaximized) or is_maximize_on_show(window):
        return
    other_positions = [
        other.pos()
        for other in other_windows
        if other is not window and not (other.windowState() & Qt.WindowState.WindowMaximized)
    ]
    if not other_positions:
        return
    pos = QPoint(window.pos())
    screens = QApplication.screens()
    available = (QApplication.screenAt(pos) or QApplication.primaryScreen()).availableGeometry() if screens else None
    threshold = max(1, step // 2)
    for _ in range(len(other_positions) + 2):
        if not any(abs(pos.x() - other_pos.x()) < threshold and abs(pos.y() - other_pos.y()) < threshold for other_pos in other_positions):
            break
        pos += QPoint(step, step)
        if available is not None:
            max_x = max(available.left(), available.right() - _MIN_VISIBLE_WINDOW_WIDTH)
            max_y = max(available.top(), available.bottom() - _MIN_VISIBLE_WINDOW_HEIGHT)
            if pos.x() > max_x or pos.y() > max_y:
                pos = QPoint(available.left() + step, available.top() + step)
    window.move(pos)


def save_window_layout_with_always_on_top(
    window: QWidget,
    window_key: str,
    *,
    gui_state: GUIState,
) -> WindowLayoutState | None:
    """Capture *window*'s geometry and Always on Top flag into *gui_state* when layout memory is enabled."""
    window_state = save_window_layout(window, window_key, gui_state=gui_state)
    if window_state is not None:
        window_state.always_on_top = bool(window.windowFlags() & Qt.WindowType.WindowStaysOnTopHint)
    return window_state


def encode_splitter_state(splitter: QSplitter) -> str:
    """Serialize *splitter*'s geometry and handle positions to an ASCII hex string."""
    return bytes(splitter.saveState().toHex().data()).decode('ascii')


def restore_splitter_state(splitter: QSplitter, splitter_hex: str | None) -> bool:
    """Restore *splitter* from a hex-encoded `QSplitter.saveState()` payload."""
    if splitter_hex is None or not splitter_hex:
        return False
    raw_bytes = QByteArray.fromHex(splitter_hex.encode('ascii'))
    if raw_bytes.isEmpty():
        return False
    return splitter.restoreState(raw_bytes)


def capture_table_sort_state(table_state: TableLayoutState, view: QTableView | QTreeView) -> None:
    """Record *view*'s active sort column (by canonical name) and direction into *table_state*."""
    header = _header_for_view(view)
    if not header or not header.isSortIndicatorShown():
        return
    section = header.sortIndicatorSection()
    column_name = _canonical_header_label(view, section)
    if not column_name:
        return
    table_state.sort_column = column_name
    table_state.sort_order = 1 if header.sortIndicatorOrder() == Qt.SortOrder.DescendingOrder else 0


def apply_table_sort_state(view: QTableView | QTreeView, table_state: TableLayoutState | None) -> bool:
    """Restore sort column and direction onto *view* from *table_state* if present and valid."""
    if table_state is None or table_state.sort_column is None:
        return False
    column_index = _find_logical_column_by_name(view, table_state.sort_column)
    if column_index is None:
        return False
    order = Qt.SortOrder.DescendingOrder if table_state.sort_order == 1 else Qt.SortOrder.AscendingOrder
    view.sortByColumn(column_index, order)
    return True


def capture_table_hidden_columns(table_state: TableLayoutState, view: QTableView | QTreeView) -> None:
    """Record canonical names of hidden columns in *view* into *table_state*."""
    model = view.model()
    header = _header_for_view(view)
    if not model or not header:
        return
    hidden: list[str] = []
    for column_index in range(model.columnCount()):
        if header.isSectionHidden(column_index):
            column_name = _canonical_header_label(view, column_index)
            if column_name:
                hidden.append(column_name)
    table_state.hidden_columns = hidden or None


def apply_table_hidden_columns(view: QTableView | QTreeView, hidden_columns: Sequence[str] | None) -> None:
    """Hide columns listed in *hidden_columns* on *view* while keeping at least one column visible."""
    if hidden_columns is None or not hidden_columns:
        return
    model = view.model()
    header = _header_for_view(view)
    if not model or not header:
        return
    column_count = model.columnCount()
    if column_count <= 1:
        return
    hidden_set = set(hidden_columns)
    to_hide = [col for col in range(column_count) if _canonical_header_label(view, col) in hidden_set]
    if len(to_hide) >= column_count:
        to_hide = to_hide[:-1]
    hide_indices = set(to_hide)
    for column_index in range(column_count):
        header.setSectionHidden(column_index, column_index in hide_indices)


def restore_table_layout(
    table_key: str,
    controller: TableColumnLayoutController,
    *,
    gui_state: GUIState | None = None,
    preserve_hidden_order: bool = False,
) -> TableLayoutState | None:
    """Apply saved column order and column widths for *table_key* to *controller*."""
    if not Settings.gui_remember_window_layout:
        return None
    state = gui_state if gui_state is not None else GUIState.load()
    table_state = state.get_table(table_key)
    if table_state is None:
        return None
    if table_state.column_order is not None and table_state.column_order:
        controller.apply_column_order(table_state.column_order, preserve_hidden=preserve_hidden_order)
    if table_state.column_widths is not None and table_state.column_widths:
        controller.apply_column_widths(table_state.column_widths)
    return table_state


def save_table_layout(
    table_key: str,
    controller: TableColumnLayoutController,
    *,
    gui_state: GUIState | None = None,
) -> TableLayoutState | None:
    """Persist *controller*'s column widths and order under *table_key*."""
    if not Settings.gui_remember_window_layout:
        return None
    state = gui_state if gui_state is not None else GUIState.load()
    table_state = state.ensure_table(table_key)
    table_state.column_widths = controller.get_persisted_widths()
    table_state.column_order = controller.get_persisted_order()
    if gui_state is None:
        state.save()
    return table_state


def clear_table_layout(
    table_key: str,
    *,
    reset_widths: bool = False,
    reset_order: bool = False,
) -> None:
    """Clear persisted column widths and/or visual order for *table_key* when layout memory is enabled."""
    if not Settings.gui_remember_window_layout:
        return
    state = GUIState.load()
    table_state = state.get_table(table_key)
    if table_state is None:
        return
    if reset_widths:
        table_state.column_widths = None
    if reset_order:
        table_state.column_order = None
    state.save()


def make_table_reset_callbacks(table_key: str, controller: TableColumnLayoutController) -> ColumnSizingMenuCallbacks:
    """Build header context-menu callbacks that reset sizes/order on *controller* and clear *table_key* persistence."""

    def _on_reset_sizes() -> None:
        controller.reset_column_sizes()
        clear_table_layout(table_key, reset_widths=True)

    def _on_reset_order() -> None:
        controller.reset_column_order()
        controller.setup_column_resizing()
        clear_table_layout(table_key, reset_order=True)

    return controller.menu_callbacks(on_reset=_on_reset_sizes, on_reset_order=_on_reset_order)


def save_window_and_table_layout(
    window: QWidget,
    layout_key: str,
    controller: TableColumnLayoutController,
    *,
    sort_view: QTableView | QTreeView | None = None,
) -> None:
    """Persist window geometry, table column layout, and optional sort state under *layout_key*."""
    if not should_save_window_layout(window):
        return
    gui_state = GUIState.load()
    if save_window_layout(window, layout_key, gui_state=gui_state) is None:
        return
    if (table_state := save_table_layout(layout_key, controller, gui_state=gui_state)) is not None and sort_view is not None:
        capture_table_sort_state(table_state, sort_view)
    gui_state.save()


def register_layout_cache_reset(callback: Callable[[], None]) -> None:
    """Register a callback invoked when all saved GUI layouts are reset."""
    if callback not in _layout_cache_resetters:
        _layout_cache_resetters.append(callback)


def reset_all_saved_layouts() -> bool:
    """Delete persisted GUI layout state and reset all registered in-memory layout caches."""
    deleted = GUIState.clear_file()
    if deleted:
        _layout_reset_state['generation'] += 1
    for callback in tuple(_layout_cache_resetters):
        callback()
    return deleted


class PersistentRateGraphWindowMixin(RateGraphWindowMixin):
    """`RateGraphWindowMixin` subclass persisting geometry/size, Always on Top, and Max History when `LAYOUT_KEY` is set."""

    LAYOUT_KEY: ClassVar[str | None] = None
    PERSIST_SIZE_ONLY: ClassVar[bool] = False

    @override
    def _on_max_history_changed(self, new_max_history: int) -> None:
        """Handle max history changes (implemented by concrete graph subclasses)."""
        raise NotImplementedError

    def _restore_extra_rate_graph_state(self, win_state: WindowLayoutState) -> None:
        """Restore subclass-specific state from *win_state* (override as needed)."""

    def _save_extra_rate_graph_state(self, win_state: WindowLayoutState) -> None:
        """Capture subclass-specific state into *win_state* (override as needed)."""

    def _restore_rate_graph_layout(self) -> None:
        """Restore saved geometry (or size), Always on Top, Max History, and subclass state."""
        if self.LAYOUT_KEY is None:
            return
        win_state = (
            restore_window_size_layout(self, self.LAYOUT_KEY)
            if self.PERSIST_SIZE_ONLY
            else restore_window_layout(self, self.LAYOUT_KEY)
        )
        if win_state is None:
            return
        if win_state.always_on_top is not None and self._aot_checkbox is not None:
            self._aot_checkbox.setChecked(win_state.always_on_top)
        if win_state.max_history is not None and self._history_combo is not None:
            history_index = self._history_combo.findData(win_state.max_history)
            if history_index >= 0:
                self._history_combo.setCurrentIndex(history_index)
        self._restore_extra_rate_graph_state(win_state)

    @override
    def showEvent(self, event: QShowEvent) -> None:
        """Apply deferred maximization when the graph window is shown."""
        super().showEvent(event)
        apply_maximize_on_show(self)

    @override
    def closeEvent(self, event: QCloseEvent) -> None:
        """Persist geometry/size, Always on Top, Max History, and subclass state on close."""
        if self.LAYOUT_KEY is not None and should_save_window_layout(self):
            gui_state = GUIState.load()
            if self.PERSIST_SIZE_ONLY:
                win_state = save_window_size_layout(self, self.LAYOUT_KEY, gui_state=gui_state)
                if win_state is not None:
                    win_state.always_on_top = bool(self.windowFlags() & Qt.WindowType.WindowStaysOnTopHint)
            else:
                win_state = save_window_layout_with_always_on_top(self, self.LAYOUT_KEY, gui_state=gui_state)
            if win_state is not None:
                if self._history_combo is not None and isinstance(raw_history := self._history_combo.currentData(), int):
                    win_state.max_history = raw_history
                self._save_extra_rate_graph_state(win_state)
                gui_state.save()
        super().closeEvent(event)
