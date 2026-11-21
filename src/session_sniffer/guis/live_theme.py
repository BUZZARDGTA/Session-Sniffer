"""Live runtime theme switching across all open Qt windows, widgets, icons, and stylesheets."""

import threading
import weakref
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, NamedTuple, cast, override

from PySide6.QtCore import QCoreApplication, QEvent, QObject, QSignalBlocker, QSize, Qt
from PySide6.QtGui import QIcon, QPixmap, QPixmapCache
from PySide6.QtWidgets import (
    QAbstractButton,
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QWidget,
)
from shiboken6 import isValid

from session_sniffer.guis.app import app
from session_sniffer.guis.loading_overlay import (
    has_active_loading_overlay,
    pump_active_loading_overlays,
    run_with_active_loading,
)
from session_sniffer.guis.rate_graph_widget import RateGraphWidget
from session_sniffer.guis.theme import build_canonical_stylesheet, get_palette
from session_sniffer.guis.theming import (
    DARK_THEME_COLORS,
    DEFAULT_THEME_NAME,
    ICONS_DIR_PATH,
    Theme,
    ThemeColors,
    ThemeTransform,
    commit_prepared_theme,
    detect_system_theme_name,
    get_active_theme,
    get_theme_generation,
    get_theme_transform,
    get_themed_icon,
    load_themes_file,
    stage_theme_transform_and_icons,
    themed_qss,
    try_recover_canonical_qss,
)
from session_sniffer.guis.theming._icons import lookup_rendered_svg_spec, lookup_themed_icon_filename
from session_sniffer.guis.utils import get_ui_scale, make_padded_icon, render_svg_pixmap_with_pair
from session_sniffer.settings.settings import Settings

if TYPE_CHECKING:
    from collections.abc import Callable

_PREVIEW_ROOT_OBJECT_NAME: Final = 'themePreviewRoot'
_OVERLAY_BACKDROP_OBJECT_NAME: Final = 'loadingOverlayBackdrop'
_UNTHEMED_SVG_NAMES: Final = frozenset({'app_icon.svg', 'update_download_badge.svg'})
_NON_THEMED_ICON_MARKER: Final = '-'
_SVG_ICON_TAG_ROLE: Final = int(Qt.ItemDataRole.UserRole) + 91
_MAX_CACHED_THEME_SETS: Final = 16
_MIN_TABS_FOR_CHUNKED_POLISH: Final = 3
_POST_REFRESH_HOOKS: list[tuple[weakref.ref[QWidget], Callable[[], None]]] = []

_QSS_CACHE_LOCK = threading.Lock()
_GLOBAL_QSS_CACHE: dict[tuple[ThemeColors, float], str] = {}
_SVG_FINGERPRINTS_BY_COLORS: dict[ThemeColors, dict[bytes, str]] = {}


@dataclass(frozen=True, slots=True)
class PreparedTheme:
    """Theme transform, staged disk icons, and global QSS prepared prior to GUI polishing."""

    theme: Theme
    transform: ThemeTransform
    stylesheet: str


class _DetachedTabEntry(NamedTuple):
    tab_index: int
    page: QWidget
    text: str
    icon: QIcon
    tooltip: str
    whats_this: str
    enabled: bool
    visible: bool


class _DetachedTabGroup(NamedTuple):
    tab_widget: QTabWidget
    current_index: int
    entries: list[_DetachedTabEntry]


@dataclass(slots=True)
class _LiveSyncState:
    applying: bool = False
    filter_installed: bool = False
    watcher_installed: bool = False
    global_stylesheet: str = ''
    dialog_follow_checkbox: weakref.ref[QCheckBox] | None = None


_SYNC_STATE = _LiveSyncState()


def _is_in_preview_subtree(widget: QWidget) -> bool:
    current: QWidget | None = widget
    while current is not None:
        if current.objectName() == _PREVIEW_ROOT_OBJECT_NAME:
            return True
        current = current.parentWidget()
    return False


def _is_root_window(widget: QWidget) -> bool:
    return widget.isWindow() and widget.parentWidget() is None


def _should_skip_widget(widget: QWidget) -> bool:
    return (
        not isValid(widget)
        or widget.objectName().startswith(('qt_', '_q_'))
        or isinstance(widget.parentWidget(), QLineEdit)
        or _is_in_preview_subtree(widget)
    )


def _sync_root_window_stylesheet(win: QWidget, global_qss: str) -> None:
    """Apply *global_qss* (preserving any custom dialog stylesheet) to a root window."""
    if not isValid(win) or not _is_root_window(win) or _is_in_preview_subtree(win) or win.objectName() == _OVERLAY_BACKDROP_OBJECT_NAME:
        return
    gen = get_theme_generation()
    existing_qss = win.styleSheet()
    if win.property('_ss_root_global_only') == 1 or not existing_qss:
        win.setProperty('_ss_root_global_only', 1)
        win.setProperty('_ss_root_qss_gen', gen)
        if existing_qss != global_qss:
            win.setStyleSheet(global_qss)
        return

    canon_custom = win.property('_ss_root_custom_canon')
    if not isinstance(canon_custom, str):
        canon_custom = try_recover_canonical_qss(existing_qss)
    if isinstance(canon_custom, str):
        win.setProperty('_ss_root_custom_canon', canon_custom)
        merged = f'{global_qss}\n{themed_qss(canon_custom)}'
        win.setProperty('_ss_root_qss_gen', gen)
        if existing_qss != merged:
            win.setStyleSheet(merged)
        return

    unthemed_custom = win.property('_ss_root_custom_unthemed')
    if not isinstance(unthemed_custom, str):
        unthemed_custom = existing_qss
        win.setProperty('_ss_root_custom_unthemed', unthemed_custom)
    merged_unthemed = f'{global_qss}\n{unthemed_custom}'
    win.setProperty('_ss_root_qss_gen', gen)
    if existing_qss != merged_unthemed:
        win.setStyleSheet(merged_unthemed)


class _LiveThemeStyleFilter(QObject):
    """Apply the active global and inline theme stylesheets to newly created or shown widgets."""

    @override
    def eventFilter(self, watched: QObject, event: QEvent) -> bool:
        ev_type = event.type()
        if ev_type not in (QEvent.Type.Polish, QEvent.Type.Show) or _SYNC_STATE.applying or not get_theme_generation():
            return False
        if not isinstance(watched, QWidget) or not isValid(watched) or _is_in_preview_subtree(watched):
            return False

        if _is_root_window(watched):
            if _SYNC_STATE.global_stylesheet and watched.property('_ss_root_qss_gen') != get_theme_generation():
                _SYNC_STATE.applying = True
                try:
                    _sync_root_window_stylesheet(watched, _SYNC_STATE.global_stylesheet)
                finally:
                    _SYNC_STATE.applying = False
            return False

        if ev_type == QEvent.Type.Polish and (current_qss := watched.styleSheet()):
            canonical_qss = try_recover_canonical_qss(current_qss)
            if canonical_qss is not None:
                updated_qss = themed_qss(canonical_qss)
                if updated_qss != current_qss:
                    _SYNC_STATE.applying = True
                    try:
                        watched.setStyleSheet(updated_qss)
                        watched.setProperty('_ss_qss_last', updated_qss)
                        watched.setProperty('_ss_qss_canon', canonical_qss)
                    finally:
                        _SYNC_STATE.applying = False
        return False


_STYLE_FILTER = _LiveThemeStyleFilter(app)


def _set_style_filter_attached(*, attached: bool) -> None:
    if attached and not _SYNC_STATE.filter_installed:
        app.installEventFilter(_STYLE_FILTER)
        _SYNC_STATE.filter_installed = True
    elif not attached and _SYNC_STATE.filter_installed:
        app.removeEventFilter(_STYLE_FILTER)
        _SYNC_STATE.filter_installed = False


def _get_or_snapshot_svg_fingerprints(colors: ThemeColors) -> dict[bytes, str]:
    """Return cached `16x16 RGBA -> rel_posix_path` fingerprints for *colors*."""
    cached = _SVG_FINGERPRINTS_BY_COLORS.get(colors)
    if cached is not None:
        return cached

    fingerprints: dict[bytes, str] = {}
    if ICONS_DIR_PATH.is_dir():
        for svg_path in ICONS_DIR_PATH.rglob('*.svg'):
            if not svg_path.is_file() or svg_path.name in _UNTHEMED_SVG_NAMES:
                continue
            icon = QIcon(str(svg_path))
            if not icon.isNull():
                rel_posix = svg_path.relative_to(ICONS_DIR_PATH).as_posix()
                fingerprints[bytes(icon.pixmap(16, 16).toImage().bits())] = rel_posix

    if len(_SVG_FINGERPRINTS_BY_COLORS) >= _MAX_CACHED_THEME_SETS:
        _SVG_FINGERPRINTS_BY_COLORS.clear()
    _SVG_FINGERPRINTS_BY_COLORS[colors] = fingerprints
    return fingerprints


def _format_icon_tag(icon: QIcon, rel_posix: str) -> str:
    return f'{icon.cacheKey()}:{rel_posix}'


def _extract_valid_tag(tag_obj: object, icon: QIcon) -> str | None:
    if isinstance(tag_obj, str) and ':' in tag_obj:
        key_str, rel_posix = tag_obj.split(':', 1)
        if key_str == str(icon.cacheKey()):
            return rel_posix
    return None


def _has_tracked_spec(icon: QIcon, size_hint: QSize) -> bool:
    candidate_sizes = icon.availableSizes()
    if size_hint.isValid() and size_hint not in candidate_sizes:
        candidate_sizes.append(size_hint)
    if QSize(16, 16) not in candidate_sizes:
        candidate_sizes.append(QSize(16, 16))
    return any(lookup_rendered_svg_spec(icon.pixmap(size)) is not None for size in candidate_sizes)


def _resolve_icon_rel_posix(icon: QIcon, size_hint: QSize, tag_obj: object, active_colors: ThemeColors) -> str:
    """Identify the relative SVG path for *icon* (or `_NON_THEMED_ICON_MARKER` if tracked/unthemed)."""
    if icon.isNull():
        return _NON_THEMED_ICON_MARKER
    existing = _extract_valid_tag(tag_obj, icon)
    if existing is not None:
        return existing
    if (known_filename := lookup_themed_icon_filename(icon)) is not None:
        return known_filename
    if _has_tracked_spec(icon, size_hint):
        return _NON_THEMED_ICON_MARKER
    fingerprints = _get_or_snapshot_svg_fingerprints(active_colors)
    return fingerprints.get(bytes(icon.pixmap(16, 16).toImage().bits()), _NON_THEMED_ICON_MARKER)


def _prime_qobject_icon(holder: QObject, prop_name: str, icon: QIcon, size_hint: QSize, active_colors: ThemeColors) -> None:
    if icon.isNull():
        return
    if _extract_valid_tag(holder.property(prop_name), icon) is not None:
        return
    rel_posix = _resolve_icon_rel_posix(icon, size_hint, None, active_colors)
    holder.setProperty(prop_name, _format_icon_tag(icon, rel_posix))


def _prime_tree_item(item: QTreeWidgetItem, size_hint: QSize, active_colors: ThemeColors) -> None:
    for col in range(item.columnCount()):
        icon = item.icon(col)
        if not icon.isNull() and _extract_valid_tag(item.data(col, _SVG_ICON_TAG_ROLE), icon) is None:
            rel_posix = _resolve_icon_rel_posix(icon, size_hint, None, active_colors)
            item.setData(col, _SVG_ICON_TAG_ROLE, _format_icon_tag(icon, rel_posix))
    for idx in range(item.childCount()):
        if (child := item.child(idx)) is not None:
            _prime_tree_item(child, size_hint, active_colors)


def _read_tab_tags(widget: QTabWidget) -> dict[str, str]:
    raw_map = widget.property('_ss_tab_svgs')
    if not isinstance(raw_map, dict):
        return {}
    raw_dict = cast('dict[object, object]', raw_map)
    return {k: v for k, v in raw_dict.items() if isinstance(k, str) and isinstance(v, str)}


def prime_current_theme_icon_tags() -> None:
    """Ensure all live untinted `QIcon`s record their source SVG path before `ICONS_DIR_PATH` changes."""
    active_colors = get_active_theme().colors
    for widget in list(QApplication.allWidgets()):
        if _should_skip_widget(widget):
            continue
        if widget.isWindow():
            _prime_qobject_icon(widget, '_ss_win_svg', widget.windowIcon(), QSize(16, 16), active_colors)
        for action in widget.actions():
            _prime_qobject_icon(action, '_ss_act_svg', action.icon(), QSize(16, 16), active_colors)
        if isinstance(widget, QAbstractButton):
            _prime_qobject_icon(widget, '_ss_btn_svg', widget.icon(), widget.iconSize(), active_colors)
            orig_icon = widget.property('_feedback_orig_icon')
            if isinstance(orig_icon, QIcon):
                _prime_qobject_icon(widget, '_ss_orig_svg', orig_icon, widget.iconSize(), active_colors)
        if isinstance(widget, QTabWidget):
            tab_tags = _read_tab_tags(widget)
            changed = False
            for tab_idx in range(widget.count()):
                tab_icon = widget.tabIcon(tab_idx)
                if tab_icon.isNull():
                    continue
                idx_key = str(tab_idx)
                if _extract_valid_tag(tab_tags.get(idx_key), tab_icon) is None:
                    rel_posix = _resolve_icon_rel_posix(tab_icon, widget.iconSize(), None, active_colors)
                    tab_tags[idx_key] = _format_icon_tag(tab_icon, rel_posix)
                    changed = True
            if changed:
                widget.setProperty('_ss_tab_svgs', tab_tags)
        if isinstance(widget, QListWidget):
            for row in range(widget.count()):
                list_item = widget.item(row)
                item_icon = list_item.icon()
                if not item_icon.isNull() and _extract_valid_tag(list_item.data(_SVG_ICON_TAG_ROLE), item_icon) is None:
                    rel_posix = _resolve_icon_rel_posix(item_icon, widget.iconSize(), None, active_colors)
                    list_item.setData(_SVG_ICON_TAG_ROLE, _format_icon_tag(item_icon, rel_posix))
        if isinstance(widget, QTreeWidget):
            for top_idx in range(widget.topLevelItemCount()):
                if (top_item := widget.topLevelItem(top_idx)) is not None:
                    _prime_tree_item(top_item, widget.iconSize(), active_colors)
        pump_active_loading_overlays()


def _rerender_tracked_pixmap(pixmap: QPixmap) -> QPixmap | None:
    spec = lookup_rendered_svg_spec(pixmap)
    return None if spec is None else render_svg_pixmap_with_pair(spec.filename, spec.width, spec.height, spec.tint_pair)


def _rerender_tracked_icon(icon: QIcon, size_hint: QSize) -> QIcon | None:
    if icon.isNull():
        return None
    candidate_sizes = icon.availableSizes()
    if size_hint.isValid() and size_hint not in candidate_sizes:
        candidate_sizes.append(size_hint)
    if QSize(16, 16) not in candidate_sizes:
        candidate_sizes.append(QSize(16, 16))
    for size in candidate_sizes:
        spec = lookup_rendered_svg_spec(icon.pixmap(size))
        if spec is not None:
            base_icon = QIcon(render_svg_pixmap_with_pair(spec.filename, spec.width, spec.height, spec.tint_pair))
            return make_padded_icon(base_icon, (spec.width, spec.height), spec.right_padding) if spec.right_padding else base_icon
    return None


def _swap_tagged_icon(icon: QIcon, size_hint: QSize, tag_obj: object) -> tuple[QIcon, str] | None:
    if icon.isNull():
        return None
    rel_posix = _extract_valid_tag(tag_obj, icon)
    if rel_posix is not None and rel_posix != _NON_THEMED_ICON_MARKER:
        new_icon = get_themed_icon(rel_posix)
        return new_icon, _format_icon_tag(new_icon, rel_posix)
    tracked = _rerender_tracked_icon(icon, size_hint)
    if tracked is not None:
        return tracked, _format_icon_tag(tracked, _NON_THEMED_ICON_MARKER)
    return None


def _refresh_qobject_icon(
    holder: QObject,
    prop_name: str,
    icon: QIcon,
    size_hint: QSize,
) -> QIcon | None:
    swapped = _swap_tagged_icon(icon, size_hint, holder.property(prop_name))
    if swapped is None:
        return None
    new_icon, new_tag = swapped
    holder.setProperty(prop_name, new_tag)
    return new_icon


def _refresh_list_item_icon(list_item: QListWidgetItem, size_hint: QSize) -> None:
    swapped = _swap_tagged_icon(list_item.icon(), size_hint, list_item.data(_SVG_ICON_TAG_ROLE))
    if swapped is not None:
        new_icon, new_tag = swapped
        list_item.setIcon(new_icon)
        list_item.setData(_SVG_ICON_TAG_ROLE, new_tag)


def _refresh_tree_item_icons(item: QTreeWidgetItem, size_hint: QSize) -> None:
    for col in range(item.columnCount()):
        swapped = _swap_tagged_icon(item.icon(col), size_hint, item.data(col, _SVG_ICON_TAG_ROLE))
        if swapped is not None:
            new_icon, new_tag = swapped
            item.setIcon(col, new_icon)
            item.setData(col, _SVG_ICON_TAG_ROLE, new_tag)
    for idx in range(item.childCount()):
        if (child := item.child(idx)) is not None:
            _refresh_tree_item_icons(child, size_hint)


def _recover_tagged_canonical(holder: QObject, last_prop: str, canon_prop: str, current_text: str) -> str | None:
    if holder.property(last_prop) == current_text:
        canon = holder.property(canon_prop)
        if isinstance(canon, str):
            return canon
    return try_recover_canonical_qss(current_text)


def _refresh_single_widget(widget: QWidget) -> None:
    if _should_skip_widget(widget):
        return

    if not _is_root_window(widget) and (current_qss := widget.styleSheet()):
        canonical_qss = _recover_tagged_canonical(widget, '_ss_qss_last', '_ss_qss_canon', current_qss)
        if canonical_qss is not None:
            updated_qss = themed_qss(canonical_qss)
            widget.setProperty('_ss_qss_last', updated_qss)
            widget.setProperty('_ss_qss_canon', canonical_qss)
            if updated_qss != current_qss:
                widget.setStyleSheet(updated_qss)

    if widget.isWindow() and (new_win_icon := _refresh_qobject_icon(widget, '_ss_win_svg', widget.windowIcon(), QSize(16, 16))) is not None:
        widget.setWindowIcon(new_win_icon)

    if isinstance(widget, QLineEdit):
        refresh_search_fn = widget.property('_ss_refresh_search_icon')
        if callable(refresh_search_fn):
            refresh_search_fn()
            for action in widget.actions():
                action_icon = action.icon()
                if not action_icon.isNull():
                    action.setProperty('_ss_act_svg', _format_icon_tag(action_icon, _NON_THEMED_ICON_MARKER))

    for action in widget.actions():
        if (new_action_icon := _refresh_qobject_icon(action, '_ss_act_svg', action.icon(), QSize(16, 16))) is not None:
            action.setIcon(new_action_icon)

    if isinstance(widget, QAbstractButton):
        if (new_btn_icon := _refresh_qobject_icon(widget, '_ss_btn_svg', widget.icon(), widget.iconSize())) is not None:
            widget.setIcon(new_btn_icon)
        orig_icon = widget.property('_feedback_orig_icon')
        if isinstance(orig_icon, QIcon) and (new_orig := _refresh_qobject_icon(widget, '_ss_orig_svg', orig_icon, widget.iconSize())) is not None:
            widget.setProperty('_feedback_orig_icon', new_orig)

    if isinstance(widget, QTabWidget):
        tab_tags = _read_tab_tags(widget)
        for tab_idx in range(widget.count()):
            idx_key = str(tab_idx)
            swapped = _swap_tagged_icon(widget.tabIcon(tab_idx), widget.iconSize(), tab_tags.get(idx_key))
            if swapped is not None:
                new_tab_icon, new_tag = swapped
                widget.setTabIcon(tab_idx, new_tab_icon)
                tab_tags[idx_key] = new_tag
        if tab_tags:
            widget.setProperty('_ss_tab_svgs', tab_tags)

    if isinstance(widget, QListWidget):
        for row in range(widget.count()):
            _refresh_list_item_icon(widget.item(row), widget.iconSize())

    if isinstance(widget, QTreeWidget):
        for top_idx in range(widget.topLevelItemCount()):
            if (top_item := widget.topLevelItem(top_idx)) is not None:
                _refresh_tree_item_icons(top_item, widget.iconSize())

    if isinstance(widget, QLabel):
        pixmap = widget.pixmap()
        if not pixmap.isNull() and (new_pixmap := _rerender_tracked_pixmap(pixmap)) is not None:
            widget.setPixmap(new_pixmap)
        label_text = widget.text()
        if label_text and '<' in label_text:
            canonical_html = _recover_tagged_canonical(widget, '_ss_html_last', '_ss_html_canon', label_text)
            if canonical_html is not None:
                new_html = themed_qss(canonical_html)
                widget.setProperty('_ss_html_last', new_html)
                widget.setProperty('_ss_html_canon', canonical_html)
                if new_html != label_text:
                    widget.setText(new_html)

    if isinstance(widget, RateGraphWidget):
        widget.refresh_theme_colors()

    if isinstance(widget, QAbstractItemView) and widget.isVisible():
        widget.viewport().update()


def _detach_hidden_tabs(root_win: QWidget) -> list[_DetachedTabGroup]:
    """Temporarily detach non-current pages from multi-tab `QTabWidget`s in *root_win* for <20ms QSS slices."""
    groups: list[_DetachedTabGroup] = []
    for tab_widget in root_win.findChildren(QTabWidget):
        if not isValid(tab_widget) or tab_widget.count() < _MIN_TABS_FOR_CHUNKED_POLISH:
            continue
        cur_idx = tab_widget.currentIndex()
        entries: list[_DetachedTabEntry] = []
        with QSignalBlocker(tab_widget):
            for idx in range(tab_widget.count() - 1, -1, -1):
                if idx == cur_idx:
                    continue
                page = tab_widget.widget(idx)
                if page is None:
                    continue
                entries.append(
                    _DetachedTabEntry(
                        tab_index=idx,
                        page=page,
                        text=tab_widget.tabText(idx),
                        icon=tab_widget.tabIcon(idx),
                        tooltip=tab_widget.tabToolTip(idx),
                        whats_this=tab_widget.tabWhatsThis(idx),
                        enabled=tab_widget.isTabEnabled(idx),
                        visible=tab_widget.isTabVisible(idx),
                    ),
                )
                tab_widget.removeTab(idx)
                page.setParent(None)
                pump_active_loading_overlays()
        if entries:
            groups.append(_DetachedTabGroup(tab_widget=tab_widget, current_index=cur_idx, entries=entries))
    return groups


def _reinsert_detached_tabs(groups: list[_DetachedTabGroup]) -> None:
    """Restore detached `QTabWidget` pages one by one while keeping active spinner overlays animated."""
    for group in groups:
        tab_widget = group.tab_widget
        if not isValid(tab_widget):
            continue
        with QSignalBlocker(tab_widget):
            for entry in reversed(group.entries):
                if not isValid(entry.page):
                    continue
                tab_widget.insertTab(entry.tab_index, entry.page, entry.icon, entry.text)
                if entry.tooltip:
                    tab_widget.setTabToolTip(entry.tab_index, entry.tooltip)
                if entry.whats_this:
                    tab_widget.setTabWhatsThis(entry.tab_index, entry.whats_this)
                if not entry.enabled:
                    tab_widget.setTabEnabled(entry.tab_index, entry.enabled)
                if not entry.visible:
                    tab_widget.setTabVisible(entry.tab_index, entry.visible)
                pump_active_loading_overlays()
            if 0 <= group.current_index < tab_widget.count():
                tab_widget.setCurrentIndex(group.current_index)


def _apply_global_stylesheet_chunked(global_qss: str) -> None:
    """Apply *global_qss* across root windows and tabs in <20ms increments so spinners never stall."""
    root_windows = [
        win
        for win in QApplication.topLevelWidgets()
        if isValid(win) and _is_root_window(win) and not _is_in_preview_subtree(win) and win.objectName() != _OVERLAY_BACKDROP_OBJECT_NAME
    ]
    root_windows.sort(key=lambda win: not win.isVisible())

    detached_by_window: list[list[_DetachedTabGroup]] = []
    try:
        detached_by_window.extend(_detach_hidden_tabs(win) for win in root_windows)

        if app.styleSheet():
            app.setStyleSheet('')
            pump_active_loading_overlays()

        for win in root_windows:
            _sync_root_window_stylesheet(win, global_qss)
            pump_active_loading_overlays()
    finally:
        for groups in detached_by_window:
            _reinsert_detached_tabs(groups)


def prepare_theme_assets(theme: Theme, ui_scale: float) -> PreparedTheme:
    """Build *theme*'s `ThemeTransform`, active SVG files, and global QSS (safe on worker threads)."""
    transform = stage_theme_transform_and_icons(theme)

    qss_key = (theme.colors, ui_scale)
    with _QSS_CACHE_LOCK:
        stylesheet = _GLOBAL_QSS_CACHE.get(qss_key)
    if stylesheet is None:
        stylesheet = transform.qss(build_canonical_stylesheet(ui_scale))
        with _QSS_CACHE_LOCK:
            if len(_GLOBAL_QSS_CACHE) >= _MAX_CACHED_THEME_SETS:
                _GLOBAL_QSS_CACHE.clear()
            _GLOBAL_QSS_CACHE[qss_key] = stylesheet

    return PreparedTheme(theme=theme, transform=transform, stylesheet=stylesheet)


def apply_prepared_runtime_theme(prepared: PreparedTheme) -> None:
    """Commit a `PreparedTheme` on the GUI thread while continuously pumping active loading spinners."""
    if prepared.theme == get_active_theme():
        _set_style_filter_attached(attached=True)
        return

    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    _SYNC_STATE.applying = True
    _SYNC_STATE.global_stylesheet = prepared.stylesheet
    _set_style_filter_attached(attached=False)
    try:
        commit_prepared_theme(prepared.theme, prepared.transform)
        QPixmapCache.clear()
        app.setPalette(get_palette())
        pump_active_loading_overlays()

        for widget in list(QApplication.allWidgets()):
            _refresh_single_widget(widget)
            pump_active_loading_overlays()

        _apply_global_stylesheet_chunked(prepared.stylesheet)

        alive_hooks: list[tuple[weakref.ref[QWidget], Callable[[], None]]] = []
        for widget_ref, callback in _POST_REFRESH_HOOKS:
            target = widget_ref()
            if target is not None and isValid(target):
                alive_hooks.append((widget_ref, callback))
                callback()
                pump_active_loading_overlays()
        _POST_REFRESH_HOOKS[:] = alive_hooks
    finally:
        _set_style_filter_attached(attached=True)
        _SYNC_STATE.applying = False


def register_post_theme_refresh(widget: QWidget, callback: Callable[[], None]) -> None:
    """Register *callback* to run after a live theme switch while *widget* remains alive."""
    _POST_REFRESH_HOOKS.append((weakref.ref(widget), callback))


def resolve_theme_by_name(theme_name: str) -> Theme:
    """Resolve *theme_name* from `themes.json` / built-in presets, falling back to `Dark`."""
    found = load_themes_file()[0].find_theme(theme_name)
    return found if found is not None else Theme(DEFAULT_THEME_NAME, DARK_THEME_COLORS, builtin=True)


def resolve_effective_theme(theme_name: str | None = None, *, follow_system: bool | None = None) -> Theme:
    """Resolve the effective runtime `Theme`, honoring *follow_system* (or `Settings.gui_theme_follow_system`)."""
    use_system = Settings.gui_theme_follow_system if follow_system is None else follow_system
    effective_name = detect_system_theme_name() if use_system else (Settings.gui_theme if theme_name is None else theme_name)
    return resolve_theme_by_name(effective_name)


def set_live_follow_system_checkbox(checkbox: QCheckBox | None) -> None:
    """Track an open `SettingsDialog` Follow System Theme checkbox so OS scheme changes respect unsaved previews."""
    _SYNC_STATE.dialog_follow_checkbox = weakref.ref(checkbox) if checkbox is not None else None


def _on_os_color_scheme_changed(_scheme: Qt.ColorScheme) -> None:
    if _SYNC_STATE.applying:
        return
    checkbox = _SYNC_STATE.dialog_follow_checkbox() if _SYNC_STATE.dialog_follow_checkbox is not None else None
    follow_active = checkbox.isChecked() if checkbox is not None and isValid(checkbox) and checkbox.window().isVisible() else Settings.gui_theme_follow_system
    if not follow_active:
        return
    apply_runtime_theme(resolve_effective_theme(follow_system=True))


def install_system_theme_watcher() -> None:
    """Reconcile the startup theme with `Settings` / OS scheme and watch live OS color-scheme changes."""
    apply_runtime_theme(resolve_effective_theme())
    if _SYNC_STATE.watcher_installed:
        return
    _SYNC_STATE.watcher_installed = True
    app.styleHints().colorSchemeChanged.connect(_on_os_color_scheme_changed)


def apply_runtime_theme(theme: Theme) -> None:
    """Apply *theme* immediately across the running QApplication and all open widgets without restarting."""
    active = get_active_theme()
    if theme == active:
        _set_style_filter_attached(attached=True)
        return
    if theme.colors == active.colors:
        commit_prepared_theme(theme, get_theme_transform(theme.colors))
        _set_style_filter_attached(attached=True)
        return
    prime_current_theme_icon_tags()
    ui_scale = get_ui_scale()
    prepared = (
        run_with_active_loading(prepare_theme_assets, theme, ui_scale)
        if has_active_loading_overlay()
        else prepare_theme_assets(theme, ui_scale)
    )
    apply_prepared_runtime_theme(prepared)
