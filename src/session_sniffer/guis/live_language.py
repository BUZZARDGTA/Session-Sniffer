"""Live runtime language switching, QTranslator synchronization, and widget retranslation."""

import weakref
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, cast, override

from PySide6.QtCore import QAbstractListModel, QCoreApplication, QEvent, QObject, QSignalBlocker, Qt
from PySide6.QtGui import QAction, QIcon
from PySide6.QtWidgets import (
    QAbstractButton,
    QAbstractItemView,
    QAbstractSpinBox,
    QApplication,
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QGroupBox,
    QLabel,
    QLineEdit,
    QMenu,
    QSpinBox,
    QTableView,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTreeView,
    QTreeWidget,
    QWidget,
)
from shiboken6 import isValid

from session_sniffer.guis.app import app
from session_sniffer.i18n import (
    DEFAULT_LANGUAGE,
    SUPPORTED_LANGUAGES,
    get_active_language,
    lookup_canonical_message,
    normalize_language_code,
    resolve_effective_language,
    set_active_language,
    tr,
)
from session_sniffer.rendering_core.events import wake_rendering_core
from session_sniffer.settings.settings import Settings

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence
    from pathlib import Path

    from PySide6.QtCore import QAbstractItemModel

CANONICAL_HEADER_ROLE: Final[int] = int(Qt.ItemDataRole.UserRole) + 64
CANONICAL_HEADER_TOOLTIP_ROLE: Final[int] = int(Qt.ItemDataRole.UserRole) + 65

_REFRESH_HOOKS: list[tuple[weakref.ref[QObject], Callable[[], None]]] = []


@dataclass(slots=True)
class _LanguageSyncState:
    applying: bool = False
    watcher_installed: bool = False
    dialog_follow_checkbox: weakref.ref[QCheckBox] | None = None


_SYNC_STATE = _LanguageSyncState()


def set_table_headers(
    table: QTableWidget,
    canonical_headers: Sequence[str],
    tooltips: Mapping[str, str] | None = None,
) -> None:
    """Populate *table*'s horizontal headers with translated labels while storing canonical keys."""
    for col_index, canonical_header in enumerate(canonical_headers):
        item = table.horizontalHeaderItem(col_index)
        if item is None:
            item = QTableWidgetItem()
            table.setHorizontalHeaderItem(col_index, item)
        item.setData(CANONICAL_HEADER_ROLE, canonical_header)
        item.setText(tr(canonical_header))
        if tooltips is not None and canonical_header in tooltips:
            canonical_tooltip = tooltips[canonical_header]
            item.setData(CANONICAL_HEADER_TOOLTIP_ROLE, canonical_tooltip)
            item.setToolTip(tr(canonical_tooltip))


def set_tree_headers(
    tree: QTreeWidget,
    canonical_headers: Sequence[str],
    tooltips: Mapping[str, str] | None = None,
) -> None:
    """Populate *tree*'s column headers with translated labels while storing canonical keys."""
    header_item = tree.headerItem()
    for col_index, canonical_header in enumerate(canonical_headers):
        header_item.setData(col_index, CANONICAL_HEADER_ROLE, canonical_header)
        header_item.setText(col_index, tr(canonical_header))
        if tooltips is not None and canonical_header in tooltips:
            canonical_tooltip = tooltips[canonical_header]
            header_item.setData(col_index, CANONICAL_HEADER_TOOLTIP_ROLE, canonical_tooltip)
            header_item.setToolTip(col_index, tr(canonical_tooltip))


def set_i18n_colon_label(label: QLabel, canonical_text: str) -> None:
    """Set *label* to translated *canonical_text* followed by a colon and track it for live switching."""
    rendered = f'{tr(canonical_text)}:'
    label.setProperty('_ss_i18n_colon_canon', canonical_text)
    label.setProperty('_ss_i18n_colon_last', rendered)
    if label.text() != rendered:
        label.setText(rendered)


def add_i18n_menu_actions(
    parent: QObject,
    menu: QMenu,
    icons_dir: Path,
    specs: Sequence[tuple[str, str, str, Callable[[], object]] | None],
    records: list[tuple[QAction, str, str]],
) -> list[QAction]:
    """Populate *menu* from *(icon_name, text_key, tooltip_key, callback)* specs and record actions for retranslation."""
    created: list[QAction] = []
    for spec in specs:
        if spec is None:
            menu.addSeparator()
            continue
        icon_name, text_key, tooltip_key, callback = spec
        action = QAction(QIcon(str(icons_dir / icon_name)), tr(text_key), parent)
        action.setToolTip(tr(tooltip_key))
        action.triggered.connect(callback)
        menu.addAction(action)
        records.append((action, text_key, tooltip_key))
        created.append(action)
    return created


def register_language_refresh(owner: QObject, callback: Callable[[], None]) -> None:
    """Register *callback* to run after a live language switch while *owner* remains alive."""
    _REFRESH_HOOKS.append((weakref.ref(owner), callback))


def _should_skip_widget(widget: QWidget) -> bool:
    return (
        not isValid(widget)
        or widget.objectName().startswith(('qt_', '_q_'))
        or isinstance(widget.parentWidget(), (QLineEdit, QAbstractSpinBox))
    )


def _resolve_canonical_with_leading_space(
    rendered_text: str,
    *,
    previous_language: str,
    escape_ampersand: bool,
) -> tuple[str, str] | None:
    normalized = rendered_text.replace('&&', '&') if escape_ampersand else rendered_text
    if (direct := lookup_canonical_message(normalized, from_language=previous_language)) is not None:
        return direct, ''
    if normalized.startswith(' ') and not normalized.startswith('  ') and not normalized.endswith(' '):
        stripped = normalized[1:]
        if (inner := lookup_canonical_message(stripped, from_language=previous_language)) is not None:
            return inner, ' '
    return None


_TAB_PAIR_LENGTH: Final[int] = 2


def _parse_tab_property_map(raw_map: object) -> dict[str, tuple[str, str]]:
    parsed: dict[str, tuple[str, str]] = {}
    if not isinstance(raw_map, dict):
        return parsed
    for key_obj, value_obj in cast('dict[object, object]', raw_map).items():
        if not isinstance(key_obj, str) or not isinstance(value_obj, tuple):
            continue
        pair = cast('tuple[object, ...]', value_obj)
        if len(pair) == _TAB_PAIR_LENGTH and isinstance(pair[0], str) and isinstance(pair[1], str):
            parsed[key_obj] = (pair[0], pair[1])
    return parsed


def _retranslate_object_property(
    holder: QObject,
    prop_prefix: str,
    current_value: str,
    setter: Callable[[str], None],
    *,
    previous_language: str,
) -> None:
    if not current_value:
        return

    escape_ampersand = isinstance(holder, QGroupBox) and prop_prefix == 'title'
    canon_prop = f'_ss_i18n_{prop_prefix}_canon'
    prefix_prop = f'_ss_i18n_{prop_prefix}_prefix'
    last_prop = f'_ss_i18n_{prop_prefix}_last'

    stored_canon = holder.property(canon_prop)
    stored_prefix = holder.property(prefix_prop)
    stored_last = holder.property(last_prop)

    canonical: str | None = None
    leading_prefix = ''
    if isinstance(stored_canon, str) and isinstance(stored_last, str) and stored_last == current_value:
        canonical = stored_canon
        leading_prefix = stored_prefix if isinstance(stored_prefix, str) else ''
    elif (resolved := _resolve_canonical_with_leading_space(
        current_value,
        previous_language=previous_language,
        escape_ampersand=escape_ampersand,
    )) is not None:
        canonical, leading_prefix = resolved

    if canonical is None:
        return

    translated = f'{leading_prefix}{tr(canonical)}'
    rendered = translated.replace('&', '&&') if escape_ampersand else translated
    holder.setProperty(canon_prop, canonical)
    holder.setProperty(prefix_prop, leading_prefix)
    holder.setProperty(last_prop, rendered)
    if rendered != current_value:
        setter(rendered)


def _retranslate_tab_widget(widget: QTabWidget, *, previous_language: str) -> None:
    text_map = _parse_tab_property_map(widget.property('_ss_i18n_tab_texts'))
    tip_map = _parse_tab_property_map(widget.property('_ss_i18n_tab_tips'))

    for tab_idx in range(widget.count()):
        idx_key = str(tab_idx)
        cur_tab_text = widget.tabText(tab_idx)
        if cur_tab_text:
            canon_pair = text_map.get(idx_key)
            tab_canon = canon_pair[0] if canon_pair is not None and canon_pair[1] == cur_tab_text else lookup_canonical_message(cur_tab_text, from_language=previous_language)
            if tab_canon is not None:
                rendered_text = tr(tab_canon)
                text_map[idx_key] = (tab_canon, rendered_text)
                if rendered_text != cur_tab_text:
                    widget.setTabText(tab_idx, rendered_text)

        cur_tab_tip = widget.tabToolTip(tab_idx)
        if cur_tab_tip:
            tip_pair = tip_map.get(idx_key)
            tip_canon = tip_pair[0] if tip_pair is not None and tip_pair[1] == cur_tab_tip else lookup_canonical_message(cur_tab_tip, from_language=previous_language)
            if tip_canon is not None:
                rendered_tip = tr(tip_canon)
                tip_map[idx_key] = (tip_canon, rendered_tip)
                if rendered_tip != cur_tab_tip:
                    widget.setTabToolTip(tab_idx, rendered_tip)

    if text_map:
        widget.setProperty('_ss_i18n_tab_texts', text_map)
    if tip_map:
        widget.setProperty('_ss_i18n_tab_tips', tip_map)


def _retranslate_combobox(combo: QComboBox, *, previous_language: str) -> None:
    with QSignalBlocker(combo):
        for index in range(combo.count()):
            user_data = combo.itemData(index, Qt.ItemDataRole.UserRole)
            if isinstance(user_data, str):
                if user_data in SUPPORTED_LANGUAGES:
                    expected = SUPPORTED_LANGUAGES[user_data]
                    if combo.itemText(index) != expected:
                        combo.setItemText(index, expected)
                    continue
                canonical = lookup_canonical_message(user_data, from_language=DEFAULT_LANGUAGE)
                if canonical is not None:
                    translated = tr(canonical)
                    if combo.itemText(index) != translated:
                        combo.setItemText(index, translated)
                    continue
            current_item_text = combo.itemText(index)
            if current_item_text:
                canonical = lookup_canonical_message(current_item_text, from_language=previous_language)
                if canonical is not None:
                    translated = tr(canonical)
                    if combo.itemText(index) != translated:
                        combo.setItemText(index, translated)


def _retranslate_table_widget(table: QTableWidget, *, previous_language: str) -> None:
    for col_index in range(table.columnCount()):
        header_item = table.horizontalHeaderItem(col_index)
        if header_item is None:
            continue
        raw_canon = header_item.data(CANONICAL_HEADER_ROLE)
        canonical = raw_canon if isinstance(raw_canon, str) else lookup_canonical_message(header_item.text(), from_language=previous_language)
        if canonical is not None:
            header_item.setData(CANONICAL_HEADER_ROLE, canonical)
            translated = tr(canonical)
            if header_item.text() != translated:
                header_item.setText(translated)

        raw_tip_canon = header_item.data(CANONICAL_HEADER_TOOLTIP_ROLE)
        tip_canon = raw_tip_canon if isinstance(raw_tip_canon, str) else lookup_canonical_message(header_item.toolTip(), from_language=previous_language)
        if tip_canon is not None:
            header_item.setData(CANONICAL_HEADER_TOOLTIP_ROLE, tip_canon)
            translated_tip = tr(tip_canon)
            if header_item.toolTip() != translated_tip:
                header_item.setToolTip(translated_tip)


def _retranslate_tree_widget(tree: QTreeWidget, *, previous_language: str) -> None:
    header_item = tree.headerItem()
    for col_index in range(tree.columnCount()):
        raw_canon = header_item.data(col_index, CANONICAL_HEADER_ROLE)
        canonical = raw_canon if isinstance(raw_canon, str) else lookup_canonical_message(header_item.text(col_index), from_language=previous_language)
        if canonical is not None:
            header_item.setData(col_index, CANONICAL_HEADER_ROLE, canonical)
            translated = tr(canonical)
            if header_item.text(col_index) != translated:
                header_item.setText(col_index, translated)

        raw_tip_canon = header_item.data(col_index, CANONICAL_HEADER_TOOLTIP_ROLE)
        tip_canon = raw_tip_canon if isinstance(raw_tip_canon, str) else lookup_canonical_message(header_item.toolTip(col_index), from_language=previous_language)
        if tip_canon is not None:
            header_item.setData(col_index, CANONICAL_HEADER_TOOLTIP_ROLE, tip_canon)
            translated_tip = tr(tip_canon)
            if header_item.toolTip(col_index) != translated_tip:
                header_item.setToolTip(col_index, translated_tip)


def _retranslate_single_widget(widget: QWidget, *, previous_language: str, seen_actions: set[int]) -> None:
    if _should_skip_widget(widget):
        return

    if widget.isWindow():
        _retranslate_object_property(widget, 'title', widget.windowTitle(), widget.setWindowTitle, previous_language=previous_language)

    _retranslate_object_property(widget, 'tooltip', widget.toolTip(), widget.setToolTip, previous_language=previous_language)

    for action in widget.actions():
        action_id = id(action)
        if action_id in seen_actions or not isValid(action):
            continue
        seen_actions.add(action_id)
        _retranslate_object_property(action, 'text', action.text(), action.setText, previous_language=previous_language)
        _retranslate_object_property(action, 'tooltip', action.toolTip(), action.setToolTip, previous_language=previous_language)

    if isinstance(widget, QLabel):
        colon_canon = widget.property('_ss_i18n_colon_canon')
        colon_last = widget.property('_ss_i18n_colon_last')
        if isinstance(colon_canon, str) and isinstance(colon_last, str) and colon_last == widget.text():
            set_i18n_colon_label(widget, colon_canon)
        else:
            _retranslate_object_property(widget, 'text', widget.text(), widget.setText, previous_language=previous_language)
    elif isinstance(widget, QAbstractButton):
        _retranslate_object_property(widget, 'text', widget.text(), widget.setText, previous_language=previous_language)
    elif isinstance(widget, QGroupBox):
        _retranslate_object_property(widget, 'title', widget.title(), widget.setTitle, previous_language=previous_language)
    elif isinstance(widget, QLineEdit):
        _retranslate_object_property(widget, 'placeholder', widget.placeholderText(), widget.setPlaceholderText, previous_language=previous_language)
    elif isinstance(widget, (QSpinBox, QDoubleSpinBox)):
        _retranslate_object_property(widget, 'suffix', widget.suffix(), widget.setSuffix, previous_language=previous_language)
        _retranslate_object_property(widget, 'special', widget.specialValueText(), widget.setSpecialValueText, previous_language=previous_language)
    elif isinstance(widget, QTabWidget):
        _retranslate_tab_widget(widget, previous_language=previous_language)
    elif isinstance(widget, QComboBox):
        _retranslate_combobox(widget, previous_language=previous_language)

    if isinstance(widget, QTableWidget):
        _retranslate_table_widget(widget, previous_language=previous_language)
    elif isinstance(widget, QTreeWidget):
        _retranslate_tree_widget(widget, previous_language=previous_language)
    elif isinstance(widget, QAbstractItemView):
        if (
            isinstance(widget, (QTableView, QTreeView))
            and (model := cast('QAbstractItemModel | None', widget.model())) is not None
            and not isinstance(model, QAbstractListModel)
            and (col_count := model.columnCount()) > 0
        ):
            model.headerDataChanged.emit(Qt.Orientation.Horizontal, 0, col_count - 1)
        if widget.isVisible():
            widget.viewport().update()


def retranslate_widget_tree(root: QWidget | None = None, *, previous_language: str) -> None:
    """Retranslate all live widgets (or descendants of *root*) from *previous_language* to active language."""
    widgets = [root, *root.findChildren(QWidget)] if root is not None else list(QApplication.allWidgets())
    seen_actions: set[int] = set()
    for widget in widgets:
        _retranslate_single_widget(widget, previous_language=previous_language, seen_actions=seen_actions)


def set_live_follow_system_language_checkbox(checkbox: QCheckBox | None) -> None:
    """Track an open `SettingsDialog` Follow System Language checkbox so OS locale changes respect unsaved previews."""
    _SYNC_STATE.dialog_follow_checkbox = weakref.ref(checkbox) if checkbox is not None else None


class _LocaleChangeWatcher(QObject):
    """Application-level event filter reacting to OS locale changes when following system language."""

    @override
    def eventFilter(self, watched: QObject, event: QEvent) -> bool:
        if watched is QCoreApplication.instance() and event.type() == QEvent.Type.LocaleChange and not _SYNC_STATE.applying:
            checkbox = _SYNC_STATE.dialog_follow_checkbox() if _SYNC_STATE.dialog_follow_checkbox is not None else None
            follow_active = (
                checkbox.isChecked()
                if checkbox is not None and isValid(checkbox) and checkbox.window().isVisible()
                else Settings.gui_language_follow_system
            )
            if follow_active:
                apply_runtime_language(resolve_effective_language(language='', follow_system=True), wake_renderer=True)
        return False


_LOCALE_WATCHER = _LocaleChangeWatcher(app)


def install_system_language_watcher() -> None:
    """Apply the startup language from `Settings` and watch OS locale changes."""
    effective_language = resolve_effective_language(
        language=Settings.gui_language,
        follow_system=Settings.gui_language_follow_system,
    )
    set_active_language(effective_language)
    if not _SYNC_STATE.watcher_installed:
        _SYNC_STATE.watcher_installed = True
        app.installEventFilter(_LOCALE_WATCHER)


def apply_runtime_language(target_language: str | None = None, *, wake_renderer: bool = True) -> bool:
    """Synchronize the active language with *target_language* (or `Settings`), retranslate live widgets, and invoke refresh hooks.

    Returns:
        `True` if the effective language changed, `False` otherwise.
    """
    previous_language = get_active_language()
    effective_language = (
        resolve_effective_language(
            language=Settings.gui_language,
            follow_system=Settings.gui_language_follow_system,
        )
        if target_language is None
        else (normalize_language_code(target_language) or DEFAULT_LANGUAGE)
    )
    changed = set_active_language(effective_language)
    if not changed:
        return False

    _SYNC_STATE.applying = True
    try:
        retranslate_widget_tree(previous_language=previous_language)

        alive_hooks: list[tuple[weakref.ref[QObject], Callable[[], None]]] = []
        for owner_ref, callback in _REFRESH_HOOKS:
            owner = owner_ref()
            if owner is not None and isValid(owner):
                alive_hooks.append((owner_ref, callback))
                callback()
        _REFRESH_HOOKS[:] = alive_hooks
    finally:
        _SYNC_STATE.applying = False

    if wake_renderer:
        wake_rendering_core()
    return True
