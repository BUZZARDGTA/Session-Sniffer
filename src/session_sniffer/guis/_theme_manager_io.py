"""File and clipboard import/export dialogs and confirmation helpers for `ThemeManagerDialog`."""

import re
from pathlib import Path
from typing import TYPE_CHECKING, Literal, cast

from pydantic import ValidationError
from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication, QFileDialog, QMenu, QMessageBox, QPushButton, QWidget

from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis.live_theme import apply_runtime_theme, resolve_theme_by_name
from session_sniffer.guis.stylesheets import SVG_ICON_CONTEXT_MENU_STYLESHEET
from session_sniffer.guis.theming import (
    BUILTIN_THEME_NAMES,
    DEFAULT_THEME_NAME,
    ICONS_DIR_PATH,
    CustomThemeModel,
    Theme,
    ThemesFile,
    get_active_theme,
    save_themes_file,
)
from session_sniffer.i18n import tr, tr_plural
from session_sniffer.settings.settings import Settings

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from PySide6.QtCore import QPoint

_MAX_DELETE_LISTED_NAMES = 10


type ThemeListMenuAction = Literal['apply', 'new', 'duplicate', 'copy_json', 'export', 'delete']


def configure_action_button(button: QPushButton, stylesheet: str, slot: Callable[[], None], tooltip: str = '') -> QPushButton:
    """Apply standard non-default dialog button styling, cursor, and click handler to *button*."""
    if tooltip:
        button.setToolTip(tooltip)
    button.setStyleSheet(stylesheet)
    button.setCursor(Qt.CursorShape.PointingHandCursor)
    button.setAutoDefault(False)
    button.clicked.connect(slot)
    return button


def validate_custom_theme_name(proposed_name: str, existing_custom_casefold: set[str]) -> str | None:
    """Return a localized validation error if *proposed_name* is empty, reserved, or duplicate, else `None`."""
    if not proposed_name:
        return tr('Theme name cannot be empty.')
    if proposed_name.casefold() in BUILTIN_THEME_NAMES:
        return tr('"{name}" is reserved by a built-in theme. Choose a different name.', name=proposed_name)
    if proposed_name.casefold() in existing_custom_casefold:
        return tr('A custom theme named "{name}" already exists.', name=proposed_name)
    return None


def format_selection_status_text(theme: Theme, *, multi_count: int, custom_selected_count: int) -> str:
    """Return the localized editor status hint for the current theme list selection."""
    if not multi_count:
        return tr('No theme selected — click a theme in the list to view or edit it.')
    if multi_count > 1:
        if custom_selected_count > 0:
            return tr(
                '{total} themes selected ({custom} custom) — select a single custom theme to edit its name or colors.',
                total=multi_count,
                custom=custom_selected_count,
            )
        return tr('{count} built-in presets selected — click Duplicate ({count}) to create editable copies.', count=multi_count)
    if theme.builtin:
        return tr('Built-in preset (read-only) — click Duplicate to create an editable copy.')
    return tr('Custom theme — color and name changes are saved automatically.')


def sync_persisted_theme_after_rename(old_name: str, new_name: str) -> None:
    """Keep persisted `Settings.gui_theme` and the active runtime theme aligned after a custom theme rename."""
    if Settings.gui_theme.casefold() == old_name.casefold():
        Settings.gui_theme = new_name
        Settings.rewrite_settings_file()
    if get_active_theme().name.casefold() == old_name.casefold():
        apply_runtime_theme(resolve_theme_by_name(new_name))


def sync_persisted_theme_after_delete(raw_deleted_names: object) -> set[str]:
    """Fall back to `DEFAULT_THEME_NAME` if any deleted custom theme was persisted or active; return deleted casefold names."""
    if not isinstance(raw_deleted_names, tuple):
        return set()
    deleted_items = cast('tuple[object, ...]', raw_deleted_names)
    deleted_cf = {name.casefold() for name in deleted_items if isinstance(name, str)}
    if not deleted_cf:
        return set()
    if Settings.gui_theme.casefold() in deleted_cf:
        Settings.gui_theme = DEFAULT_THEME_NAME
        Settings.rewrite_settings_file()
    if get_active_theme().name.casefold() in deleted_cf:
        apply_runtime_theme(resolve_theme_by_name(DEFAULT_THEME_NAME))
    return deleted_cf


def exec_theme_list_context_menu(
    parent: QWidget,
    global_pos: QPoint,
    *,
    total_selected: int,
    selected_custom: Sequence[CustomThemeModel],
    can_apply: bool,
) -> ThemeListMenuAction | None:
    """Show the theme-list right-click context menu at *global_pos* and return the chosen action key."""
    custom_count = len(selected_custom)
    menu = QMenu(parent)
    menu.setStyleSheet(SVG_ICON_CONTEXT_MENU_STYLESHEET)

    actions: dict[object, ThemeListMenuAction] = {}
    if total_selected == 1:
        apply_action = menu.addAction(QIcon(str(ICONS_DIR_PATH / 'check.svg')), tr('Apply Theme'))
        apply_action.setEnabled(can_apply)
        actions[apply_action] = 'apply'
        menu.addSeparator()

    actions[menu.addAction(QIcon(str(ICONS_DIR_PATH / 'plus.svg')), tr('New Custom Theme'))] = 'new'
    if total_selected > 0:
        dup_label = tr('Duplicate ({count})', count=total_selected) if total_selected > 1 else tr('Duplicate')
        actions[menu.addAction(QIcon(str(ICONS_DIR_PATH / 'copy.svg')), dup_label)] = 'duplicate'
        actions[menu.addAction(QIcon(str(ICONS_DIR_PATH / 'code.svg')), tr('Copy JSON'))] = 'copy_json'

    if custom_count > 0:
        export_label = (
            tr('Export Selected Custom Themes ({count})…', count=custom_count)
            if custom_count > 1
            else tr('Export "{name}"…', name=selected_custom[0].name)
        )
        actions[menu.addAction(QIcon(str(ICONS_DIR_PATH / 'upload.svg')), export_label)] = 'export'
        menu.addSeparator()
        delete_label = tr('Delete Custom Themes ({count})', count=custom_count) if custom_count > 1 else tr('Delete Custom Theme')
        actions[menu.addAction(QIcon(str(ICONS_DIR_PATH / 'trash.svg')), delete_label)] = 'delete'

    chosen = menu.exec(global_pos)
    return actions.get(chosen)


def format_delete_confirmation(targets: Sequence[CustomThemeModel]) -> str:
    """Build the confirmation message for deleting one or more custom themes."""
    if len(targets) == 1:
        return tr('Delete custom theme "{name}"?\n\nThis action cannot be undone.', name=targets[0].name)
    listed_lines = [f'• {model.name}' for model in targets[:_MAX_DELETE_LISTED_NAMES]]
    if len(targets) > _MAX_DELETE_LISTED_NAMES:
        listed_lines.append(tr('…and {count} more', count=len(targets) - _MAX_DELETE_LISTED_NAMES))
    names_block = '\n'.join(listed_lines)
    return tr('Delete {count} custom themes?\n\n{names}\n\nThis action cannot be undone.', count=len(targets), names=names_block)


def prompt_import_source_choice(parent: QWidget, anchor_button: QPushButton) -> Literal['file', 'clipboard'] | None:
    """Show the Import popup menu under *anchor_button* and return `'file'`, `'clipboard'`, or `None`."""
    menu = QMenu(parent)
    menu.setStyleSheet(SVG_ICON_CONTEXT_MENU_STYLESHEET)
    from_file_action = menu.addAction(QIcon(str(ICONS_DIR_PATH / 'folder.svg')), tr('Import from JSON File…'))
    from_clipboard_action = menu.addAction(QIcon(str(ICONS_DIR_PATH / 'copy.svg')), tr('Import from Clipboard'))
    chosen = menu.exec(anchor_button.mapToGlobal(anchor_button.rect().bottomLeft()))
    if chosen == from_file_action:
        return 'file'
    if chosen == from_clipboard_action:
        return 'clipboard'
    return None


def prompt_import_themes_from_file(parent: QWidget) -> ThemesFile | None:
    """Prompt the user to pick a JSON file and return its validated `ThemesFile`, or `None`."""
    file_path, _ = QFileDialog.getOpenFileName(parent, tr('Import Custom Themes'), '', tr('JSON Files (*.json);;All Files (*.*)'))
    if not file_path:
        return None
    try:
        imported_file = ThemesFile.model_validate_json(Path(file_path).read_text(encoding='utf-8'))
    except (OSError, UnicodeDecodeError, ValidationError) as e:
        QMessageBox.critical(parent, TITLE, tr('Failed to import themes:\n\n{error}', error=e))
        return None
    if not imported_file.custom_themes:
        QMessageBox.information(parent, TITLE, tr('The selected file does not contain any custom themes.'))
        return None
    return imported_file


def read_themes_from_clipboard(parent: QWidget) -> ThemesFile | None:
    """Read and validate a `themes.json` payload from the system clipboard, or return `None`."""
    raw_text = QApplication.clipboard().text().strip()
    if not raw_text:
        QMessageBox.information(parent, TITLE, tr('The clipboard is empty. Copy a themes.json snippet first.'))
        return None
    try:
        imported_file = ThemesFile.model_validate_json(raw_text)
    except ValidationError as e:
        QMessageBox.critical(parent, TITLE, tr('Failed to import themes from clipboard:\n\n{error}', error=e))
        return None
    if not imported_file.custom_themes:
        QMessageBox.information(parent, TITLE, tr('The clipboard JSON does not contain any custom themes.'))
        return None
    return imported_file


def _write_exported_themes(parent: QWidget, themes_to_export: list[CustomThemeModel], suggested_filename: str) -> None:
    file_path, _ = QFileDialog.getSaveFileName(parent, tr('Export Custom Themes'), suggested_filename, tr('JSON Files (*.json);;All Files (*.*)'))
    if not file_path:
        return
    export_payload = ThemesFile(custom_themes=themes_to_export)
    try:
        save_themes_file(export_payload, Path(file_path))
    except OSError as e:
        QMessageBox.critical(parent, TITLE, tr('Failed to export themes:\n\n{error}', error=e))
        return
    count = len(themes_to_export)
    QMessageBox.information(
        parent,
        TITLE,
        tr_plural('Exported {count} custom theme successfully.', 'Exported {count} custom themes successfully.', count),
    )


def export_custom_models_selection(parent: QWidget, models: list[CustomThemeModel]) -> None:
    """Export *models* to a user-chosen JSON file with a sensible suggested filename."""
    if not models:
        return
    if len(models) == 1:
        safe_stem = re.sub(r'[<>:"/\\|?*]+', '_', models[0].name).strip() or 'theme'
        _write_exported_themes(parent, models, f'{safe_stem}.json')
        return
    _write_exported_themes(parent, models, 'selected_themes.json')


def export_themes_interactive(
    parent: QWidget,
    anchor_button: QPushButton,
    all_custom: list[CustomThemeModel],
    selected_custom: list[CustomThemeModel],
) -> None:
    """Export selected or all custom themes, offering a popup menu when a partial subset is selected."""
    total_custom = len(all_custom)
    if not total_custom:
        return

    custom_count = len(selected_custom)
    if 0 < custom_count < total_custom:
        menu = QMenu(parent)
        menu.setStyleSheet(SVG_ICON_CONTEXT_MENU_STYLESHEET)
        selected_label = (
            tr('Export Selected Custom Themes ({count})…', count=custom_count)
            if custom_count > 1
            else tr('Export "{name}"…', name=selected_custom[0].name)
        )
        export_selected_action = menu.addAction(QIcon(str(ICONS_DIR_PATH / 'upload.svg')), selected_label)
        export_all_action = menu.addAction(
            QIcon(str(ICONS_DIR_PATH / 'upload.svg')),
            tr('Export All Custom Themes ({count})…', count=total_custom),
        )
        chosen_action = menu.exec(anchor_button.mapToGlobal(anchor_button.rect().bottomLeft()))
        if chosen_action == export_selected_action:
            export_custom_models_selection(parent, selected_custom)
        elif chosen_action == export_all_action:
            _write_exported_themes(parent, all_custom, 'themes.json')
        return

    if custom_count == 1:
        export_custom_models_selection(parent, selected_custom)
        return

    _write_exported_themes(parent, all_custom, 'themes.json')
