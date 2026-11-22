"""Theme Manager dialog for creating, duplicating, editing, importing, and exporting custom themes."""

import re
from dataclasses import replace
from typing import TYPE_CHECKING, override

from PySide6.QtCore import QItemSelectionModel, QPoint, QSignalBlocker, Qt, Signal
from PySide6.QtGui import QIcon, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QDialog,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.local import THEMES_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis._theme_manager_io import (
    configure_action_button,
    exec_theme_list_context_menu,
    export_custom_models_selection,
    export_themes_interactive,
    format_delete_confirmation,
    format_selection_status_text,
    prompt_import_source_choice,
    prompt_import_themes_from_file,
    read_themes_from_clipboard,
    validate_custom_theme_name,
)
from session_sniffer.guis._theme_palette_grid import (
    PaletteEditorCallbacks,
    build_palette_group,
    pick_color_with_live_preview,
    show_full_palette_preset_menu,
)
from session_sniffer.guis._theme_preview_card import (
    PREVIEW_BASE_QSS,
    build_theme_preview_tabs,
    create_theme_list_icon,
    token_swatch_stylesheet,
)
from session_sniffer.guis.delegates import ElidedTextTooltipDelegate
from session_sniffer.guis.live_language import register_language_refresh, set_i18n_colon_label
from session_sniffer.guis.live_theme import apply_runtime_theme, register_post_theme_refresh
from session_sniffer.guis.loading_overlay import loading_overlay_scope
from session_sniffer.guis.stylesheets import (
    COMPACT_BUTTON_STYLESHEET,
    COMPACT_DANGER_BUTTON_STYLESHEET,
    DIALOG_BUTTON_STYLESHEET,
    DIALOG_PRIMARY_BUTTON_STYLESHEET,
)
from session_sniffer.guis.theming import (
    DARK_THEME_COLORS,
    DEFAULT_THEME_NAME,
    ICONS_DIR_PATH,
    THEME_COLOR_TOKENS,
    THEME_NAME_MAX_LENGTH,
    CustomThemeModel,
    Theme,
    ThemeColors,
    ThemeColorsModel,
    ThemesFile,
    build_exportable_themes_json,
    detect_system_theme_name,
    get_active_theme,
    load_themes_file,
    make_unique_theme_name,
    save_themes_file,
    themed_qss,
)
from session_sniffer.guis.theming._engine import ThemeTransform
from session_sniffer.guis.utils import (
    animate_button_feedback,
    resize_window_for_screen,
    scale_by_ui,
    set_clipboard_text,
    set_dialog_window_flags,
)
from session_sniffer.i18n import tr, tr_plural
from session_sniffer.settings.settings import Settings

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

    from PySide6.QtGui import QCloseEvent, QKeyEvent

_HEX_COLOR_RE = re.compile(r'^#?[0-9a-fA-F]{6}$')

_STATUS_LABEL_STYLESHEET = themed_qss('color: @text_muted; font-size: 8.5pt; background: transparent;')
_ERROR_STATUS_LABEL_STYLESHEET = themed_qss('color: @danger; font-size: 8.5pt; background: transparent;')


class ThemeManagerDialog(QDialog):
    """Manager dialog for applying, creating, editing, duplicating, deleting, importing, and exporting themes."""

    themes_changed = Signal()
    theme_applied = Signal(str)
    theme_renamed = Signal(str, str)
    themes_deleted = Signal(object)
    follow_system_toggled = Signal(bool)

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        initial_theme_name: str = DEFAULT_THEME_NAME,
        follow_system: bool | None = None,
        manual_theme_name: str | None = None,
        themes_path: Path = THEMES_PATH,
    ) -> None:
        """Initialize the Theme Manager dialog and load `themes.json`."""
        super().__init__(parent)
        self._themes_path = themes_path
        self._themes_file, load_error = load_themes_file(self._themes_path)
        self._selected_theme_name: str = DEFAULT_THEME_NAME
        self._manual_theme_name: str = manual_theme_name or initial_theme_name or Settings.gui_theme
        self._edited_theme_name: str | None = None
        self._live_preview_colors: ThemeColors | None = None
        self._live_name_override: str | None = None
        self._populating_editor = False
        self._committing_rename = False

        self.setWindowTitle(f"{tr('Theme Manager')} - {TITLE}")
        self.setWindowIcon(QIcon(str(ICONS_DIR_PATH / 'palette.svg')))
        set_dialog_window_flags(self)
        self.setWindowModality(Qt.WindowModality.WindowModal)
        self.setMinimumSize(scale_by_ui(980), scale_by_ui(660))
        resize_window_for_screen(self)

        self._swatch_buttons: dict[str, QPushButton] = {}
        self._hex_edits: dict[str, QLineEdit] = {}
        self._follow_system_checkbox = QCheckBox(tr('Follow System Theme'))
        self._follow_system_checkbox.setChecked(Settings.gui_theme_follow_system if follow_system is None else follow_system)
        self._theme_list = QListWidget()
        self._new_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'plus.svg')), f" {tr('New')}")
        self._duplicate_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'copy.svg')), f" {tr('Duplicate')}")
        self._import_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'import.svg')), f" {tr('Import…')}")
        self._export_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'upload.svg')), f" {tr('Export…')}")
        self._delete_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'trash.svg')), f" {tr('Delete Custom Theme')}")
        self._name_edit = QLineEdit()
        self._reset_palette_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'rotate-ccw.svg')), f" {tr('Copy Preset…')}")
        self._apply_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'check.svg')), f" {tr('Apply Theme')}")
        self._mode_status_label = QLabel()
        self._preview_root = QFrame()
        self._json_output = QPlainTextEdit()
        self._copy_json_button = QPushButton()

        self._build_ui()
        effective_initial = detect_system_theme_name() if self._follow_system_checkbox.isChecked() else initial_theme_name
        self._rebuild_theme_list(select_names=[effective_initial])
        register_language_refresh(self, self._on_language_refreshed)
        register_post_theme_refresh(self, self._sync_active_theme_indicators)

        if load_error is not None:
            QMessageBox.warning(self, TITLE, tr('{error}\n\nDefault built-in themes have been loaded.', error=load_error))

    def _on_language_refreshed(self) -> None:
        """Refresh dynamic titles, theme badges, and selection status after a live language change."""
        self.setWindowTitle(f"{tr('Theme Manager')} - {TITLE}")
        for row in range(self._theme_list.count()):
            item = self._theme_list.item(row)
            raw_name = item.data(Qt.ItemDataRole.UserRole)
            if isinstance(raw_name, str) and (found := self._themes_file.find_theme(raw_name)) is not None:
                item.setText(tr('{name} (Built-in)', name=found.name) if found.builtin else found.name)
        self._sync_selection_state()

    @property
    def selected_theme_name(self) -> str:
        """Return the currently selected theme name in the manager list."""
        return self._selected_theme_name

    @property
    def follow_system_enabled(self) -> bool:
        """Return whether the Follow System Theme checkbox is currently checked."""
        return self._follow_system_checkbox.isChecked()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        root_layout = QVBoxLayout(self)
        root_layout.setSpacing(10)

        panes_layout = QHBoxLayout()
        panes_layout.setSpacing(12)
        panes_layout.addWidget(self._build_left_pane(), 0)
        panes_layout.addWidget(self._build_right_pane(), 1)
        root_layout.addLayout(panes_layout, 1)

        footer_layout = QHBoxLayout()
        footer_note = QLabel(tr('Custom theme changes are saved automatically. Right-click any token to reset it from a built-in preset.'))
        footer_note.setStyleSheet(_STATUS_LABEL_STYLESHEET)
        footer_layout.addWidget(footer_note)
        footer_layout.addStretch()
        footer_layout.addWidget(configure_action_button(self._apply_button, DIALOG_PRIMARY_BUTTON_STYLESHEET, self._apply_selected_theme))
        footer_layout.addWidget(
            configure_action_button(QPushButton(QIcon(str(ICONS_DIR_PATH / 'x.svg')), f" {tr('Close')}"), DIALOG_BUTTON_STYLESHEET, self._on_close_clicked),
        )
        root_layout.addLayout(footer_layout)

    def _build_left_pane(self) -> QGroupBox:
        group = QGroupBox(tr('Themes'))
        group.setFixedWidth(scale_by_ui(300))
        layout = QVBoxLayout(group)
        layout.setSpacing(8)

        self._follow_system_checkbox.setCursor(Qt.CursorShape.PointingHandCursor)
        self._follow_system_checkbox.setToolTip(tr('Automatically apply the built-in Dark or Light theme to match your operating system color scheme.'))
        self._follow_system_checkbox.toggled.connect(self._on_follow_system_toggled)
        layout.addWidget(self._follow_system_checkbox)

        self._theme_list.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self._theme_list.setItemDelegate(ElidedTextTooltipDelegate(self._theme_list))
        self._theme_list.setToolTip(tr('Double-click a theme to apply it live. Hold Ctrl or Shift while clicking to select multiple themes.'))
        self._theme_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._theme_list.customContextMenuRequested.connect(self._show_theme_list_context_menu)
        self._theme_list.itemSelectionChanged.connect(self._on_theme_selection_changed)
        self._theme_list.currentRowChanged.connect(self._on_current_row_changed)
        self._theme_list.itemDoubleClicked.connect(self._on_theme_item_double_clicked)

        delete_shortcut = QShortcut(QKeySequence(Qt.Key.Key_Delete), self._theme_list)
        delete_shortcut.setContext(Qt.ShortcutContext.WidgetShortcut)
        delete_shortcut.activated.connect(self._delete_selected_themes)
        layout.addWidget(self._theme_list, 1)

        top_buttons = QHBoxLayout()
        top_buttons.setSpacing(6)
        top_buttons.addWidget(
            configure_action_button(self._new_button, COMPACT_BUTTON_STYLESHEET, self._create_new_theme, tr('Create a new custom theme initialized from the selected theme')),
        )
        top_buttons.addWidget(
            configure_action_button(
                self._duplicate_button, COMPACT_BUTTON_STYLESHEET, self._duplicate_selected_themes, tr('Duplicate the selected theme as a new editable custom theme'),
            ),
        )
        layout.addLayout(top_buttons)

        bottom_buttons = QHBoxLayout()
        bottom_buttons.setSpacing(6)
        bottom_buttons.addWidget(
            configure_action_button(
                self._import_button, COMPACT_BUTTON_STYLESHEET, self._open_import_menu, tr('Import custom themes from a JSON file or from the clipboard'),
            ),
        )
        bottom_buttons.addWidget(configure_action_button(self._export_button, COMPACT_BUTTON_STYLESHEET, self._export_themes))
        layout.addLayout(bottom_buttons)

        layout.addWidget(
            configure_action_button(self._delete_button, COMPACT_DANGER_BUTTON_STYLESHEET, self._delete_selected_themes, tr('Delete the selected custom theme')),
        )
        return group

    def _build_right_pane(self) -> QWidget:
        pane = QWidget()
        layout = QVBoxLayout(pane)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        details_group = QGroupBox(tr('Theme Details'))
        details_layout = QVBoxLayout(details_group)
        details_layout.setSpacing(5)

        name_row = QHBoxLayout()
        name_row.setSpacing(8)
        name_label = QLabel()
        set_i18n_colon_label(name_label, 'Name')
        name_row.addWidget(name_label, 0)

        self._name_edit.setMaxLength(THEME_NAME_MAX_LENGTH)
        self._name_edit.setPlaceholderText(tr('Enter custom theme name…'))
        self._name_edit.textEdited.connect(self._on_name_text_edited)
        self._name_edit.returnPressed.connect(self._on_name_return_pressed)
        self._name_edit.editingFinished.connect(self._commit_pending_rename)
        name_row.addWidget(self._name_edit, 1)

        name_row.addWidget(
            configure_action_button(
                self._reset_palette_button,
                COMPACT_BUTTON_STYLESHEET,
                self._open_reset_palette_menu,
                tr('Copy all 20 color tokens from any built-in preset (or right-click an individual token below)'),
            ),
            0,
        )
        details_layout.addLayout(name_row)

        self._mode_status_label.setStyleSheet(_STATUS_LABEL_STYLESHEET)
        details_layout.addWidget(self._mode_status_label)
        layout.addWidget(details_group, 0)

        palette_controls = build_palette_group(
            self,
            PaletteEditorCallbacks(
                pick_token_color=self._pick_token_color,
                preview_token_hex_edit=self._on_hex_text_edited,
                on_hex_return_pressed=self._on_hex_return_pressed,
                commit_token_hex_edit=self._commit_token_hex_edit,
                apply_token_color=self._apply_token_color,
                is_editable=lambda: self._edited_custom_model() is not None,
            ),
        )
        self._swatch_buttons = palette_controls.swatch_buttons
        self._hex_edits = palette_controls.hex_edits
        layout.addWidget(palette_controls.group_box, 3)

        preview_tabs = build_theme_preview_tabs(
            self._preview_root,
            on_copy_json=self._copy_selected_themes_json,
            on_import_clipboard=self._import_themes_from_clipboard,
        )
        self._json_output = preview_tabs.json_output
        self._copy_json_button = preview_tabs.copy_json_button
        layout.addWidget(preview_tabs.tab_widget, 2)
        return pane

    def _apply_theme_live(self, theme: Theme, title: str, message: str) -> None:
        if self.isVisible():
            with loading_overlay_scope(self, title, message):
                apply_runtime_theme(theme)
        else:
            apply_runtime_theme(theme)

    def _on_follow_system_toggled(self) -> None:
        self._commit_all_pending_edits()
        checked = self._follow_system_checkbox.isChecked()
        target_name = detect_system_theme_name() if checked else self._manual_theme_name
        self._rebuild_theme_list(select_names=[target_name])
        target_theme = self._themes_file.find_theme(target_name) or Theme(DEFAULT_THEME_NAME, DARK_THEME_COLORS, builtin=True)
        if target_theme != get_active_theme():
            self._apply_theme_live(target_theme, tr('Applying Theme…'), tr('Switching to "{name}"…', name=target_theme.name))
        self._sync_active_theme_indicators()
        self.follow_system_toggled.emit(checked)

    def _on_theme_item_double_clicked(self, _item: QListWidgetItem) -> None:
        self._apply_selected_theme()

    def _apply_selected_theme(self) -> None:
        self._commit_all_pending_edits()
        selected_themes = self._selected_themes_in_order()
        if len(selected_themes) != 1:
            return
        target_theme = selected_themes[0]
        if self._follow_system_checkbox.isChecked():
            with QSignalBlocker(self._follow_system_checkbox):
                self._follow_system_checkbox.setChecked(False)
        self._manual_theme_name = target_theme.name
        if target_theme != get_active_theme():
            self._apply_theme_live(target_theme, tr('Applying Theme…'), tr('Switching to "{name}"…', name=target_theme.name))
        self._sync_active_theme_indicators()
        self.theme_applied.emit(target_theme.name)

    def _sync_active_theme_indicators(self) -> None:
        active_cf = get_active_theme().name.casefold()
        for row in range(self._theme_list.count()):
            item = self._theme_list.item(row)
            raw_name = item.data(Qt.ItemDataRole.UserRole)
            font = item.font()
            font.setBold(isinstance(raw_name, str) and raw_name.casefold() == active_cf)
            item.setFont(font)

        selected_themes = self._selected_themes_in_order()
        if len(selected_themes) == 1:
            single = selected_themes[0]
            already_active = single.name.casefold() == active_cf and not self._follow_system_checkbox.isChecked()
            self._apply_button.setEnabled(not already_active)
            self._apply_button.setToolTip(
                tr('"{name}" is currently active.', name=single.name)
                if already_active
                else tr('Apply "{name}" live across Session Sniffer', name=single.name),
            )
            return
        self._apply_button.setEnabled(False)
        self._apply_button.setToolTip(tr('Select a single theme to apply it live'))

    # ------------------------------------------------------------------
    # State synchronization & persistence
    # ------------------------------------------------------------------

    def _persist_themes(self) -> bool:
        """Persist `self._themes_file` to disk, alerting the user on failure."""
        try:
            save_themes_file(self._themes_file, self._themes_path)
        except OSError as e:
            QMessageBox.critical(self, TITLE, tr('Failed to save custom themes:\n\n{error}', error=e))
            return False
        return True

    def _find_custom_model(self, name: str) -> CustomThemeModel | None:
        key = name.casefold()
        return next((item for item in self._themes_file.custom_themes if item.name.casefold() == key), None)

    def _selected_themes_in_order(self) -> list[Theme]:
        themes: list[Theme] = []
        for row in range(self._theme_list.count()):
            item = self._theme_list.item(row)
            if item.isSelected():
                raw_name = item.data(Qt.ItemDataRole.UserRole)
                if isinstance(raw_name, str) and (found := self._themes_file.find_theme(raw_name)) is not None:
                    themes.append(found)
        return themes

    def _selected_custom_models_in_order(self) -> list[CustomThemeModel]:
        models: list[CustomThemeModel] = []
        for row in range(self._theme_list.count()):
            item = self._theme_list.item(row)
            if item.isSelected():
                raw_name = item.data(Qt.ItemDataRole.UserRole)
                if isinstance(raw_name, str) and (model := self._find_custom_model(raw_name)) is not None:
                    models.append(model)
        return models

    def _rebuild_theme_list(self, *, select_names: Sequence[str] | None = None) -> None:
        requested = [name for name in (select_names or [self._selected_theme_name or DEFAULT_THEME_NAME]) if name]
        requested_cf = {name.casefold() for name in requested}
        primary_cf = requested[0].casefold() if requested else DEFAULT_THEME_NAME.casefold()
        all_themes = self._themes_file.all_themes()

        primary_index: int | None = None
        first_matched_index: int | None = None
        with QSignalBlocker(self._theme_list):
            self._theme_list.clear()
            for i, theme in enumerate(all_themes):
                display_text = tr('{name} (Built-in)', name=theme.name) if theme.builtin else theme.name
                item = QListWidgetItem(create_theme_list_icon(theme.colors), display_text)
                item.setData(Qt.ItemDataRole.UserRole, theme.name)
                self._theme_list.addItem(item)
                name_cf = theme.name.casefold()
                if name_cf in requested_cf:
                    item.setSelected(True)
                    if first_matched_index is None:
                        first_matched_index = i
                    if name_cf == primary_cf:
                        primary_index = i

            if self._theme_list.count() > 0:
                anchor = primary_index if primary_index is not None else (first_matched_index if first_matched_index is not None else 0)
                selection_flag = QItemSelectionModel.SelectionFlag.ClearAndSelect if first_matched_index is None else QItemSelectionModel.SelectionFlag.NoUpdate
                self._theme_list.selectionModel().setCurrentIndex(self._theme_list.model().index(anchor, 0), selection_flag)
                self._theme_list.scrollToItem(self._theme_list.item(anchor))

        self._sync_selection_state()

    def _current_theme(self) -> Theme:
        found = self._themes_file.find_theme(self._selected_theme_name)
        return found if found is not None else Theme(DEFAULT_THEME_NAME, DARK_THEME_COLORS, builtin=True)

    def _focused_or_fallback_theme(self, selected_themes: Sequence[Theme]) -> Theme:
        row = self._theme_list.currentRow()
        if 0 <= row < self._theme_list.count():
            item = self._theme_list.item(row)
            if not selected_themes or item.isSelected():
                raw_name = item.data(Qt.ItemDataRole.UserRole)
                if isinstance(raw_name, str) and (found := self._themes_file.find_theme(raw_name)) is not None:
                    return found
        return selected_themes[-1] if selected_themes else self._current_theme()

    def _on_theme_selection_changed(self) -> None:
        if self._edited_theme_name is not None:
            self._commit_all_pending_edits()
        self._sync_selection_state()

    def _on_current_row_changed(self, row: int) -> None:
        if self._edited_theme_name is not None or row < 0 or row >= self._theme_list.count():
            return
        raw_name = self._theme_list.item(row).data(Qt.ItemDataRole.UserRole)
        if not isinstance(raw_name, str) or (found := self._themes_file.find_theme(raw_name)) is None:
            return
        self._selected_theme_name = found.name
        selected_count = len(self._selected_themes_in_order())
        if selected_count != 1:
            self._populate_editor_from_theme(found, multi_count=selected_count, custom_selected_count=len(self._selected_custom_models_in_order()))

    def _sync_selection_state(self) -> None:
        selected_themes = self._selected_themes_in_order()
        selected_custom = self._selected_custom_models_in_order()
        total_selected = len(selected_themes)
        custom_count = len(selected_custom)

        self._duplicate_button.setEnabled(total_selected > 0)
        self._duplicate_button.setText(f" {tr('Duplicate ({count})', count=total_selected)}" if total_selected > 1 else f" {tr('Duplicate')}")
        self._duplicate_button.setToolTip(
            tr('Duplicate the {count} selected themes as new editable custom themes', count=total_selected)
            if total_selected > 1
            else tr('Duplicate the selected theme as a new editable custom theme'),
        )

        self._delete_button.setEnabled(custom_count > 0)
        self._delete_button.setText(f" {tr('Delete Custom Themes ({count})', count=custom_count)}" if custom_count > 1 else f" {tr('Delete Custom Theme')}")
        if custom_count > 1:
            self._delete_button.setToolTip(tr('Delete the {count} selected custom themes (Del)', count=custom_count))
        elif custom_count == 1:
            self._delete_button.setToolTip(tr('Delete the selected custom theme (Del)'))
        else:
            self._delete_button.setToolTip(tr('Select one or more custom themes to delete (Ctrl+Click or Shift+Click to multi-select)'))

        has_custom_themes = bool(self._themes_file.custom_themes)
        self._export_button.setEnabled(has_custom_themes)
        if not has_custom_themes:
            self._export_button.setToolTip(tr('Create or duplicate a custom theme first to export it'))
        elif custom_count > 1:
            self._export_button.setToolTip(tr('Export the {count} selected custom themes or all custom themes to JSON', count=custom_count))
        else:
            self._export_button.setToolTip(tr('Export custom themes to a JSON file'))

        if total_selected == 1:
            single = selected_themes[0]
            self._selected_theme_name = single.name
            self._edited_theme_name = None if single.builtin else single.name
            self._populate_editor_from_theme(single, multi_count=1, custom_selected_count=custom_count)
            return

        self._edited_theme_name = None
        preview_theme = self._focused_or_fallback_theme(selected_themes)
        self._selected_theme_name = preview_theme.name
        self._populate_editor_from_theme(preview_theme, multi_count=total_selected, custom_selected_count=custom_count)

    def _populate_editor_from_theme(self, theme: Theme, *, multi_count: int = 1, custom_selected_count: int = 0) -> None:
        self._populating_editor = True
        self._live_preview_colors = None
        self._live_name_override = None
        try:
            is_editable = multi_count == 1 and not theme.builtin
            self._reset_palette_button.setEnabled(is_editable)
            with QSignalBlocker(self._name_edit):
                if multi_count == 1:
                    self._name_edit.setPlaceholderText(tr('Enter custom theme name…'))
                    self._name_edit.setText(theme.name)
                else:
                    self._name_edit.setText('')
                    self._name_edit.setPlaceholderText(
                        tr('{count} themes selected', count=multi_count) if multi_count > 1 else tr('No theme selected'),
                    )
                self._name_edit.setEnabled(is_editable)

            self._mode_status_label.setStyleSheet(_STATUS_LABEL_STYLESHEET)
            self._mode_status_label.setText(
                format_selection_status_text(theme, multi_count=multi_count, custom_selected_count=custom_selected_count),
            )

            for token_name, hex_value in theme.colors.as_dict().items():
                swatch = self._swatch_buttons[token_name]
                swatch.setEnabled(is_editable)
                swatch.setStyleSheet(token_swatch_stylesheet(hex_value))
                hex_edit = self._hex_edits[token_name]
                with QSignalBlocker(hex_edit):
                    hex_edit.setText(hex_value)
                    hex_edit.setEnabled(is_editable)

            self._refresh_live_preview(theme.colors)
            self._refresh_json_output()
            self._sync_active_theme_indicators()
        finally:
            self._populating_editor = False

    def _refresh_live_preview(self, colors: ThemeColors) -> None:
        self._preview_root.setStyleSheet(ThemeTransform(colors).qss(PREVIEW_BASE_QSS))

    def _refresh_json_output(self) -> None:
        selected = self._selected_themes_in_order()
        json_text = build_exportable_themes_json(
            selected,
            edited_theme_name=self._edited_theme_name,
            override_name=self._live_name_override,
            override_colors=self._live_preview_colors,
        )
        self._json_output.setPlainText(json_text)
        self._copy_json_button.setEnabled(bool(selected))

    def _copy_selected_themes_json(self, *, animate_button: bool = True) -> None:
        json_text = self._json_output.toPlainText()
        if not json_text:
            return
        set_clipboard_text(json_text)
        if animate_button:
            animate_button_feedback(self._copy_json_button)

    def _update_list_item_visuals(self, lookup_name: str, theme: Theme) -> None:
        target_cf = lookup_name.casefold()
        for row in range(self._theme_list.count()):
            item = self._theme_list.item(row)
            raw_name = item.data(Qt.ItemDataRole.UserRole)
            if isinstance(raw_name, str) and raw_name.casefold() == target_cf:
                item.setData(Qt.ItemDataRole.UserRole, theme.name)
                item.setText(tr('{name} (Built-in)', name=theme.name) if theme.builtin else theme.name)
                item.setIcon(create_theme_list_icon(theme.colors))
                return

    # ------------------------------------------------------------------
    # Theme actions (Create / Duplicate / Rename / Edit / Delete / I/O)
    # ------------------------------------------------------------------

    def _existing_custom_names_casefold(self, *, exclude: str | None = None) -> set[str]:
        excluded = exclude.casefold() if exclude is not None else None
        return {item.name.casefold() for item in self._themes_file.custom_themes if item.name.casefold() != excluded}

    def _show_theme_list_context_menu(self, pos: QPoint) -> None:
        self._commit_all_pending_edits()
        selected_themes = self._selected_themes_in_order()
        selected_custom = self._selected_custom_models_in_order()
        action = exec_theme_list_context_menu(
            self,
            self._theme_list.viewport().mapToGlobal(pos),
            total_selected=len(selected_themes),
            selected_custom=selected_custom,
            can_apply=self._apply_button.isEnabled(),
        )
        if action == 'apply':
            self._apply_selected_theme()
        elif action == 'new':
            self._create_new_theme()
        elif action == 'duplicate':
            self._duplicate_selected_themes()
        elif action == 'copy_json':
            self._copy_selected_themes_json(animate_button=False)
        elif action == 'export':
            export_custom_models_selection(self, selected_custom)
        elif action == 'delete':
            self._delete_selected_themes()

    def _create_new_theme(self) -> None:
        self._commit_all_pending_edits()
        base_colors = self._current_theme().colors
        new_name = make_unique_theme_name(tr('Custom Theme'), self._existing_custom_names_casefold(), fallback_base=tr('Custom Theme'))
        self._themes_file.custom_themes.append(CustomThemeModel(name=new_name, colors=ThemeColorsModel.from_theme_colors(base_colors)))
        if not self._persist_themes():
            self._themes_file.custom_themes.pop()
            return
        self._rebuild_theme_list(select_names=[new_name])
        self.themes_changed.emit()
        self._name_edit.setFocus()
        self._name_edit.selectAll()

    def _duplicate_selected_themes(self) -> None:
        self._commit_all_pending_edits()
        sources = self._selected_themes_in_order()
        if not sources:
            return

        previous_themes = list(self._themes_file.custom_themes)
        existing_names = self._existing_custom_names_casefold()
        created_names: list[str] = []
        for source in sources:
            new_name = make_unique_theme_name(tr('{name} Copy', name=source.name), existing_names, fallback_base=tr('Custom Theme'))
            existing_names.add(new_name.casefold())
            self._themes_file.custom_themes.append(CustomThemeModel(name=new_name, colors=ThemeColorsModel.from_theme_colors(source.colors)))
            created_names.append(new_name)

        if not self._persist_themes():
            self._themes_file.custom_themes = previous_themes
            return

        self._rebuild_theme_list(select_names=created_names)
        self.themes_changed.emit()
        if len(created_names) == 1:
            self._name_edit.setFocus()
            self._name_edit.selectAll()
        else:
            self._theme_list.setFocus()

    def _on_name_text_edited(self, raw_text: str) -> None:
        if self._populating_editor or (custom_model := self._edited_custom_model()) is None:
            return
        self._live_name_override = raw_text
        if (error_text := validate_custom_theme_name(raw_text.strip(), self._existing_custom_names_casefold(exclude=custom_model.name))) is not None:
            self._mode_status_label.setStyleSheet(_ERROR_STATUS_LABEL_STYLESHEET)
            self._mode_status_label.setText(error_text)
        else:
            self._mode_status_label.setStyleSheet(_STATUS_LABEL_STYLESHEET)
            self._mode_status_label.setText(tr('Custom theme — color and name changes are saved automatically.'))
        self._refresh_json_output()

    def _on_name_return_pressed(self) -> None:
        if self._commit_pending_rename():
            self._theme_list.setFocus()
        else:
            self._name_edit.setFocus()
            self._name_edit.selectAll()

    def _on_hex_return_pressed(self, token_name: str, edit: QLineEdit) -> None:
        self._commit_token_hex_edit(token_name)
        edit.deselect()

    def _validate_proposed_custom_name(self, proposed_name: str, old_name: str) -> bool:
        if (error_text := validate_custom_theme_name(proposed_name, self._existing_custom_names_casefold(exclude=old_name))) is not None:
            QMessageBox.warning(self, TITLE, error_text)
            return False
        return True

    def _edited_custom_model(self) -> CustomThemeModel | None:
        return self._find_custom_model(self._edited_theme_name) if self._edited_theme_name is not None else None

    def _set_name_edit_text(self, text: str) -> None:
        with QSignalBlocker(self._name_edit):
            self._name_edit.setText(text)

    def _commit_pending_rename(self) -> bool:
        if self._populating_editor or self._committing_rename or (custom_model := self._edited_custom_model()) is None:
            return True

        self._committing_rename = True
        self._live_name_override = None
        try:
            proposed_name = self._name_edit.text().strip()
            old_name = custom_model.name
            self._mode_status_label.setStyleSheet(_STATUS_LABEL_STYLESHEET)
            self._mode_status_label.setText(tr('Custom theme — color and name changes are saved automatically.'))
            if not proposed_name or proposed_name == old_name:
                self._set_name_edit_text(old_name)
                self._refresh_json_output()
                return True
            if not self._validate_proposed_custom_name(proposed_name, old_name):
                self._set_name_edit_text(old_name)
                self._refresh_json_output()
                return False

            custom_model.name = proposed_name
            if not self._persist_themes():
                custom_model.name = old_name
                self._set_name_edit_text(old_name)
                self._refresh_json_output()
                return False

            if self._selected_theme_name.casefold() == old_name.casefold():
                self._selected_theme_name = proposed_name
            if self._manual_theme_name.casefold() == old_name.casefold():
                self._manual_theme_name = proposed_name
            self._edited_theme_name = proposed_name
            self._set_name_edit_text(proposed_name)
            self._update_list_item_visuals(old_name, custom_model.to_theme())
            self._refresh_json_output()
            self._sync_active_theme_indicators()
            self.theme_renamed.emit(old_name, proposed_name)
            return True
        finally:
            self._committing_rename = False

    def _notify_edited_theme_updated(self, updated_theme: Theme) -> None:
        self._live_preview_colors = None
        self._update_list_item_visuals(updated_theme.name, updated_theme)
        self._refresh_live_preview(updated_theme.colors)
        self._refresh_json_output()
        if updated_theme.name.casefold() == get_active_theme().name.casefold():
            self._apply_theme_live(updated_theme, tr('Updating Theme…'), tr('Applying changes to "{name}"…', name=updated_theme.name))
        self.themes_changed.emit()

    def _open_reset_palette_menu(self) -> None:
        self._commit_all_pending_edits()
        if self._edited_custom_model() is None:
            return
        show_full_palette_preset_menu(self, self._reset_palette_button, self._apply_full_palette)

    def _apply_full_palette(self, preset_colors: ThemeColors) -> None:
        if (custom_model := self._edited_custom_model()) is None:
            return
        previous_colors = custom_model.colors
        new_colors_model = ThemeColorsModel.from_theme_colors(preset_colors)
        if new_colors_model == previous_colors:
            return
        custom_model.colors = new_colors_model
        if not self._persist_themes():
            custom_model.colors = previous_colors
            return

        for token_name, hex_value in preset_colors.as_dict().items():
            self._swatch_buttons[token_name].setStyleSheet(token_swatch_stylesheet(hex_value))
            with QSignalBlocker(self._hex_edits[token_name]):
                self._hex_edits[token_name].setText(hex_value)

        self._notify_edited_theme_updated(custom_model.to_theme())

    def _preview_token_color(self, token_name: str, normalized_hex: str, *, update_hex_edit: bool = True) -> None:
        if (custom_model := self._edited_custom_model()) is None:
            return
        base_colors = self._live_preview_colors or custom_model.colors.to_theme_colors()
        preview_colors = replace(base_colors, **{token_name: normalized_hex})
        self._live_preview_colors = preview_colors
        self._swatch_buttons[token_name].setStyleSheet(token_swatch_stylesheet(normalized_hex))
        if update_hex_edit:
            with QSignalBlocker(self._hex_edits[token_name]):
                self._hex_edits[token_name].setText(normalized_hex)
        self._refresh_live_preview(preview_colors)
        self._refresh_json_output()

    def _on_hex_text_edited(self, token_name: str, raw_text: str) -> None:
        if self._populating_editor or self._edited_custom_model() is None:
            return
        stripped = raw_text.strip()
        if _HEX_COLOR_RE.fullmatch(stripped):
            self._preview_token_color(token_name, f'#{stripped.lstrip("#").lower()}', update_hex_edit=False)

    def _restore_token_color_ui(self, token_name: str, hex_value: str, colors: ThemeColors) -> None:
        self._live_preview_colors = None
        self._swatch_buttons[token_name].setStyleSheet(token_swatch_stylesheet(hex_value))
        with QSignalBlocker(self._hex_edits[token_name]):
            self._hex_edits[token_name].setText(hex_value)
        self._refresh_live_preview(colors)
        self._refresh_json_output()

    def _apply_token_color(self, token_name: str, normalized_hex: str) -> None:
        if (custom_model := self._edited_custom_model()) is None:
            return
        previous_hex = str(getattr(custom_model.colors, token_name))
        if normalized_hex == previous_hex:
            self._restore_token_color_ui(token_name, normalized_hex, custom_model.colors.to_theme_colors())
            return

        updated_dict = custom_model.colors.model_dump()
        updated_dict[token_name] = normalized_hex
        custom_model.colors = ThemeColorsModel(**updated_dict)
        if not self._persist_themes():
            updated_dict[token_name] = previous_hex
            custom_model.colors = ThemeColorsModel(**updated_dict)
            return

        self._swatch_buttons[token_name].setStyleSheet(token_swatch_stylesheet(normalized_hex))
        with QSignalBlocker(self._hex_edits[token_name]):
            self._hex_edits[token_name].setText(normalized_hex)

        self._notify_edited_theme_updated(custom_model.to_theme())

    def _pick_token_color(self, token_name: str, token_label: str) -> None:
        if (custom_model := self._edited_custom_model()) is None:
            return
        original_hex = str(getattr(custom_model.colors, token_name))
        canonical_label = next((token.label for token in THEME_COLOR_TOKENS if token.name == token_name), token_label)
        chosen_hex = pick_color_with_live_preview(
            self,
            original_hex,
            tr('Select {token} Color', token=tr(canonical_label)),
            lambda hex_value: self._preview_token_color(token_name, hex_value),
        )
        if chosen_hex is not None:
            self._apply_token_color(token_name, chosen_hex)
            return
        self._restore_token_color_ui(token_name, original_hex, custom_model.colors.to_theme_colors())

    def _commit_token_hex_edit(self, token_name: str) -> None:
        if self._populating_editor or (custom_model := self._edited_custom_model()) is None:
            return
        current_hex = str(getattr(custom_model.colors, token_name))
        raw_text = self._hex_edits[token_name].text().strip()
        if not _HEX_COLOR_RE.fullmatch(raw_text):
            self._restore_token_color_ui(token_name, current_hex, custom_model.colors.to_theme_colors())
            return
        self._apply_token_color(token_name, f'#{raw_text.lstrip("#").lower()}')

    def _first_deleted_row(self, deleted_cf: set[str]) -> int:
        for row in range(self._theme_list.count()):
            raw_name = self._theme_list.item(row).data(Qt.ItemDataRole.UserRole)
            if isinstance(raw_name, str) and raw_name.casefold() in deleted_cf:
                return row
        return max(0, self._theme_list.currentRow())

    def _delete_selected_themes(self) -> None:
        self._commit_all_pending_edits()
        targets = self._selected_custom_models_in_order()
        if not targets:
            return

        confirmation = QMessageBox.question(
            self,
            TITLE,
            format_delete_confirmation(targets),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if confirmation != QMessageBox.StandardButton.Yes:
            return

        deleted_names = tuple(model.name for model in targets)
        deleted_cf = {name.casefold() for name in deleted_names}
        anchor_row = self._first_deleted_row(deleted_cf)
        previous_themes = list(self._themes_file.custom_themes)
        self._themes_file.custom_themes = [item for item in self._themes_file.custom_themes if item.name.casefold() not in deleted_cf]
        if not self._persist_themes():
            self._themes_file.custom_themes = previous_themes
            return

        remaining = self._themes_file.all_themes()
        next_index = min(max(0, anchor_row), len(remaining) - 1)
        fallback_name = remaining[next_index].name if remaining else DEFAULT_THEME_NAME
        self._rebuild_theme_list(select_names=[fallback_name])

        if self._manual_theme_name.casefold() in deleted_cf:
            self._manual_theme_name = DEFAULT_THEME_NAME
        if get_active_theme().name.casefold() in deleted_cf:
            default_theme = Theme(DEFAULT_THEME_NAME, DARK_THEME_COLORS, builtin=True)
            self._apply_theme_live(default_theme, tr('Restoring Default Theme…'), tr('Reverting to "{name}"…', name=DEFAULT_THEME_NAME))

        self._sync_active_theme_indicators()
        self.themes_deleted.emit(deleted_names)

    def _open_import_menu(self) -> None:
        self._commit_all_pending_edits()
        source = prompt_import_source_choice(self, self._import_button)
        if source == 'file':
            self._import_themes_from_file()
        elif source == 'clipboard':
            self._import_themes_from_clipboard()

    def _apply_imported_themes(self, imported_file: ThemesFile) -> None:
        previous_themes = list(self._themes_file.custom_themes)
        existing_names = self._existing_custom_names_casefold()
        imported_names: list[str] = []
        for entry in imported_file.custom_themes:
            unique_name = make_unique_theme_name(entry.name, existing_names, fallback_base=tr('Custom Theme'))
            existing_names.add(unique_name.casefold())
            self._themes_file.custom_themes.append(CustomThemeModel(name=unique_name, colors=entry.colors))
            imported_names.append(unique_name)

        if not self._persist_themes():
            self._themes_file.custom_themes = previous_themes
            return

        self._rebuild_theme_list(select_names=imported_names)
        self.themes_changed.emit()
        count = len(imported_names)
        QMessageBox.information(
            self,
            TITLE,
            tr_plural('Imported {count} custom theme successfully.', 'Imported {count} custom themes successfully.', count),
        )

    def _import_themes_from_file(self) -> None:
        self._commit_all_pending_edits()
        if (imported_file := prompt_import_themes_from_file(self)) is not None:
            self._apply_imported_themes(imported_file)

    def _import_themes_from_clipboard(self) -> None:
        self._commit_all_pending_edits()
        if (imported_file := read_themes_from_clipboard(self)) is not None:
            self._apply_imported_themes(imported_file)

    def _export_themes(self) -> None:
        self._commit_all_pending_edits()
        export_themes_interactive(self, self._export_button, self._themes_file.custom_themes, self._selected_custom_models_in_order())

    # ------------------------------------------------------------------
    # Key & close handling
    # ------------------------------------------------------------------

    @override
    def keyPressEvent(self, event: QKeyEvent) -> None:
        """Prevent Enter/Return in input fields from triggering action buttons while preserving focused-button Enter activation."""
        if event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            focused = self.focusWidget()
            if isinstance(focused, QPushButton) and focused.isEnabled():
                focused.click()
            event.accept()
            return
        super().keyPressEvent(event)

    def _commit_all_pending_edits(self) -> None:
        self._commit_pending_rename()
        for token in THEME_COLOR_TOKENS:
            self._commit_token_hex_edit(token.name)

    def _on_close_clicked(self) -> None:
        self._commit_all_pending_edits()
        self.accept()

    @override
    def done(self, result: int) -> None:
        self._commit_all_pending_edits()
        super().done(result)

    @override
    def closeEvent(self, event: QCloseEvent) -> None:
        self._commit_all_pending_edits()
        super().closeEvent(event)
