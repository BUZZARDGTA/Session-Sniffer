"""Themes tab, preview gallery cards, and Theme Manager integration mixin for `SettingsDialog`."""

from typing import TYPE_CHECKING, Final, cast, override

from PySide6.QtCore import QSignalBlocker, Qt, QTimer, Signal
from PySide6.QtGui import QCloseEvent, QIcon
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QFormLayout,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)
from shiboken6 import isValid

from session_sniffer.background.events import gui_closed__event
from session_sniffer.guis._crashing_qthread import CrashingQThread
from session_sniffer.guis._dialog_mixins import UnsavedChangesMixin
from session_sniffer.guis._settings_widget_builders import format_setting_tooltip
from session_sniffer.guis._theme_preview_card import ThemePreviewCard
from session_sniffer.guis.live_theme import (
    PreparedTheme,
    apply_prepared_runtime_theme,
    apply_runtime_theme,
    prepare_theme_assets,
    prime_current_theme_icon_tags,
    register_post_theme_refresh,
    resolve_effective_theme,
    resolve_theme_by_name,
    set_live_follow_system_checkbox,
)
from session_sniffer.guis.loading_overlay import LoadingOverlay, loading_overlay_scope, pump_active_loading_overlays
from session_sniffer.guis.stylesheets import COMPACT_BUTTON_STYLESHEET
from session_sniffer.guis.theme_manager_dialog import ThemeManagerDialog
from session_sniffer.guis.theming import (
    BUILTIN_THEMES,
    DEFAULT_THEME_NAME,
    ICONS_DIR_PATH,
    Theme,
    detect_system_theme_name,
    get_active_theme,
    load_themes_file,
    themed_qss,
)
from session_sniffer.guis.utils import get_ui_scale
from session_sniffer.settings import SETTING_METADATA
from session_sniffer.settings.settings import Settings

if TYPE_CHECKING:
    from collections.abc import Sequence

    from session_sniffer.guis._settings_runtime import SettingValue
    from session_sniffer.models.themes import ThemesFile

_PREVIEW_GRID_COLUMNS: Final = 3


def _clear_grid_layout(grid: QGridLayout) -> None:
    while (item := grid.takeAt(0)) is not None:
        if (widget := item.widget()) is not None:
            widget.hide()
            widget.setParent(None)
            widget.deleteLater()


class _ThemePrepWorker(CrashingQThread):
    """Background worker preparing SVG icons, `ThemeTransform`, and global QSS for a target theme."""

    prepared_ready: Signal = Signal(object)

    def __init__(self, theme: Theme, ui_scale: float) -> None:
        super().__init__(name='LiveThemePrep')
        self._theme = theme
        self._ui_scale = ui_scale

    @override
    def _run(self) -> None:
        prepared = prepare_theme_assets(self._theme, self._ui_scale)
        if not self.isInterruptionRequested():
            self.prepared_ready.emit(prepared)


class SettingsDialogThemeMixin(UnsavedChangesMixin, QDialog):
    """Themes tab preview gallery and `ThemeManagerDialog` synchronization helpers."""

    _widgets: dict[str, QWidget]
    _labels: dict[str, QLabel]
    _old_values: dict[str, SettingValue]
    _initial_values: dict[str, SettingValue]
    _loading_settings: bool
    _saved: bool
    _restart_notice_banner: QFrame
    _restart_notice_label: QLabel

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize theme state, async switch state, and preview gallery containers."""
        super().__init__(parent)
        self._cached_themes_file: ThemesFile = load_themes_file()[0]
        self._theme_preview_cards: list[ThemePreviewCard] = []
        self._builtin_preview_grid = QGridLayout()
        self._custom_themes_group = QGroupBox('Custom Themes')
        self._custom_preview_grid = QGridLayout(self._custom_themes_group)
        self._theme_prep_worker: _ThemePrepWorker | None = None
        self._theme_loading_overlay: LoadingOverlay | None = None
        self._pending_live_theme: Theme | None = None

    def _set_enum(self, widget: QWidget, value: SettingValue) -> None:
        raise NotImplementedError

    def _has_unsaved_restart_changes(self) -> bool:
        raise NotImplementedError

    def cancel_pending_live_theme_switch(self) -> None:
        """Cancel any in-flight background theme preparation and dismiss its loading overlay."""
        self._pending_live_theme = None
        if self._theme_prep_worker is not None:
            self._theme_prep_worker.cancel(2000)
            self._theme_prep_worker = None
        if self._theme_loading_overlay is not None:
            self._theme_loading_overlay.close_overlay()
            self._theme_loading_overlay = None

    def _revert_live_theme_to_persisted(self) -> None:
        """Restore the active runtime theme to the persisted effective theme when changes are discarded."""
        self.cancel_pending_live_theme_switch()
        persisted_theme = resolve_effective_theme()
        if persisted_theme == get_active_theme():
            return
        if self.isVisible():
            with loading_overlay_scope(self, 'Restoring Theme\u2026', f'Reverting to "{persisted_theme.name}"\u2026'):
                apply_runtime_theme(persisted_theme)
        else:
            apply_runtime_theme(persisted_theme)

    @override
    def done(self, result: int) -> None:
        """Revert any unsaved live-previewed theme when the dialog is rejected."""
        if result == QDialog.DialogCode.Rejected and not gui_closed__event.is_set():
            self._revert_live_theme_to_persisted()
        else:
            self.cancel_pending_live_theme_switch()
        super().done(result)

    @override
    def closeEvent(self, event: QCloseEvent) -> None:
        """Revert any unsaved live-previewed theme if the user discards changes on close."""
        super().closeEvent(event)
        if event.isAccepted() and not self._saved and not gui_closed__event.is_set():
            self._revert_live_theme_to_persisted()

    def _update_restart_notice(self, *_args: object) -> None:
        """Update visibility of the packet capture restart notice banner."""
        if self._loading_settings:
            return
        needs_capture_restart = self._has_unsaved_restart_changes()
        if needs_capture_restart:
            self._restart_notice_label.setText('Saving changes will restart packet capture.')
            self._restart_notice_banner.setToolTip('One or more modified settings require a capture restart upon saving.')
        self._restart_notice_banner.setVisible(needs_capture_restart)

    def _is_follow_system_checked(self) -> bool:
        follow_cb = self._widgets.get('gui_theme_follow_system')
        return follow_cb.isChecked() if isinstance(follow_cb, QCheckBox) else Settings.gui_theme_follow_system

    def _effective_dialog_theme_name(self) -> str:
        if self._is_follow_system_checked():
            return detect_system_theme_name()
        combo = self._widgets.get('gui_theme')
        return combo.currentText() if isinstance(combo, QComboBox) and combo.currentText() else Settings.gui_theme

    def _sync_follow_system_ui_state(self) -> None:
        follow_system = self._is_follow_system_checked()
        combo = self._widgets.get('gui_theme')
        label = self._labels.get('gui_theme')
        base_tooltip = format_setting_tooltip(SETTING_METADATA['gui_theme']) or ''
        if follow_system:
            system_name = detect_system_theme_name()
            note = f'Disabled while Follow System Theme is enabled (currently following system {system_name} theme).'
            tooltip = f'{base_tooltip}\n\n{note}' if base_tooltip else note
        else:
            tooltip = base_tooltip
        if label is not None:
            label.setEnabled(not follow_system)
            label.setToolTip(tooltip)
        if isinstance(combo, QComboBox):
            combo.setEnabled(not follow_system)
            combo.setToolTip(tooltip)

    def _build_theme_setting_row(self, form: QFormLayout, label: QLabel, widget: QWidget) -> None:
        """Append the `Theme` selector paired with the `Theme Manager…` button to *form*."""
        follow_cb = self._widgets.get('gui_theme_follow_system')
        if isinstance(follow_cb, QCheckBox):
            follow_cb.toggled.connect(self._apply_selected_theme_live)
            set_live_follow_system_checkbox(follow_cb)
        register_post_theme_refresh(self, self._sync_selected_theme_card)
        if isinstance(widget, QComboBox):
            widget.currentTextChanged.connect(self._apply_selected_theme_live)

        theme_row = QWidget()
        theme_row_layout = QHBoxLayout(theme_row)
        theme_row_layout.setContentsMargins(0, 0, 0, 0)
        theme_row_layout.setSpacing(6)
        theme_row_layout.addWidget(widget, 1)

        manager_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'palette.svg')), ' Theme Manager\u2026')
        manager_button.setToolTip('Create, edit, duplicate, import, or export custom color themes')
        manager_button.setStyleSheet(COMPACT_BUTTON_STYLESHEET)
        manager_button.setCursor(Qt.CursorShape.PointingHandCursor)
        manager_button.setAutoDefault(False)
        manager_button.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        manager_button.clicked.connect(self._open_theme_manager)
        theme_row_layout.addWidget(manager_button)

        form.addRow(label, theme_row)

    def _populate_themes_tab(self, outer_layout: QVBoxLayout) -> None:
        """Append built-in and custom theme preview galleries to the `Themes` settings tab."""
        builtin_group = QGroupBox('Built-in Themes')
        builtin_vbox = QVBoxLayout(builtin_group)
        builtin_vbox.setSpacing(8)

        hint_label = QLabel(
            'Click any preview card below to apply a theme live (click Save to keep it, or Cancel to revert). '
            'Use Theme Manager\u2026 above to create or customize your own themes.',
        )
        hint_label.setStyleSheet(themed_qss('color: #9ca3af; font-size: 8.5pt; background: transparent;'))
        hint_label.setWordWrap(True)
        builtin_vbox.addWidget(hint_label)

        for grid in (self._builtin_preview_grid, self._custom_preview_grid):
            grid.setHorizontalSpacing(12)
            grid.setVerticalSpacing(12)
            for col in range(_PREVIEW_GRID_COLUMNS):
                grid.setColumnStretch(col, 1)

        builtin_vbox.addLayout(self._builtin_preview_grid)
        outer_layout.addWidget(builtin_group)
        outer_layout.addWidget(self._custom_themes_group)
        self._rebuild_theme_preview_cards()
        QTimer.singleShot(0, prime_current_theme_icon_tags)

    def _fill_preview_grid(self, grid: QGridLayout, themes: Sequence[Theme], selected_cf: str) -> None:
        _clear_grid_layout(grid)
        for index, theme in enumerate(themes):
            card = ThemePreviewCard(theme, selected=theme.name.casefold() == selected_cf)
            card.clicked.connect(self._on_preview_card_clicked)
            grid.addWidget(card, index // _PREVIEW_GRID_COLUMNS, index % _PREVIEW_GRID_COLUMNS)
            self._theme_preview_cards.append(card)

    def _rebuild_theme_preview_cards(self) -> None:
        """Rebuild built-in and custom theme preview cards to match `self._cached_themes_file`."""
        self._theme_preview_cards.clear()
        self._sync_follow_system_ui_state()
        selected_cf = self._effective_dialog_theme_name().casefold()

        self._fill_preview_grid(self._builtin_preview_grid, BUILTIN_THEMES, selected_cf)
        custom_themes = [model.to_theme() for model in self._cached_themes_file.custom_themes]
        self._fill_preview_grid(self._custom_preview_grid, custom_themes, selected_cf)
        self._custom_themes_group.setVisible(bool(custom_themes))

    def _sync_selected_theme_card(self, *_args: object) -> None:
        """Synchronize Follow System Theme control state and highlight the effective preview card."""
        self._sync_follow_system_ui_state()
        selected_cf = self._effective_dialog_theme_name().casefold()
        for card in self._theme_preview_cards:
            card.set_selected(selected=card.theme_name.casefold() == selected_cf)

    def _launch_pending_theme_worker(self) -> None:
        target_theme = self._pending_live_theme
        if target_theme is None or self._theme_prep_worker is not None:
            return
        prime_current_theme_icon_tags()
        worker = _ThemePrepWorker(target_theme, get_ui_scale())
        worker.prepared_ready.connect(self._on_theme_worker_ready)
        self._theme_prep_worker = worker
        worker.start()

    def _on_theme_worker_ready(self, raw_prepared: object) -> None:
        self._theme_prep_worker = None
        if not isValid(self) or gui_closed__event.is_set() or self._pending_live_theme is None or not isinstance(raw_prepared, PreparedTheme):
            if self._theme_loading_overlay is not None:
                self._theme_loading_overlay.close_overlay()
                self._theme_loading_overlay = None
            return

        prepared = raw_prepared
        if self._pending_live_theme != prepared.theme:
            self._launch_pending_theme_worker()
            return

        self._pending_live_theme = None
        try:
            if self._theme_loading_overlay is not None:
                self._theme_loading_overlay.set_status(f'Updating interface for "{prepared.theme.name}"\u2026')
                pump_active_loading_overlays(force=True)
            apply_prepared_runtime_theme(prepared)
        finally:
            if self._theme_loading_overlay is not None:
                self._theme_loading_overlay.close_overlay()
                self._theme_loading_overlay = None

    def _request_live_theme_switch(self, target_theme: Theme) -> None:
        if not self.isVisible():
            apply_runtime_theme(target_theme)
            return
        if self._theme_prep_worker is None and target_theme == get_active_theme():
            self._pending_live_theme = None
            if self._theme_loading_overlay is not None:
                self._theme_loading_overlay.close_overlay()
                self._theme_loading_overlay = None
            return

        self._pending_live_theme = target_theme
        status_text = f'Switching to "{target_theme.name}"\u2026'
        if self._theme_loading_overlay is None:
            self._theme_loading_overlay = LoadingOverlay(self, 'Applying Theme\u2026', status_text)
            self._theme_loading_overlay.present_immediately()
        else:
            self._theme_loading_overlay.set_status(status_text)
            self._theme_loading_overlay.tick_frame()

        self._launch_pending_theme_worker()

    def _apply_selected_theme_live(self, *_args: object) -> None:
        """Apply the effective dialog theme live across the application and update preview cards."""
        self._sync_selected_theme_card()
        if self._loading_settings:
            return
        self._request_live_theme_switch(resolve_theme_by_name(self._effective_dialog_theme_name()))

    def _on_preview_card_clicked(self, theme_name: str) -> None:
        """Uncheck Follow System Theme if active, select *theme_name*, and apply it live immediately."""
        follow_cb = self._widgets.get('gui_theme_follow_system')
        follow_was_checked = False
        if isinstance(follow_cb, QCheckBox) and follow_cb.isChecked():
            follow_was_checked = True
            with QSignalBlocker(follow_cb):
                follow_cb.setChecked(False)
        combo = self._widgets.get('gui_theme')
        if isinstance(combo, QComboBox) and combo.currentText() != theme_name:
            self._set_enum(combo, theme_name)
        else:
            self._apply_selected_theme_live()
        if follow_was_checked:
            self._update_restart_notice()

    def _refresh_theme_combo_options(self, selected_name: str | None = None) -> None:
        """Reload built-in and custom theme names into the `gui_theme` combo box and preview gallery."""
        self._cached_themes_file = load_themes_file()[0]
        combo = self._widgets.get('gui_theme')
        if not isinstance(combo, QComboBox):
            return
        target_name = selected_name if selected_name is not None else combo.currentText()
        with QSignalBlocker(combo):
            combo.clear()
            combo.addItems([theme.name for theme in self._cached_themes_file.all_themes()])
            self._set_enum(combo, target_name)
        self._rebuild_theme_preview_cards()

    def _open_theme_manager(self) -> None:
        """Open the modal Theme Manager dialog and synchronize custom theme and system-theme updates."""
        self.cancel_pending_live_theme_switch()
        combo = self._widgets.get('gui_theme')
        manual_name = combo.currentText() if isinstance(combo, QComboBox) and combo.currentText() else Settings.gui_theme
        follow_checked = self._is_follow_system_checked()
        initial_selection = detect_system_theme_name() if follow_checked else manual_name
        dialog = ThemeManagerDialog(
            self,
            initial_theme_name=initial_selection,
            follow_system=follow_checked,
            manual_theme_name=manual_name,
        )
        dialog.follow_system_toggled.connect(self._on_theme_manager_follow_system_toggled)
        dialog.theme_renamed.connect(self._on_custom_theme_renamed)
        dialog.themes_deleted.connect(self._on_custom_themes_deleted)
        dialog.themes_changed.connect(self._on_themes_changed)
        dialog.exec()

    def _on_theme_manager_follow_system_toggled(self, raw_checked: object) -> None:
        """Synchronize `gui_theme_follow_system` in `SettingsDialog` when toggled inside `ThemeManagerDialog`."""
        checked = bool(raw_checked)
        follow_cb = self._widgets.get('gui_theme_follow_system')
        if isinstance(follow_cb, QCheckBox) and follow_cb.isChecked() != checked:
            with QSignalBlocker(follow_cb):
                follow_cb.setChecked(checked)
        self._sync_selected_theme_card()
        self._update_restart_notice()

    def _on_custom_theme_renamed(self, old_name: str, new_name: str) -> None:
        """Keep `Settings.gui_theme` and the active runtime theme aligned when a custom theme is renamed."""
        if Settings.gui_theme.casefold() == old_name.casefold():
            Settings.gui_theme = new_name
            Settings.rewrite_settings_file()
        if get_active_theme().name.casefold() == old_name.casefold():
            apply_runtime_theme(resolve_theme_by_name(new_name))
        for mapping in (self._old_values, self._initial_values):
            existing = mapping.get('gui_theme')
            if isinstance(existing, str) and existing.casefold() == old_name.casefold():
                mapping['gui_theme'] = new_name

        combo = self._widgets.get('gui_theme')
        target = new_name if isinstance(combo, QComboBox) and combo.currentText().casefold() == old_name.casefold() else None
        self._refresh_theme_combo_options(selected_name=target)

    def _on_custom_themes_deleted(self, raw_deleted_names: object) -> None:
        """Fall back to `DEFAULT_THEME_NAME` live if any deleted custom theme was persisted or selected."""
        if not isinstance(raw_deleted_names, tuple):
            return
        deleted_items = cast('tuple[object, ...]', raw_deleted_names)
        deleted_cf = {name.casefold() for name in deleted_items if isinstance(name, str)}
        if not deleted_cf:
            return
        if Settings.gui_theme.casefold() in deleted_cf:
            Settings.gui_theme = DEFAULT_THEME_NAME
            Settings.rewrite_settings_file()
        if get_active_theme().name.casefold() in deleted_cf:
            apply_runtime_theme(resolve_theme_by_name(DEFAULT_THEME_NAME))
        for mapping in (self._old_values, self._initial_values):
            existing = mapping.get('gui_theme')
            if isinstance(existing, str) and existing.casefold() in deleted_cf:
                mapping['gui_theme'] = DEFAULT_THEME_NAME

        combo = self._widgets.get('gui_theme')
        target = DEFAULT_THEME_NAME if isinstance(combo, QComboBox) and combo.currentText().casefold() in deleted_cf else None
        self._refresh_theme_combo_options(selected_name=target)

    def _on_themes_changed(self) -> None:
        """Refresh the theme dropdown and preview cards after custom theme changes."""
        self._refresh_theme_combo_options()
