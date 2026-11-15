"""Settings dialog for viewing, editing, saving, and resetting all application settings."""

from functools import partial
from typing import TYPE_CHECKING, cast, override

from PySide6.QtCore import QSignalBlocker, QTimer
from PySide6.QtGui import QColor, QIcon
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDoubleSpinBox,
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.capture.process import matches_process_name
from session_sniffer.constants.standalone import TITLE
from session_sniffer.discord.webhook import is_valid_webhook_url
from session_sniffer.guis._dialog_mixins import UnsavedChangesMixin, equalize_button_sizes, setup_tab_dialog_buttons
from session_sniffer.guis._settings_discord_mixin import SettingsDialogDiscordMixin, build_discord_info_group
from session_sniffer.guis._settings_looky_mixin import SettingsDialogLookyMixin
from session_sniffer.guis._settings_runtime import SettingValue, apply_runtime_settings_changes
from session_sniffer.guis._settings_theme_mixin import SettingsDialogThemeMixin
from session_sniffer.guis._settings_widget_builders import (
    HotkeyEditWidget,
    build_shortcuts_help_group,
    build_webserver_help_group,
    combo_canonical_value,
    create_boolean_widget,
    create_color_widget,
    create_column_tuple_widget,
    create_enum_widget,
    create_float_widget,
    create_hotkey_widget,
    create_integer_or_all_widget,
    create_integer_widget,
    create_ip_range_tuple_widget,
    create_setting_label,
    create_standard_form_layout,
    create_standard_vbox_layout,
    create_string_tuple_widget,
    create_text_widget,
    create_third_party_servers_split_widget,
    format_setting_tooltip,
    set_combo_by_canonical,
)
from session_sniffer.guis.color_picker_dialog import ColorPickerButton
from session_sniffer.guis.live_language import register_language_refresh, set_i18n_colon_label, set_live_follow_system_language_checkbox
from session_sniffer.guis.process_selector_widget import ProcessSelectorWidget
from session_sniffer.guis.stylesheets import (
    DIALOG_BUTTON_STYLESHEET,
    DIALOG_DANGER_BUTTON_STYLESHEET,
    SETTINGS_RESTART_BANNER_STYLESHEET,
)
from session_sniffer.guis.theming import DEFAULT_THEME_NAME, ICONS_DIR_PATH, load_themes_file, themed_color, themed_qss, themed_text_qcolor
from session_sniffer.guis.utils import (
    render_svg_icon_from_resource,
    render_svg_pixmap_from_resource,
    resize_window_for_screen,
    scale_by_ui,
    set_dialog_window_flags,
)
from session_sniffer.i18n import normalize_language_code, tr
from session_sniffer.networking.looky_system import LookyState
from session_sniffer.networking.utils import format_mac_address, is_ipv4_address, is_mac_address
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings import SETTING_CATEGORIES_ORDER, SETTING_DEFAULTS, SETTING_METADATA, SettingMeta, SettingType
from session_sniffer.settings.settings import Settings
from session_sniffer.utils import validate_and_strip_balanced_outer_parens
from session_sniffer.utils_exceptions import ParenthesisMismatchError

if TYPE_CHECKING:
    from collections.abc import Callable

    from session_sniffer.capture.packet_capture import PacketCapture

_NONE_PLACEHOLDER = 'None'
_DISCORD_PRESENCE_TITLE_MIN_LEN = 2


class SettingsDialog(SettingsDialogThemeMixin, SettingsDialogLookyMixin, SettingsDialogDiscordMixin, UnsavedChangesMixin, QDialog):
    """Non-modal dialog exposing every settings.json option for viewing, editing, saving, and resetting."""

    def __init__(self, parent: QWidget | None, capture: PacketCapture, on_change_interface: Callable[[], None]) -> None:
        """Build the tabbed settings dialog from setting metadata.

        Args:
            parent: Parent widget, or None for a top-level dialog.
            capture: The active packet capture instance.
            on_change_interface: Callback invoked to close this dialog and open the interface selection screen.
        """
        super().__init__(parent)
        self.setWindowTitle(f"{tr('Settings')} - {TITLE}")
        set_dialog_window_flags(self)
        self.setMinimumSize(scale_by_ui(950), scale_by_ui(750))
        resize_window_for_screen(self)

        self._capture = capture
        self._on_change_interface = on_change_interface
        self._interface_name_label: QLabel | None = None
        self._arp_spoofing_label: QLabel | None = None
        self._ip_address_label: QLabel | None = None
        self._mac_address_label: QLabel | None = None
        self._widgets: dict[str, QWidget] = {}
        self._labels: dict[str, QLabel] = {}
        self._old_values: dict[str, SettingValue] = {key: getattr(Settings, key) for key in SETTING_METADATA}
        self._initial_values: dict[str, SettingValue] = dict(self._old_values)
        self._changed_settings: set[str] = set()
        self._saved = self._loading_settings = self._pending_webhook_message_ids_reset = False
        self._manual_gui_language: str = normalize_language_code(Settings.gui_language) or 'en'
        self._last_verified_key: str = Settings.looky_api_key or '' if LookyState.user_data is not None else ''
        self._verify_worker = None
        self._verify_debounce: QTimer = QTimer(self)
        self._verify_debounce.setSingleShot(True)
        self._verify_debounce.timeout.connect(self._trigger_looky_verify)

        root_layout = QVBoxLayout(self)

        self._tabs = QTabWidget()
        self._game_tab_index: int = -1
        self._session_relays_group_box: QGroupBox | None = None
        for i, category in enumerate(SETTING_CATEGORIES_ORDER):
            tab_widget = self._build_tab(category)
            tab_widget.setProperty('category', category)
            self._tabs.addTab(tab_widget, tr(category))
            if category == 'GTA V':
                self._game_tab_index = i
        self._tabs.currentChanged.connect(self._on_tab_changed)
        root_layout.addWidget(self._tabs)

        self._restart_notice_banner = QFrame()
        self._restart_notice_banner.setObjectName('restartNoticeBanner')
        self._restart_notice_banner.setStyleSheet(SETTINGS_RESTART_BANNER_STYLESHEET)
        self._restart_notice_banner.setToolTip(tr('One or more modified settings require a capture restart upon saving.'))
        banner_layout = QHBoxLayout(self._restart_notice_banner)
        banner_layout.setContentsMargins(10, 6, 10, 6)
        banner_layout.setSpacing(8)

        banner_icon_label = QLabel()
        banner_icon_label.setPixmap(render_svg_pixmap_from_resource('triangle-alert.svg', 16, 16, themed_color('#f59e0b')))
        banner_layout.addWidget(banner_icon_label)

        self._restart_notice_label = QLabel(tr('Saving changes will restart packet capture.'))
        self._restart_notice_label.setStyleSheet(themed_qss('color: #f59e0b; font-size: 9pt; font-weight: 600;'))
        banner_layout.addWidget(self._restart_notice_label)
        banner_layout.addStretch()

        self._restart_notice_banner.setVisible(False)
        root_layout.addWidget(self._restart_notice_banner)

        button_row = QHBoxLayout()
        import_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'import.svg')), f" {tr('Import')}")
        import_button.setToolTip(tr('Import settings from a settings.json file (review before saving)'))
        import_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        import_button.clicked.connect(self._import_settings)
        button_row.addWidget(import_button)

        export_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'upload.svg')), f" {tr('Export')}")
        export_button.setToolTip(tr('Export current settings to a settings.json file'))
        export_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        export_button.clicked.connect(self._export_settings)
        button_row.addWidget(export_button)

        reset_fg = themed_text_qcolor('#ffffff', '#c0392b').name(QColor.NameFormat.HexArgb)
        reset_icon = render_svg_icon_from_resource('rotate-ccw.svg', scale_by_ui(16), scale_by_ui(16), reset_fg)
        reset_button = QPushButton(reset_icon, f" {tr('Reset all…')}")
        reset_button.setToolTip(tr('Reset all settings across all tabs to their default values (review before saving)'))
        reset_button.setStyleSheet(DIALOG_DANGER_BUTTON_STYLESHEET)
        save_button = setup_tab_dialog_buttons(button_row, reset_button, self._reset_to_defaults, self._reset_current_tab)
        save_button.setToolTip(tr('Validate and save all settings to settings.json'))
        save_button.clicked.connect(self._save_settings)
        button_row.addWidget(save_button)

        cancel_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'x.svg')), f" {tr('Cancel')}")
        cancel_button.setToolTip(tr('Discard changes and close'))
        cancel_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        cancel_button.clicked.connect(self.reject)
        button_row.addWidget(cancel_button)
        equalize_button_sizes(button_row)
        self._button_row = button_row
        root_layout.addLayout(button_row)

        self._connect_widget_change_signals()
        self._load_current_values()
        self._sync_loaded_process_baseline()
        self._update_restart_notice()

        # Force the webhook enable cascade once even if the value matches the
        # default (in which case `setChecked` would not fire `toggled`).
        webhook_enabled_widget = self._widgets.get('discord_webhook_enabled')
        if isinstance(webhook_enabled_widget, QCheckBox):
            webhook_enabled_widget.toggled.emit(webhook_enabled_widget.isChecked())

        # Show/hide Session Host Detection based on Feature Set.
        preset_widget = self._widgets.get('capture_feature_set')
        if isinstance(preset_widget, QComboBox):
            preset_widget.currentIndexChanged.connect(lambda _index=0, pw=preset_widget: self._on_feature_set_changed(combo_canonical_value(pw)))
            self._on_feature_set_changed(combo_canonical_value(preset_widget))

        # Show/hide Account Information based on API key presence.
        api_key_widget = self._widgets.get('looky_api_key')
        if isinstance(api_key_widget, QLineEdit):
            api_key_widget.textChanged.connect(self._on_looky_api_key_changed)
            api_key_widget.installEventFilter(self)
            self._on_looky_api_key_changed(api_key_widget.text())

        # Update Session tab controls and labels based on the Disconnected Players toggle.
        disconnected_enabled_widget = self._widgets.get('gui_disconnected_players_enabled')
        if isinstance(disconnected_enabled_widget, QCheckBox):
            disconnected_enabled_widget.toggled.connect(self._on_disconnected_players_enabled_toggled)
            self._on_disconnected_players_enabled_toggled()

        # Enable/disable High Rate Monitor threshold fields based on Smart vs Manual mode.
        hrm_mode_widget = self._widgets.get('high_rate_monitor_mode')
        if isinstance(hrm_mode_widget, QComboBox):
            hrm_mode_widget.currentIndexChanged.connect(lambda _index=0, hw=hrm_mode_widget: self._on_high_rate_monitor_mode_changed(combo_canonical_value(hw)))
            self._on_high_rate_monitor_mode_changed(combo_canonical_value(hrm_mode_widget))

        # Wire live language preview & Follow System Language toggling (never mutates Settings until Save).
        lang_widget = self._widgets.get('gui_language')
        if isinstance(lang_widget, QComboBox):
            lang_widget.currentIndexChanged.connect(self._on_gui_language_changed)

        follow_lang_widget = self._widgets.get('gui_language_follow_system')
        if isinstance(follow_lang_widget, QCheckBox):
            follow_lang_widget.toggled.connect(self._on_follow_system_language_toggled)
            set_live_follow_system_language_checkbox(follow_lang_widget)
            self._sync_follow_system_language_ui_state()

        register_language_refresh(self, self._on_language_refreshed)

    # ------------------------------------------------------------------
    # Tab / widget construction
    # ------------------------------------------------------------------

    def _build_tab(self, category: str) -> QWidget:
        """Create one tab page containing all settings for *category*."""
        page = QWidget()
        page_layout = QVBoxLayout(page)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)

        container = QWidget()
        outer_layout = QVBoxLayout(container)

        # Collect settings for this category, preserving insertion order.
        ungrouped: list[tuple[str, SettingMeta]] = []
        grouped: dict[str, list[tuple[str, SettingMeta]]] = {}
        for key, meta in SETTING_METADATA.items():
            if meta.category != category:
                continue
            if meta.hidden:
                continue
            if meta.group is not None and meta.group:
                grouped.setdefault(meta.group, []).append((key, meta))
            else:
                ungrouped.append((key, meta))

        if category == 'Web Server':
            outer_layout.addWidget(build_webserver_help_group())
        elif category == 'Shortcuts':
            outer_layout.addWidget(build_shortcuts_help_group())
        elif category == 'Discord':
            outer_layout.addWidget(build_discord_info_group())
        elif category == 'Capture':
            outer_layout.addWidget(self._build_interface_info_group())

        # Render ungrouped settings first in a plain form layout.
        if ungrouped:
            form = create_standard_form_layout()
            for key, meta in ungrouped:
                self._add_setting_row(form, key, meta)
            outer_layout.addLayout(form)

        # Render each group as a titled QGroupBox.
        for group_name, items in grouped.items():
            # The Discord Webhook group has a custom layout (masked URL, enable
            # cascade, reset-messages, automod warning).
            if category == 'Discord' and group_name == 'Webhook':
                outer_layout.addWidget(self._build_discord_webhook_group(items, self._add_setting_row))
                continue
            if category == 'GTA V' and group_name == 'Looky System':
                outer_layout.addWidget(self._build_looky_group(items, self._add_setting_row))
                continue

            group_box = QGroupBox(tr(group_name).replace('&', '&&'))
            if category == 'GTA V' and group_name == 'Session Relays':
                self._session_relays_group_box = group_box
            direct_items = [(setting_key, setting_meta) for setting_key, setting_meta in items if setting_meta.subgroup is None or not setting_meta.subgroup]
            subgrouped: dict[str, list[tuple[str, SettingMeta]]] = {}
            for setting_key, setting_meta in items:
                if setting_meta.subgroup is not None and setting_meta.subgroup:
                    subgrouped.setdefault(setting_meta.subgroup, []).append((setting_key, setting_meta))

            if subgrouped:
                group_vbox = create_standard_vbox_layout(group_box)
                if direct_items:
                    direct_form = create_standard_form_layout()
                    for key, meta in direct_items:
                        self._add_setting_row(direct_form, key, meta)
                    group_vbox.addLayout(direct_form)
                for sub_name, sub_items in subgrouped.items():
                    sub_box = QGroupBox(tr(sub_name).replace('&', '&&'))
                    sub_form = create_standard_form_layout(sub_box)
                    for key, meta in sub_items:
                        self._add_setting_row(sub_form, key, meta)
                    group_vbox.addWidget(sub_box)
            else:
                group_form = create_standard_form_layout(group_box)
                for key, meta in items:
                    self._add_setting_row(group_form, key, meta)
            outer_layout.addWidget(group_box)

        if category == 'Themes':
            self._populate_themes_tab(outer_layout)

        outer_layout.addStretch()
        scroll.setWidget(container)
        page_layout.addWidget(scroll)

        return page

    def _add_setting_row(self, form: QFormLayout, key: str, meta: SettingMeta) -> None:
        """Create a widget for *key* and append a labeled row to *form*."""
        widget = self._create_widget(key, meta)
        if meta.min_width is not None:
            widget.setMinimumWidth(meta.min_width)
        if meta.max_width is not None:
            widget.setMaximumWidth(meta.max_width)
        self._widgets[key] = widget

        # COLUMN_TUPLE, IP_RANGE_TUPLE, STRING_TUPLE and THIRD_PARTY_SERVERS_TUPLE widgets carry their label as the QGroupBox title — add
        # as a full-width spanning row so the widget gets all available horizontal space.
        if meta.setting_type in (SettingType.COLUMN_TUPLE, SettingType.IP_RANGE_TUPLE, SettingType.STRING_TUPLE, SettingType.THIRD_PARTY_SERVERS_TUPLE):
            form.addRow(widget)
            return

        label = create_setting_label(meta)
        self._labels[key] = label
        if tooltip := label.toolTip():
            widget.setToolTip(tooltip)

        if key == 'gui_theme':
            self._build_theme_setting_row(form, label, widget)
            return

        if key == 'capture_filter_process_pid' and not CaptureState.is_local_capture():
            label.setEnabled(False)
            widget.setEnabled(False)
            disabled_tooltip = tr('Process PID filtering is disabled when capturing traffic from an external device.')
            label.setToolTip(disabled_tooltip)
            widget.setToolTip(disabled_tooltip)

        form.addRow(label, widget)

    def _on_feature_set_changed(self, feature_set: str) -> None:
        """Show or hide feature-set-dependent tabs and update dynamic game tab title."""
        is_gta5 = feature_set == 'GTA V'
        is_rdr2 = feature_set == 'RDR2'
        is_supported_game = is_gta5 or is_rdr2

        if self._game_tab_index != -1:
            self._tabs.setTabVisible(self._game_tab_index, is_supported_game)
            if is_supported_game:
                self._tabs.setTabText(self._game_tab_index, tr(feature_set))

        self._looky_group_box.setVisible(is_gta5)
        if self._session_relays_group_box is not None:
            self._session_relays_group_box.setVisible(is_gta5)
        if is_gta5:
            api_key_widget = self._widgets.get('looky_api_key')
            self._on_looky_api_key_changed(api_key_widget.text() if isinstance(api_key_widget, QLineEdit) else '')
        else:
            self._verify_debounce.stop()
            if self._verify_worker is not None and self._verify_worker.isRunning():
                self._verify_worker.cancel()

    def _on_disconnected_players_enabled_toggled(self) -> None:
        """Update dependent controls and labels based on the Disconnected Players toggle."""
        disconnected_enabled_widget = self._widgets.get('gui_disconnected_players_enabled')
        checked = isinstance(disconnected_enabled_widget, QCheckBox) and disconnected_enabled_widget.isChecked()

        connected_rpp_label = self._labels.get('gui_connected_table_rows_per_page')
        connected_rpp_widget = self._widgets.get('gui_connected_table_rows_per_page')
        if connected_rpp_label is not None:
            set_i18n_colon_label(connected_rpp_label, 'Connected Rows Per Page' if checked else 'Rows Per Page')
            rpp_tooltip = (
                tr('Maximum rows per page in the connected-players table. 0 = show all.')
                if checked
                else tr('Maximum rows per page in the players table. 0 = show all.')
            )
            connected_rpp_label.setToolTip(rpp_tooltip)
            if connected_rpp_widget is not None:
                connected_rpp_widget.setToolTip(rpp_tooltip)

        connected_sort_col_label = self._labels.get('gui_connected_table_sort_column')
        if connected_sort_col_label is not None:
            set_i18n_colon_label(connected_sort_col_label, 'Connected Sort Column' if checked else 'Sort Column')
        connected_sort_order_label = self._labels.get('gui_connected_table_sort_order')
        if connected_sort_order_label is not None:
            set_i18n_colon_label(connected_sort_order_label, 'Connected Sort Order' if checked else 'Sort Order')
        for dep_key in (
            'gui_disconnected_table_rows_per_page',
            'gui_disconnected_players_timer',
            'gui_disconnected_players_limit',
            'gui_disconnected_table_sort_column',
            'gui_disconnected_table_sort_order',
        ):
            if (label := self._labels.get(dep_key)) is not None:
                label.setEnabled(checked)
            if (dep_widget := self._widgets.get(dep_key)) is not None:
                dep_widget.setEnabled(checked)

    def _on_high_rate_monitor_mode_changed(self, mode: str) -> None:
        """Enable or disable manual threshold inputs based on whether High Rate Monitor is in Smart or Manual mode."""
        is_manual = mode == 'Manual'
        for setting_key in ('high_rate_monitor_pps_threshold', 'high_rate_monitor_bps_threshold'):
            label = self._labels.get(setting_key)
            widget = self._widgets.get(setting_key)
            meta = SETTING_METADATA.get(setting_key)
            if label is not None:
                label.setEnabled(is_manual)
            if widget is not None:
                widget.setEnabled(is_manual)
            if meta is not None:
                tooltip = format_setting_tooltip(meta) or ''
                if not is_manual:
                    disabled_note = tr('Disabled in Smart mode (packet rate thresholds are calculated dynamically from the session average).')
                    tooltip = f'{tooltip}\n\n{disabled_note}' if tooltip else disabled_note
                if label is not None:
                    label.setToolTip(tooltip)
                if widget is not None:
                    widget.setToolTip(tooltip)

    def _update_high_rate_monitor_mode_state(self) -> None:
        """Update enabled state of High Rate Monitor threshold fields based on current combo selection."""
        hrm_mode_widget = self._widgets.get('high_rate_monitor_mode')
        if isinstance(hrm_mode_widget, QComboBox):
            self._on_high_rate_monitor_mode_changed(combo_canonical_value(hrm_mode_widget))

    def _on_language_refreshed(self) -> None:
        """Refresh window title, dynamic tabs, compound tooltips, and dependent UI states after a language switch."""
        self.setWindowTitle(f"{tr('Settings')} - {TITLE}")
        for i in range(self._tabs.count()):
            page = self._tabs.widget(i)
            if page is None:
                continue
            category = page.property('category')
            if isinstance(category, str) and category:
                self._tabs.setTabText(i, tr(category))

        preset_widget = self._widgets.get('capture_feature_set')
        if isinstance(preset_widget, QComboBox) and self._game_tab_index != -1 and self._tabs.isTabVisible(self._game_tab_index):
            self._tabs.setTabText(self._game_tab_index, tr(combo_canonical_value(preset_widget)))

        for key, meta in SETTING_METADATA.items():
            tooltip = format_setting_tooltip(meta) or ''
            if (label := self._labels.get(key)) is not None:
                label.setToolTip(tooltip)
            if (widget := self._widgets.get(key)) is not None and meta.setting_type not in (
                SettingType.COLUMN_TUPLE,
                SettingType.IP_RANGE_TUPLE,
                SettingType.STRING_TUPLE,
                SettingType.THIRD_PARTY_SERVERS_TUPLE,
            ):
                widget.setToolTip(tooltip)

        if not CaptureState.is_local_capture():
            disabled_tooltip = tr('Process PID filtering is disabled when capturing traffic from an external device.')
            if (pid_label := self._labels.get('capture_filter_process_pid')) is not None:
                pid_label.setToolTip(disabled_tooltip)
            if (pid_widget := self._widgets.get('capture_filter_process_pid')) is not None:
                pid_widget.setToolTip(disabled_tooltip)

        self._on_disconnected_players_enabled_toggled()
        self._update_high_rate_monitor_mode_state()
        self._sync_follow_system_language_ui_state()
        self._sync_follow_system_ui_state()
        self._update_restart_notice()
        self._refresh_interface_info_labels()
        self._update_sort_column_options()
        self._refresh_looky_language()
        equalize_button_sizes(self._button_row)

    def _create_widget(self, key: str, meta: SettingMeta) -> QWidget:
        """Return the appropriate input widget for a single setting."""
        if key == 'capture_filter_process_pid':
            return ProcessSelectorWidget(self, meta=meta)
        if key == 'gui_theme':
            combo = create_enum_widget(meta)
            combo.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
            combo.clear()
            for theme in self._cached_themes_file.all_themes():
                combo.addItem(theme.name, theme.name)
            return combo

        dispatch: dict[SettingType, Callable[[], QWidget]] = {
            SettingType.BOOLEAN: partial(create_boolean_widget, meta),
            SettingType.STRING: partial(create_text_widget, meta),
            SettingType.IPV4: partial(create_text_widget, meta),
            SettingType.MAC_ADDRESS: partial(create_text_widget, meta),
            SettingType.FLOAT: partial(create_float_widget, meta),
            SettingType.INTEGER: partial(create_integer_widget, meta),
            SettingType.INTEGER_OR_ALL: partial(create_integer_or_all_widget, meta),
            SettingType.ENUM: partial(create_enum_widget, meta),
            SettingType.COLUMN_TUPLE: partial(create_column_tuple_widget, key, meta),
            SettingType.COLOR: partial(create_color_widget, meta),
            SettingType.HOTKEY: partial(create_hotkey_widget, meta),
            SettingType.THIRD_PARTY_SERVERS_TUPLE: partial(create_third_party_servers_split_widget, key, meta),
            SettingType.IP_RANGE_TUPLE: partial(create_ip_range_tuple_widget, meta, self),
            SettingType.STRING_TUPLE: partial(create_string_tuple_widget, meta, self),
        }
        factory = dispatch.get(meta.setting_type)
        return factory() if factory is not None else QLineEdit()

    # ------------------------------------------------------------------
    # Load / save / reset
    # ------------------------------------------------------------------

    @override
    def _populate_widgets(self, getter: Callable[[str], SettingValue]) -> None:
        """Populate every widget using values returned by *getter* without triggering intermediate notices."""
        self._loading_settings = True
        try:
            self._refresh_theme_combo_options()
            for key, widget in self._widgets.items():
                self._set_widget_value(key, widget, getter(key), source_getter=getter)
            self._sync_follow_system_language_ui_state()
            self._update_sort_column_options()
            self._update_high_rate_monitor_mode_state()
            self._sync_selected_theme_card()
        finally:
            self._loading_settings = False

    def _load_current_values(self) -> None:
        """Populate every widget from the current in-memory Settings values."""
        self._populate_widgets(lambda key: cast('SettingValue', getattr(Settings, key)))

    def _set_widget_value(self, key: str, widget: QWidget, value: SettingValue, *, source_getter: Callable[[str], SettingValue] | None = None) -> None:
        """Push *value* into the appropriate *widget*."""
        meta = SETTING_METADATA[key]
        if key == 'gui_language':
            self._manual_gui_language = normalize_language_code(value) or 'en'

        match meta.setting_type:
            case SettingType.BOOLEAN:
                cast('QCheckBox', widget).setChecked(bool(value))
            case SettingType.STRING | SettingType.IPV4 | SettingType.MAC_ADDRESS:
                cast('QLineEdit', widget).setText('' if value is None else str(value))
            case SettingType.COLOR:
                cast('ColorPickerButton', widget).set_color(str(value) if value is not None else '')
            case SettingType.HOTKEY:
                cast('HotkeyEditWidget', widget).set_value(value if isinstance(value, str) else None)
            case SettingType.FLOAT:
                cast('QDoubleSpinBox', widget).setValue(float(value) if isinstance(value, (int, float)) else 0.0)
            case SettingType.INTEGER | SettingType.INTEGER_OR_ALL:
                if key == 'capture_filter_process_pid':
                    pid_value = int(value) if isinstance(value, (int, float)) else 0
                    process_name = cast('str | None', source_getter('capture_filter_process_name')) if source_getter is not None else None
                    default_track_by_name = SETTING_DEFAULTS['capture_filter_process_track_by_name']
                    track_by_name = bool(source_getter('capture_filter_process_track_by_name')) if source_getter is not None else default_track_by_name
                    cast('ProcessSelectorWidget', widget).set_value(pid_value, process_name, track_by_name=track_by_name)
                else:
                    cast('QSpinBox', widget).setValue(int(value) if isinstance(value, (int, float)) else 0)
            case SettingType.ENUM:
                self._set_enum(widget, value)
            case SettingType.COLUMN_TUPLE | SettingType.THIRD_PARTY_SERVERS_TUPLE:
                shown_set = set(value if isinstance(value, tuple) else ())
                for checkbox in widget.findChildren(QCheckBox):
                    checkbox.setChecked(checkbox.objectName() in shown_set)
            case SettingType.IP_RANGE_TUPLE | SettingType.STRING_TUPLE:
                entries: tuple[str, ...] = value if isinstance(value, tuple) else ()
                list_widget = next(iter(widget.findChildren(QListWidget)), None)
                if list_widget is not None:
                    list_widget.clear()
                    list_widget.addItems(list(entries))

    @override
    def _set_enum(self, widget: QWidget, value: SettingValue) -> None:
        """Set value for an enum combo box."""
        combo = cast('QComboBox', widget)
        set_combo_by_canonical(combo, _NONE_PLACEHOLDER if value is None else str(value), fallback=DEFAULT_THEME_NAME)

    def _read_widget_value(self, key: str, widget: QWidget) -> SettingValue:
        """Extract the current value from *widget* for setting *key*."""
        meta = SETTING_METADATA[key]
        value: SettingValue = None

        match meta.setting_type:
            case SettingType.BOOLEAN:
                value = cast('QCheckBox', widget).isChecked()
            case SettingType.STRING | SettingType.IPV4 | SettingType.MAC_ADDRESS:
                text = cast('QLineEdit', widget).text().strip()
                value = text or None
            case SettingType.COLOR:
                value = cast('ColorPickerButton', widget).color()
            case SettingType.HOTKEY:
                value = cast('HotkeyEditWidget', widget).value()
            case SettingType.FLOAT:
                value = cast('QDoubleSpinBox', widget).value()
            case SettingType.INTEGER | SettingType.INTEGER_OR_ALL:
                value = cast('ProcessSelectorWidget', widget).value() if key == 'capture_filter_process_pid' else cast('QSpinBox', widget).value()
            case SettingType.ENUM:
                if key == 'gui_language' and isinstance(follow_cb := self._widgets.get('gui_language_follow_system'), QCheckBox) and follow_cb.isChecked():
                    value = self._manual_gui_language
                else:
                    text = combo_canonical_value(cast('QComboBox', widget))
                    value = None if text == _NONE_PLACEHOLDER else text
            case SettingType.COLUMN_TUPLE | SettingType.THIRD_PARTY_SERVERS_TUPLE:
                value = self._read_column_tuple(meta, widget)
            case SettingType.IP_RANGE_TUPLE | SettingType.STRING_TUPLE:
                list_widget = next(iter(widget.findChildren(QListWidget)), None)
                value = () if not list_widget else tuple(item.text() for i in range(list_widget.count()) if (item := list_widget.item(i)))

        return value

    def _read_column_tuple(self, meta: SettingMeta, widget: QWidget) -> tuple[str, ...]:
        """Read checked column names from the column-tuple group box."""
        allowed_attr = meta.allowed_columns_attr or ''
        allowed_columns = cast('tuple[str, ...]', getattr(Settings, allowed_attr, ()))
        checkboxes = {checkbox.objectName(): checkbox for checkbox in widget.findChildren(QCheckBox)}
        return tuple(column_name for column_name in allowed_columns if (checkbox := checkboxes.get(column_name)) is not None and checkbox.isChecked())

    def _validate(self) -> tuple[list[str], dict[str, SettingValue]]:
        """Read every widget once and return validation errors alongside the collected values."""
        errors: list[str] = []
        values: dict[str, SettingValue] = {}

        for key, widget in self._widgets.items():
            meta = SETTING_METADATA[key]
            value = self._read_widget_value(key, widget)
            values[key] = value

            if meta.setting_type == SettingType.IPV4 and isinstance(value, str) and not is_ipv4_address(value):
                errors.append(tr('{label}: "{value}" is not a valid IPv4 address.', label=tr(meta.display_label), value=value))

            elif meta.setting_type == SettingType.COLOR and (not isinstance(value, str) or not QColor(value).isValid()):
                errors.append(tr('{label}: "{value}" is not a valid color.', label=tr(meta.display_label), value=value))

            elif meta.setting_type == SettingType.MAC_ADDRESS and isinstance(value, str):
                formatted = format_mac_address(value)
                if not is_mac_address(formatted):
                    errors.append(
                        tr(
                            '{label}: "{value}" is not a valid MAC address (expected format: AA:BB:CC:DD:EE:FF).',
                            label=tr(meta.display_label),
                            value=value,
                        ),
                    )

            elif meta.setting_type == SettingType.STRING and key == 'capture_prepend_custom_capture_filter' and isinstance(value, str):
                try:
                    validate_and_strip_balanced_outer_parens(value)
                except ParenthesisMismatchError:
                    errors.append(tr('{label}: filter expression has unbalanced parentheses.', label=tr(meta.display_label)))

            elif key == 'discord_presence_title' and isinstance(value, str) and 0 < len(value) < _DISCORD_PRESENCE_TITLE_MIN_LEN:
                errors.append(tr('Presence Title must be either empty (to disable) or at least 2 characters long.'))

        if bool(values.get('discord_webhook_enabled')):
            url_value = values.get('discord_webhook_url')
            if not isinstance(url_value, str) or not is_valid_webhook_url(url_value):
                errors.append(
                    tr(
                        'Discord Webhook is enabled but the Webhook URL is missing or invalid. '
                        'Expected format: https://discord.com/api/webhooks/<id>/<token>',
                    ),
                )

        datetime_option_keys = (
            'gui_columns_datetime_show_date',
            'gui_columns_datetime_show_time',
            'gui_columns_datetime_show_elapsed_time',
        )
        if not any(values.get(opt_key) for opt_key in datetime_option_keys):
            options_list = '\n'.join(f'  - {tr(SETTING_METADATA[opt_key].display_label)}' for opt_key in datetime_option_keys)
            errors.append(
                tr(
                    'At least one of the DateTime column display options must be enabled:\n{options}',
                    options=options_list,
                ),
            )

        hotkey_bindings: dict[str, list[tuple[str, str]]] = {}
        for key, meta in SETTING_METADATA.items():
            if meta.setting_type != SettingType.HOTKEY:
                continue
            chord_val = values.get(key)
            if isinstance(chord_val, str) and chord_val:
                label_text = f'{tr(meta.group)} \u2014 {tr(meta.display_label)}' if meta.group is not None and meta.group else tr(meta.display_label)
                hotkey_bindings.setdefault(chord_val.casefold(), []).append((chord_val, label_text))
        for bound_items in hotkey_bindings.values():
            if len(bound_items) > 1:
                display_chord = bound_items[0][0]
                actions_list = '\n'.join(f'  - {item_label}' for _, item_label in bound_items)
                errors.append(
                    tr(
                        'Shortcut "{shortcut}" is assigned to multiple actions:\n{actions}',
                        shortcut=display_chord,
                        actions=actions_list,
                    ),
                )

        return errors, values

    def _save_settings(self) -> None:
        """Validate, apply widget values to Settings, persist, and close."""
        errors, new_values = self._validate()
        if errors:
            QMessageBox.critical(self, TITLE, '\n\n'.join(errors))
            return

        live_process_pid = Settings.capture_filter_process_pid
        live_process_name = Settings.capture_filter_process_name
        runtime_old_values = {
            **self._old_values,
            'capture_filter_process_pid': live_process_pid,
            'capture_filter_process_name': live_process_name,
        }
        process_selector = cast('ProcessSelectorWidget', self._widgets['capture_filter_process_pid']) if 'capture_filter_process_pid' in self._widgets else None
        process_pid_modified = process_selector is not None and self._is_setting_modified('capture_filter_process_pid', process_selector)

        for key, value in new_values.items():
            if SETTING_METADATA[key].setting_type == SettingType.MAC_ADDRESS and isinstance(value, str):
                formatted_value: SettingValue = format_mac_address(value)
                new_values[key] = formatted_value
                setattr(Settings, key, formatted_value)
            else:
                setattr(Settings, key, value)

        if process_selector is not None:
            if (
                not process_pid_modified
                and bool(new_values.get('capture_filter_process_track_by_name'))
                and bool(runtime_old_values.get('capture_filter_process_track_by_name'))
            ):
                new_values['capture_filter_process_pid'] = live_process_pid
                new_values['capture_filter_process_name'] = live_process_name
                Settings.capture_filter_process_pid = live_process_pid
                Settings.capture_filter_process_name = live_process_name
            else:
                selected_process_name = process_selector.process_name()
                new_values['capture_filter_process_name'] = selected_process_name
                Settings.capture_filter_process_name = selected_process_name
                if process_selector.value() > 0 and selected_process_name is None and bool(new_values.get('capture_filter_process_track_by_name')):
                    new_values['capture_filter_process_track_by_name'] = False
                    Settings.capture_filter_process_track_by_name = False

        if self._capture.is_running():
            Settings.capture_interface_name = self._capture.config.interface.name
            Settings.capture_ip_address = self._capture.config.interface.ip_address
            Settings.capture_mac_address = self._capture.config.interface.mac_address

        if self._pending_webhook_message_ids_reset:
            Settings.discord_webhook_message_ids = None
            self._old_values['discord_webhook_message_ids'] = None
            self._pending_webhook_message_ids_reset = False

        self.cancel_pending_live_theme_switch()
        Settings.rewrite_settings_file()
        apply_runtime_settings_changes(self._capture, runtime_old_values, new_values, dialog_parent=self)

        self._changed_settings = {key for key, value in new_values.items() if value != self._initial_values.get(key)}
        self._saved = True
        self.accept()

    def _sync_loaded_process_baseline(self) -> None:
        """Align baseline process target values with the resolved ProcessSelectorWidget state."""
        process_selector = self._widgets.get('capture_filter_process_pid')
        if isinstance(process_selector, ProcessSelectorWidget):
            resolved_pid = process_selector.value()
            resolved_name = process_selector.process_name()
            self._old_values['capture_filter_process_pid'] = resolved_pid
            self._old_values['capture_filter_process_name'] = resolved_name
            self._initial_values['capture_filter_process_pid'] = resolved_pid
            self._initial_values['capture_filter_process_name'] = resolved_name

    def update_capture(self, capture: PacketCapture) -> None:
        """Bind a replaced `PacketCapture` instance and refresh the Interface info summary labels."""
        self._capture = capture
        self._refresh_interface_info_labels()

    def refresh_from_external_settings(self) -> None:
        """Reload widget values from `Settings`."""
        self._refresh_interface_info_labels()
        if not self.isVisible() or self._has_unsaved_changes_for_close():
            return
        self._cached_themes_file = load_themes_file()[0]
        self._old_values = {key: getattr(Settings, key) for key in SETTING_METADATA}
        self._initial_values = dict(self._old_values)
        self._load_current_values()
        self._sync_loaded_process_baseline()
        self._update_restart_notice()

    @property
    def changed_settings(self) -> set[str]:
        """Return the set of setting keys that were changed during this dialog session."""
        return self._changed_settings

    def _reset_tab_to_defaults(self, category: str) -> None:
        """Populate widgets belonging to *category* with default values without saving."""
        defaults_dict = cast('dict[str, SettingValue]', SETTING_DEFAULTS)
        preset_widget = self._widgets.get('capture_feature_set')
        is_rdr2 = isinstance(preset_widget, QComboBox) and combo_canonical_value(preset_widget) == 'RDR2'
        for key, widget in self._widgets.items():
            if key in defaults_dict and SETTING_METADATA[key].category == category:
                if is_rdr2 and category == 'GTA V' and SETTING_METADATA[key].group in ('Looky System', 'Session Relays'):
                    continue
                self._set_widget_value(key, widget, defaults_dict[key])
        self._apply_selected_language_live()
        self._update_sort_column_options()
        self._update_high_rate_monitor_mode_state()
        self._update_restart_notice()

    def _reset_current_tab(self) -> None:
        """Reset the current tab's settings to their default values."""
        current_widget = self._tabs.currentWidget()
        category_property = current_widget.property('category')
        self._reset_tab_to_defaults(str(category_property) if category_property else self._tabs.tabText(self._tabs.currentIndex()))

    def _reset_to_defaults(self) -> None:
        """Populate all widgets with default values without saving."""
        defaults_dict = cast('dict[str, SettingValue]', SETTING_DEFAULTS)
        self._populate_widgets(defaults_dict.get)
        self._apply_selected_theme_live()
        self._apply_selected_language_live()
        self._update_restart_notice()

    def _connect_widget_change_signals(self) -> None:
        """Connect change signals for all setting widgets to dynamically update dialog notices."""
        for key, widget in self._widgets.items():
            meta = SETTING_METADATA[key]
            match widget:
                case QCheckBox():
                    if key == 'capture_filter_process_track_by_name':
                        process_selector = self._widgets.get('capture_filter_process_pid')
                        if isinstance(process_selector, ProcessSelectorWidget):

                            def _make_process_scope_sync_handler(
                                selector: ProcessSelectorWidget,
                                track_by_name_checkbox: QCheckBox,
                            ) -> Callable[[], None]:
                                def _sync_process_scope() -> None:
                                    selector.sync_scope_state(track_by_name=track_by_name_checkbox.isChecked())

                                return _sync_process_scope

                            widget.toggled.connect(_make_process_scope_sync_handler(process_selector, widget))
                    widget.toggled.connect(self._update_restart_notice)
                case ColorPickerButton():
                    widget.color_changed.connect(self._update_restart_notice)
                case HotkeyEditWidget():
                    widget.hotkey_changed.connect(self._update_restart_notice)
                case QSpinBox() | QDoubleSpinBox():
                    widget.valueChanged.connect(self._update_restart_notice)
                case QComboBox():
                    widget.currentIndexChanged.connect(self._update_restart_notice)
                case ProcessSelectorWidget():
                    widget.process_target_changed.connect(self._update_restart_notice)
                    widget.process_selection_applied.connect(self._on_process_selection_applied)
                case QLineEdit():
                    widget.textChanged.connect(self._update_restart_notice)
                case _:
                    if meta.setting_type in (SettingType.COLUMN_TUPLE, SettingType.THIRD_PARTY_SERVERS_TUPLE):
                        for checkbox in widget.findChildren(QCheckBox):
                            checkbox.toggled.connect(self._update_restart_notice)
                            if key in ('gui_columns_connected_shown', 'gui_columns_disconnected_shown'):
                                checkbox.toggled.connect(self._update_sort_column_options)
                    elif meta.setting_type in (SettingType.IP_RANGE_TUPLE, SettingType.STRING_TUPLE):
                        list_widget = next(iter(widget.findChildren(QListWidget)), None)
                        if list_widget is not None:
                            list_widget.model().rowsInserted.connect(self._on_list_rows_changed)
                            list_widget.model().rowsRemoved.connect(self._on_list_rows_changed)

    def _on_list_rows_changed(self, *_args: object) -> None:
        """Handle rows added or removed in IP range list widgets."""
        self._update_restart_notice()

    def _update_sort_column_options(self, *_args: object) -> None:
        """Update table sort column combo boxes based on currently enabled columns."""
        specs = (
            ('gui_columns_connected_shown', 'gui_connected_table_sort_column', Settings.GUI_ALL_CONNECTED_COLUMNS, 'Last Rejoin'),
            ('gui_columns_disconnected_shown', 'gui_disconnected_table_sort_column', Settings.GUI_ALL_DISCONNECTED_COLUMNS, 'Last Seen'),
        )
        for shown_key, sort_key, all_columns, fallback_col in specs:
            shown_widget = self._widgets.get(shown_key)
            sort_widget = self._widgets.get(sort_key)
            if shown_widget is None or not isinstance(sort_widget, QComboBox):
                continue
            checked = {cb.objectName() for cb in shown_widget.findChildren(QCheckBox) if cb.isChecked()}
            available = [col for col in all_columns if col in checked or col in Settings.GUI_FORCED_COLUMNS]
            current_selected = combo_canonical_value(sort_widget)
            target_selected = current_selected if current_selected in available else fallback_col
            with QSignalBlocker(sort_widget):
                sort_widget.clear()
                for col in available:
                    sort_widget.addItem(tr(col), col)
                set_combo_by_canonical(sort_widget, target_selected, fallback=fallback_col)

    def _on_process_selection_applied(self) -> None:
        """Synchronize dialog widgets after TargetProcessDialog updates the process selector."""
        process_selector = self._widgets.get('capture_filter_process_pid')
        if not isinstance(process_selector, ProcessSelectorWidget):
            return
        track_by_name_widget = self._widgets.get('capture_filter_process_track_by_name')
        if isinstance(track_by_name_widget, QCheckBox):
            with QSignalBlocker(track_by_name_widget):
                track_by_name_widget.setChecked(process_selector.track_by_name)
        process_selector.sync_scope_state(track_by_name=process_selector.track_by_name)
        self._update_restart_notice()

    def _is_setting_modified(self, key: str, widget: QWidget) -> bool:
        """Return `True` if *widget*'s current value for *key* differs from its initial value."""
        current_value = self._read_widget_value(key, widget)
        original_value = self._old_values.get(key)
        if key == 'capture_filter_process_pid' and isinstance(widget, ProcessSelectorWidget):
            current_name = widget.process_name()
            original_name = self._old_values.get('capture_filter_process_name')
            same_tracked_name = isinstance(current_name, str) and isinstance(original_name, str) and matches_process_name(current_name, original_name)
            if (
                bool(self._old_values.get('capture_filter_process_track_by_name'))
                and widget.track_by_name
                and same_tracked_name
                and current_value in (original_value, Settings.capture_filter_process_pid)
            ):
                return False
            return current_value != original_value or current_name != original_name
        if SETTING_METADATA[key].setting_type in (SettingType.IP_RANGE_TUPLE, SettingType.STRING_TUPLE):
            return sorted(current_value if isinstance(current_value, tuple) else ()) != sorted(original_value if isinstance(original_value, tuple) else ())
        return current_value != original_value

    @override
    def _has_unsaved_restart_changes(self) -> bool:
        """Return `True` if any modified setting requires a packet capture restart."""
        return any(SETTING_METADATA[key].requires_capture_restart and self._is_setting_modified(key, widget) for key, widget in self._widgets.items())

    @override
    def _has_unsaved_changes_for_close(self) -> bool:
        """Return `True` if there are unsaved changes that should be saved before closing."""
        return self._pending_webhook_message_ids_reset or any(self._is_setting_modified(key, widget) for key, widget in self._widgets.items())

    @override
    def _save_on_close(self) -> bool:
        """Save settings; return `True` if save succeeded."""
        self._saved = False
        self._save_settings()
        return self._saved

    def _on_tab_changed(self, _index: int) -> None:
        """Handle tab switching; automatically re-blurs Looky System sensitive fields and masks passwords."""
        self._hide_looky_account_sensitive_values()
        self._hide_secret_fields()
