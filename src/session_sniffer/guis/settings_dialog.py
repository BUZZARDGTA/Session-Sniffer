"""Settings dialog for viewing, editing, saving, and resetting all application settings."""

from dataclasses import replace
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING, cast, override

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QAction, QColor, QIcon
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDoubleSpinBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.background import clear_voice_notification_queue, ensure_looky_core_running
from session_sniffer.capture.arp_spoofing import ArpSpoofingController
from session_sniffer.capture.filters import build_capture_filters
from session_sniffer.capture.process_monitor import ensure_process_monitor_running
from session_sniffer.constants.local import RESOURCES_DIR_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.discord.webhook import is_valid_webhook_url
from session_sniffer.guis._dialog_mixins import (
    UnsavedChangesMixin,
    equalize_button_sizes,
    setup_tab_dialog_buttons,
)
from session_sniffer.guis._settings_discord_mixin import SettingsDialogDiscordMixin
from session_sniffer.guis._settings_looky_mixin import SettingsDialogLookyMixin
from session_sniffer.guis._settings_widget_builders import (
    build_discord_info_group,
    build_webserver_help_group,
    create_bool_or_enum_widget,
    create_boolean_widget,
    create_color_widget,
    create_column_tuple_widget,
    create_enum_widget,
    create_float_widget,
    create_integer_or_all_widget,
    create_integer_widget,
    create_ip_range_tuple_widget,
    create_standard_form_layout,
    create_standard_vbox_layout,
    create_text_widget,
    create_third_party_servers_split_widget,
    format_setting_tooltip,
    get_line_edit,
)
from session_sniffer.guis.color_picker_dialog import ColorPickerButton
from session_sniffer.guis.process_selector_widget import ProcessSelectorWidget
from session_sniffer.guis.relay_conflict import prompt_to_disable_gta5_relay_if_filtered
from session_sniffer.guis.secret_line_edit import SecretLineEdit
from session_sniffer.guis.stylesheets import (
    DIALOG_BUTTON_STYLESHEET,
    DIALOG_DANGER_BUTTON_STYLESHEET,
    DIALOG_PRIMARY_BUTTON_STYLESHEET,
    INTERFACE_INFO_CARD_STYLESHEET,
    INTERFACE_INFO_VALUE_LABEL_STYLESHEET,
    SETTINGS_RESTART_BANNER_STYLESHEET,
)
from session_sniffer.guis.utils import (
    get_screen_size,
    resize_window_for_screen,
    scale_by_ui,
    set_dialog_window_flags,
)
from session_sniffer.networking.looky_system import LookyState
from session_sniffer.networking.utils import format_mac_address, is_ipv4_address, is_mac_address
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings import SETTING_CATEGORIES_ORDER, SETTING_DEFAULTS, SETTING_METADATA, SettingMeta, SettingType
from session_sniffer.settings.settings import Settings
from session_sniffer.text_templates import build_settings_ini_header_text
from session_sniffer.utils import validate_and_strip_balanced_outer_parens
from session_sniffer.utils_exceptions import ParenthesisMismatchError
from session_sniffer.webserver import WebServer, start_webserver_from_settings

if TYPE_CHECKING:
    from collections.abc import Callable

    from session_sniffer.capture.packet_capture import PacketCapture

_NONE_PLACEHOLDER = 'None'
_DISCORD_PRESENCE_TITLE_MIN_LEN = 2

SettingValue = bool | str | int | float | tuple[str, ...] | None


class SettingsDialog(SettingsDialogLookyMixin, SettingsDialogDiscordMixin, UnsavedChangesMixin, QDialog):
    """Non-modal dialog exposing every Settings.ini option for viewing, editing, saving, and resetting."""

    def __init__(self, parent: QWidget | None, capture: PacketCapture, on_change_interface: Callable[[], None]) -> None:
        """Build the tabbed settings dialog from setting metadata.

        Args:
            parent: Parent widget, or None for a top-level dialog.
            capture: The active packet capture instance.
            on_change_interface: Callback invoked to close this dialog and open the interface selection screen.
        """
        super().__init__(parent)
        self.setWindowTitle(f'Settings - {TITLE}')
        set_dialog_window_flags(self)
        self.setMinimumSize(scale_by_ui(950), scale_by_ui(750))
        screen_size = get_screen_size()
        resize_window_for_screen(self, screen_size)

        self._capture = capture
        self._on_change_interface = on_change_interface
        self._widgets: dict[str, QWidget] = {}
        self._labels: dict[str, QLabel] = {}
        self._old_values: dict[str, SettingValue] = {key: getattr(Settings, key) for key in SETTING_METADATA}
        self._saved: bool = False
        self._loading_settings: bool = False
        self._last_verified_key: str = Settings.looky_api_key or '' if LookyState.user_data is not None else ''
        self._verify_worker = None
        self._verify_debounce: QTimer = QTimer(self)
        self._verify_debounce.setSingleShot(True)
        self._verify_debounce.timeout.connect(self._trigger_looky_verify)

        root_layout = QVBoxLayout(self)

        self._tabs = QTabWidget()
        self._looky_tab_index: int = -1
        self._game_tab_index: int = -1
        for i, category in enumerate(SETTING_CATEGORIES_ORDER):
            tab_widget = self._build_tab(category)
            tab_widget.setProperty('category', category)
            self._tabs.addTab(tab_widget, category)
            if category == 'Looky System':
                self._looky_tab_index = i
            elif category == 'GTA V':
                self._game_tab_index = i
        self._tabs.currentChanged.connect(self._on_tab_changed)
        root_layout.addWidget(self._tabs)

        self._restart_notice_banner = QFrame()
        self._restart_notice_banner.setObjectName('restartNoticeBanner')
        self._restart_notice_banner.setStyleSheet(SETTINGS_RESTART_BANNER_STYLESHEET)
        self._restart_notice_banner.setToolTip('One or more modified settings require a capture restart upon saving.')
        banner_layout = QHBoxLayout(self._restart_notice_banner)
        banner_layout.setContentsMargins(10, 6, 10, 6)
        banner_layout.setSpacing(8)

        banner_icon_label = QLabel()
        banner_icon_label.setPixmap(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'warning.svg')).pixmap(16, 16))
        banner_layout.addWidget(banner_icon_label)

        banner_text_label = QLabel('Saving changes will restart packet capture.')
        banner_text_label.setStyleSheet('color: #f59e0b; font-size: 9pt; font-weight: 600;')
        banner_layout.addWidget(banner_text_label)
        banner_layout.addStretch()

        self._restart_notice_banner.setVisible(False)
        root_layout.addWidget(self._restart_notice_banner)

        button_row = QHBoxLayout()

        import_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'import.svg')), ' Import')
        import_button.setToolTip('Import settings from a Settings.ini file')
        import_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        import_button.clicked.connect(self._import_settings)
        button_row.addWidget(import_button)

        export_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'export.svg')), ' Export')
        export_button.setToolTip('Export current settings to a Settings.ini file')
        export_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        export_button.clicked.connect(self._export_settings)
        button_row.addWidget(export_button)

        reset_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'reset.svg')), ' Reset all…')
        reset_button.setToolTip('Reset all settings across all tabs to their default values (review before saving)')
        reset_button.setStyleSheet(DIALOG_DANGER_BUTTON_STYLESHEET)
        save_button = setup_tab_dialog_buttons(button_row, reset_button, self._reset_to_defaults, self._reset_current_tab)
        save_button.setToolTip('Validate and save all settings to Settings.ini')
        save_button.clicked.connect(self._save_settings)
        button_row.addWidget(save_button)

        cancel_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'close.svg')), ' Cancel')
        cancel_button.setToolTip('Discard changes and close')
        cancel_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        cancel_button.clicked.connect(self.reject)
        button_row.addWidget(cancel_button)

        equalize_button_sizes(button_row)

        root_layout.addLayout(button_row)

        self._connect_widget_change_signals()
        self._load_current_values()

        # Force the webhook enable cascade once even if the value matches the
        # default (in which case `setChecked` would not fire `toggled`).
        webhook_enabled_widget = self._widgets.get('discord_webhook_enabled')
        if isinstance(webhook_enabled_widget, QCheckBox):
            webhook_enabled_widget.toggled.emit(webhook_enabled_widget.isChecked())

        # Show/hide Session Host Detection based on Feature Set.
        preset_widget = self._widgets.get('capture_feature_set')
        if isinstance(preset_widget, QComboBox):
            preset_widget.currentTextChanged.connect(self._on_feature_set_changed)
            self._on_feature_set_changed(preset_widget.currentText())

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
            self._on_disconnected_players_enabled_toggled(disconnected_enabled_widget.isChecked())

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
            if meta.group:
                grouped.setdefault(meta.group, []).append((key, meta))
            else:
                ungrouped.append((key, meta))

        if category == 'Web Server':
            outer_layout.addWidget(build_webserver_help_group())
        elif category == 'Discord':
            outer_layout.addWidget(build_discord_info_group())
        elif category == 'Looky System':
            outer_layout.addWidget(self._build_looky_info_group())
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
            if category == 'Discord' and group_name == 'Server Webhook':
                outer_layout.addWidget(self._build_discord_webhook_group(items, self._add_setting_row))
                continue

            group_box = QGroupBox(group_name.replace('&', '&&'))
            direct_items = [(setting_key, setting_meta) for setting_key, setting_meta in items if not setting_meta.subgroup]
            subgrouped: dict[str, list[tuple[str, SettingMeta]]] = {}
            for setting_key, setting_meta in items:
                if setting_meta.subgroup:
                    subgrouped.setdefault(setting_meta.subgroup, []).append((setting_key, setting_meta))

            if subgrouped:
                group_vbox = create_standard_vbox_layout(group_box)
                if direct_items:
                    direct_form = create_standard_form_layout()
                    for key, meta in direct_items:
                        self._add_setting_row(direct_form, key, meta)
                    group_vbox.addLayout(direct_form)
                for sub_name, sub_items in subgrouped.items():
                    sub_box = QGroupBox(sub_name.replace('&', '&&'))
                    sub_form = create_standard_form_layout(sub_box)
                    for key, meta in sub_items:
                        self._add_setting_row(sub_form, key, meta)
                    group_vbox.addWidget(sub_box)
            elif category == 'Looky System' and group_name == 'Authentication':
                auth_vbox = create_standard_vbox_layout(group_box)
                auth_row = QHBoxLayout()
                auth_row.setContentsMargins(0, 0, 0, 0)
                auth_row.setSpacing(10)
                auth_row.addStretch(1)
                for key, meta in items:
                    widget = self._create_widget(key, meta)
                    if meta.min_width is not None:
                        widget.setMinimumWidth(meta.min_width)
                    if meta.max_width is not None:
                        widget.setMaximumWidth(meta.max_width)
                    self._widgets[key] = widget

                    label = QLabel(f'{meta.display_label}:')
                    self._labels[key] = label
                    tooltip = format_setting_tooltip(meta)
                    if tooltip:
                        label.setToolTip(tooltip)

                    auth_row.addWidget(label, 0, Qt.AlignmentFlag.AlignVCenter)
                    auth_row.addWidget(widget, 0, Qt.AlignmentFlag.AlignVCenter)
                auth_row.addStretch(1)
                auth_vbox.addLayout(auth_row)
                self._looky_account_info_group = self._build_looky_account_info_group()
                auth_vbox.addWidget(self._looky_account_info_group)
            else:
                group_form = create_standard_form_layout(group_box)
                for key, meta in items:
                    self._add_setting_row(group_form, key, meta)
            outer_layout.addWidget(group_box)

        outer_layout.addStretch()
        scroll.setWidget(container)
        page_layout.addWidget(scroll)

        return page

    def _build_interface_info_group(self) -> QGroupBox:
        """Build a styled read-only interface summary panel with a primary action button."""
        group_box = QGroupBox('Interface')
        group_box.setStyleSheet(INTERFACE_INFO_CARD_STYLESHEET)
        layout = QVBoxLayout(group_box)
        layout.setSpacing(8)
        layout.setContentsMargins(10, 6, 10, 10)

        def _make_label(text: str) -> QLabel:
            label = QLabel(text + ':')
            label.setStyleSheet('color: #a5b4c4; font-weight: 600; background: transparent;')
            label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            return label

        def _make_value(value: str | None) -> QLabel:
            label = QLabel(value if value is not None else '\u2014')
            label.setStyleSheet(INTERFACE_INFO_VALUE_LABEL_STYLESHEET)
            label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            return label

        arp_state = ('Running' if ArpSpoofingController.is_running() else 'Stopped') if Settings.capture_arp_spoofing else 'Disabled'

        grid = QGridLayout()
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(6)
        grid.setColumnStretch(1, 1)
        grid.setColumnStretch(3, 1)
        grid.setColumnMinimumWidth(2, 20)  # Gap between the two pairs.
        grid.addWidget(_make_label('Interface Name'), 0, 0)
        grid.addWidget(_make_value(Settings.capture_interface_name), 0, 1)
        grid.addWidget(_make_label('ARP Spoofing'), 0, 2)
        grid.addWidget(_make_value(arp_state), 0, 3)
        grid.addWidget(_make_label('IP Address'), 1, 0)
        grid.addWidget(_make_value(Settings.capture_ip_address), 1, 1)
        grid.addWidget(_make_label('MAC Address'), 1, 2)
        grid.addWidget(_make_value(Settings.capture_mac_address), 1, 3)
        layout.addLayout(grid)

        separator = QFrame()
        separator.setFrameShape(QFrame.Shape.HLine)
        separator.setFrameShadow(QFrame.Shadow.Sunken)
        separator.setStyleSheet('background: rgba(61, 142, 201, 0.25); border: none; max-height: 1px;')
        layout.addWidget(separator)

        change_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'refresh.svg')), ' Change Interface\u2026')
        change_button.setToolTip('Close settings and open the network interface selection screen')
        change_button.setStyleSheet(DIALOG_PRIMARY_BUTTON_STYLESHEET)
        change_button.clicked.connect(self._open_interface_selection)
        layout.addWidget(change_button)

        return group_box

    def _open_interface_selection(self) -> None:
        """Discard any unsaved settings changes, close this dialog, and trigger interface selection."""
        self._saved = True  # Suppress the unsaved-changes prompt on close.
        self.reject()
        self._on_change_interface()

    def _add_setting_row(self, form: QFormLayout, key: str, meta: SettingMeta) -> None:
        """Create a widget for *key* and append a labeled row to *form*."""
        widget = self._create_widget(key, meta)
        if meta.min_width is not None:
            widget.setMinimumWidth(meta.min_width)
        if meta.max_width is not None:
            widget.setMaximumWidth(meta.max_width)
        self._widgets[key] = widget

        # COLUMN_TUPLE, IP_RANGE_TUPLE and THIRD_PARTY_SERVERS_TUPLE widgets carry their label as the QGroupBox title — add
        # as a full-width spanning row so the widget gets all available horizontal space.
        if meta.setting_type in (SettingType.COLUMN_TUPLE, SettingType.IP_RANGE_TUPLE, SettingType.THIRD_PARTY_SERVERS_TUPLE):
            form.addRow(widget)
            return

        label = QLabel(f'{meta.display_label}:')
        self._labels[key] = label

        tooltip = format_setting_tooltip(meta)
        if tooltip:
            label.setToolTip(tooltip)
            widget.setToolTip(tooltip)

        if key == 'capture_filter_process_pid' and not CaptureState.is_local_capture():
            label.setEnabled(False)
            widget.setEnabled(False)
            disabled_tooltip = 'Process PID filtering is disabled when capturing traffic from an external device.'
            label.setToolTip(disabled_tooltip)
            widget.setToolTip(disabled_tooltip)

        form.addRow(label, widget)

    def _on_feature_set_changed(self, feature_set: str) -> None:
        """Show or hide feature-set-dependent tabs and update dynamic game tab title."""
        is_gta5 = feature_set == 'GTA V'
        is_rdr2 = feature_set == 'RDR2'
        is_supported_game = is_gta5 or is_rdr2

        if self._looky_tab_index != -1:
            self._tabs.setTabVisible(self._looky_tab_index, is_gta5)

        if self._game_tab_index != -1:
            self._tabs.setTabVisible(self._game_tab_index, is_supported_game)
            if is_supported_game:
                self._tabs.setTabText(self._game_tab_index, feature_set)

    def _on_disconnected_players_enabled_toggled(self, checked: bool) -> None:  # noqa: FBT001
        """Update Session tab controls and labels based on the Disconnected Players toggle."""
        connected_rpp_label = self._labels.get('gui_connected_table_rows_per_page')
        connected_rpp_widget = self._widgets.get('gui_connected_table_rows_per_page')
        if connected_rpp_label is not None:
            connected_rpp_label.setText('Connected Rows Per Page:' if checked else 'Rows Per Page:')
            rpp_tooltip = 'Maximum rows per page in the connected-players table. 0 = show all.' if checked else 'Maximum rows per page in the players table. 0 = show all.'
            connected_rpp_label.setToolTip(rpp_tooltip)
            if connected_rpp_widget is not None:
                connected_rpp_widget.setToolTip(rpp_tooltip)

        disconnected_rpp_label = self._labels.get('gui_disconnected_table_rows_per_page')
        disconnected_rpp_widget = self._widgets.get('gui_disconnected_table_rows_per_page')
        if disconnected_rpp_label is not None:
            disconnected_rpp_label.setEnabled(checked)
        if disconnected_rpp_widget is not None:
            disconnected_rpp_widget.setEnabled(checked)

        disconnected_timer_label = self._labels.get('gui_disconnected_players_timer')
        disconnected_timer_widget = self._widgets.get('gui_disconnected_players_timer')
        if disconnected_timer_label is not None:
            disconnected_timer_label.setEnabled(checked)
        if disconnected_timer_widget is not None:
            disconnected_timer_widget.setEnabled(checked)

        connected_sort_col_label = self._labels.get('gui_connected_table_sort_column')
        if connected_sort_col_label is not None:
            connected_sort_col_label.setText('Connected Sort Column:' if checked else 'Sort Column:')
        connected_sort_order_label = self._labels.get('gui_connected_table_sort_order')
        if connected_sort_order_label is not None:
            connected_sort_order_label.setText('Connected Sort Order:' if checked else 'Sort Order:')
        for sort_key in ('gui_disconnected_table_sort_column', 'gui_disconnected_table_sort_order'):
            if (label := self._labels.get(sort_key)) is not None:
                label.setEnabled(checked)
            if (sort_widget := self._widgets.get(sort_key)) is not None:
                sort_widget.setEnabled(checked)

    def _create_widget(self, key: str, meta: SettingMeta) -> QWidget:
        """Return the appropriate input widget for a single setting."""
        if key == 'capture_filter_process_pid':
            return ProcessSelectorWidget(self, meta=meta)

        dispatch: dict[SettingType, Callable[[], QWidget]] = {
            SettingType.BOOLEAN: partial(create_boolean_widget, meta),
            SettingType.STRING: partial(create_text_widget, meta),
            SettingType.IPV4: partial(create_text_widget, meta),
            SettingType.MAC_ADDRESS: partial(create_text_widget, meta),
            SettingType.FLOAT: partial(create_float_widget, meta),
            SettingType.INTEGER: partial(create_integer_widget, meta),
            SettingType.INTEGER_OR_ALL: partial(create_integer_or_all_widget, meta),
            SettingType.ENUM: partial(create_enum_widget, meta),
            SettingType.BOOL_OR_ENUM: partial(create_bool_or_enum_widget, meta),
            SettingType.COLUMN_TUPLE: partial(create_column_tuple_widget, key, meta),
            SettingType.COLOR: partial(create_color_widget, meta),
            SettingType.THIRD_PARTY_SERVERS_TUPLE: partial(create_third_party_servers_split_widget, key, meta),
            SettingType.IP_RANGE_TUPLE: partial(create_ip_range_tuple_widget, meta, self),
        }
        factory = dispatch.get(meta.setting_type)
        return factory() if factory is not None else QLineEdit()

    # ------------------------------------------------------------------
    # Load / save / reset
    # ------------------------------------------------------------------

    def _load_current_values(self) -> None:
        """Populate every widget from the current in-memory Settings values."""
        self._loading_settings = True
        try:
            for key, widget in self._widgets.items():
                value = cast('SettingValue', getattr(Settings, key))
                self._set_widget_value(key, widget, value)
            self._update_sort_column_options()
        finally:
            self._loading_settings = False

    def _set_widget_value(self, key: str, widget: QWidget, value: SettingValue) -> None:
        """Push *value* into the appropriate *widget*."""
        meta = SETTING_METADATA[key]

        match meta.setting_type:
            case SettingType.BOOLEAN:
                cast('QCheckBox', widget).setChecked(bool(value))

            case SettingType.STRING | SettingType.IPV4 | SettingType.MAC_ADDRESS:
                get_line_edit(widget).setText('' if value is None else str(value))

            case SettingType.COLOR:
                cast('ColorPickerButton', widget).set_color(str(value) if value is not None else '')

            case SettingType.FLOAT:
                cast('QDoubleSpinBox', widget).setValue(float(value) if isinstance(value, (int, float)) else 0.0)

            case SettingType.INTEGER | SettingType.INTEGER_OR_ALL:
                if key == 'capture_filter_process_pid':
                    cast('ProcessSelectorWidget', widget).set_value(int(value) if isinstance(value, (int, float)) else 0)
                else:
                    cast('QSpinBox', widget).setValue(int(value) if isinstance(value, (int, float)) else 0)

            case SettingType.ENUM:
                self._set_enum(widget, value)

            case SettingType.BOOL_OR_ENUM:
                self._set_bool_or_enum(widget, value)

            case SettingType.COLUMN_TUPLE | SettingType.THIRD_PARTY_SERVERS_TUPLE:
                shown: tuple[str, ...] = value if isinstance(value, tuple) else ()
                shown_set = set(shown)
                for checkbox in widget.findChildren(QCheckBox):
                    checkbox.setChecked(checkbox.objectName() in shown_set)

            case SettingType.IP_RANGE_TUPLE:
                entries: tuple[str, ...] = value if isinstance(value, tuple) else ()
                list_widget = next(iter(widget.findChildren(QListWidget)), None)
                if list_widget is not None:
                    list_widget.clear()
                    list_widget.addItems(list(entries))

    def _set_enum(self, widget: QWidget, value: SettingValue) -> None:
        """Set value for an enum combo box."""
        combo = cast('QComboBox', widget)
        text = _NONE_PLACEHOLDER if value is None else str(value)
        index = combo.findText(text, Qt.MatchFlag.MatchFixedString)
        if index >= 0:
            combo.setCurrentIndex(index)

    def _set_bool_or_enum(self, widget: QWidget, value: SettingValue) -> None:
        """Set value for a bool-or-enum combo box."""
        combo_be = cast('QComboBox', widget)
        if value is False:
            combo_be.setCurrentIndex(0)
        else:
            index = combo_be.findText(str(value), Qt.MatchFlag.MatchFixedString)
            if index >= 0:
                combo_be.setCurrentIndex(index)

    def _read_widget_value(self, key: str, widget: QWidget) -> SettingValue:
        """Extract the current value from *widget* for setting *key*."""
        meta = SETTING_METADATA[key]
        value: SettingValue = None

        match meta.setting_type:
            case SettingType.BOOLEAN:
                value = cast('QCheckBox', widget).isChecked()
            case SettingType.STRING | SettingType.IPV4 | SettingType.MAC_ADDRESS:
                text = get_line_edit(widget).text().strip()
                value = text or None
            case SettingType.COLOR:
                value = cast('ColorPickerButton', widget).color()
            case SettingType.FLOAT:
                value = cast('QDoubleSpinBox', widget).value()
            case SettingType.INTEGER | SettingType.INTEGER_OR_ALL:
                value = cast('ProcessSelectorWidget', widget).value() if key == 'capture_filter_process_pid' else cast('QSpinBox', widget).value()
            case SettingType.ENUM:
                text = cast('QComboBox', widget).currentText()
                value = None if text == _NONE_PLACEHOLDER else text
            case SettingType.BOOL_OR_ENUM:
                text = cast('QComboBox', widget).currentText()
                value = False if text == 'Disabled' else text
            case SettingType.COLUMN_TUPLE | SettingType.THIRD_PARTY_SERVERS_TUPLE:
                value = self._read_column_tuple(meta, widget)
            case SettingType.IP_RANGE_TUPLE:
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
                errors.append(f'{meta.display_label}: "{value}" is not a valid IPv4 address.')

            elif meta.setting_type == SettingType.COLOR and (not isinstance(value, str) or not QColor(value).isValid()):
                errors.append(f'{meta.display_label}: "{value}" is not a valid color.')

            elif meta.setting_type == SettingType.MAC_ADDRESS and isinstance(value, str):
                formatted = format_mac_address(value)
                if not is_mac_address(formatted):
                    errors.append(f'{meta.display_label}: "{value}" is not a valid MAC address (expected format: AA:BB:CC:DD:EE:FF).')

            elif meta.setting_type == SettingType.STRING and key == 'capture_prepend_custom_capture_filter' and isinstance(value, str):
                try:
                    validate_and_strip_balanced_outer_parens(value)
                except ParenthesisMismatchError:
                    errors.append(f'{meta.display_label}: filter expression has unbalanced parentheses.')

            elif key == 'discord_presence_title' and isinstance(value, str) and 0 < len(value) < _DISCORD_PRESENCE_TITLE_MIN_LEN:
                errors.append('Presence Title must be either empty (to disable) or at least 2 characters long.')

        if values.get('discord_webhook_enabled'):
            url_value = values.get('discord_webhook_url')
            if not isinstance(url_value, str) or not is_valid_webhook_url(url_value):
                errors.append(
                    'Discord Webhook is enabled but the Webhook URL is missing or invalid. Expected format: https://discord.com/api/webhooks/<id>/<token>',
                )

        if not any(
            (
                values.get('gui_columns_datetime_show_date'),
                values.get('gui_columns_datetime_show_time'),
                values.get('gui_columns_datetime_show_elapsed_time'),
            ),
        ):
            errors.append(
                'At least one of the DateTime column display options must be enabled:\n'
                '  - Show Date in DateTime Columns\n'
                '  - Show Time in DateTime Columns\n'
                '  - Show Elapsed Time',
            )

        return errors, values

    def _save_settings(self) -> None:
        """Validate, apply widget values to Settings, persist, and close."""
        errors, new_values = self._validate()
        if errors:
            QMessageBox.critical(self, TITLE, '\n\n'.join(errors))
            return

        for key, value in new_values.items():
            if SETTING_METADATA[key].setting_type == SettingType.MAC_ADDRESS and isinstance(value, str):
                formatted_value: SettingValue = format_mac_address(value)
                new_values[key] = formatted_value
                setattr(Settings, key, formatted_value)
            else:
                setattr(Settings, key, value)

        if self._capture.is_running():
            Settings.capture_interface_name = self._capture.config.interface.name
            Settings.capture_ip_address = self._capture.config.interface.ip_address
            Settings.capture_mac_address = self._capture.config.interface.mac_address

        Settings.rewrite_settings_file()
        Settings.rebuild_blocked_ip_ranges()

        ensure_process_monitor_running()
        ensure_looky_core_running()

        capture_settings_changed = any(value != self._old_values.get(key) for key, value in new_values.items() if SETTING_METADATA[key].requires_capture_restart)
        if capture_settings_changed and self._capture.is_running():
            capture_filter_str, display_filter_fn = build_capture_filters(
                capture_ip_address=self._capture.config.interface.ip_address,
                broadcast_support=self._capture.config.broadcast_support,
                multicast_support=self._capture.config.multicast_support,
            )
            self._capture.config = replace(
                self._capture.config,
                capture_filter=capture_filter_str,
                display_filter_fn=display_filter_fn,
            )
            self._capture.request_restart()

        webserver_enabled_changed = new_values['webserver_enabled'] != self._old_values.get('webserver_enabled')
        webserver_host_changed = new_values['webserver_host'] != self._old_values.get('webserver_host')
        webserver_port_changed = new_values['webserver_port'] != self._old_values.get('webserver_port')
        webserver_credentials_changed = new_values['webserver_username'] != self._old_values.get('webserver_username') or new_values[
            'webserver_password'
        ] != self._old_values.get('webserver_password')

        if webserver_enabled_changed:
            if Settings.webserver_enabled:
                start_webserver_from_settings()
            else:
                WebServer.stop_server()
        elif Settings.webserver_enabled and (webserver_host_changed or webserver_port_changed):
            start_webserver_from_settings()
        elif Settings.webserver_enabled and webserver_credentials_changed:
            WebServer.update_auth_credentials(
                auth_username=Settings.webserver_username,
                auth_password=Settings.webserver_password,
            )

        if not Settings.voice_notifications_enabled:
            clear_voice_notification_queue()

        prompt_to_disable_gta5_relay_if_filtered(self, context='settings')

        self._saved = True
        self.accept()

    def _reset_tab_to_defaults(self, category: str) -> None:
        """Populate widgets belonging to *category* with default values without saving."""
        defaults_dict = cast('dict[str, SettingValue]', SETTING_DEFAULTS)
        for key, widget in self._widgets.items():
            if key in defaults_dict and SETTING_METADATA[key].category == category:
                self._set_widget_value(key, widget, defaults_dict[key])
        self._update_sort_column_options()
        self._update_restart_notice()

    def _reset_current_tab(self) -> None:
        """Reset the current tab's settings to their default values."""
        current_widget = self._tabs.currentWidget()
        category_property = current_widget.property('category')
        category = str(category_property) if category_property else self._tabs.tabText(self._tabs.currentIndex())
        self._reset_tab_to_defaults(category)

    def _reset_to_defaults(self) -> None:
        """Populate all widgets with default values without saving."""
        defaults_dict = cast('dict[str, SettingValue]', SETTING_DEFAULTS)
        for key, widget in self._widgets.items():
            if key in defaults_dict:
                self._set_widget_value(key, widget, defaults_dict[key])
        self._update_sort_column_options()
        self._update_restart_notice()

    def _export_settings(self) -> None:
        """Export current in-memory settings to a user-chosen Settings.ini file."""
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            'Export Settings',
            'Settings.ini',
            'INI Files (*.ini);;All Files (*.*)',
        )
        if not file_path:
            return
        text = build_settings_ini_header_text()
        for setting_name, setting_value in Settings.iterate_over_settings():
            text += f'{setting_name}={setting_value}\n'
        Path(file_path).write_text(text, encoding='utf-8')
        QMessageBox.information(self, TITLE, 'Settings exported successfully.')

    def _import_settings(self) -> None:
        """Import settings from a user-chosen Settings.ini file and refresh widgets."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            'Import Settings',
            '',
            'INI Files (*.ini);;All Files (*.*)',
        )
        if not file_path:
            return
        Settings.load_from_settings_file(Path(file_path))
        if self._capture.is_running():
            Settings.capture_interface_name = self._capture.config.interface.name
            Settings.capture_ip_address = self._capture.config.interface.ip_address
            Settings.capture_mac_address = self._capture.config.interface.mac_address
        self._old_values = {key: getattr(Settings, key) for key in SETTING_METADATA}
        self._load_current_values()
        QMessageBox.information(self, TITLE, 'Settings imported successfully.')

    def _connect_widget_change_signals(self) -> None:
        """Connect change signals for all setting widgets to dynamically update dialog notices."""
        for key, widget in self._widgets.items():
            meta = SETTING_METADATA[key]
            match widget:
                case QCheckBox():
                    widget.toggled.connect(self._update_restart_notice)
                case ColorPickerButton():
                    widget.color_changed.connect(self._update_restart_notice)
                case QSpinBox() | QDoubleSpinBox():
                    widget.valueChanged.connect(self._update_restart_notice)
                case QComboBox():
                    widget.currentIndexChanged.connect(self._update_restart_notice)
                case ProcessSelectorWidget():
                    combo = widget.findChild(QComboBox)
                    if combo is not None:
                        combo.currentIndexChanged.connect(self._update_restart_notice)
                case _:
                    if meta.setting_type in (SettingType.COLUMN_TUPLE, SettingType.THIRD_PARTY_SERVERS_TUPLE):
                        for checkbox in widget.findChildren(QCheckBox):
                            checkbox.toggled.connect(self._update_restart_notice)
                            if key in ('gui_columns_connected_shown', 'gui_columns_disconnected_shown'):
                                checkbox.toggled.connect(self._update_sort_column_options)
                    elif meta.setting_type == SettingType.IP_RANGE_TUPLE:
                        list_widget = next(iter(widget.findChildren(QListWidget)), None)
                        if list_widget is not None:
                            list_widget.model().rowsInserted.connect(self._on_list_rows_changed)
                            list_widget.model().rowsRemoved.connect(self._on_list_rows_changed)
                    else:
                        try:
                            line_edit = get_line_edit(widget)
                            line_edit.textChanged.connect(self._update_restart_notice)
                        except RuntimeError:
                            pass

    def _on_list_rows_changed(self, *_args: object) -> None:
        """Handle rows added or removed in IP range list widgets."""
        self._update_restart_notice()

    def _update_sort_column_options(self, *_args: object) -> None:
        """Update table sort column combo boxes based on currently enabled columns."""
        connected_widget = self._widgets.get('gui_columns_connected_shown')
        connected_sort_widget = self._widgets.get('gui_connected_table_sort_column')
        if connected_widget is not None and isinstance(connected_sort_widget, QComboBox):
            checked_connected = {cb.objectName() for cb in connected_widget.findChildren(QCheckBox) if cb.isChecked()}
            available_connected = [col for col in Settings.GUI_ALL_CONNECTED_COLUMNS if col in checked_connected or col in Settings.GUI_FORCED_COLUMNS]
            current_selected = connected_sort_widget.currentText()
            target_selected = current_selected if current_selected in available_connected else 'Last Rejoin'
            connected_sort_widget.blockSignals(True)  # noqa: FBT003
            connected_sort_widget.clear()
            connected_sort_widget.addItems(available_connected)
            connected_sort_widget.setCurrentText(target_selected)
            connected_sort_widget.blockSignals(False)  # noqa: FBT003

        disconnected_widget = self._widgets.get('gui_columns_disconnected_shown')
        disconnected_sort_widget = self._widgets.get('gui_disconnected_table_sort_column')
        if disconnected_widget is not None and isinstance(disconnected_sort_widget, QComboBox):
            checked_disconnected = {cb.objectName() for cb in disconnected_widget.findChildren(QCheckBox) if cb.isChecked()}
            available_disconnected = [col for col in Settings.GUI_ALL_DISCONNECTED_COLUMNS if col in checked_disconnected or col in Settings.GUI_FORCED_COLUMNS]
            current_selected = disconnected_sort_widget.currentText()
            target_selected = current_selected if current_selected in available_disconnected else 'Last Seen'
            disconnected_sort_widget.blockSignals(True)  # noqa: FBT003
            disconnected_sort_widget.clear()
            disconnected_sort_widget.addItems(available_disconnected)
            disconnected_sort_widget.setCurrentText(target_selected)
            disconnected_sort_widget.blockSignals(False)  # noqa: FBT003

    def _update_restart_notice(self, *_args: object) -> None:
        """Update visibility of the capture restart notice banner."""
        if getattr(self, '_loading_settings', False):
            return
        self._restart_notice_banner.setVisible(self._has_unsaved_restart_changes())

    def _has_unsaved_restart_changes(self) -> bool:
        """Return `True` if any modified setting requires a packet capture restart."""
        for key, widget in self._widgets.items():
            if not SETTING_METADATA[key].requires_capture_restart:
                continue
            current_value = self._read_widget_value(key, widget)
            original_value = self._old_values.get(key)
            if SETTING_METADATA[key].setting_type == SettingType.IP_RANGE_TUPLE:
                if sorted(current_value if isinstance(current_value, tuple) else ()) != sorted(original_value if isinstance(original_value, tuple) else ()):
                    return True
            elif current_value != original_value:
                return True
        return False

    def _has_unsaved_changes(self) -> bool:
        """Return True if any widget value differs from the value at dialog open."""
        for key, widget in self._widgets.items():
            current_value = self._read_widget_value(key, widget)
            original_value = self._old_values.get(key)
            if SETTING_METADATA[key].setting_type == SettingType.IP_RANGE_TUPLE:
                if sorted(current_value if isinstance(current_value, tuple) else ()) != sorted(original_value if isinstance(original_value, tuple) else ()):
                    return True
            elif current_value != original_value:
                return True
        return False

    @override
    def _has_unsaved_changes_for_close(self) -> bool:
        """Return `True` if there are unsaved changes that should be saved before closing."""
        return self._has_unsaved_changes()

    @override
    def _save_on_close(self) -> bool:
        """Save settings; return `True` if save succeeded."""
        self._save_settings()
        return self._saved

    def _hide_secret_fields(self) -> None:
        """Reset any revealed password / secret QLineEdits back to hidden."""
        for widget in self._widgets.values():
            if isinstance(widget, QLineEdit):
                act = widget.property('secret_action')
                if isinstance(act, QAction) and act.isChecked():
                    act.setChecked(False)
                elif isinstance(widget, SecretLineEdit) and widget.is_revealed:
                    widget.set_revealed(revealed=False)

    def _on_tab_changed(self, _index: int) -> None:
        """Handle tab switching; automatically re-blurs Looky System sensitive fields and masks passwords."""
        self._hide_looky_account_sensitive_values()
        self._hide_secret_fields()
