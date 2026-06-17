"""Settings dialog for viewing, editing, saving, and resetting all application settings."""

from dataclasses import replace
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING, cast, override

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.background import ensure_looky_core_running
from session_sniffer.capture.filters import build_capture_filters
from session_sniffer.constants.standalone import DISCORD_INVITE_URL, TITLE
from session_sniffer.discord.webhook import is_valid_webhook_url, send_test_message
from session_sniffer.gta5.monitor import ensure_gta5_process_monitor_running
from session_sniffer.guis._dialog_mixins import UnsavedChangesMixin, setup_tab_dialog_buttons
from session_sniffer.guis._settings_looky_mixin import SettingsDialogLookyMixin
from session_sniffer.guis._settings_widget_builders import (
    RESTART_INDICATOR,
    create_bool_or_enum_widget,
    create_boolean_widget,
    create_column_tuple_widget,
    create_enum_widget,
    create_float_widget,
    create_integer_or_all_widget,
    create_integer_widget,
    create_ip_range_tuple_widget,
    create_text_widget,
    create_third_party_servers_split_widget,
)
from session_sniffer.guis.relay_conflict import prompt_to_disable_gta5_relay_if_filtered
from session_sniffer.guis.stylesheets import (
    DIALOG_BUTTON_STYLESHEET,
    DISCORD_INFO_LABEL_STYLESHEET,
    WEBHOOK_NOTE_LABEL_STYLESHEET,
    WEBSERVER_HELP_LABEL_STYLESHEET,
)
from session_sniffer.guis.utils import set_dialog_window_flags
from session_sniffer.networking.interface import AllInterfaces
from session_sniffer.networking.looky_system import LookyState
from session_sniffer.networking.utils import format_mac_address, is_ipv4_address, is_mac_address
from session_sniffer.settings import SETTING_CATEGORIES_ORDER, SETTING_DEFAULTS, SETTING_METADATA, SettingMeta, SettingType
from session_sniffer.settings.settings import Settings
from session_sniffer.text_templates import build_settings_ini_header_text
from session_sniffer.utils import validate_and_strip_balanced_outer_parens
from session_sniffer.utils_exceptions import ParenthesisMismatchError
from session_sniffer.webserver import WebServer, start_webserver_from_settings

if TYPE_CHECKING:
    from collections.abc import Callable

    from PyQt6.QtWidgets import QDoubleSpinBox, QSpinBox

    from session_sniffer.capture.packet_capture import PacketCapture

_NONE_PLACEHOLDER = 'None'
_DISCORD_PRESENCE_TITLE_MIN_LEN = 2

SettingValue = bool | str | int | float | tuple[str, ...] | None


def _get_line_edit(widget: QWidget) -> QLineEdit:
    """Return the `QLineEdit` from *widget*, which may itself be a `QLineEdit` or a container holding one."""
    if isinstance(widget, QLineEdit):
        return widget
    child = cast('QLineEdit | None', widget.findChild(QLineEdit))
    if child is None:
        msg = f'No QLineEdit child found in {widget!r}'
        raise RuntimeError(msg)
    return child


class SettingsDialog(SettingsDialogLookyMixin, UnsavedChangesMixin, QDialog):
    """Non-modal dialog exposing every Settings.ini option for viewing, editing, saving, and resetting."""

    def __init__(self, parent: QWidget | None, capture: PacketCapture) -> None:
        """Build the tabbed settings dialog from setting metadata."""
        super().__init__(parent)
        self.setWindowTitle(f'Settings - {TITLE}')
        set_dialog_window_flags(self)
        self.setMinimumSize(700, 520)
        self.resize(780, 600)

        self._capture = capture
        self._widgets: dict[str, QWidget] = {}
        self._labels: dict[str, QLabel] = {}
        self._old_values: dict[str, SettingValue] = {
            key: getattr(Settings, key) for key in SETTING_METADATA
        }
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
        for idx, category in enumerate(SETTING_CATEGORIES_ORDER):
            tab_widget = self._build_tab(category)
            self._tabs.addTab(tab_widget, category)
            if category == 'Looky System':
                self._looky_tab_index = idx
        root_layout.addWidget(self._tabs)

        button_row = QHBoxLayout()

        import_button = QPushButton('\U0001f4e5 Import')
        import_button.setToolTip('Import settings from a Settings.ini file')
        import_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        import_button.clicked.connect(self._import_settings)
        button_row.addWidget(import_button)

        export_button = QPushButton('\U0001f4e4 Export')
        export_button.setToolTip('Export current settings to a Settings.ini file')
        export_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        export_button.clicked.connect(self._export_settings)
        button_row.addWidget(export_button)

        reset_button = QPushButton('\U0001f504 Reset all…')
        reset_button.setToolTip('Reset all settings across every tab to their default values (review before saving)')
        save_button = setup_tab_dialog_buttons(button_row, reset_button, self._reset_to_defaults, self._reset_current_tab)
        save_button.setToolTip('Validate and save all settings to Settings.ini')
        save_button.clicked.connect(self._save_settings)
        button_row.addWidget(save_button)

        cancel_button = QPushButton('\u274c Cancel')
        cancel_button.setToolTip('Discard changes and close')
        cancel_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        cancel_button.clicked.connect(self.reject)
        button_row.addWidget(cancel_button)

        root_layout.addLayout(button_row)

        self._load_current_values()

        # Force the webhook enable cascade once even if the value matches the
        # default (in which case `setChecked` would not fire `toggled`).
        webhook_enabled_widget = self._widgets.get('discord_webhook_enabled')
        if isinstance(webhook_enabled_widget, QCheckBox):
            webhook_enabled_widget.toggled.emit(webhook_enabled_widget.isChecked())

        # Show/hide Session Host Detection based on Game Preset.
        preset_widget = self._widgets.get('capture_game_preset')
        if isinstance(preset_widget, QComboBox):
            preset_widget.currentTextChanged.connect(self._on_preset_changed)
            self._on_preset_changed(preset_widget.currentText())

        # Show/hide Account Information based on API key presence.
        api_key_widget = self._widgets.get('looky_api_key')
        if isinstance(api_key_widget, QLineEdit):
            api_key_widget.textChanged.connect(self._on_looky_api_key_changed)
            api_key_widget.installEventFilter(self)
            self._on_looky_api_key_changed(api_key_widget.text())

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
            outer_layout.addWidget(self._build_web_server_help_group())
        elif category == 'Discord':
            outer_layout.addWidget(self._build_discord_info_group())
        elif category == 'Looky System':
            outer_layout.addWidget(self._build_looky_info_group())

        # Render ungrouped settings first in a plain form layout.
        if ungrouped:
            form = QFormLayout()
            form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)
            form.setLabelAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            for key, meta in ungrouped:
                self._add_setting_row(form, key, meta)
            outer_layout.addLayout(form)

        # Render each group as a titled QGroupBox.
        for group_name, items in grouped.items():
            # The Discord Webhook group has a custom layout (masked URL, enable
            # cascade, reset-messages, automod warning).
            if category == 'Discord' and group_name == 'Server Webhook':
                outer_layout.addWidget(self._build_discord_webhook_group(items))
                continue

            group_box = QGroupBox(group_name)
            direct_items = [(k, m) for k, m in items if not m.subgroup]
            subgrouped: dict[str, list[tuple[str, SettingMeta]]] = {}
            for k, m in items:
                if m.subgroup:
                    subgrouped.setdefault(m.subgroup, []).append((k, m))

            if subgrouped:
                group_vbox = QVBoxLayout(group_box)
                if direct_items:
                    direct_form = QFormLayout()
                    direct_form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)
                    direct_form.setLabelAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                    for key, meta in direct_items:
                        self._add_setting_row(direct_form, key, meta)
                    group_vbox.addLayout(direct_form)
                for sub_name, sub_items in subgrouped.items():
                    sub_box = QGroupBox(sub_name)
                    sub_form = QFormLayout(sub_box)
                    sub_form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)
                    sub_form.setLabelAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                    for key, meta in sub_items:
                        self._add_setting_row(sub_form, key, meta)
                    group_vbox.addWidget(sub_box)
            elif category == 'Looky System' and group_name == 'Authentication':
                auth_vbox = QVBoxLayout(group_box)
                auth_form = QFormLayout()
                auth_form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)
                auth_form.setLabelAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                for key, meta in items:
                    self._add_setting_row(auth_form, key, meta)
                auth_vbox.addLayout(auth_form)
                self._looky_account_info_group = self._build_looky_account_info_group()
                auth_vbox.addWidget(self._looky_account_info_group)
            else:
                group_form = QFormLayout(group_box)
                group_form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)
                group_form.setLabelAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                for key, meta in items:
                    self._add_setting_row(group_form, key, meta)
            outer_layout.addWidget(group_box)

        outer_layout.addStretch()
        scroll.setWidget(container)
        page_layout.addWidget(scroll)

        return page

    def _build_discord_info_group(self) -> QGroupBox:
        """Build a Discord server invite header for the Discord settings tab."""
        group_box = QGroupBox('Session Sniffer Community')
        layout = QVBoxLayout(group_box)

        info_label = QLabel(
            'Join the Session Sniffer Discord server for support, announcements, and community discussion.<br><br>'
            f'<a href="{DISCORD_INVITE_URL}" title="{DISCORD_INVITE_URL}" style="color: #61afef; text-decoration: underline;">{DISCORD_INVITE_URL}</a>',
        )
        info_label.setWordWrap(True)
        info_label.setTextFormat(Qt.TextFormat.RichText)
        info_label.setOpenExternalLinks(True)
        info_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextBrowserInteraction)
        info_label.setStyleSheet(DISCORD_INFO_LABEL_STYLESHEET)
        info_label.linkHovered.connect(info_label.setToolTip)
        layout.addWidget(info_label)

        return group_box

    def _build_web_server_help_group(self) -> QGroupBox:
        """Build an explanatory guide for Web Server host/port behavior and common usage patterns."""
        group_box = QGroupBox('Web Server Usage Guide')
        layout = QVBoxLayout(group_box)

        help_label = QLabel(
            '<b>Host binding explained</b><br>'
            '<b>127.0.0.1</b> (or localhost): only this PC can open the panel.<br>'
            '<b>0.0.0.0</b>: listens on all interfaces so other devices on your LAN can connect.<br><br>'
            '<b>Typical setups</b><br>'
            '- Desktop only: host = 127.0.0.1<br>'
            '- Phone/tablet on same Wi-Fi: host = 0.0.0.0, then open http://&lt;PC_LAN_IP&gt;:&lt;PORT&gt;/<br><br>'
            '<b>Troubleshooting tips</b><br>'
            '- Phone and PC must be on the same local network (avoid guest/isolated Wi-Fi).<br>'
            '- If remote devices cannot connect, allow inbound TCP on the selected port in Windows Firewall.<br>'
            '- If port 80 conflicts with another app, switch to a different port (for example 8091).<br>'
            '- Use http:// (not https://) unless you add your own TLS reverse proxy.<br><br>'
            '<b>Security note</b><br>'
            'When using 0.0.0.0, anyone on the same allowed network path can reach the panel.<br>'
            'Use trusted networks and firewall scope limits.',
        )
        help_label.setWordWrap(True)
        help_label.setTextFormat(Qt.TextFormat.RichText)
        help_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        help_label.setStyleSheet(WEBSERVER_HELP_LABEL_STYLESHEET)
        layout.addWidget(help_label)

        return group_box

    def _add_setting_row(self, form: QFormLayout, key: str, meta: SettingMeta) -> None:
        """Create a widget for *key* and append a labeled row to *form*."""
        widget = self._create_widget(key, meta)
        self._widgets[key] = widget

        # COLUMN_TUPLE, IP_RANGE_TUPLE and THIRD_PARTY_SERVERS_TUPLE widgets carry their label as the QGroupBox title — add
        # as a full-width spanning row so the widget gets all available horizontal space.
        if meta.setting_type in (SettingType.COLUMN_TUPLE, SettingType.IP_RANGE_TUPLE, SettingType.THIRD_PARTY_SERVERS_TUPLE):
            form.addRow(widget)
            return

        label_text = meta.display_label
        if meta.requires_capture_restart:
            label_text += RESTART_INDICATOR
        label = QLabel(label_text + ':')
        self._labels[key] = label

        tooltip = meta.tooltip
        if meta.requires_capture_restart:
            tooltip += ' (requires capture restart)' if tooltip else 'Requires capture restart'
        if tooltip:
            label.setToolTip(tooltip)

        form.addRow(label, widget)

    def _on_preset_changed(self, preset: str) -> None:
        """Show or hide preset-dependent rows depending on the active preset."""
        gta5_only = preset == 'GTA5'
        has_preset = bool(preset) and preset != 'None'
        for key in ('gui_session_host_detection',):
            widget = self._widgets.get(key)
            label = self._labels.get(key)
            if widget:
                widget.setVisible(gta5_only)
                widget.setEnabled(gta5_only)
            if label:
                label.setVisible(gta5_only)
        for key in ('capture_filter_preset_packet_size',):
            widget = self._widgets.get(key)
            label = self._labels.get(key)
            if widget:
                widget.setVisible(has_preset)
            if label:
                label.setVisible(has_preset)
        if self._looky_tab_index != -1:
            self._tabs.setTabVisible(self._looky_tab_index, gta5_only)

    def _build_discord_webhook_group(self, items: list[tuple[str, SettingMeta]]) -> QGroupBox:
        """Build the custom Discord Webhook group with masked URL and enable cascade."""
        group_box = QGroupBox('Server Webhook')
        outer = QVBoxLayout(group_box)
        outer.setSpacing(8)

        meta_by_key = dict(items)

        # Top form: Enabled + Webhook URL row (with Show + Test buttons).
        top_form = QFormLayout()
        top_form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)
        top_form.setLabelAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

        # Enabled checkbox
        enabled_meta = meta_by_key.get('discord_webhook_enabled')
        if enabled_meta is not None:
            enabled_widget = create_boolean_widget(enabled_meta)
            self._widgets['discord_webhook_enabled'] = enabled_widget
            enabled_label = QLabel(enabled_meta.display_label + ':')
            if enabled_meta.tooltip:
                enabled_label.setToolTip(enabled_meta.tooltip)
            top_form.addRow(enabled_label, enabled_widget)

        # URL row: QLineEdit (masked) + 'Show' toggle + 'Test' button
        url_meta = meta_by_key.get('discord_webhook_url')
        url_line: QLineEdit | None = None
        if url_meta is not None:
            url_line = QLineEdit()
            url_line.setEchoMode(QLineEdit.EchoMode.Password)
            url_line.setPlaceholderText('https://discord.com/api/webhooks/<id>/<token>')
            url_line.setToolTip(
                url_meta.tooltip
                or 'Discord channel webhook URL. Treat this like a password — anyone with it can post to the channel.',
            )
            self._widgets['discord_webhook_url'] = url_line

            url_row = QWidget()
            url_row_layout = QHBoxLayout(url_row)
            url_row_layout.setContentsMargins(0, 0, 0, 0)
            url_row_layout.setSpacing(6)
            url_row_layout.addWidget(url_line, 1)

            show_button = QPushButton('\U0001f441 Show')
            show_button.setCheckable(True)
            show_button.setToolTip('Reveal or hide the webhook URL')
            show_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
            show_button.toggled.connect(partial(self._toggle_url_visibility, url_line, show_button))
            url_row_layout.addWidget(show_button)

            test_button = QPushButton('\U0001f527 Test')
            test_button.setToolTip('Send a one-time test message to this webhook URL')
            test_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
            test_button.clicked.connect(partial(self._test_webhook, url_line))
            url_row_layout.addWidget(test_button)

            url_label = QLabel(url_meta.display_label + ':')
            url_label.setToolTip(url_line.toolTip())
            top_form.addRow(url_label, url_row)

        outer.addLayout(top_form)

        # Remaining settings (refresh interval, include flags, max rows) in a
        # separate form so we can disable them all when 'Enabled' is unchecked.
        details_widget = QWidget()
        details_form = QFormLayout(details_widget)
        details_form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)
        details_form.setLabelAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        details_form.setContentsMargins(0, 0, 0, 0)

        for key, meta in items:
            if key in ('discord_webhook_enabled', 'discord_webhook_url'):
                continue
            self._add_setting_row(details_form, key, meta)

        outer.addWidget(details_widget)

        # Reset Stored Messages button (separate row, also gated on enabled).
        reset_msgs_row = QHBoxLayout()
        reset_msgs_row.addStretch()
        reset_msgs_button = QPushButton('\U0001f5d1 Reset Stored Messages')
        reset_msgs_button.setToolTip(
            'Forget the IDs of the two posted messages so the next refresh creates fresh ones.\n'
            'Use this after changing channels or after Wick/automod deletes the old messages.',
        )
        reset_msgs_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        reset_msgs_button.clicked.connect(self._reset_stored_messages)
        reset_msgs_row.addWidget(reset_msgs_button)
        outer.addLayout(reset_msgs_row)

        # Footer note about automod / Wick.
        note = QLabel(
            '\u26a0 If your server runs Wick or another automod with a "wall of text" filter, '
            'whitelist this webhook (or its channel) to prevent the messages — and the webhook itself — from being deleted.',
        )
        note.setWordWrap(True)
        note.setStyleSheet(WEBHOOK_NOTE_LABEL_STYLESHEET)
        outer.addWidget(note)

        # Wire enable cascade.
        if enabled_meta is not None:
            enabled_checkbox = cast('QCheckBox', self._widgets['discord_webhook_enabled'])
            enabled_checkbox.toggled.connect(partial(self._on_webhook_enabled_toggled, details_widget, url_line))

        return group_box

    def _on_webhook_enabled_toggled(self, details_widget: QWidget, url_line: QLineEdit | None, checked: bool) -> None:  # noqa: FBT001
        """Enable/disable child webhook fields based on the master checkbox."""
        details_widget.setEnabled(checked)
        if url_line is not None:
            url_line.setEnabled(checked)

    def _toggle_url_visibility(self, url_line: QLineEdit, show_button: QPushButton, checked: bool) -> None:  # noqa: FBT001
        """Toggle masked/plain echo for the webhook URL."""
        if checked:
            url_line.setEchoMode(QLineEdit.EchoMode.Normal)
            show_button.setText('\U0001f648 Hide')
        else:
            url_line.setEchoMode(QLineEdit.EchoMode.Password)
            show_button.setText('\U0001f441 Show')

    def _reset_stored_messages(self) -> None:
        """Clear persisted Discord webhook message IDs so the next post creates new messages."""
        if Settings.discord_webhook_message_ids in (None, ''):
            QMessageBox.information(self, TITLE, 'No stored Discord messages to reset.')
            return
        confirm = QMessageBox.question(
            self,
            TITLE,
            'Forget the IDs of the two posted Discord messages?\n\n'
            'The next refresh will create two fresh messages instead of editing the old ones.',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return
        Settings.discord_webhook_message_ids = None
        Settings.rewrite_settings_file()
        QMessageBox.information(self, TITLE, 'Stored Discord message IDs cleared.')

    def _test_webhook(self, url_widget: QLineEdit) -> None:
        """Send a test message to the URL currently in the URL widget."""
        url = url_widget.text().strip()
        if not url:
            QMessageBox.warning(self, TITLE, 'Please enter a Discord webhook URL first.')
            return
        ok, message = send_test_message(url)
        if ok:
            QMessageBox.information(self, TITLE, message)
        else:
            QMessageBox.critical(self, TITLE, message)

    def _create_widget(self, key: str, meta: SettingMeta) -> QWidget:
        """Return the appropriate input widget for a single setting."""
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
                value: SettingValue = getattr(Settings, key)
                self._set_widget_value(key, widget, value)
        finally:
            self._loading_settings = False

    def _set_widget_value(self, key: str, widget: QWidget, value: SettingValue) -> None:
        """Push *value* into the appropriate *widget*."""
        meta = SETTING_METADATA[key]

        if meta.setting_type == SettingType.BOOLEAN:
            cast('QCheckBox', widget).setChecked(bool(value))

        elif meta.setting_type in (SettingType.STRING, SettingType.IPV4, SettingType.MAC_ADDRESS):
            _get_line_edit(widget).setText('' if value is None else str(value))

        elif meta.setting_type == SettingType.FLOAT:
            cast('QDoubleSpinBox', widget).setValue(float(value) if isinstance(value, (int, float)) else 0.0)

        elif meta.setting_type in (SettingType.INTEGER, SettingType.INTEGER_OR_ALL):
            cast('QSpinBox', widget).setValue(int(value) if isinstance(value, (int, float)) else 0)

        elif meta.setting_type == SettingType.ENUM:
            self._set_enum(widget, value)

        elif meta.setting_type == SettingType.BOOL_OR_ENUM:
            self._set_bool_or_enum(widget, value)

        elif meta.setting_type in (SettingType.COLUMN_TUPLE, SettingType.THIRD_PARTY_SERVERS_TUPLE):
            shown: tuple[str, ...] = value if isinstance(value, tuple) else ()
            shown_set = set(shown)
            for checkbox in widget.findChildren(QCheckBox):
                checkbox.setChecked(checkbox.objectName() in shown_set)

        elif meta.setting_type == SettingType.IP_RANGE_TUPLE:
            entries: tuple[str, ...] = value if isinstance(value, tuple) else ()
            list_widget = next(iter(widget.findChildren(QListWidget)), None)
            if list_widget is not None:
                list_widget.clear()
                list_widget.addItems(list(entries))

    def _set_enum(self, widget: QWidget, value: SettingValue) -> None:
        """Set value for an enum combo box."""
        combo = cast('QComboBox', widget)
        text = _NONE_PLACEHOLDER if value is None else str(value)
        idx = combo.findText(text, Qt.MatchFlag.MatchFixedString)
        if idx >= 0:
            combo.setCurrentIndex(idx)

    def _set_bool_or_enum(self, widget: QWidget, value: SettingValue) -> None:
        """Set value for a bool-or-enum combo box."""
        combo_be = cast('QComboBox', widget)
        if value is False:
            combo_be.setCurrentIndex(0)
        else:
            idx = combo_be.findText(str(value), Qt.MatchFlag.MatchFixedString)
            if idx >= 0:
                combo_be.setCurrentIndex(idx)

    def _read_widget_value(self, key: str, widget: QWidget) -> SettingValue:
        """Extract the current value from *widget* for setting *key*."""
        meta = SETTING_METADATA[key]
        value: SettingValue = None

        match meta.setting_type:
            case SettingType.BOOLEAN:
                value = cast('QCheckBox', widget).isChecked()
            case SettingType.STRING | SettingType.IPV4 | SettingType.MAC_ADDRESS:
                text = _get_line_edit(widget).text().strip()
                value = text or None
            case SettingType.FLOAT:
                value = cast('QDoubleSpinBox', widget).value()
            case SettingType.INTEGER | SettingType.INTEGER_OR_ALL:
                value = cast('QSpinBox', widget).value()
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
                value = () if list_widget is None else tuple(
                    item.text() for i in range(list_widget.count()) if (item := list_widget.item(i)) is not None
                )

        return value

    def _read_column_tuple(self, meta: SettingMeta, widget: QWidget) -> tuple[str, ...]:
        """Read checked column names from the column-tuple group box."""
        allowed_attr = meta.allowed_columns_attr or ''
        allowed_columns: tuple[str, ...] = getattr(Settings, allowed_attr, ())
        checkboxes = {checkbox.objectName(): checkbox for checkbox in widget.findChildren(QCheckBox)}
        return tuple(
            col_name for col_name in allowed_columns
            if (checkbox := checkboxes.get(col_name)) is not None and checkbox.isChecked()
        )

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
                    'Discord Webhook is enabled but the Webhook URL is missing or invalid. '
                    'Expected format: https://discord.com/api/webhooks/<id>/<token>',
                )

        if not any((
            values.get('gui_columns_datetime_show_date'),
            values.get('gui_columns_datetime_show_time'),
            values.get('gui_columns_datetime_show_elapsed_time'),
        )):
            errors.append(
                'At least one of the DateTime column display options must be enabled:\n'
                '  - Show Date in DateTime Columns\n'
                '  - Show Time in DateTime Columns\n'
                '  - Show Elapsed Time',
            )

        return errors, values

    def _warn_interface_name(self, new_values: dict[str, SettingValue]) -> bool:
        """Show a warning if the interface name does not match any known interface.

        Returns:
            True if the user chose to continue saving, False to abort.
        """
        value = new_values.get('capture_interface_name')
        if not isinstance(value, str):
            return True
        if AllInterfaces.get_interface_by_name(value) is not None:
            return True

        known_names = sorted(iface.identity.name for iface in AllInterfaces.iterate() if iface.identity.name)
        names_list = '\n  - '.join(known_names) if known_names else '(no interfaces discovered)'
        result = QMessageBox.warning(
            self,
            TITLE,
            f'Interface Name "{value}" does not match any known network interface.\n\n'
            f'Known interfaces:\n  - {names_list}\n\n'
            'Save anyway?',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        return result == QMessageBox.StandardButton.Yes

    def _save_settings(self) -> None:
        """Validate, apply widget values to Settings, persist, and close."""
        errors, new_values = self._validate()
        if errors:
            QMessageBox.critical(self, TITLE, '\n\n'.join(errors))
            return

        if not self._warn_interface_name(new_values):
            return

        for key, value in new_values.items():
            if SETTING_METADATA[key].setting_type == SettingType.MAC_ADDRESS and isinstance(value, str):
                formatted_value: SettingValue = format_mac_address(value)
                new_values[key] = formatted_value
                setattr(Settings, key, formatted_value)
            else:
                setattr(Settings, key, value)

        Settings.rewrite_settings_file()
        Settings.rebuild_blocked_ip_ranges()

        ensure_gta5_process_monitor_running()
        ensure_looky_core_running()

        capture_settings_changed = any(
            new_values[key] != self._old_values.get(key)
            for key, meta in SETTING_METADATA.items()
            if meta.requires_capture_restart
        )
        if capture_settings_changed and self._capture.is_running():
            if Settings.capture_ip_address is None:
                msg = 'capture_ip_address is None while capture is running'
                raise RuntimeError(msg)
            capture_filter_str, display_filter_fn = build_capture_filters(
                capture_ip_address=Settings.capture_ip_address,
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
        webserver_credentials_changed = (
            new_values['webserver_username'] != self._old_values.get('webserver_username')
            or new_values['webserver_password'] != self._old_values.get('webserver_password')
        )

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

        prompt_to_disable_gta5_relay_if_filtered(self, context='settings')

        self._saved = True
        self.accept()

    def _reset_tab_to_defaults(self, category: str) -> None:
        """Populate widgets belonging to *category* with default values without saving."""
        for key, widget in self._widgets.items():
            if key in SETTING_DEFAULTS and SETTING_METADATA[key].category == category:
                self._set_widget_value(key, widget, SETTING_DEFAULTS[key])

    def _reset_current_tab(self) -> None:
        """Reset the current tab's settings to their default values."""
        category = SETTING_CATEGORIES_ORDER[self._tabs.currentIndex()]
        self._reset_tab_to_defaults(category)

    def _reset_to_defaults(self) -> None:
        """Populate all widgets with default values without saving."""
        for key, widget in self._widgets.items():
            if key in SETTING_DEFAULTS:
                self._set_widget_value(key, widget, SETTING_DEFAULTS[key])

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
        self._old_values = {key: getattr(Settings, key) for key in SETTING_METADATA}
        self._load_current_values()
        QMessageBox.information(self, TITLE, 'Settings imported successfully.')

    def _has_unsaved_changes(self) -> bool:
        """Return True if any widget value differs from the value at dialog open."""
        for key, widget in self._widgets.items():
            current = self._read_widget_value(key, widget)
            original = self._old_values.get(key)
            if SETTING_METADATA[key].setting_type == SettingType.IP_RANGE_TUPLE:
                if sorted(current if isinstance(current, tuple) else ()) != sorted(original if isinstance(original, tuple) else ()):
                    return True
            elif current != original:
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
