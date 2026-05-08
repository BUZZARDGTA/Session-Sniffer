"""Settings dialog for viewing, editing, saving, and resetting all application settings."""

import webbrowser
from dataclasses import replace
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING, cast

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDoubleSpinBox,
    QFileDialog,
    QFormLayout,
    QGridLayout,
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

from session_sniffer.capture.filters import build_capture_filters
from session_sniffer.constants.standalone import DISCORD_INVITE_URL, TITLE
from session_sniffer.discord.webhook import is_valid_webhook_url, send_test_message
from session_sniffer.guis.stylesheets import DIALOG_BUTTON_STYLESHEET, DIALOG_PRIMARY_BUTTON_STYLESHEET
from session_sniffer.guis.userip_manager_helpers import IPRangeBuilderDialog
from session_sniffer.guis.utils import set_dialog_window_flags
from session_sniffer.networking.interface import AllInterfaces
from session_sniffer.networking.utils import format_mac_address, is_ipv4_address, is_mac_address
from session_sniffer.settings import SETTING_CATEGORIES_ORDER, SETTING_DEFAULTS, SETTING_METADATA, SettingMeta, SettingType
from session_sniffer.settings.settings import Settings
from session_sniffer.text_templates import build_settings_ini_header_text
from session_sniffer.utils import validate_and_strip_balanced_outer_parens
from session_sniffer.utils_exceptions import ParenthesisMismatchError

if TYPE_CHECKING:
    from session_sniffer.capture.packet_capture import PacketCapture

_NONE_PLACEHOLDER = 'None'

_RESTART_INDICATOR = ' \u27F3'

SettingValue = bool | str | int | float | tuple[str, ...] | None


class SettingsDialog(QDialog):  # pylint: disable=too-few-public-methods
    """Modal dialog exposing every Settings.ini option for viewing, editing, saving, and resetting."""

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

        root_layout = QVBoxLayout(self)

        tabs = QTabWidget()
        for category in SETTING_CATEGORIES_ORDER:
            tab_widget = self._build_tab(category)
            tabs.addTab(tab_widget, category)
        root_layout.addWidget(tabs)

        button_row = QHBoxLayout()

        import_button = QPushButton('\U0001f4e5 Import')
        import_button.setToolTip('Import settings from a Settings.ini file')
        import_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        import_button.clicked.connect(self._import_settings)  # pyright: ignore[reportUnknownMemberType]
        button_row.addWidget(import_button)

        export_button = QPushButton('\U0001f4e4 Export')
        export_button.setToolTip('Export current settings to a Settings.ini file')
        export_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        export_button.clicked.connect(self._export_settings)  # pyright: ignore[reportUnknownMemberType]
        button_row.addWidget(export_button)

        button_row.addStretch()

        reset_button = QPushButton('\U0001f504 Reset All to Defaults')
        reset_button.setToolTip('Reset all settings across every tab to their default values (review before saving)')
        reset_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        reset_button.clicked.connect(self._reset_to_defaults)
        button_row.addWidget(reset_button)

        save_button = QPushButton('\U0001f4be Save')
        save_button.setToolTip('Validate and save all settings to Settings.ini')
        save_button.setStyleSheet(DIALOG_PRIMARY_BUTTON_STYLESHEET)
        save_button.setDefault(True)
        save_button.clicked.connect(self._save_settings)
        button_row.addWidget(save_button)

        cancel_button = QPushButton('\u274c Cancel')
        cancel_button.setToolTip('Discard changes and close')
        cancel_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        cancel_button.clicked.connect(self.close)
        button_row.addWidget(cancel_button)

        root_layout.addLayout(button_row)

        self._load_current_values()
        # Force the webhook enable cascade once even if the value matches the
        # default (in which case `setChecked` would not fire `toggled`).
        webhook_enabled_widget = self._widgets.get('discord_webhook_enabled')
        if isinstance(webhook_enabled_widget, QCheckBox):
            webhook_enabled_widget.toggled.emit(webhook_enabled_widget.isChecked())  # pyright: ignore[reportUnknownMemberType]

        # Show/hide Session Host Detection based on Program Preset.
        preset_widget = self._widgets.get('capture_program_preset')
        if isinstance(preset_widget, QComboBox):
            preset_widget.currentTextChanged.connect(self._on_preset_changed)  # pyright: ignore[reportUnknownMemberType]
            self._on_preset_changed(preset_widget.currentText())

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

        # For the Discord tab, the join button is appended at the bottom of
        # the page (see below). Other tabs have no extra page-level widgets.

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
            group_form = QFormLayout(group_box)
            group_form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)
            group_form.setLabelAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            for key, meta in items:
                self._add_setting_row(group_form, key, meta)
            outer_layout.addWidget(group_box)

        # Append the Discord join button at the bottom of the Discord tab.
        if category == 'Discord':
            join_row = QHBoxLayout()
            join_button = QPushButton('\U0001f3ae Join Session Sniffer Discord Server')
            join_button.setToolTip('Open the Session Sniffer Discord server invite in your browser')
            join_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
            join_button.clicked.connect(lambda: webbrowser.open(DISCORD_INVITE_URL))  # pyright: ignore[reportUnknownMemberType]
            join_row.addStretch()
            join_row.addWidget(join_button)
            join_row.addStretch()
            outer_layout.addLayout(join_row)

        outer_layout.addStretch()
        scroll.setWidget(container)
        page_layout.addWidget(scroll)

        reset_tab_row = QHBoxLayout()
        reset_tab_row.addStretch()
        reset_tab_button = QPushButton('\U0001f504 Reset Tab to Defaults')
        reset_tab_button.setToolTip(f'Reset all {category} settings to their default values (review before saving)')
        reset_tab_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        reset_tab_button.clicked.connect(partial(self._reset_tab_to_defaults, category))
        reset_tab_row.addWidget(reset_tab_button)
        page_layout.addLayout(reset_tab_row)

        return page

    def _add_setting_row(self, form: QFormLayout, key: str, meta: SettingMeta) -> None:
        """Create a widget for *key* and append a labeled row to *form*."""
        widget = self._create_widget(key, meta)
        self._widgets[key] = widget

        label_text = meta.display_label
        if meta.requires_capture_restart:
            label_text += _RESTART_INDICATOR
        label = QLabel(label_text + ':')
        self._labels[key] = label

        tooltip = meta.tooltip
        if meta.requires_capture_restart:
            tooltip += ' (requires capture restart)' if tooltip else 'Requires capture restart'
        if tooltip:
            label.setToolTip(tooltip)

        form.addRow(label, widget)

    def _on_preset_changed(self, preset: str) -> None:
        """Show or hide the Session Host Detection row depending on the active preset."""
        gta5_only = preset == 'GTA5'
        for key in ('gui_session_host_detection',):
            widget = self._widgets.get(key)
            label = self._labels.get(key)
            if widget:
                widget.setVisible(gta5_only)
                widget.setEnabled(gta5_only)
            if label:
                label.setVisible(gta5_only)

    def _build_discord_webhook_group(self, items: list[tuple[str, SettingMeta]]) -> QGroupBox:  # pylint: disable=too-many-locals,too-many-statements
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
            enabled_widget = self._create_widget('discord_webhook_enabled', enabled_meta)
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
                or 'Discord channel webhook URL. Treat this like a password \u2014 anyone with it can post to the channel.',
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
            show_button.toggled.connect(partial(self._toggle_url_visibility, url_line, show_button))  # pyright: ignore[reportUnknownMemberType]
            url_row_layout.addWidget(show_button)

            test_button = QPushButton('\U0001f527 Test')
            test_button.setToolTip('Send a one-time test message to this webhook URL')
            test_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
            test_button.clicked.connect(partial(self._test_webhook, url_line))  # pyright: ignore[reportUnknownMemberType]
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
        reset_msgs_button.clicked.connect(self._reset_stored_messages)  # pyright: ignore[reportUnknownMemberType]
        reset_msgs_row.addWidget(reset_msgs_button)
        outer.addLayout(reset_msgs_row)

        # Footer note about automod / Wick.
        note = QLabel(
            '\u26a0 If your server runs Wick or another automod with a "wall of text" filter, '
            'whitelist this webhook (or its channel) to prevent the messages \u2014 and the webhook itself \u2014 from being deleted.',
        )
        note.setWordWrap(True)
        note.setStyleSheet('color: #888; font-size: 11px;')
        outer.addWidget(note)

        # Wire enable cascade.
        if enabled_meta is not None:
            enabled_cb = cast('QCheckBox', self._widgets['discord_webhook_enabled'])
            enabled_cb.toggled.connect(partial(self._on_webhook_enabled_toggled, details_widget, url_line))  # pyright: ignore[reportUnknownMemberType]

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

    def _create_widget(self, key: str, meta: SettingMeta) -> QWidget:  # pylint: disable=too-many-return-statements
        """Return the appropriate input widget for a single setting."""
        if meta.setting_type == SettingType.BOOLEAN:
            return self._create_boolean_widget(meta)
        if meta.setting_type in (SettingType.STRING, SettingType.IPV4, SettingType.MAC_ADDRESS):
            return self._create_text_widget(meta)
        if meta.setting_type == SettingType.FLOAT:
            return self._create_float_widget(meta)
        if meta.setting_type == SettingType.INTEGER:
            return self._create_integer_widget(meta)
        if meta.setting_type == SettingType.INTEGER_OR_ALL:
            return self._create_integer_or_all_widget(meta)
        if meta.setting_type == SettingType.ENUM:
            return self._create_enum_widget(meta)
        if meta.setting_type == SettingType.BOOL_OR_ENUM:
            return self._create_bool_or_enum_widget(meta)
        if meta.setting_type == SettingType.COLUMN_TUPLE:
            return self._create_column_tuple_widget(key, meta)
        if meta.setting_type == SettingType.IP_RANGE_TUPLE:
            return self._create_ip_range_tuple_widget(meta)
        return QLineEdit()

    def _create_boolean_widget(self, meta: SettingMeta) -> QCheckBox:
        cb = QCheckBox()
        if meta.tooltip:
            cb.setToolTip(meta.tooltip)
        return cb

    def _create_text_widget(self, meta: SettingMeta) -> QLineEdit:
        le = QLineEdit()
        if meta.setting_type == SettingType.IPV4:
            le.setPlaceholderText('e.g. 192.168.1.100')
        elif meta.setting_type == SettingType.MAC_ADDRESS:
            le.setPlaceholderText('e.g. AA:BB:CC:DD:EE:FF')
        if meta.tooltip:
            le.setToolTip(meta.tooltip)
        return le

    def _create_float_widget(self, meta: SettingMeta) -> QDoubleSpinBox:
        spin = QDoubleSpinBox()
        spin.setDecimals(1)
        spin.setSingleStep(0.5)
        spin.setMinimum(meta.min_value if meta.min_value is not None else 0.0)
        spin.setMaximum(meta.max_value if meta.max_value is not None else 99999.0)
        if meta.tooltip:
            spin.setToolTip(meta.tooltip)
        return spin

    def _create_integer_widget(self, meta: SettingMeta) -> QSpinBox:
        spin = QSpinBox()
        spin.setSingleStep(int(meta.step) if meta.step is not None else 1)
        spin.setMinimum(int(meta.min_value) if meta.min_value is not None else 0)
        spin.setMaximum(int(meta.max_value) if meta.max_value is not None else 99999)
        if meta.tooltip:
            spin.setToolTip(meta.tooltip)
        return spin

    def _create_integer_or_all_widget(self, meta: SettingMeta) -> QSpinBox:
        spin = QSpinBox()
        spin.setSingleStep(int(meta.step) if meta.step is not None else 1)
        spin.setMinimum(0)
        spin.setMaximum(int(meta.max_value) if meta.max_value is not None else 99999)
        spin.setSpecialValueText('All')
        if meta.tooltip:
            spin.setToolTip(meta.tooltip)
        return spin

    def _create_enum_widget(self, meta: SettingMeta) -> QComboBox:
        combo = QComboBox()
        if meta.allowed_values:
            combo.addItems(meta.allowed_values)
        if meta.tooltip:
            combo.setToolTip(meta.tooltip)
        return combo

    def _create_bool_or_enum_widget(self, meta: SettingMeta) -> QComboBox:
        combo = QComboBox()
        items = ['Disabled']
        if meta.allowed_values:
            items.extend(meta.allowed_values)
        combo.addItems(items)
        if meta.tooltip:
            combo.setToolTip(meta.tooltip)
        return combo

    def _create_column_tuple_widget(self, key: str, meta: SettingMeta) -> QGroupBox:
        """Create a scrollable multi-column grid of checkboxes for column visibility."""
        allowed_attr = meta.allowed_columns_attr or ''
        allowed_columns: tuple[str, ...] = getattr(Settings, allowed_attr, ())
        default_columns: tuple[str, ...] = tuple(SETTING_DEFAULTS.get(key, ()))

        group = QGroupBox()
        group.setFlat(True)
        if meta.tooltip:
            group.setToolTip(meta.tooltip)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setMaximumHeight(340)
        scroll.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)

        inner = QWidget()
        grid = QGridLayout(inner)
        grid.setContentsMargins(4, 4, 4, 4)
        grid.setSpacing(2)

        num_columns = 3
        for i, col_name in enumerate(allowed_columns):
            display_text = meta.display_labels.get(col_name, col_name) if meta.display_labels else col_name
            cb = QCheckBox(display_text)
            cb.setObjectName(col_name)
            grid.addWidget(cb, i // num_columns, i % num_columns)

        scroll.setWidget(inner)

        btn_select_all = QPushButton('Select All')
        btn_deselect_all = QPushButton('Deselect All')
        btn_reset = QPushButton('Reset')
        btn_reset.setToolTip('Reset to default selected columns')
        compact_btn_style = (
            'QPushButton { background: qlineargradient(x1:0,y1:0,x2:0,y2:1,'
            ' stop:0 rgba(236,240,241,0.12), stop:1 rgba(189,195,199,0.18));'
            ' color: #ecf0f1; border: 1px solid rgba(52,73,94,0.6);'
            ' border-radius: 4px; padding: 2px 10px; font-size: 11px; font-weight: bold; }'
            ' QPushButton:hover { background: qlineargradient(x1:0,y1:0,x2:0,y2:1,'
            ' stop:0 rgba(52,152,219,0.25), stop:1 rgba(41,128,185,0.35));'
            ' border: 1px solid rgba(52,152,219,0.8); color: #ffffff; }'
            ' QPushButton:pressed { background: qlineargradient(x1:0,y1:0,x2:0,y2:1,'
            ' stop:0 rgba(41,128,185,0.45), stop:1 rgba(52,152,219,0.55));'
            ' border: 1px solid rgba(41,128,185,1.0); }'
        )
        for btn in (btn_select_all, btn_deselect_all, btn_reset):
            btn.setStyleSheet(compact_btn_style)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        btn_select_all.clicked.connect(lambda: self._set_all_checkboxes(inner, checked=True))
        btn_deselect_all.clicked.connect(lambda: self._set_all_checkboxes(inner, checked=False))
        btn_reset.clicked.connect(lambda: self._set_checkboxes_to(inner, default_columns))

        btn_row = QHBoxLayout()
        btn_row.setContentsMargins(0, 0, 0, 0)
        btn_row.setSpacing(6)
        btn_row.addWidget(btn_select_all)
        btn_row.addWidget(btn_deselect_all)
        btn_row.addWidget(btn_reset)
        btn_row.addStretch()

        outer = QVBoxLayout(group)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(4)
        outer.addLayout(btn_row)
        outer.addWidget(scroll, 1)
        return group

    def _create_ip_range_tuple_widget(self, meta: SettingMeta) -> QGroupBox:
        """Create an add/remove list widget for managing a tuple of IP addresses and ranges."""
        group = QGroupBox()
        group.setFlat(True)
        if meta.tooltip:
            group.setToolTip(meta.tooltip)

        list_widget = QListWidget()
        list_widget.setMaximumHeight(180)
        list_widget.setSelectionMode(QListWidget.SelectionMode.ExtendedSelection)
        list_widget.setSortingEnabled(True)

        compact_btn_style = (
            'QPushButton { background: qlineargradient(x1:0,y1:0,x2:0,y2:1,'
            ' stop:0 rgba(236,240,241,0.12), stop:1 rgba(189,195,199,0.18));'
            ' color: #ecf0f1; border: 1px solid rgba(52,73,94,0.6);'
            ' border-radius: 4px; padding: 2px 10px; font-size: 11px; font-weight: bold; }'
            ' QPushButton:hover { background: qlineargradient(x1:0,y1:0,x2:0,y2:1,'
            ' stop:0 rgba(52,152,219,0.25), stop:1 rgba(41,128,185,0.35));'
            ' border: 1px solid rgba(52,152,219,0.8); color: #ffffff; }'
            ' QPushButton:pressed { background: qlineargradient(x1:0,y1:0,x2:0,y2:1,'
            ' stop:0 rgba(41,128,185,0.45), stop:1 rgba(52,152,219,0.55));'
            ' border: 1px solid rgba(41,128,185,1.0); }'
        )

        add_button = QPushButton('\u2795 Add')
        add_button.setToolTip('Add a new blocked IP address, range, or subnet')
        add_button.setStyleSheet(compact_btn_style)
        add_button.setCursor(Qt.CursorShape.PointingHandCursor)
        add_button.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)

        remove_button = QPushButton('\U0001f5d1 Remove')
        remove_button.setToolTip('Remove the selected entries')
        remove_button.setStyleSheet(compact_btn_style)
        remove_button.setCursor(Qt.CursorShape.PointingHandCursor)
        remove_button.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)

        def _add_entry() -> None:
            dialog = IPRangeBuilderDialog(self)
            if dialog.exec() != QDialog.DialogCode.Accepted:
                return
            entry = dialog.result_entry()
            if not entry:
                return
            existing = {item.text() for i in range(list_widget.count()) if (item := list_widget.item(i)) is not None}
            if entry not in existing:
                list_widget.addItem(entry)

        def _remove_entries() -> None:
            for item in list_widget.selectedItems():
                list_widget.takeItem(list_widget.row(item))

        add_button.clicked.connect(_add_entry)  # pyright: ignore[reportUnknownMemberType]
        remove_button.clicked.connect(_remove_entries)  # pyright: ignore[reportUnknownMemberType]

        btn_row = QHBoxLayout()
        btn_row.setContentsMargins(0, 0, 0, 0)
        btn_row.setSpacing(6)
        btn_row.addWidget(add_button)
        btn_row.addWidget(remove_button)
        btn_row.addStretch()

        outer_layout = QVBoxLayout(group)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(4)
        outer_layout.addLayout(btn_row)
        outer_layout.addWidget(list_widget, 1)
        return group

    @staticmethod
    def _set_all_checkboxes(container: QWidget, *, checked: bool) -> None:
        """Set all QCheckBox children of *container* to *checked*."""
        for cb in container.findChildren(QCheckBox):
            cb.setChecked(checked)

    @staticmethod
    def _set_checkboxes_to(container: QWidget, selected: tuple[str, ...]) -> None:
        """Check exactly the QCheckBox children whose objectName is in *selected*."""
        wanted = set(selected)
        for cb in container.findChildren(QCheckBox):
            cb.setChecked(cb.objectName() in wanted)

    # ------------------------------------------------------------------
    # Load / save / reset
    # ------------------------------------------------------------------

    def _load_current_values(self) -> None:
        """Populate every widget from the current in-memory Settings values."""
        for key, widget in self._widgets.items():
            value: SettingValue = getattr(Settings, key)
            self._set_widget_value(key, widget, value)

    def _set_widget_value(self, key: str, widget: QWidget, value: SettingValue) -> None:
        """Push *value* into the appropriate *widget*."""
        meta = SETTING_METADATA[key]

        if meta.setting_type == SettingType.BOOLEAN:
            cast('QCheckBox', widget).setChecked(bool(value))

        elif meta.setting_type in (SettingType.STRING, SettingType.IPV4, SettingType.MAC_ADDRESS):
            cast('QLineEdit', widget).setText('' if value is None else str(value))

        elif meta.setting_type == SettingType.FLOAT:
            cast('QDoubleSpinBox', widget).setValue(float(value) if isinstance(value, (int, float)) else 0.0)

        elif meta.setting_type in (SettingType.INTEGER, SettingType.INTEGER_OR_ALL):
            cast('QSpinBox', widget).setValue(int(value) if isinstance(value, (int, float)) else 0)

        elif meta.setting_type == SettingType.ENUM:
            self._set_enum(widget, value)

        elif meta.setting_type == SettingType.BOOL_OR_ENUM:
            self._set_bool_or_enum(widget, value)

        elif meta.setting_type == SettingType.COLUMN_TUPLE:
            shown: tuple[str, ...] = value if isinstance(value, tuple) else ()
            shown_set = set(shown)
            for cb in widget.findChildren(QCheckBox):
                cb.setChecked(cb.objectName() in shown_set)

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

    def _read_widget_value(self, key: str, widget: QWidget) -> SettingValue:  # pylint: disable=too-many-return-statements
        """Extract the current value from *widget* for setting *key*."""
        meta = SETTING_METADATA[key]

        if meta.setting_type == SettingType.BOOLEAN:
            return cast('QCheckBox', widget).isChecked()

        if meta.setting_type in (SettingType.STRING, SettingType.IPV4, SettingType.MAC_ADDRESS):
            text = cast('QLineEdit', widget).text().strip()
            return text or None

        if meta.setting_type == SettingType.FLOAT:
            return cast('QDoubleSpinBox', widget).value()

        if meta.setting_type == SettingType.INTEGER:
            return cast('QSpinBox', widget).value()

        if meta.setting_type == SettingType.INTEGER_OR_ALL:
            return cast('QSpinBox', widget).value()

        if meta.setting_type == SettingType.ENUM:
            text = cast('QComboBox', widget).currentText()
            return None if text == _NONE_PLACEHOLDER else text

        if meta.setting_type == SettingType.BOOL_OR_ENUM:
            text = cast('QComboBox', widget).currentText()
            return False if text == 'Disabled' else text

        if meta.setting_type == SettingType.COLUMN_TUPLE:
            return self._read_column_tuple(meta, widget)

        if meta.setting_type == SettingType.IP_RANGE_TUPLE:
            list_widget = next(iter(widget.findChildren(QListWidget)), None)
            if list_widget is None:
                return ()
            return tuple(item.text() for i in range(list_widget.count()) if (item := list_widget.item(i)) is not None)

        return None

    def _read_column_tuple(self, meta: SettingMeta, widget: QWidget) -> tuple[str, ...]:
        """Read checked column names from the column-tuple group box."""
        allowed_attr = meta.allowed_columns_attr or ''
        allowed_columns: tuple[str, ...] = getattr(Settings, allowed_attr, ())
        checkboxes = {cb.objectName(): cb for cb in widget.findChildren(QCheckBox)}
        return tuple(
            col_name for col_name in allowed_columns
            if (cb := checkboxes.get(col_name)) is not None and cb.isChecked()
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

            elif meta.setting_type == SettingType.STRING and key in (
                'capture_prepend_custom_capture_filter',
                'capture_prepend_custom_display_filter',
            ) and isinstance(value, str):
                try:
                    validate_and_strip_balanced_outer_parens(value)
                except ParenthesisMismatchError:
                    errors.append(f'{meta.display_label}: filter expression has unbalanced parentheses.')

            elif key == 'discord_presence_title' and isinstance(value, str) and len(value) == 1:
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

        capture_settings_changed = any(
            new_values[key] != self._old_values.get(key)
            for key, meta in SETTING_METADATA.items()
            if meta.requires_capture_restart
        )
        if capture_settings_changed and self._capture.is_running():
            capture_filter_str, display_filter_fn = build_capture_filters(
                broadcast_support=self._capture.config.broadcast_support,
                multicast_support=self._capture.config.multicast_support,
            )
            self._capture.config = replace(
                self._capture.config,
                capture_filter=capture_filter_str,
                display_filter_fn=display_filter_fn,
            )
            self._capture.request_restart()

        self.accept()

    def _reset_tab_to_defaults(self, category: str) -> None:
        """Populate widgets belonging to *category* with default values without saving."""
        for key, widget in self._widgets.items():
            if key in SETTING_DEFAULTS and SETTING_METADATA[key].category == category:
                self._set_widget_value(key, widget, SETTING_DEFAULTS[key])

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
