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
from session_sniffer.guis.stylesheets import DIALOG_BUTTON_STYLESHEET, DIALOG_PRIMARY_BUTTON_STYLESHEET
from session_sniffer.networking.interface import AllInterfaces
from session_sniffer.networking.utils import format_mac_address, is_ipv4_address, is_mac_address
from session_sniffer.settings import SETTING_CATEGORIES_ORDER, SETTING_DEFAULTS, SETTING_METADATA, SettingMeta, SettingType
from session_sniffer.settings.settings import Settings
from session_sniffer.text_templates import SETTINGS_INI_HEADER_TEMPLATE
from session_sniffer.text_utils import format_triple_quoted_text
from session_sniffer.utils import validate_and_strip_balanced_outer_parens
from session_sniffer.utils_exceptions import ParenthesisMismatchError

if TYPE_CHECKING:
    from session_sniffer.capture.tshark_capture import PacketCapture

_NONE_PLACEHOLDER = 'None'

_RESTART_INDICATOR = ' \u27F3'

SettingValue = bool | str | int | float | tuple[str, ...] | None


class SettingsDialog(QDialog):  # pylint: disable=too-few-public-methods
    """Modal dialog exposing every Settings.ini option for viewing, editing, saving, and resetting."""

    def __init__(self, parent: QWidget | None, capture: PacketCapture) -> None:
        """Build the tabbed settings dialog from setting metadata."""
        super().__init__(parent)
        self.setWindowTitle(f'Settings - {TITLE}')
        self.setWindowModality(Qt.WindowModality.NonModal)
        self.setWindowFlags(
            Qt.WindowType.Window
            | Qt.WindowType.WindowCloseButtonHint
            | Qt.WindowType.WindowMinimizeButtonHint
            | Qt.WindowType.WindowMaximizeButtonHint,
        )
        self.setMinimumSize(700, 520)
        self.resize(780, 600)

        self._capture = capture
        self._widgets: dict[str, QWidget] = {}
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
            if meta.group:
                grouped.setdefault(meta.group, []).append((key, meta))
            else:
                ungrouped.append((key, meta))

        # For the Discord tab, add a join button at the top.
        if category == 'Discord':
            join_row = QHBoxLayout()
            join_button = QPushButton('🎮 Join Discord Server')
            join_button.setToolTip('Open the Session Sniffer Discord server invite in your browser')
            join_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
            join_button.clicked.connect(lambda: webbrowser.open(DISCORD_INVITE_URL))  # pyright: ignore[reportUnknownMemberType]
            join_row.addStretch()
            join_row.addWidget(join_button)
            join_row.addStretch()
            outer_layout.addLayout(join_row)

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
            group_box = QGroupBox(group_name)
            group_form = QFormLayout(group_box)
            group_form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)
            group_form.setLabelAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            for key, meta in items:
                self._add_setting_row(group_form, key, meta)
            outer_layout.addWidget(group_box)

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
        widget = self._create_widget(meta)
        self._widgets[key] = widget

        label_text = meta.display_label
        if meta.requires_capture_restart:
            label_text += _RESTART_INDICATOR
        label = QLabel(label_text + ':')

        tooltip = meta.tooltip
        if meta.requires_capture_restart:
            tooltip += ' (requires capture restart)' if tooltip else 'Requires capture restart'
        if tooltip:
            label.setToolTip(tooltip)
        form.addRow(label, widget)

    def _create_widget(self, meta: SettingMeta) -> QWidget:  # pylint: disable=too-many-return-statements
        """Return the appropriate input widget for a single setting."""
        if meta.setting_type == SettingType.BOOLEAN:
            return self._create_boolean_widget(meta)
        if meta.setting_type in (SettingType.STRING, SettingType.IPV4, SettingType.MAC_ADDRESS):
            return self._create_text_widget(meta)
        if meta.setting_type == SettingType.FLOAT:
            return self._create_float_widget(meta)
        if meta.setting_type == SettingType.INTEGER:
            return self._create_integer_widget(meta)
        if meta.setting_type == SettingType.ENUM:
            return self._create_enum_widget(meta)
        if meta.setting_type == SettingType.BOOL_OR_ENUM:
            return self._create_bool_or_enum_widget(meta)
        if meta.setting_type == SettingType.COLUMN_TUPLE:
            return self._create_column_tuple_widget(meta)
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

    def _create_column_tuple_widget(self, meta: SettingMeta) -> QGroupBox:
        """Create a scrollable multi-column grid of checkboxes for column visibility."""
        allowed_attr = meta.allowed_columns_attr or ''
        allowed_columns: tuple[str, ...] = getattr(Settings, allowed_attr, ())

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
        for btn in (btn_select_all, btn_deselect_all):
            btn.setStyleSheet(compact_btn_style)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        btn_select_all.clicked.connect(lambda: self._set_all_checkboxes(inner, checked=True))
        btn_deselect_all.clicked.connect(lambda: self._set_all_checkboxes(inner, checked=False))

        btn_row = QHBoxLayout()
        btn_row.setContentsMargins(0, 0, 0, 0)
        btn_row.setSpacing(6)
        btn_row.addWidget(btn_select_all)
        btn_row.addWidget(btn_deselect_all)
        btn_row.addStretch()

        outer = QVBoxLayout(group)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(4)
        outer.addLayout(btn_row)
        outer.addWidget(scroll, 1)
        return group

    @staticmethod
    def _set_all_checkboxes(container: QWidget, *, checked: bool) -> None:
        """Set all QCheckBox children of *container* to *checked*."""
        for cb in container.findChildren(QCheckBox):
            cb.setChecked(checked)

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

        elif meta.setting_type == SettingType.INTEGER:
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

        if meta.setting_type == SettingType.ENUM:
            text = cast('QComboBox', widget).currentText()
            return None if text == _NONE_PLACEHOLDER else text

        if meta.setting_type == SettingType.BOOL_OR_ENUM:
            text = cast('QComboBox', widget).currentText()
            return False if text == 'Disabled' else text

        if meta.setting_type == SettingType.COLUMN_TUPLE:
            return self._read_column_tuple(meta, widget)

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

        capture_settings_changed = any(
            new_values[key] != self._old_values.get(key)
            for key, meta in SETTING_METADATA.items()
            if meta.requires_capture_restart
        )
        if capture_settings_changed and self._capture.is_running():
            capture_filter_str, display_filter_str = build_capture_filters(
                broadcast_support=self._capture.config.broadcast_support,
                multicast_support=self._capture.config.multicast_support,
            )
            self._capture.config = replace(
                self._capture.config,
                capture_filter=capture_filter_str,
                display_filter=display_filter_str,
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
        text = format_triple_quoted_text(
            SETTINGS_INI_HEADER_TEMPLATE.format(
                title=TITLE,
                configuration_guide_url='https://github.com/BUZZARDGTA/Session-Sniffer/wiki/Configuration-Guide#script-settings-configuration',
            ),
            add_trailing_newline=True,
        )
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
        try:
            Settings.load_from_settings_file(Path(file_path))
        except Exception as exc:  # pylint: disable=broad-except  # noqa: BLE001
            QMessageBox.critical(self, 'Import Error', f'Failed to import settings:\n{exc}')
            return
        self._old_values = {key: getattr(Settings, key) for key in SETTING_METADATA}
        self._load_current_values()
        QMessageBox.information(self, TITLE, 'Settings imported successfully.')
