"""Detections Manager dialog for configuring advanced per-detection protection rules."""  # pylint: disable=too-many-lines

import json
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, Literal

from PyQt6.QtCore import QSortFilterProxyModel, Qt
from PyQt6.QtGui import QIcon, QPixmap, QStandardItem, QStandardItemModel
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QCompleter,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.background import clear_voice_notification_queue
from session_sniffer.constants.local import COMBO_RULES_PATH, IMAGES_DIR_PATH, PROTECTIONS_JSON_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis.country_data import COUNTRY_NAMES, get_country_flag_code
from session_sniffer.guis.stylesheets import DIALOG_BUTTON_STYLESHEET, DIALOG_PRIMARY_BUTTON_STYLESHEET
from session_sniffer.guis.utils import (
    SUSPEND_TOOLTIP_ADAPTIVE,
    SUSPEND_TOOLTIP_AUTO,
    SUSPEND_TOOLTIP_CUSTOM,
    SUSPEND_TOOLTIP_MANUAL,
    set_dialog_window_flags,
)
from session_sniffer.player.combo_rules import ComboRule, ComboRulesManager
from session_sniffer.player.protections import GUIProtectionSettings
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings import Settings

if TYPE_CHECKING:
    from session_sniffer.models.player import Player

_COUNTRY_FLAGS_DIR = IMAGES_DIR_PATH / 'country_flags'
# Pre-scan available flag codes once to avoid per-country filesystem checks
_AVAILABLE_FLAG_CODES: frozenset[str] = frozenset(
    p.stem for p in _COUNTRY_FLAGS_DIR.glob('*.png')
) if _COUNTRY_FLAGS_DIR.is_dir() else frozenset()

_GROUPBOX_STYLE = """
    QGroupBox {
        font-size: 12pt;
        font-weight: bold;
        border: 2px solid #4A90E2;
        border-radius: 8px;
        margin-top: 12px;
        padding-top: 15px;
        background: rgba(74, 144, 226, 0.05);
    }
    QGroupBox::title {
        subcontrol-origin: margin;
        subcontrol-position: top left;
        left: 15px;
        padding: 0 5px;
        color: #4A90E2;
    }
"""

_LIST_WIDGET_STYLE = """
    QListWidget {
        background: #2d2d2d;
        border: 2px solid #4A90E2;
        border-radius: 4px;
        padding: 5px;
        font-family: 'Consolas', 'Courier New', monospace;
    }
    QListWidget::item {
        padding: 5px;
        border-radius: 3px;
    }
    QListWidget::item:selected {
        background: #4A90E2;
        color: white;
    }
"""


def _set_duration_widgets_helper(combo: QComboBox, spin: QSpinBox, duration: int | str) -> None:
    """Set duration combo and spin box from a stored duration value."""
    if isinstance(duration, int):
        combo.setCurrentText('Custom (seconds)')
        spin.setValue(int(duration))
        spin.setEnabled(True)
    elif duration == 'Manual':
        combo.setCurrentText('Manual')
    elif duration == 'Adaptive':
        combo.setCurrentText('Adaptive')
    else:
        combo.setCurrentText('Auto')


def _read_duration_widgets_helper(combo: QComboBox, spin: QSpinBox) -> int | Literal['Auto', 'Manual', 'Adaptive']:
    """Read duration value from combo and spin box widgets."""
    text = combo.currentText()
    if text == 'Custom (seconds)':
        return spin.value()
    if text == 'Manual':
        return 'Manual'
    if text == 'Adaptive':
        return 'Adaptive'
    return 'Auto'


def _set_voice_combo_helper(combo: QComboBox, value: Literal['Male', 'Female'] | bool) -> None:  # noqa: FBT001
    """Set voice combo from a stored voice notification value."""
    if value == 'Male':
        combo.setCurrentText('Male')
    elif value == 'Female':
        combo.setCurrentText('Female')
    else:
        combo.setCurrentText('Disabled')


def _read_voice_combo_helper(combo: QComboBox) -> Literal['Male', 'Female'] | bool:
    """Read voice notification value from a combo widget."""
    text = combo.currentText()
    if text == 'Male':
        return 'Male'
    if text == 'Female':
        return 'Female'
    return False


_COUNTRY_SELECTOR_COMBO_STYLE = """
    QComboBox {
        font-size: 11pt;
        padding: 6px 10px;
        min-height: 28px;
    }
    QComboBox QAbstractItemView {
        font-size: 10pt;
    }
"""


class _CountrySelectionDialog(QDialog):
    """Searchable country selection dialog with flag icons and auto-complete."""

    def __init__(self, parent: QWidget, existing_countries: set[str]) -> None:
        super().__init__(parent)
        self.setWindowTitle('Select Country')
        self.setMinimumWidth(420)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint)

        layout = QVBoxLayout(self)

        hint = QLabel('Type to search by country name or code:')
        hint.setStyleSheet('color: #a0a0a0; font-style: italic; padding-bottom: 4px;')
        layout.addWidget(hint)

        self._combo = QComboBox()
        self._combo.setEditable(True)
        self._combo.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        self._combo.setStyleSheet(_COUNTRY_SELECTOR_COMBO_STYLE)
        self._combo.setMaxVisibleItems(15)

        model = QStandardItemModel(self._combo)
        for code in sorted(COUNTRY_NAMES, key=lambda c: COUNTRY_NAMES[c]):
            name = COUNTRY_NAMES[code]
            if name in existing_countries:
                continue
            display = f'{code} - {name}'
            item = QStandardItem(display)
            item.setData(name, Qt.ItemDataRole.UserRole)
            if code in _AVAILABLE_FLAG_CODES:
                item.setIcon(QIcon(QPixmap(str(_COUNTRY_FLAGS_DIR / f'{code}.png'))))
            model.appendRow(item)

        self._combo.setModel(model)
        self._combo.setCurrentIndex(-1)
        line_edit = self._combo.lineEdit()
        if line_edit is not None:
            line_edit.setPlaceholderText('e.g. Switzerland, US, Russia ...')

        proxy = QSortFilterProxyModel(self._combo)
        proxy.setSourceModel(model)
        proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)

        completer = QCompleter(proxy, self._combo)
        completer.setCompletionMode(QCompleter.CompletionMode.PopupCompletion)
        completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        completer.setFilterMode(Qt.MatchFlag.MatchContains)
        completer.setMaxVisibleItems(15)
        self._combo.setCompleter(completer)

        layout.addWidget(self._combo)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)  # pyright: ignore[reportUnknownMemberType]
        buttons.rejected.connect(self.reject)  # pyright: ignore[reportUnknownMemberType]
        layout.addWidget(buttons)

    def selected_country(self) -> str | None:
        """Return the selected country name, or None if nothing valid is selected."""
        idx = self._combo.currentIndex()
        if idx >= 0:
            data = self._combo.itemData(idx, Qt.ItemDataRole.UserRole)
            if isinstance(data, str):
                return data
        text = self._combo.currentText().strip()
        text_upper = text.upper()
        for code, name in COUNTRY_NAMES.items():
            if text_upper == code or text_upper == f'{code} - {name}'.upper() or text_upper == name.upper():
                return name
        return None


class _ComboRuleEditorDialog(QDialog):
    """Dialog for creating or editing a single combo rule."""

    # Condition display names → internal keys
    _CONDITION_LABELS: ClassVar[dict[str, str]] = {
        'Country': 'country',
        'City': 'city',
        'Region': 'region',
        'Organization': 'org',
        'ISP': 'isp',
        'ASN': 'asn',
        'AS Name': 'as_name',
        'Mobile Connection': 'mobile',
        'VPN / Proxy': 'vpn',
        'Hosting / Datacenter': 'hosting',
        'Player Event': 'event',
    }

    _EVENT_LABELS: ClassVar[dict[str, str]] = {
        'Player Joined': 'join',
        'Player Rejoined': 'rejoin',
        'Player Left': 'leave',
    }

    def __init__(self, parent: QWidget, rule: ComboRule | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle('Edit Combo Rule' if rule else 'New Combo Rule')
        self.setMinimumWidth(600)
        self.setMinimumHeight(500)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint)

        self._condition_rows: list[tuple[QComboBox, QWidget]] = []
        self._editing_rule = rule

        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(10)

        # Rule name
        name_layout = QHBoxLayout()
        name_layout.addWidget(QLabel('Rule Name:'))
        self._name_edit = QLineEdit()
        self._name_edit.setPlaceholderText('e.g., Block VPN from Russia')
        if rule:
            self._name_edit.setText(rule.name)
        name_layout.addWidget(self._name_edit)
        main_layout.addLayout(name_layout)

        # Enabled checkbox
        self._enabled_checkbox = QCheckBox('Rule Enabled')
        self._enabled_checkbox.setChecked(rule.enabled if rule else True)
        main_layout.addWidget(self._enabled_checkbox)

        # Conditions section
        conditions_group = QGroupBox('Conditions (ALL must match)')
        conditions_group.setStyleSheet(_GROUPBOX_STYLE)
        conditions_layout = QVBoxLayout()

        self._conditions_container = QVBoxLayout()
        conditions_layout.addLayout(self._conditions_container)

        add_condition_btn = QPushButton('\u2795 Add Condition')
        add_condition_btn.clicked.connect(self._add_condition_row)  # pyright: ignore[reportUnknownMemberType]
        conditions_layout.addWidget(add_condition_btn)

        conditions_group.setLayout(conditions_layout)

        conditions_scroll = QScrollArea()
        conditions_scroll.setWidgetResizable(True)
        conditions_scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        conditions_scroll.setWidget(conditions_group)
        main_layout.addWidget(conditions_scroll, stretch=1)

        # Action settings
        action_group = QGroupBox('Actions')
        action_group.setStyleSheet(_GROUPBOX_STYLE)
        action_layout = QVBoxLayout()

        # Protection Settings
        # -- Protection section (hidden when ARP interface / protection not supported) --
        protection_section = QWidget()
        protection_section_layout = QVBoxLayout(protection_section)
        protection_section_layout.setContentsMargins(0, 0, 0, 0)

        protection_separator = QLabel('\u2500\u2500\u2500 Protection Settings \u2500\u2500\u2500')
        protection_separator.setStyleSheet('color: #666; font-size: 9pt; padding: 5px 0;')
        protection_separator.setAlignment(Qt.AlignmentFlag.AlignCenter)
        protection_section_layout.addWidget(protection_separator)

        self._protection_enabled_checkbox = QCheckBox('Enable Protection')
        self._protection_enabled_checkbox.setChecked(rule.protection_enabled if rule else False)
        protection_section_layout.addWidget(self._protection_enabled_checkbox)

        # Process path
        process_row = QHBoxLayout()
        process_row.addWidget(QLabel('Process Path:'))
        self._process_edit = QLineEdit()
        self._process_edit.setPlaceholderText('e.g., C:\\Program Files\\Game\\game.exe')
        if rule and rule.process_path:
            self._process_edit.setText(str(rule.process_path))
        process_row.addWidget(self._process_edit)
        browse_btn = QPushButton('\U0001f4c1 Browse')
        browse_btn.setMaximumWidth(100)
        browse_btn.clicked.connect(self._browse_process)  # pyright: ignore[reportUnknownMemberType]
        process_row.addWidget(browse_btn)
        protection_section_layout.addLayout(process_row)

        # Duration
        duration_row = QHBoxLayout()
        duration_row.addWidget(QLabel('Suspend Mode:'))
        self._duration_combo = QComboBox()
        self._duration_combo.addItems(['Auto', 'Manual', 'Adaptive', 'Custom (seconds)'])  # pyright: ignore[reportUnknownMemberType]
        duration_row.addWidget(self._duration_combo)
        self._duration_spin = QSpinBox()
        self._duration_spin.setRange(1, 3600)
        self._duration_spin.setValue(60)
        self._duration_spin.setSuffix(' seconds')
        self._duration_spin.setEnabled(False)
        self._duration_combo.currentTextChanged.connect(  # pyright: ignore[reportUnknownMemberType]
            lambda text: self._duration_spin.setEnabled(text == 'Custom (seconds)'),  # pyright: ignore[reportUnknownLambdaType, reportUnknownArgumentType]
        )
        duration_row.addWidget(self._duration_spin)
        duration_row.addStretch()
        protection_section_layout.addLayout(duration_row)

        if rule:
            _set_duration_widgets_helper(self._duration_combo, self._duration_spin, rule.duration)

        action_layout.addWidget(protection_section)
        if Settings.capture_program_preset != 'GTA5' or CaptureState.is_arp_interface:
            protection_section.setVisible(False)
            self._protection_enabled_checkbox.setChecked(False)

        # Notification Settings
        notification_separator = QLabel('\u2500\u2500\u2500 Notification Settings \u2500\u2500\u2500')
        notification_separator.setStyleSheet('color: #666; font-size: 9pt; padding: 5px 0;')
        notification_separator.setAlignment(Qt.AlignmentFlag.AlignCenter)
        action_layout.addWidget(notification_separator)

        voice_row = QHBoxLayout()
        voice_row.addWidget(QLabel('Voice Notifications:'))
        self._voice_combo = QComboBox()
        self._voice_combo.addItems(['Disabled', 'Male', 'Female'])  # pyright: ignore[reportUnknownMemberType]
        self._voice_combo.setToolTip('Select voice for text-to-speech notifications')
        if rule:
            _set_voice_combo_helper(self._voice_combo, rule.voice_notifications)
        voice_row.addWidget(self._voice_combo)
        voice_row.addStretch()
        action_layout.addLayout(voice_row)

        self._msgbox_checkbox = QCheckBox('Show Message Box')
        self._msgbox_checkbox.setToolTip('Show a message box popup when this protection triggers')
        self._msgbox_checkbox.setChecked(rule.message_box if rule else False)
        action_layout.addWidget(self._msgbox_checkbox)

        self._logging_checkbox = QCheckBox('Detection Logging')
        self._logging_checkbox.setToolTip('Log detection events to the detection logging file')
        self._logging_checkbox.setChecked(rule.logging if rule else False)
        action_layout.addWidget(self._logging_checkbox)

        action_group.setLayout(action_layout)
        main_layout.addWidget(action_group)

        # Dialog buttons
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._validate_and_accept)  # pyright: ignore[reportUnknownMemberType]
        buttons.rejected.connect(self.reject)  # pyright: ignore[reportUnknownMemberType]
        main_layout.addWidget(buttons)

        # Pre-populate conditions from existing rule
        if rule:
            for key, value in rule.conditions.items():
                self._add_condition_row(key, value)

    def _add_condition_row(
        self, preset_key: str | None = None, preset_value: str | bool | list[str] | None = None,  # noqa: FBT001
    ) -> None:
        """Add a new condition row with type selector and value widget."""
        row_layout = QHBoxLayout()

        type_combo = QComboBox()
        type_combo.addItems(list(self._CONDITION_LABELS.keys()))  # pyright: ignore[reportUnknownMemberType]
        type_combo.setCurrentIndex(-1)

        value_stack = QWidget()
        value_layout = QVBoxLayout(value_stack)
        value_layout.setContentsMargins(0, 0, 0, 0)

        # Default: text input
        text_edit = QLineEdit()
        text_edit.setPlaceholderText('Enter value...')
        value_layout.addWidget(text_edit)

        def on_type_changed(label: str) -> None:
            key = self._CONDITION_LABELS.get(label, '')
            # Clear and rebuild value widget
            while value_layout.count():
                child = value_layout.takeAt(0)
                if child is not None:
                    widget = child.widget()
                    if widget is not None:
                        widget.setParent(None)
                        widget.deleteLater()

            if key in ('mobile', 'vpn', 'hosting'):
                bool_combo = QComboBox()
                bool_combo.addItem('Yes', userData=True)
                bool_combo.addItem('No', userData=False)
                value_layout.addWidget(bool_combo)
            elif key == 'event':
                events_widget = QWidget()
                events_layout = QHBoxLayout(events_widget)
                events_layout.setContentsMargins(0, 0, 0, 0)
                for display_name in self._EVENT_LABELS:
                    cb = QCheckBox(display_name)
                    events_layout.addWidget(cb)
                value_layout.addWidget(events_widget)
            elif key == 'country':
                country_combo = QComboBox()
                country_combo.setEditable(True)
                country_combo.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
                model = QStandardItemModel(country_combo)
                for code in sorted(COUNTRY_NAMES, key=lambda c: COUNTRY_NAMES[c]):
                    name = COUNTRY_NAMES[code]
                    display = f'{code} - {name}'
                    item = QStandardItem(display)
                    item.setData(name, Qt.ItemDataRole.UserRole)
                    if code in _AVAILABLE_FLAG_CODES:
                        item.setIcon(QIcon(QPixmap(str(_COUNTRY_FLAGS_DIR / f'{code}.png'))))
                    model.appendRow(item)
                country_combo.setModel(model)
                country_combo.setCurrentIndex(-1)
                line_edit = country_combo.lineEdit()
                if line_edit is not None:
                    line_edit.setPlaceholderText('Search country...')
                proxy = QSortFilterProxyModel(country_combo)
                proxy.setSourceModel(model)
                proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
                completer = QCompleter(proxy, country_combo)
                completer.setCompletionMode(QCompleter.CompletionMode.PopupCompletion)
                completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
                completer.setFilterMode(Qt.MatchFlag.MatchContains)
                country_combo.setCompleter(completer)
                value_layout.addWidget(country_combo)
            else:
                new_edit = QLineEdit()
                new_edit.setPlaceholderText(f'Enter {label.lower()} value...')
                value_layout.addWidget(new_edit)

        type_combo.currentTextChanged.connect(on_type_changed)  # pyright: ignore[reportUnknownMemberType]

        remove_btn = QPushButton('\u2796')
        remove_btn.setMaximumWidth(40)

        row_widget = QWidget()
        row_layout.addWidget(type_combo, stretch=1)
        row_layout.addWidget(value_stack, stretch=2)
        row_layout.addWidget(remove_btn)
        row_widget.setLayout(row_layout)

        self._conditions_container.addWidget(row_widget)
        self._condition_rows.append((type_combo, value_stack))

        def remove_row() -> None:
            self._condition_rows.remove((type_combo, value_stack))
            row_widget.deleteLater()

        remove_btn.clicked.connect(remove_row)  # pyright: ignore[reportUnknownMemberType]

        # Set preset values if provided
        if preset_key is not None:
            # Find the display label for the key
            for label, k in self._CONDITION_LABELS.items():
                if k == preset_key:
                    type_combo.setCurrentText(label)
                    break
            # Now set the value
            if preset_key in ('mobile', 'vpn', 'hosting') and isinstance(preset_value, bool):
                bool_combo_widget = value_stack.findChild(QComboBox)
                if bool_combo_widget is not None:  # pyright: ignore[reportUnnecessaryComparison]
                    idx = bool_combo_widget.findData(preset_value)
                    if idx >= 0:
                        bool_combo_widget.setCurrentIndex(idx)
            elif preset_key == 'event' and isinstance(preset_value, list):
                events_widget = value_stack.findChild(QWidget)
                if events_widget is not None:  # pyright: ignore[reportUnnecessaryComparison]
                    for cb in events_widget.findChildren(QCheckBox):
                        event_key = self._EVENT_LABELS.get(cb.text(), '')
                        cb.setChecked(event_key in preset_value)
            elif preset_key == 'country' and isinstance(preset_value, str):
                country_combo_widget = value_stack.findChild(QComboBox)
                if country_combo_widget is not None:  # pyright: ignore[reportUnnecessaryComparison]
                    # Find the matching country entry
                    for i in range(country_combo_widget.count()):
                        data = country_combo_widget.itemData(i, Qt.ItemDataRole.UserRole)
                        if data == preset_value:
                            country_combo_widget.setCurrentIndex(i)
                            break
            elif isinstance(preset_value, str):
                line_edit_widget = value_stack.findChild(QLineEdit)
                if line_edit_widget is not None:  # pyright: ignore[reportUnnecessaryComparison]
                    line_edit_widget.setText(preset_value)

    def _browse_process(self) -> None:
        """Open file dialog to select a process executable."""
        file_path, _ = QFileDialog.getOpenFileName(self, 'Select Process', '', 'Executables (*.exe);;All Files (*.*)')
        if file_path:
            self._process_edit.setText(file_path)

    def _validate_and_accept(self) -> None:
        """Validate rule data and accept dialog."""
        name = self._name_edit.text().strip()
        if not name:
            QMessageBox.warning(self, 'Validation Error', 'Rule name is required.')
            return

        conditions = self._read_conditions()
        if not conditions:
            QMessageBox.warning(self, 'Validation Error', 'At least one condition is required.')
            return

        # Require at least one IP condition if event condition is present
        has_event = 'event' in conditions
        has_ip = bool(conditions.keys() - {'event'})
        if has_event and not has_ip:
            QMessageBox.warning(self, 'Validation Error', 'Rules with an event condition must also have at least one IP-based condition.')
            return

        self.accept()

    def _read_conditions(self) -> dict[str, str | bool | list[str]]:
        """Read conditions from the UI rows."""
        conditions: dict[str, str | bool | list[str]] = {}
        for type_combo, value_stack in self._condition_rows:
            label = type_combo.currentText()
            key = self._CONDITION_LABELS.get(label)
            if key is None:
                continue

            if key in ('mobile', 'vpn', 'hosting'):
                bool_combo_widget = value_stack.findChild(QComboBox)
                if bool_combo_widget is not None:  # pyright: ignore[reportUnnecessaryComparison]
                    conditions[key] = bool(bool_combo_widget.currentData())
            elif key == 'event':
                selected = self._read_event_checkboxes(value_stack)
                if selected:
                    conditions[key] = selected
            elif key == 'country':
                country = self._read_country_value(value_stack)
                if country:
                    conditions[key] = country
            else:
                line_edit_widget = value_stack.findChild(QLineEdit)
                if line_edit_widget is not None:  # pyright: ignore[reportUnnecessaryComparison]
                    val = line_edit_widget.text().strip()
                    if val:
                        conditions[key] = val
        return conditions

    def _read_event_checkboxes(self, value_stack: QWidget) -> list[str]:
        """Read selected event checkboxes from a value stack widget."""
        events_widget = value_stack.findChild(QWidget)
        if events_widget is None:  # pyright: ignore[reportUnnecessaryComparison]
            return []
        selected: list[str] = []
        for cb in events_widget.findChildren(QCheckBox):
            if cb.isChecked():
                event_key = self._EVENT_LABELS.get(cb.text(), '')
                if event_key:
                    selected.append(event_key)
        return selected

    @staticmethod
    def _read_country_value(value_stack: QWidget) -> str | None:
        """Read the selected country name from a value stack widget."""
        country_combo_widget = value_stack.findChild(QComboBox)
        if country_combo_widget is None:  # pyright: ignore[reportUnnecessaryComparison]
            return None
        idx = country_combo_widget.currentIndex()
        if idx < 0:
            return None
        data = country_combo_widget.itemData(idx, Qt.ItemDataRole.UserRole)
        return data if isinstance(data, str) and data else None

    def get_rule(self) -> ComboRule:
        """Build a ComboRule from dialog state."""
        path_text = self._process_edit.text().strip()
        return ComboRule(
            name=self._name_edit.text().strip(),
            enabled=self._enabled_checkbox.isChecked(),
            conditions=self._read_conditions(),
            protection_enabled=self._protection_enabled_checkbox.isChecked(),
            process_path=Path(path_text) if path_text else None,
            duration=_read_duration_widgets_helper(self._duration_combo, self._duration_spin),
            voice_notifications=_read_voice_combo_helper(self._voice_combo),
            logging=self._logging_checkbox.isChecked(),
            message_box=self._msgbox_checkbox.isChecked(),
        )


class DetectionsManagerDialog(QDialog):  # pylint: disable=too-many-instance-attributes,too-few-public-methods
    """Comprehensive detections manager with VPN, IP range, and advanced threat detection capabilities."""

    def __init__(self, parent: QWidget) -> None:  # pylint: disable=too-many-statements
        """Initialize the Detections Manager dialog."""
        super().__init__(parent)
        self.setWindowTitle(f'{TITLE} - Detections Manager')
        self.setMinimumSize(720, 560)
        self.resize(800, 640)
        set_dialog_window_flags(self)

        # Widget references (populated by tab builders)
        # -- Network-based (mobile, vpn, hosting) --
        self.mobile_enable_checkbox: QCheckBox
        self.mobile_process_edit: QLineEdit
        self.mobile_duration_combo: QComboBox
        self.mobile_duration_spin: QSpinBox
        self.mobile_voice_combo: QComboBox
        self.mobile_logging_checkbox: QCheckBox
        self.mobile_msgbox_checkbox: QCheckBox
        self.vpn_enable_checkbox: QCheckBox
        self.vpn_process_edit: QLineEdit
        self.vpn_duration_combo: QComboBox
        self.vpn_duration_spin: QSpinBox
        self.vpn_voice_combo: QComboBox
        self.vpn_logging_checkbox: QCheckBox
        self.vpn_msgbox_checkbox: QCheckBox
        self.hosting_enable_checkbox: QCheckBox
        self.hosting_process_edit: QLineEdit
        self.hosting_duration_combo: QComboBox
        self.hosting_duration_spin: QSpinBox
        self.hosting_voice_combo: QComboBox
        self.hosting_logging_checkbox: QCheckBox
        self.hosting_msgbox_checkbox: QCheckBox
        # -- Geography-based (country, isp, asn) --
        self.country_enable_checkbox: QCheckBox
        self.country_list: QListWidget
        self.country_process_edit: QLineEdit
        self.country_duration_combo: QComboBox
        self.country_duration_spin: QSpinBox
        self.country_voice_combo: QComboBox
        self.country_logging_checkbox: QCheckBox
        self.country_msgbox_checkbox: QCheckBox
        self.isp_enable_checkbox: QCheckBox
        self.isp_list: QListWidget
        self.isp_process_edit: QLineEdit
        self.isp_duration_combo: QComboBox
        self.isp_duration_spin: QSpinBox
        self.isp_voice_combo: QComboBox
        self.isp_logging_checkbox: QCheckBox
        self.isp_msgbox_checkbox: QCheckBox
        self.asn_enable_checkbox: QCheckBox
        self.asn_list: QListWidget
        self.asn_process_edit: QLineEdit
        self.asn_duration_combo: QComboBox
        self.asn_duration_spin: QSpinBox
        self.asn_voice_combo: QComboBox
        self.asn_logging_checkbox: QCheckBox
        self.asn_msgbox_checkbox: QCheckBox
        # -- Player events (join, rejoin, leave) --
        self.player_join_enable_checkbox: QCheckBox
        self.player_join_process_edit: QLineEdit
        self.player_join_duration_combo: QComboBox
        self.player_join_duration_spin: QSpinBox
        self.player_join_voice_combo: QComboBox
        self.player_join_logging_checkbox: QCheckBox
        self.player_join_msgbox_checkbox: QCheckBox
        self.player_rejoin_enable_checkbox: QCheckBox
        self.player_rejoin_process_edit: QLineEdit
        self.player_rejoin_duration_combo: QComboBox
        self.player_rejoin_duration_spin: QSpinBox
        self.player_rejoin_voice_combo: QComboBox
        self.player_rejoin_logging_checkbox: QCheckBox
        self.player_rejoin_msgbox_checkbox: QCheckBox
        self.player_leave_enable_checkbox: QCheckBox
        self.player_leave_process_edit: QLineEdit
        self.player_leave_duration_combo: QComboBox
        self.player_leave_duration_spin: QSpinBox
        self.player_leave_voice_combo: QComboBox
        self.player_leave_logging_checkbox: QCheckBox
        self.player_leave_msgbox_checkbox: QCheckBox
        # -- GTA5 Relays (GTA5 preset only) --
        self.gta5_relay_enable_checkbox: QCheckBox
        self.gta5_relay_packet_threshold_spin: QSpinBox
        self.gta5_relay_process_edit: QLineEdit
        self.gta5_relay_duration_combo: QComboBox
        self.gta5_relay_duration_spin: QSpinBox
        self.gta5_relay_voice_combo: QComboBox
        self.gta5_relay_logging_checkbox: QCheckBox
        self.gta5_relay_msgbox_checkbox: QCheckBox
        # -- Combo rules --
        self._combo_rules_list: QListWidget

        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        # Header
        header = QLabel('\U0001f6e1\ufe0f Advanced Protection & Security Manager')
        header.setStyleSheet(
            'font-size: 16pt; font-weight: bold; color: #4A90E2; padding: 10px;'
            'background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #1e1e2e, stop:1 #2d2d4e);'
            'border-radius: 6px;',
        )
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(header)

        # Tabs
        tabs = QTabWidget()
        tabs.addTab(self._create_player_events_tab(), '\U0001f464 Player Events')
        tabs.addTab(self._create_network_based_tab(), '\U0001f310 Network-Based')
        tabs.addTab(self._create_geo_based_tab(), '\U0001f30d Geography-Based')
        tabs.addTab(self._create_combo_rules_tab(), '\U0001f517 Combo Rules')
        if Settings.capture_program_preset == 'GTA5':
            tabs.addTab(self._create_gta5_relays_tab(), '\U0001f3ae GTA5 Relays')
        layout.addWidget(tabs)

        # Bottom buttons
        button_row = QHBoxLayout()

        import_button = QPushButton('\U0001f4e5 Import')
        import_button.setToolTip('Import protection settings from a JSON file')
        import_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        import_button.clicked.connect(self._import_protections)  # pyright: ignore[reportUnknownMemberType]
        button_row.addWidget(import_button)

        export_button = QPushButton('\U0001f4e4 Export')
        export_button.setToolTip('Export protection settings to a JSON file')
        export_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        export_button.clicked.connect(self._export_protections)  # pyright: ignore[reportUnknownMemberType]
        button_row.addWidget(export_button)

        button_row.addStretch()

        save_button = QPushButton('\U0001f4be Save & Apply')
        save_button.setToolTip('Save all protection settings and apply them immediately')
        save_button.setStyleSheet(DIALOG_PRIMARY_BUTTON_STYLESHEET)
        save_button.setDefault(True)
        save_button.clicked.connect(self._save_and_apply)  # pyright: ignore[reportUnknownMemberType]
        button_row.addWidget(save_button)

        cancel_button = QPushButton('\u274c Cancel')
        cancel_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        cancel_button.clicked.connect(self.reject)  # pyright: ignore[reportUnknownMemberType]
        button_row.addWidget(cancel_button)

        layout.addLayout(button_row)

        self._load_current_settings()
        if Settings.capture_program_preset != 'GTA5' or CaptureState.is_arp_interface:
            self._apply_protection_restrictions()

    # ------------------------------------------------------------------
    # Protection support restrictions
    # ------------------------------------------------------------------

    def _apply_protection_restrictions(self) -> None:
        """Hide all protection action widgets when protection is not supported (non-GTA5 preset or ARP interface)."""
        for prefix in ('mobile', 'vpn', 'hosting', 'country', 'isp', 'asn', 'player_join', 'player_rejoin', 'player_leave', 'gta5_relay'):
            if not hasattr(self, f'{prefix}_enable_checkbox'):
                continue
            enable_section: QWidget = getattr(self, f'{prefix}_enable_section')
            enable_section.setVisible(False)

            enable_checkbox: QCheckBox = getattr(self, f'{prefix}_enable_checkbox')
            enable_checkbox.setChecked(True)

            action_section: QWidget = getattr(self, f'{prefix}_action_section')
            action_section.setVisible(False)
    # ------------------------------------------------------------------

    def _create_player_events_tab(self) -> QWidget:
        """Create the player events tab with full protection groups for join/rejoin/leave."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(15)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)
        scroll_layout.setSpacing(20)

        join_group = self._create_protection_group(
            '\u2795 Player Join Protection',
            'Configure actions and notifications when a player joins your session',
            'player_join',
        )
        scroll_layout.addWidget(join_group)

        rejoin_group = self._create_protection_group(
            '\U0001f504 Player Rejoin Protection',
            'Configure actions and notifications when a player rejoins your session after disconnecting',
            'player_rejoin',
        )
        scroll_layout.addWidget(rejoin_group)

        leave_group = self._create_protection_group(
            '\u274c Player Leave Protection',
            'Configure actions and notifications when a player leaves your session',
            'player_leave',
        )
        scroll_layout.addWidget(leave_group)

        scroll_layout.addStretch()
        scroll.setWidget(scroll_content)
        layout.addWidget(scroll)

        return widget

    def _create_network_based_tab(self) -> QWidget:
        """Create the network-based protections tab (VPN, Hosting, Mobile, IP Range)."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(15)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)
        scroll_layout.setSpacing(20)

        mobile_group = self._create_protection_group(
            '\U0001f4f1 Mobile Connection Protection',
            'Protect against mobile/cellular connections',
            'mobile',
        )
        scroll_layout.addWidget(mobile_group)

        vpn_group = self._create_protection_group(
            '\U0001f512 VPN/Proxy/Tor Protection',
            'Protect against connections from VPN, proxy, or Tor exit nodes',
            'vpn',
        )
        scroll_layout.addWidget(vpn_group)

        hosting_group = self._create_protection_group(
            '\U0001f3e2 Hosting/Data Center Protection',
            'Protect against connections from hosting providers and data centers',
            'hosting',
        )
        scroll_layout.addWidget(hosting_group)

        scroll_layout.addStretch()
        scroll.setWidget(scroll_content)
        layout.addWidget(scroll)

        return widget

    def _create_geo_based_tab(self) -> QWidget:
        """Create the geography-based protections tab (Country, ISP, ASN)."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(15)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)
        scroll_layout.setSpacing(20)

        country_group = self._create_blocklist_group(
            '\U0001f30d Country Blocklist',
            'Block or restrict players from specific countries',
            'country',
        )
        scroll_layout.addWidget(country_group)

        isp_group = self._create_blocklist_group(
            '\U0001f310 ISP/Company Blocklist',
            'Block specific ISPs or companies by name (e.g., Vodafone, Orange, Cloudflare)',
            'isp',
        )
        scroll_layout.addWidget(isp_group)

        asn_group = self._create_blocklist_group(
            '\U0001f522 ASN Number Blocklist',
            'Block specific ASN numbers (e.g., AS15169, AS13335, or just 15169, 13335)',
            'asn',
        )
        scroll_layout.addWidget(asn_group)

        scroll_layout.addStretch()
        scroll.setWidget(scroll_content)
        layout.addWidget(scroll)

        return widget

    def _create_gta5_relays_tab(self) -> QWidget:
        """Create the GTA5 Relays protection tab (only shown with the GTA5 preset)."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(15)

        desc = QLabel(
            'Automatically suspend GTA5 when a Take-Two relay IP exceeds the configured '
            'packet threshold while still connected. '
            'Relay IPs are identified by the GTAV Take-Two CIDR ranges '
            '(104.255.104.0/22, 185.56.64.0/22, 192.81.240.0/21).',
        )
        desc.setWordWrap(True)
        desc.setStyleSheet('color: #a0a0a0; font-style: italic; font-size: 10pt; padding: 5px;')
        layout.addWidget(desc)

        # Packet threshold row (tab-level setting, not part of the standard protection group)
        threshold_row = QWidget()
        threshold_layout = QHBoxLayout(threshold_row)
        threshold_layout.setContentsMargins(5, 0, 5, 0)
        threshold_label = QLabel('Packet Threshold:')
        threshold_label.setStyleSheet('font-weight: bold;')
        threshold_label.setToolTip('Suspend GTA5 once the relay IP has exchanged this many packets and is still connected.')
        threshold_layout.addWidget(threshold_label)
        threshold_spin = QSpinBox()
        threshold_spin.setRange(10, 10000)
        threshold_spin.setValue(40)
        threshold_spin.setSuffix(' packets')
        threshold_spin.setToolTip('Suspend GTA5 once the relay IP has exchanged this many packets and is still connected.')
        self.gta5_relay_packet_threshold_spin = threshold_spin
        threshold_layout.addWidget(threshold_spin)
        threshold_layout.addStretch()
        layout.addWidget(threshold_row)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)
        scroll_layout.setSpacing(20)

        relay_group = self._create_protection_group(
            '\U0001f6e1 GTA5 Relay Protection',
            'Suspend GTA5 when a relay IP exceeds the packet threshold and is still connected',
            'gta5_relay',
        )
        scroll_layout.addWidget(relay_group)

        scroll_layout.addStretch()
        scroll.setWidget(scroll_content)
        layout.addWidget(scroll)

        return widget

    def _create_combo_rules_tab(self) -> QWidget:
        """Create the combo rules tab with rule list and management buttons."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(15)

        desc = QLabel(
            'Combine multiple conditions into a single rule using AND logic. '
            'All conditions in a rule must match for it to trigger. '
            'Rules with an event condition require at least one IP-based condition.',
        )
        desc.setWordWrap(True)
        desc.setStyleSheet('color: #a0a0a0; font-style: italic; font-size: 10pt; padding: 5px;')
        layout.addWidget(desc)

        # Rule list
        self._combo_rules_list = QListWidget()
        self._combo_rules_list.setStyleSheet(_LIST_WIDGET_STYLE)
        self._combo_rules_list.setSelectionMode(QListWidget.SelectionMode.SingleSelection)
        layout.addWidget(self._combo_rules_list, stretch=1)

        # Buttons row
        btn_layout = QHBoxLayout()

        add_btn = QPushButton('\u2795 Add Rule')
        add_btn.clicked.connect(self._add_combo_rule)  # pyright: ignore[reportUnknownMemberType]
        btn_layout.addWidget(add_btn)

        self._combo_edit_btn = QPushButton('\u270f\ufe0f Edit')
        self._combo_edit_btn.setEnabled(False)
        self._combo_edit_btn.clicked.connect(self._edit_combo_rule)  # pyright: ignore[reportUnknownMemberType]
        btn_layout.addWidget(self._combo_edit_btn)

        self._combo_duplicate_btn = QPushButton('\U0001f4cb Duplicate')
        self._combo_duplicate_btn.setEnabled(False)
        self._combo_duplicate_btn.clicked.connect(self._duplicate_combo_rule)  # pyright: ignore[reportUnknownMemberType]
        btn_layout.addWidget(self._combo_duplicate_btn)

        self._combo_remove_btn = QPushButton('\u2796 Remove')
        self._combo_remove_btn.setEnabled(False)
        self._combo_remove_btn.clicked.connect(self._remove_combo_rule)  # pyright: ignore[reportUnknownMemberType]
        btn_layout.addWidget(self._combo_remove_btn)

        self._combo_clear_btn = QPushButton('\U0001f5d1\ufe0f Clear All')
        self._combo_clear_btn.setEnabled(False)
        self._combo_clear_btn.clicked.connect(self._clear_combo_rules)  # pyright: ignore[reportUnknownMemberType]
        btn_layout.addWidget(self._combo_clear_btn)

        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        self._combo_rules_list.currentRowChanged.connect(self._update_combo_rule_buttons)  # pyright: ignore[reportUnknownMemberType]

        return widget

    def _update_combo_rule_buttons(self) -> None:
        """Enable or disable combo rule action buttons based on list state."""
        has_selection = self._combo_rules_list.currentRow() >= 0
        has_items = self._combo_rules_list.count() > 0
        self._combo_edit_btn.setEnabled(has_selection)
        self._combo_duplicate_btn.setEnabled(has_selection)
        self._combo_remove_btn.setEnabled(has_selection)
        self._combo_clear_btn.setEnabled(has_items)

    def _refresh_combo_rules_list(self) -> None:
        """Reload the combo rules QListWidget from ComboRulesManager."""
        self._combo_rules_list.clear()
        for rule in ComboRulesManager.rules:
            conditions_summary = ', '.join(
                f'{k}={v}' if not isinstance(v, bool) else k for k, v in rule.conditions.items()
            )
            status = '\u2705' if rule.enabled else '\u274c'
            item = QListWidgetItem(f'{status} {rule.name}  [{conditions_summary}]')
            item.setData(Qt.ItemDataRole.UserRole, id(rule))
            self._combo_rules_list.addItem(item)  # pyright: ignore[reportUnknownMemberType]
        self._update_combo_rule_buttons()

    def _get_selected_combo_rule_index(self) -> int | None:
        """Return the index of the selected combo rule, or None."""
        current = self._combo_rules_list.currentRow()
        if current < 0 or current >= len(ComboRulesManager.rules):
            return None
        return current

    def _add_combo_rule(self) -> None:
        """Open editor dialog to create a new combo rule."""
        dialog = _ComboRuleEditorDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            ComboRulesManager.rules.append(dialog.get_rule())
            self._refresh_combo_rules_list()

    def _edit_combo_rule(self) -> None:
        """Open editor dialog to edit the selected combo rule."""
        idx = self._get_selected_combo_rule_index()
        if idx is None:
            QMessageBox.information(self, TITLE, 'Select a rule to edit.')
            return
        existing_rule = ComboRulesManager.rules[idx]
        dialog = _ComboRuleEditorDialog(self, rule=existing_rule)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            ComboRulesManager.rules[idx] = dialog.get_rule()
            self._refresh_combo_rules_list()

    def _duplicate_combo_rule(self) -> None:
        """Duplicate the selected combo rule."""
        idx = self._get_selected_combo_rule_index()
        if idx is None:
            QMessageBox.information(self, TITLE, 'Select a rule to duplicate.')
            return
        original = ComboRulesManager.rules[idx]
        copy = ComboRule(
            name=f'{original.name} (Copy)',
            enabled=original.enabled,
            conditions=dict(original.conditions),
            process_path=original.process_path,
            duration=original.duration,
            voice_notifications=original.voice_notifications,
            logging=original.logging,
            message_box=original.message_box,
        )
        ComboRulesManager.rules.append(copy)
        self._refresh_combo_rules_list()

    def _remove_combo_rule(self) -> None:
        """Remove the selected combo rule."""
        idx = self._get_selected_combo_rule_index()
        if idx is None:
            QMessageBox.information(self, TITLE, 'Select a rule to remove.')
            return
        rule = ComboRulesManager.rules[idx]
        reply = QMessageBox.question(
            self, TITLE, f'Remove rule "{rule.name}"?',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            del ComboRulesManager.rules[idx]
            self._refresh_combo_rules_list()

    def _clear_combo_rules(self) -> None:
        """Remove all combo rules."""
        if not ComboRulesManager.rules:
            return
        reply = QMessageBox.question(
            self, TITLE, 'Remove all combo rules?',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            ComboRulesManager.rules.clear()
            self._refresh_combo_rules_list()

    # ------------------------------------------------------------------
    # Group factories
    # ------------------------------------------------------------------

    def _create_protection_group(self, title: str, description: str, protection_type: str) -> QGroupBox:
        """Create a standard protection group with enable, action, process path, duration, and notification settings."""
        group = QGroupBox(title)
        group.setStyleSheet(_GROUPBOX_STYLE)
        group_layout = QVBoxLayout()

        desc_label = QLabel(description)
        desc_label.setWordWrap(True)
        desc_label.setStyleSheet('color: #a0a0a0; font-style: italic; font-size: 10pt; padding: 5px;')
        group_layout.addWidget(desc_label)

        # Enable checkbox (hideable for ARP interface)
        enable_section = QWidget()
        enable_section_layout = QHBoxLayout(enable_section)
        enable_section_layout.setContentsMargins(0, 0, 0, 0)
        setattr(self, f'{protection_type}_enable_section', enable_section)

        enable_label = QLabel('Enable Protection:')
        enable_label.setStyleSheet('font-weight: bold;')
        enable_section_layout.addWidget(enable_label)

        enable_checkbox = QCheckBox()
        enable_checkbox.setToolTip(
            'When enabled, suspends the game process upon detection,'
            ' effectively placing you into a solo public session and keeping you safe from the threat.',
        )
        setattr(self, f'{protection_type}_enable_checkbox', enable_checkbox)
        enable_section_layout.addWidget(enable_checkbox)
        enable_section_layout.addStretch()

        # -- Action section container (hideable when protection is not supported) --
        action_section = QWidget()
        action_section_layout = QVBoxLayout(action_section)
        action_section_layout.setContentsMargins(0, 0, 0, 0)
        setattr(self, f'{protection_type}_action_section', action_section)

        protection_separator = QLabel('\u2500\u2500\u2500 Protection Settings \u2500\u2500\u2500')
        protection_separator.setStyleSheet('color: #666; font-size: 9pt; padding: 5px 0;')
        protection_separator.setAlignment(Qt.AlignmentFlag.AlignCenter)
        action_section_layout.addWidget(protection_separator)
        action_section_layout.addWidget(enable_section)

        # Process path
        process_layout = QHBoxLayout()
        process_label = QLabel('Process Path:')
        process_layout.addWidget(process_label)

        process_edit = QLineEdit()
        process_edit.setPlaceholderText('e.g., C:\\Program Files\\Game\\game.exe')
        process_edit.setToolTip('Full path to the process executable (required for Suspend actions)')
        setattr(self, f'{protection_type}_process_edit', process_edit)
        process_layout.addWidget(process_edit)

        browse_button = QPushButton('\U0001f4c1 Browse')
        browse_button.setMaximumWidth(100)
        browse_button.clicked.connect(lambda: self._browse_process(process_edit))  # pyright: ignore[reportUnknownMemberType]
        process_layout.addWidget(browse_button)
        action_section_layout.addLayout(process_layout)

        # Suspend duration
        duration_layout = QHBoxLayout()
        duration_label = QLabel('Suspend Mode:')
        duration_layout.addWidget(duration_label)

        duration_combo = QComboBox()
        duration_combo.addItems(['Auto', 'Manual', 'Adaptive', 'Custom (seconds)'])  # pyright: ignore[reportUnknownMemberType]
        duration_combo.setItemData(0, SUSPEND_TOOLTIP_AUTO, Qt.ItemDataRole.ToolTipRole)
        duration_combo.setItemData(1, SUSPEND_TOOLTIP_MANUAL, Qt.ItemDataRole.ToolTipRole)
        duration_combo.setItemData(2, SUSPEND_TOOLTIP_ADAPTIVE, Qt.ItemDataRole.ToolTipRole)
        duration_combo.setItemData(3, SUSPEND_TOOLTIP_CUSTOM, Qt.ItemDataRole.ToolTipRole)
        setattr(self, f'{protection_type}_duration_combo', duration_combo)
        duration_layout.addWidget(duration_combo)

        duration_spin = QSpinBox()
        duration_spin.setRange(1, 3600)
        duration_spin.setValue(60)
        duration_spin.setSuffix(' seconds')
        duration_spin.setEnabled(False)
        duration_combo.currentTextChanged.connect(  # pyright: ignore[reportUnknownMemberType]
            lambda text: duration_spin.setEnabled(text == 'Custom (seconds)'),  # pyright: ignore[reportUnknownLambdaType, reportUnknownArgumentType]
        )
        setattr(self, f'{protection_type}_duration_spin', duration_spin)
        duration_layout.addWidget(duration_spin)

        duration_layout.addStretch()
        action_section_layout.addLayout(duration_layout)

        group_layout.addWidget(action_section)

        # Notification controls
        self._create_notification_controls(group_layout, protection_type)

        group.setLayout(group_layout)
        return group

    def _create_blocklist_group(self, title: str, description: str, blocklist_type: str) -> QGroupBox:
        """Create a blocklist group with enable, list, action, process path, and notification settings."""
        group = QGroupBox(title)
        group.setStyleSheet(_GROUPBOX_STYLE)
        group_layout = QVBoxLayout()

        desc_label = QLabel(description)
        desc_label.setWordWrap(True)
        desc_label.setStyleSheet('color: #a0a0a0; font-style: italic; font-size: 10pt; padding: 5px;')
        group_layout.addWidget(desc_label)

        # Enable checkbox (hideable for ARP interface)
        enable_section = QWidget()
        enable_section_layout = QHBoxLayout(enable_section)
        enable_section_layout.setContentsMargins(0, 0, 0, 0)
        setattr(self, f'{blocklist_type}_enable_section', enable_section)

        enable_label = QLabel('Enable Protection:')
        enable_label.setStyleSheet('font-weight: bold;')
        enable_section_layout.addWidget(enable_label)

        enable_checkbox = QCheckBox()
        setattr(self, f'{blocklist_type}_enable_checkbox', enable_checkbox)
        enable_section_layout.addWidget(enable_checkbox)
        enable_section_layout.addStretch()

        # List widget
        list_layout = QHBoxLayout()

        list_widget = QListWidget()
        list_widget.setStyleSheet(_LIST_WIDGET_STYLE)
        setattr(self, f'{blocklist_type}_list', list_widget)
        list_layout.addWidget(list_widget)

        buttons_layout = QVBoxLayout()
        add_button = QPushButton('\u2795 Add')
        add_callback = getattr(self, f'_add_{blocklist_type}')
        add_button.clicked.connect(add_callback)  # pyright: ignore[reportUnknownMemberType]
        buttons_layout.addWidget(add_button)

        remove_button = QPushButton('\u2796 Remove')
        remove_callback = getattr(self, f'_remove_{blocklist_type}')
        remove_button.clicked.connect(remove_callback)  # pyright: ignore[reportUnknownMemberType]
        buttons_layout.addWidget(remove_button)

        clear_button = QPushButton('\U0001f5d1\ufe0f Clear All')
        clear_button.clicked.connect(list_widget.clear)  # pyright: ignore[reportUnknownMemberType]
        buttons_layout.addWidget(clear_button)

        buttons_layout.addStretch()
        list_layout.addLayout(buttons_layout)
        group_layout.addLayout(list_layout)

        # -- Action section container (hideable when protection is not supported) --
        action_section = QWidget()
        action_section_layout = QVBoxLayout(action_section)
        action_section_layout.setContentsMargins(0, 0, 0, 0)
        setattr(self, f'{blocklist_type}_action_section', action_section)

        protection_separator = QLabel('\u2500\u2500\u2500 Protection Settings \u2500\u2500\u2500')
        protection_separator.setStyleSheet('color: #666; font-size: 9pt; padding: 5px 0;')
        protection_separator.setAlignment(Qt.AlignmentFlag.AlignCenter)
        action_section_layout.addWidget(protection_separator)
        action_section_layout.addWidget(enable_section)

        # Process path
        process_layout = QHBoxLayout()
        process_label = QLabel('Process Path:')
        process_layout.addWidget(process_label)

        process_edit = QLineEdit()
        process_edit.setPlaceholderText('Required for Suspend actions')
        setattr(self, f'{blocklist_type}_process_edit', process_edit)
        process_layout.addWidget(process_edit)

        browse_button = QPushButton('\U0001f4c1 Browse')
        browse_button.setMaximumWidth(100)
        browse_button.clicked.connect(lambda: self._browse_process(process_edit))  # pyright: ignore[reportUnknownMemberType]
        process_layout.addWidget(browse_button)
        action_section_layout.addLayout(process_layout)

        # Suspend duration
        duration_layout = QHBoxLayout()
        duration_label = QLabel('Suspend Mode:')
        duration_layout.addWidget(duration_label)

        duration_combo = QComboBox()
        duration_combo.addItems(['Auto', 'Manual', 'Adaptive', 'Custom (seconds)'])  # pyright: ignore[reportUnknownMemberType]
        duration_combo.setItemData(0, SUSPEND_TOOLTIP_AUTO, Qt.ItemDataRole.ToolTipRole)
        duration_combo.setItemData(1, SUSPEND_TOOLTIP_MANUAL, Qt.ItemDataRole.ToolTipRole)
        duration_combo.setItemData(2, SUSPEND_TOOLTIP_ADAPTIVE, Qt.ItemDataRole.ToolTipRole)
        duration_combo.setItemData(3, SUSPEND_TOOLTIP_CUSTOM, Qt.ItemDataRole.ToolTipRole)
        setattr(self, f'{blocklist_type}_duration_combo', duration_combo)
        duration_layout.addWidget(duration_combo)

        duration_spin = QSpinBox()
        duration_spin.setRange(1, 3600)
        duration_spin.setValue(60)
        duration_spin.setSuffix(' seconds')
        duration_spin.setEnabled(False)
        duration_combo.currentTextChanged.connect(  # pyright: ignore[reportUnknownMemberType]
            lambda text: duration_spin.setEnabled(text == 'Custom (seconds)'),  # pyright: ignore[reportUnknownLambdaType, reportUnknownArgumentType]
        )
        setattr(self, f'{blocklist_type}_duration_spin', duration_spin)
        duration_layout.addWidget(duration_spin)

        duration_layout.addStretch()
        action_section_layout.addLayout(duration_layout)

        group_layout.addWidget(action_section)

        # Notification controls
        self._create_notification_controls(group_layout, blocklist_type)

        group.setLayout(group_layout)
        return group

    def _create_notification_controls(self, parent_layout: QVBoxLayout, prefix: str) -> None:
        """Add voice notification, logging, and message box controls to a group layout."""
        separator = QLabel('\u2500\u2500\u2500 Notification Settings \u2500\u2500\u2500')
        separator.setStyleSheet('color: #666; font-size: 9pt; padding: 5px 0;')
        separator.setAlignment(Qt.AlignmentFlag.AlignCenter)
        parent_layout.addWidget(separator)

        voice_layout = QHBoxLayout()
        voice_label = QLabel('Voice Notifications:')
        voice_layout.addWidget(voice_label)

        voice_combo = QComboBox()
        voice_combo.addItems(['Disabled', 'Male', 'Female'])  # pyright: ignore[reportUnknownMemberType]
        voice_combo.setToolTip('Select voice for text-to-speech notifications')
        setattr(self, f'{prefix}_voice_combo', voice_combo)
        voice_layout.addWidget(voice_combo)
        voice_layout.addStretch()
        parent_layout.addLayout(voice_layout)

        msgbox_checkbox = QCheckBox('Show Message Box')
        msgbox_checkbox.setToolTip('Show a message box popup when this protection triggers')
        setattr(self, f'{prefix}_msgbox_checkbox', msgbox_checkbox)
        parent_layout.addWidget(msgbox_checkbox)

        logging_checkbox = QCheckBox('Detection Logging')
        logging_checkbox.setToolTip('Log detection events to the detection logging file')
        setattr(self, f'{prefix}_logging_checkbox', logging_checkbox)
        parent_layout.addWidget(logging_checkbox)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _browse_process(line_edit: QLineEdit) -> None:
        """Open file browser to select a process executable."""
        file_path, _ = QFileDialog.getOpenFileName(
            None,
            'Select Process Executable',
            '',
            'Executables (*.exe);;All Files (*.*)',
        )
        if file_path:
            line_edit.setText(file_path)

    @staticmethod
    def _list_contains(list_widget: QListWidget, value: str) -> bool:
        """Return True if *value* already exists in the QListWidget (case-insensitive)."""
        for i in range(list_widget.count()):
            item = list_widget.item(i)
            if item is not None and item.text().casefold() == value.casefold():
                return True
        return False

    def _add_country(self) -> None:
        """Add a country via a searchable selection dialog."""
        existing_countries: set[str] = set()
        for i in range(self.country_list.count()):
            item = self.country_list.item(i)
            if item is not None:
                country = item.data(Qt.ItemDataRole.UserRole)
                if isinstance(country, str):
                    existing_countries.add(country)

        dialog = _CountrySelectionDialog(self, existing_countries)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            country = dialog.selected_country()
            if country:
                self._add_country_item(country)

    def _add_country_item(self, country_name: str) -> None:
        """Add a country list item with an icon and display name."""
        item = QListWidgetItem(country_name)
        item.setData(Qt.ItemDataRole.UserRole, country_name)
        flag_code = get_country_flag_code(country_name)
        if flag_code and flag_code in _AVAILABLE_FLAG_CODES:
            item.setIcon(QIcon(QPixmap(str(_COUNTRY_FLAGS_DIR / f'{flag_code}.png'))))
        self.country_list.addItem(item)  # pyright: ignore[reportUnknownMemberType]

    def _remove_country(self) -> None:
        """Remove selected country from the list."""
        current_item = self.country_list.currentItem()
        if current_item:
            self.country_list.takeItem(self.country_list.row(current_item))  # pyright: ignore[reportUnknownMemberType]

    def _add_isp(self) -> None:
        """Add an ISP/company name to the list."""
        text, ok = QInputDialog.getText(
            self,
            'Add ISP/Company',
            'Enter ISP or company name:\nExamples: Vodafone, Orange, Cloudflare',
        )
        if ok and text:
            stripped = text.strip()
            if stripped and not self._list_contains(self.isp_list, stripped):
                self.isp_list.addItem(stripped)  # pyright: ignore[reportUnknownMemberType]

    def _remove_isp(self) -> None:
        """Remove selected ISP from the list."""
        current_item = self.isp_list.currentItem()
        if current_item:
            self.isp_list.takeItem(self.isp_list.row(current_item))  # pyright: ignore[reportUnknownMemberType]

    def _add_asn(self) -> None:
        """Add an ASN to the list."""
        text, ok = QInputDialog.getText(
            self,
            'Add ASN',
            'Enter ASN (with or without AS prefix):\nExamples: AS13335, 15169',
        )
        if ok and text:
            asn = text.strip().upper()
            if not asn.startswith('AS'):
                asn = f'AS{asn}'
            if not self._list_contains(self.asn_list, asn):
                self.asn_list.addItem(asn)  # pyright: ignore[reportUnknownMemberType]

    def _remove_asn(self) -> None:
        """Remove selected ASN from the list."""
        current_item = self.asn_list.currentItem()
        if current_item:
            self.asn_list.takeItem(self.asn_list.row(current_item))  # pyright: ignore[reportUnknownMemberType]

    # ------------------------------------------------------------------
    # Duration & voice helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _set_duration_widgets(combo: QComboBox, spin: QSpinBox, duration: int | str) -> None:
        """Set duration combo and spin box from a stored duration value."""
        if isinstance(duration, int):
            combo.setCurrentText('Custom (seconds)')
            spin.setValue(int(duration))
            spin.setEnabled(True)
        elif duration == 'Manual':
            combo.setCurrentText('Manual')
        elif duration == 'Adaptive':
            combo.setCurrentText('Adaptive')
        else:
            combo.setCurrentText('Auto')

    @staticmethod
    def _read_duration_widgets(combo: QComboBox, spin: QSpinBox) -> int | Literal['Auto', 'Manual', 'Adaptive']:
        """Read duration value from combo and spin box widgets."""
        text = combo.currentText()
        if text == 'Custom (seconds)':
            return spin.value()
        if text == 'Manual':
            return 'Manual'
        if text == 'Adaptive':
            return 'Adaptive'
        return 'Auto'

    @staticmethod
    def _set_voice_combo(combo: QComboBox, value: Literal['Male', 'Female'] | bool) -> None:  # noqa: FBT001
        """Set voice combo from a stored voice notification value."""
        if value == 'Male':
            combo.setCurrentText('Male')
        elif value == 'Female':
            combo.setCurrentText('Female')
        else:
            combo.setCurrentText('Disabled')

    @staticmethod
    def _read_voice_combo(combo: QComboBox) -> Literal['Male', 'Female'] | bool:
        """Read voice notification value from a combo widget."""
        text = combo.currentText()
        if text == 'Male':
            return 'Male'
        if text == 'Female':
            return 'Female'
        return False

    # ------------------------------------------------------------------
    # Settings load / save
    # ------------------------------------------------------------------

    def _load_current_settings(self) -> None:  # pylint: disable=too-many-statements
        """Read GUIProtectionSettings and populate all widgets."""
        # Mobile
        self.mobile_enable_checkbox.setChecked(GUIProtectionSettings.mobile_suspend_enabled)
        self.mobile_process_edit.setText(str(GUIProtectionSettings.mobile_suspend_process_path) if GUIProtectionSettings.mobile_suspend_process_path else '')
        self._set_duration_widgets(self.mobile_duration_combo, self.mobile_duration_spin, GUIProtectionSettings.mobile_suspend_duration)
        self._set_voice_combo(self.mobile_voice_combo, GUIProtectionSettings.mobile_voice_notifications)
        self.mobile_logging_checkbox.setChecked(GUIProtectionSettings.mobile_logging)
        self.mobile_msgbox_checkbox.setChecked(GUIProtectionSettings.mobile_message_box)

        # VPN
        self.vpn_enable_checkbox.setChecked(GUIProtectionSettings.vpn_suspend_enabled)
        self.vpn_process_edit.setText(str(GUIProtectionSettings.vpn_suspend_process_path) if GUIProtectionSettings.vpn_suspend_process_path else '')
        self._set_duration_widgets(self.vpn_duration_combo, self.vpn_duration_spin, GUIProtectionSettings.vpn_suspend_duration)
        self._set_voice_combo(self.vpn_voice_combo, GUIProtectionSettings.vpn_voice_notifications)
        self.vpn_logging_checkbox.setChecked(GUIProtectionSettings.vpn_logging)
        self.vpn_msgbox_checkbox.setChecked(GUIProtectionSettings.vpn_message_box)

        # Hosting
        self.hosting_enable_checkbox.setChecked(GUIProtectionSettings.hosting_suspend_enabled)
        self.hosting_process_edit.setText(str(GUIProtectionSettings.hosting_suspend_process_path) if GUIProtectionSettings.hosting_suspend_process_path else '')
        self._set_duration_widgets(self.hosting_duration_combo, self.hosting_duration_spin, GUIProtectionSettings.hosting_suspend_duration)
        self._set_voice_combo(self.hosting_voice_combo, GUIProtectionSettings.hosting_voice_notifications)
        self.hosting_logging_checkbox.setChecked(GUIProtectionSettings.hosting_logging)
        self.hosting_msgbox_checkbox.setChecked(GUIProtectionSettings.hosting_message_box)

        # Country
        self.country_enable_checkbox.setChecked(GUIProtectionSettings.country_block_enabled)
        self.country_list.clear()
        seen_countries: set[str] = set()
        for c in GUIProtectionSettings.country_block_list:
            if c not in seen_countries:
                seen_countries.add(c)
                self._add_country_item(c)
        self.country_process_edit.setText(str(GUIProtectionSettings.country_block_process_path) if GUIProtectionSettings.country_block_process_path else '')
        self._set_duration_widgets(self.country_duration_combo, self.country_duration_spin, GUIProtectionSettings.country_block_duration)
        self._set_voice_combo(self.country_voice_combo, GUIProtectionSettings.country_voice_notifications)
        self.country_logging_checkbox.setChecked(GUIProtectionSettings.country_logging)
        self.country_msgbox_checkbox.setChecked(GUIProtectionSettings.country_message_box)

        # ISP
        self.isp_enable_checkbox.setChecked(GUIProtectionSettings.isp_block_enabled)
        self.isp_list.clear()
        seen_isps: set[str] = set()
        for i in GUIProtectionSettings.isp_block_list:
            if i not in seen_isps:
                seen_isps.add(i)
                self.isp_list.addItem(i)  # pyright: ignore[reportUnknownMemberType]
        self.isp_process_edit.setText(str(GUIProtectionSettings.isp_block_process_path) if GUIProtectionSettings.isp_block_process_path else '')
        self._set_duration_widgets(self.isp_duration_combo, self.isp_duration_spin, GUIProtectionSettings.isp_block_duration)
        self._set_voice_combo(self.isp_voice_combo, GUIProtectionSettings.isp_voice_notifications)
        self.isp_logging_checkbox.setChecked(GUIProtectionSettings.isp_logging)
        self.isp_msgbox_checkbox.setChecked(GUIProtectionSettings.isp_message_box)

        # ASN
        self.asn_enable_checkbox.setChecked(GUIProtectionSettings.asn_block_enabled)
        self.asn_list.clear()
        seen_asns: set[str] = set()
        for a in GUIProtectionSettings.asn_block_list:
            if a not in seen_asns:
                seen_asns.add(a)
                self.asn_list.addItem(a)  # pyright: ignore[reportUnknownMemberType]
        self.asn_process_edit.setText(str(GUIProtectionSettings.asn_block_process_path) if GUIProtectionSettings.asn_block_process_path else '')
        self._set_duration_widgets(self.asn_duration_combo, self.asn_duration_spin, GUIProtectionSettings.asn_block_duration)
        self._set_voice_combo(self.asn_voice_combo, GUIProtectionSettings.asn_voice_notifications)
        self.asn_logging_checkbox.setChecked(GUIProtectionSettings.asn_logging)
        self.asn_msgbox_checkbox.setChecked(GUIProtectionSettings.asn_message_box)

        # Player Join
        self.player_join_enable_checkbox.setChecked(GUIProtectionSettings.player_join_enabled)
        self.player_join_process_edit.setText(str(GUIProtectionSettings.player_join_process_path) if GUIProtectionSettings.player_join_process_path else '')
        self._set_duration_widgets(self.player_join_duration_combo, self.player_join_duration_spin, GUIProtectionSettings.player_join_duration)
        self._set_voice_combo(self.player_join_voice_combo, GUIProtectionSettings.player_join_voice_notifications)
        self.player_join_logging_checkbox.setChecked(GUIProtectionSettings.player_join_logging)
        self.player_join_msgbox_checkbox.setChecked(GUIProtectionSettings.player_join_message_box)

        # Player Rejoin
        self.player_rejoin_enable_checkbox.setChecked(GUIProtectionSettings.player_rejoin_enabled)
        self.player_rejoin_process_edit.setText(str(GUIProtectionSettings.player_rejoin_process_path) if GUIProtectionSettings.player_rejoin_process_path else '')
        self._set_duration_widgets(self.player_rejoin_duration_combo, self.player_rejoin_duration_spin, GUIProtectionSettings.player_rejoin_duration)
        self._set_voice_combo(self.player_rejoin_voice_combo, GUIProtectionSettings.player_rejoin_voice_notifications)
        self.player_rejoin_logging_checkbox.setChecked(GUIProtectionSettings.player_rejoin_logging)
        self.player_rejoin_msgbox_checkbox.setChecked(GUIProtectionSettings.player_rejoin_message_box)

        # Player Leave
        self.player_leave_enable_checkbox.setChecked(GUIProtectionSettings.player_leave_enabled)
        self.player_leave_process_edit.setText(str(GUIProtectionSettings.player_leave_process_path) if GUIProtectionSettings.player_leave_process_path else '')
        self._set_duration_widgets(self.player_leave_duration_combo, self.player_leave_duration_spin, GUIProtectionSettings.player_leave_duration)
        self._set_voice_combo(self.player_leave_voice_combo, GUIProtectionSettings.player_leave_voice_notifications)
        self.player_leave_logging_checkbox.setChecked(GUIProtectionSettings.player_leave_logging)
        self.player_leave_msgbox_checkbox.setChecked(GUIProtectionSettings.player_leave_message_box)

        # GTA5 Relay (only when the tab is present)
        if hasattr(self, 'gta5_relay_enable_checkbox'):
            self.gta5_relay_enable_checkbox.setChecked(GUIProtectionSettings.gta5_relay_enabled)
            self.gta5_relay_packet_threshold_spin.setValue(GUIProtectionSettings.gta5_relay_packet_threshold)
            self.gta5_relay_process_edit.setText(str(GUIProtectionSettings.gta5_relay_process_path) if GUIProtectionSettings.gta5_relay_process_path else '')
            self._set_duration_widgets(self.gta5_relay_duration_combo, self.gta5_relay_duration_spin, GUIProtectionSettings.gta5_relay_duration)
            self._set_voice_combo(self.gta5_relay_voice_combo, GUIProtectionSettings.gta5_relay_voice_notifications)
            self.gta5_relay_logging_checkbox.setChecked(GUIProtectionSettings.gta5_relay_logging)
            self.gta5_relay_msgbox_checkbox.setChecked(GUIProtectionSettings.gta5_relay_message_box)

        # Combo Rules
        self._refresh_combo_rules_list()

    def _save_and_apply(self) -> None:
        """Read widgets, write GUIProtectionSettings, persist to Settings.ini, and close."""
        # Clear voice queue if any protection was newly disabled
        enabled_fields = [
            'mobile_suspend_enabled', 'vpn_suspend_enabled', 'hosting_suspend_enabled',
            'country_block_enabled', 'isp_block_enabled',
            'asn_block_enabled', 'player_join_enabled', 'player_rejoin_enabled', 'player_leave_enabled',
            'gta5_relay_enabled',
        ]
        checkbox_prefixes = [
            'mobile', 'vpn', 'hosting', 'country', 'isp', 'asn',
            'player_join', 'player_rejoin', 'player_leave',
            'gta5_relay',
        ]
        for field, prefix in zip(enabled_fields, checkbox_prefixes, strict=True):
            if not hasattr(self, f'{prefix}_enable_checkbox'):
                continue
            checkbox: QCheckBox = getattr(self, f'{prefix}_enable_checkbox')
            if not checkbox.isChecked() and getattr(GUIProtectionSettings, field):
                clear_voice_notification_queue()
                break

        self._save_widgets_to_singleton()

        GUIProtectionSettings.export_to_file(PROTECTIONS_JSON_PATH)
        ComboRulesManager.save_to_file(COMBO_RULES_PATH)
        QMessageBox.information(self, TITLE, 'Protection settings saved and applied successfully.')
        self.close()

    def _export_protections(self) -> None:
        """Export current protection settings (including combo rules) to a JSON file."""
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            'Export Protection Settings',
            'protections.json',
            'JSON Files (*.json);;All Files (*.*)',
        )
        if file_path:
            # Save current widget state to GUIProtectionSettings first
            self._save_widgets_to_singleton()
            # Build combined export: standard protections + combo rules
            # First export standard protections to a temp path, read back, then add combo rules
            target = Path(file_path)
            GUIProtectionSettings.export_to_file(target)
            data = json.loads(target.read_text(encoding='utf-8'))
            data['combo_rules'] = [r.to_dict() for r in ComboRulesManager.rules]
            target.write_text(json.dumps(data, indent=4), encoding='utf-8')
            QMessageBox.information(self, TITLE, 'Protection settings exported successfully.')

    def _import_protections(self) -> None:
        """Import protection settings (including combo rules) from a JSON file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            'Import Protection Settings',
            '',
            'JSON Files (*.json);;All Files (*.*)',
        )
        if file_path:
            try:
                raw = json.loads(Path(file_path).read_text(encoding='utf-8'))
                GUIProtectionSettings.import_from_file(Path(file_path))
                # Import combo rules if present
                if isinstance(raw, dict) and 'combo_rules' in raw:
                    combo_data: object = raw['combo_rules']  # pyright: ignore[reportUnknownVariableType]
                    if isinstance(combo_data, list):
                        ComboRulesManager.rules = [
                            ComboRule.from_dict(entry)  # pyright: ignore[reportUnknownArgumentType]
                            for entry in combo_data  # pyright: ignore[reportUnknownVariableType]
                            if isinstance(entry, dict)
                        ]
            except (ValueError, KeyError, OSError, json.JSONDecodeError) as e:
                QMessageBox.critical(self, 'Import Error', f'Failed to import settings:\n{e}')
                return
            self._load_current_settings()
            QMessageBox.information(self, TITLE, 'Protection settings imported successfully.')

    def _save_widgets_to_singleton(self) -> None:  # pylint: disable=too-many-statements
        """Write current widget state to GUIProtectionSettings without persisting to disk."""
        # Mobile
        GUIProtectionSettings.mobile_suspend_enabled = self.mobile_enable_checkbox.isChecked()
        path_text = self.mobile_process_edit.text().strip()
        GUIProtectionSettings.mobile_suspend_process_path = Path(path_text) if path_text else None
        GUIProtectionSettings.mobile_suspend_duration = self._read_duration_widgets(self.mobile_duration_combo, self.mobile_duration_spin)
        GUIProtectionSettings.mobile_voice_notifications = self._read_voice_combo(self.mobile_voice_combo)
        GUIProtectionSettings.mobile_logging = self.mobile_logging_checkbox.isChecked()
        GUIProtectionSettings.mobile_message_box = self.mobile_msgbox_checkbox.isChecked()

        # VPN
        GUIProtectionSettings.vpn_suspend_enabled = self.vpn_enable_checkbox.isChecked()
        path_text = self.vpn_process_edit.text().strip()
        GUIProtectionSettings.vpn_suspend_process_path = Path(path_text) if path_text else None
        GUIProtectionSettings.vpn_suspend_duration = self._read_duration_widgets(self.vpn_duration_combo, self.vpn_duration_spin)
        GUIProtectionSettings.vpn_voice_notifications = self._read_voice_combo(self.vpn_voice_combo)
        GUIProtectionSettings.vpn_logging = self.vpn_logging_checkbox.isChecked()
        GUIProtectionSettings.vpn_message_box = self.vpn_msgbox_checkbox.isChecked()

        # Hosting
        GUIProtectionSettings.hosting_suspend_enabled = self.hosting_enable_checkbox.isChecked()
        path_text = self.hosting_process_edit.text().strip()
        GUIProtectionSettings.hosting_suspend_process_path = Path(path_text) if path_text else None
        GUIProtectionSettings.hosting_suspend_duration = self._read_duration_widgets(self.hosting_duration_combo, self.hosting_duration_spin)
        GUIProtectionSettings.hosting_voice_notifications = self._read_voice_combo(self.hosting_voice_combo)
        GUIProtectionSettings.hosting_logging = self.hosting_logging_checkbox.isChecked()
        GUIProtectionSettings.hosting_message_box = self.hosting_msgbox_checkbox.isChecked()

        # Country
        GUIProtectionSettings.country_block_enabled = self.country_enable_checkbox.isChecked()
        GUIProtectionSettings.country_block_list = [
            item.data(Qt.ItemDataRole.UserRole)
            for i in range(self.country_list.count())
            if (item := self.country_list.item(i)) is not None
        ]
        path_text = self.country_process_edit.text().strip()
        GUIProtectionSettings.country_block_process_path = Path(path_text) if path_text else None
        GUIProtectionSettings.country_block_duration = self._read_duration_widgets(self.country_duration_combo, self.country_duration_spin)
        GUIProtectionSettings.country_voice_notifications = self._read_voice_combo(self.country_voice_combo)
        GUIProtectionSettings.country_logging = self.country_logging_checkbox.isChecked()
        GUIProtectionSettings.country_message_box = self.country_msgbox_checkbox.isChecked()

        # ISP
        GUIProtectionSettings.isp_block_enabled = self.isp_enable_checkbox.isChecked()
        GUIProtectionSettings.isp_block_list = [
            item.text()
            for i in range(self.isp_list.count())
            if (item := self.isp_list.item(i)) is not None
        ]
        path_text = self.isp_process_edit.text().strip()
        GUIProtectionSettings.isp_block_process_path = Path(path_text) if path_text else None
        GUIProtectionSettings.isp_block_duration = self._read_duration_widgets(self.isp_duration_combo, self.isp_duration_spin)
        GUIProtectionSettings.isp_voice_notifications = self._read_voice_combo(self.isp_voice_combo)
        GUIProtectionSettings.isp_logging = self.isp_logging_checkbox.isChecked()
        GUIProtectionSettings.isp_message_box = self.isp_msgbox_checkbox.isChecked()

        # ASN
        GUIProtectionSettings.asn_block_enabled = self.asn_enable_checkbox.isChecked()
        GUIProtectionSettings.asn_block_list = [
            item.text()
            for i in range(self.asn_list.count())
            if (item := self.asn_list.item(i)) is not None
        ]
        path_text = self.asn_process_edit.text().strip()
        GUIProtectionSettings.asn_block_process_path = Path(path_text) if path_text else None
        GUIProtectionSettings.asn_block_duration = self._read_duration_widgets(self.asn_duration_combo, self.asn_duration_spin)
        GUIProtectionSettings.asn_voice_notifications = self._read_voice_combo(self.asn_voice_combo)
        GUIProtectionSettings.asn_logging = self.asn_logging_checkbox.isChecked()
        GUIProtectionSettings.asn_message_box = self.asn_msgbox_checkbox.isChecked()

        # Player Join
        GUIProtectionSettings.player_join_enabled = self.player_join_enable_checkbox.isChecked()
        path_text = self.player_join_process_edit.text().strip()
        GUIProtectionSettings.player_join_process_path = Path(path_text) if path_text else None
        GUIProtectionSettings.player_join_duration = self._read_duration_widgets(self.player_join_duration_combo, self.player_join_duration_spin)
        GUIProtectionSettings.player_join_voice_notifications = self._read_voice_combo(self.player_join_voice_combo)
        GUIProtectionSettings.player_join_logging = self.player_join_logging_checkbox.isChecked()
        GUIProtectionSettings.player_join_message_box = self.player_join_msgbox_checkbox.isChecked()

        # Player Rejoin
        GUIProtectionSettings.player_rejoin_enabled = self.player_rejoin_enable_checkbox.isChecked()
        path_text = self.player_rejoin_process_edit.text().strip()
        GUIProtectionSettings.player_rejoin_process_path = Path(path_text) if path_text else None
        GUIProtectionSettings.player_rejoin_duration = self._read_duration_widgets(self.player_rejoin_duration_combo, self.player_rejoin_duration_spin)
        GUIProtectionSettings.player_rejoin_voice_notifications = self._read_voice_combo(self.player_rejoin_voice_combo)
        GUIProtectionSettings.player_rejoin_logging = self.player_rejoin_logging_checkbox.isChecked()
        GUIProtectionSettings.player_rejoin_message_box = self.player_rejoin_msgbox_checkbox.isChecked()

        # Player Leave
        GUIProtectionSettings.player_leave_enabled = self.player_leave_enable_checkbox.isChecked()
        path_text = self.player_leave_process_edit.text().strip()
        GUIProtectionSettings.player_leave_process_path = Path(path_text) if path_text else None
        GUIProtectionSettings.player_leave_duration = self._read_duration_widgets(self.player_leave_duration_combo, self.player_leave_duration_spin)
        GUIProtectionSettings.player_leave_voice_notifications = self._read_voice_combo(self.player_leave_voice_combo)
        GUIProtectionSettings.player_leave_logging = self.player_leave_logging_checkbox.isChecked()
        GUIProtectionSettings.player_leave_message_box = self.player_leave_msgbox_checkbox.isChecked()

        # GTA5 Relay (only when the tab is present)
        if hasattr(self, 'gta5_relay_enable_checkbox'):
            GUIProtectionSettings.gta5_relay_enabled = self.gta5_relay_enable_checkbox.isChecked()
            GUIProtectionSettings.gta5_relay_packet_threshold = self.gta5_relay_packet_threshold_spin.value()
            path_text = self.gta5_relay_process_edit.text().strip()
            GUIProtectionSettings.gta5_relay_process_path = Path(path_text) if path_text else None
            GUIProtectionSettings.gta5_relay_duration = self._read_duration_widgets(self.gta5_relay_duration_combo, self.gta5_relay_duration_spin)
            GUIProtectionSettings.gta5_relay_voice_notifications = self._read_voice_combo(self.gta5_relay_voice_combo)
            GUIProtectionSettings.gta5_relay_logging = self.gta5_relay_logging_checkbox.isChecked()
            GUIProtectionSettings.gta5_relay_message_box = self.gta5_relay_msgbox_checkbox.isChecked()


def open_combo_rule_editor_for_player(parent: QWidget, player: Player) -> None:
    """Open the combo rule editor pre-filled with the player's known IP lookup attributes."""
    _placeholder = '...'

    def _safe(value: object) -> str | None:
        return value if isinstance(value, str) and value and value != _placeholder else None

    conditions: dict[str, str | bool | list[str]] = {}
    if country := _safe(player.iplookup.geolite2.country):
        conditions['country'] = country
    if isp := _safe(player.iplookup.ipapi.isp):
        conditions['isp'] = isp
    as_name = _safe(player.iplookup.ipapi.as_name)
    asn_geo = _safe(player.iplookup.geolite2.asn)
    if asn_val := (as_name or asn_geo):
        conditions['as_name' if as_name else 'asn'] = asn_val
    mobile = player.iplookup.ipapi.mobile
    if isinstance(mobile, bool):
        conditions['mobile'] = mobile
    proxy = player.iplookup.ipapi.proxy
    if isinstance(proxy, bool):
        conditions['vpn'] = proxy
    hosting = player.iplookup.ipapi.hosting
    if isinstance(hosting, bool):
        conditions['hosting'] = hosting

    prefilled = ComboRule(name=f'Rule for {player.ip}', conditions=conditions) if conditions else None
    dialog = _ComboRuleEditorDialog(parent, prefilled)
    if dialog.exec() == QDialog.DialogCode.Accepted:
        ComboRulesManager.rules.append(dialog.get_rule())
        ComboRulesManager.save_to_file(COMBO_RULES_PATH)


def open_combo_rule_editor(parent: QWidget) -> None:
    """Open a blank combo rule editor and save the new rule on accept."""
    dialog = _ComboRuleEditorDialog(parent)
    if dialog.exec() == QDialog.DialogCode.Accepted:
        ComboRulesManager.rules.append(dialog.get_rule())
        ComboRulesManager.save_to_file(COMBO_RULES_PATH)
