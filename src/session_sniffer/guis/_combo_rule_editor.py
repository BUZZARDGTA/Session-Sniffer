"""Private helper module: shared styles, widget helpers, and dialogs for combo-rule editing."""

from typing import ClassVar, Literal, cast

from PyQt6.QtCore import QSortFilterProxyModel, Qt
from PyQt6.QtGui import QIcon, QPixmap, QStandardItem, QStandardItemModel
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QCompleter,
    QDialog,
    QDialogButtonBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.local import IMAGES_DIR_PATH
from session_sniffer.guis.country_data import COUNTRY_NAMES
from session_sniffer.guis.utils import SUSPEND_TOOLTIP_AUTO, SUSPEND_TOOLTIP_DISABLED, SUSPEND_TOOLTIP_MANUAL
from session_sniffer.player.combo_rules import ComboRule
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings import Settings

COUNTRY_FLAGS_DIR = IMAGES_DIR_PATH / 'country_flags'
# Pre-scan available flag codes once to avoid per-country filesystem checks
AVAILABLE_FLAG_CODES: frozenset[str] = frozenset(
    p.stem for p in COUNTRY_FLAGS_DIR.glob('*.png')
) if COUNTRY_FLAGS_DIR.is_dir() else frozenset()

GROUPBOX_STYLE = """
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

LIST_WIDGET_STYLE = """
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


def set_duration_widgets_helper(combo: QComboBox, spin: QSpinBox, duration: int | str) -> None:
    """Set duration combo and spin box from a stored duration value."""
    if isinstance(duration, int):
        combo.setCurrentText('Manual')
        spin.setValue(int(duration))
        spin.setVisible(True)
    elif duration == 'Disabled':
        combo.setCurrentText('Disabled')
        spin.setVisible(False)
    else:
        combo.setCurrentText('Auto')
        spin.setVisible(False)


def read_duration_widgets_helper(combo: QComboBox, spin: QSpinBox) -> int | Literal['Auto']:
    """Read duration value from combo and spin box widgets."""
    text = combo.currentText()
    if text == 'Manual':
        return spin.value()
    return 'Auto'


def set_voice_combo_helper(combo: QComboBox, value: Literal['Male', 'Female'] | bool) -> None:  # noqa: FBT001
    """Set voice combo from a stored voice notification value."""
    if value == 'Male':
        combo.setCurrentText('Male')
    elif value == 'Female':
        combo.setCurrentText('Female')
    else:
        combo.setCurrentText('Disabled')


def read_voice_combo_helper(combo: QComboBox) -> Literal['Male', 'Female'] | bool:
    """Read voice notification value from a combo widget."""
    text = combo.currentText()
    if text == 'Male':
        return 'Male'
    if text == 'Female':
        return 'Female'
    return False


class CountrySelectionDialog(QDialog):
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
            if code in AVAILABLE_FLAG_CODES:
                item.setIcon(QIcon(QPixmap(str(COUNTRY_FLAGS_DIR / f'{code}.png'))))
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
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
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


class ComboRuleEditorDialog(QDialog):
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
        conditions_group.setStyleSheet(GROUPBOX_STYLE)
        conditions_layout = QVBoxLayout()

        self._conditions_container = QVBoxLayout()
        conditions_layout.addLayout(self._conditions_container)

        add_condition_btn = QPushButton('\u2795 Add Condition')
        add_condition_btn.clicked.connect(self._add_condition_row)
        conditions_layout.addWidget(add_condition_btn)

        conditions_group.setLayout(conditions_layout)

        conditions_scroll = QScrollArea()
        conditions_scroll.setWidgetResizable(True)
        conditions_scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        conditions_scroll.setWidget(conditions_group)
        main_layout.addWidget(conditions_scroll, stretch=1)

        # Action settings
        action_group = QGroupBox('Actions')
        action_group.setStyleSheet(GROUPBOX_STYLE)
        action_layout = QVBoxLayout()

        # Notification Settings
        notification_separator = QLabel('\u2500\u2500\u2500 Notification Settings \u2500\u2500\u2500')
        notification_separator.setStyleSheet('color: #666; font-size: 9pt; padding: 5px 0;')
        notification_separator.setAlignment(Qt.AlignmentFlag.AlignCenter)
        action_layout.addWidget(notification_separator)

        voice_row = QHBoxLayout()
        voice_row.addWidget(QLabel('Voice Notifications:'))
        self._voice_combo = QComboBox()
        self._voice_combo.addItems(['Disabled', 'Male', 'Female'])
        self._voice_combo.setToolTip('Select voice for text-to-speech notifications')
        if rule:
            set_voice_combo_helper(self._voice_combo, rule.voice_notifications)
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

        # Protection Settings
        # -- Protection section (hidden when neighbour interface / protection not supported) --
        protection_section = QWidget()
        protection_section_layout = QVBoxLayout(protection_section)
        protection_section_layout.setContentsMargins(0, 0, 0, 0)

        protection_separator = QLabel('\u2500\u2500\u2500 Protection Settings \u2500\u2500\u2500')
        protection_separator.setStyleSheet('color: #666; font-size: 9pt; padding: 5px 0;')
        protection_separator.setAlignment(Qt.AlignmentFlag.AlignCenter)
        protection_section_layout.addWidget(protection_separator)

        # Duration
        duration_row = QHBoxLayout()
        duration_row.addWidget(QLabel('Suspend Mode:'))
        self._duration_combo = QComboBox()
        self._duration_combo.addItems(['Disabled', 'Auto', 'Manual'])
        self._duration_combo.setItemData(0, SUSPEND_TOOLTIP_DISABLED, Qt.ItemDataRole.ToolTipRole)
        self._duration_combo.setItemData(1, SUSPEND_TOOLTIP_AUTO, Qt.ItemDataRole.ToolTipRole)
        self._duration_combo.setItemData(2, SUSPEND_TOOLTIP_MANUAL, Qt.ItemDataRole.ToolTipRole)
        duration_row.addWidget(self._duration_combo)
        self._duration_spin = QSpinBox()
        self._duration_spin.setRange(1, 3600)
        self._duration_spin.setValue(60)
        self._duration_spin.setSuffix(' seconds')
        self._duration_spin.setVisible(False)
        self._duration_combo.currentTextChanged.connect(self._on_duration_text_changed)
        duration_row.addWidget(self._duration_spin)
        duration_row.addStretch()
        protection_section_layout.addLayout(duration_row)

        if rule:
            set_duration_widgets_helper(
                self._duration_combo, self._duration_spin,
                rule.duration if rule.protection_enabled else 'Disabled',
            )

        action_layout.addWidget(protection_section)
        if Settings.capture_game_preset != 'GTA5' or CaptureState.is_neighbour_interface:
            protection_section.setVisible(False)

        action_group.setLayout(action_layout)
        main_layout.addWidget(action_group)

        # Dialog buttons
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._validate_and_accept)
        buttons.rejected.connect(self.reject)
        main_layout.addWidget(buttons)

        # Pre-populate conditions from existing rule
        if rule:
            for key, value in rule.conditions.items():
                self._add_condition_row(key, value)

    def _on_duration_text_changed(self, text: str) -> None:
        self._duration_spin.setVisible(text == 'Manual')

    def _add_condition_row(
        self, preset_key: str | None = None, preset_value: str | bool | list[str] | None = None,  # noqa: FBT001
    ) -> None:
        """Add a new condition row with type selector and value widget."""
        row_layout = QHBoxLayout()

        type_combo = QComboBox()
        type_combo.addItems(list(self._CONDITION_LABELS.keys()))
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
                    if code in AVAILABLE_FLAG_CODES:
                        item.setIcon(QIcon(QPixmap(str(COUNTRY_FLAGS_DIR / f'{code}.png'))))
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

        type_combo.currentTextChanged.connect(on_type_changed)

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

        remove_btn.clicked.connect(remove_row)

        # Set preset values if provided
        if preset_key is not None:
            # Find the display label for the key
            for label, k in self._CONDITION_LABELS.items():
                if k == preset_key:
                    type_combo.setCurrentText(label)
                    break
            # Now set the value
            if preset_key in ('mobile', 'vpn', 'hosting') and isinstance(preset_value, bool):
                bool_combo_widget: QComboBox | None = cast('QComboBox | None', value_stack.findChild(QComboBox))
                if bool_combo_widget is not None:
                    idx = bool_combo_widget.findData(preset_value)
                    if idx >= 0:
                        bool_combo_widget.setCurrentIndex(idx)
            elif preset_key == 'event' and isinstance(preset_value, list):
                events_widget: QWidget | None = cast('QWidget | None', value_stack.findChild(QWidget))
                if events_widget is not None:
                    for cb in events_widget.findChildren(QCheckBox):
                        event_key = self._EVENT_LABELS.get(cb.text(), '')
                        cb.setChecked(event_key in preset_value)
            elif preset_key == 'country' and isinstance(preset_value, str):
                country_combo_widget: QComboBox | None = cast('QComboBox | None', value_stack.findChild(QComboBox))
                if country_combo_widget is not None:
                    # Find the matching country entry
                    for i in range(country_combo_widget.count()):
                        data = country_combo_widget.itemData(i, Qt.ItemDataRole.UserRole)
                        if data == preset_value:
                            country_combo_widget.setCurrentIndex(i)
                            break
            elif isinstance(preset_value, str):
                line_edit_widget: QLineEdit | None = cast('QLineEdit | None', value_stack.findChild(QLineEdit))
                if line_edit_widget is not None:
                    line_edit_widget.setText(preset_value)

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
                bool_combo_widget: QComboBox | None = cast('QComboBox | None', value_stack.findChild(QComboBox))
                if bool_combo_widget is not None:
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
                line_edit_widget: QLineEdit | None = cast('QLineEdit | None', value_stack.findChild(QLineEdit))
                if line_edit_widget is not None:
                    val = line_edit_widget.text().strip()
                    if val:
                        conditions[key] = val
        return conditions

    def _read_event_checkboxes(self, value_stack: QWidget) -> list[str]:
        """Read selected event checkboxes from a value stack widget."""
        events_widget: QWidget | None = cast('QWidget | None', value_stack.findChild(QWidget))
        if events_widget is None:
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
        country_combo_widget: QComboBox | None = cast('QComboBox | None', value_stack.findChild(QComboBox))
        if country_combo_widget is None:
            return None
        idx = country_combo_widget.currentIndex()
        if idx < 0:
            return None
        data = country_combo_widget.itemData(idx, Qt.ItemDataRole.UserRole)
        return data if isinstance(data, str) and data else None

    def get_rule(self) -> ComboRule:
        """Build a ComboRule from dialog state."""
        return ComboRule(
            name=self._name_edit.text().strip(),
            enabled=self._enabled_checkbox.isChecked(),
            conditions=self._read_conditions(),
            protection_enabled=self._duration_combo.currentText() != 'Disabled',
            duration=read_duration_widgets_helper(self._duration_combo, self._duration_spin),
            voice_notifications=read_voice_combo_helper(self._voice_combo),
            logging=self._logging_checkbox.isChecked(),
            message_box=self._msgbox_checkbox.isChecked(),
        )
