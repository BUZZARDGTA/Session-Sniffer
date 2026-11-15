"""Widget factory helpers shared by `SettingsDialog`."""

import re
from typing import TYPE_CHECKING, cast, override

from PySide6.QtCore import QPoint, QRegularExpression, QSignalBlocker, QSize, Qt, Signal
from PySide6.QtGui import QAction, QIcon, QKeySequence, QRegularExpressionValidator, QShortcut
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDoubleSpinBox,
    QFormLayout,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QInputDialog,
    QKeySequenceEdit,
    QLabel,
    QLineEdit,
    QListWidget,
    QMenu,
    QPushButton,
    QSizePolicy,
    QSpinBox,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.guis.color_picker_dialog import ColorPickerButton
from session_sniffer.guis.delegates import ElidedTextTooltipDelegate
from session_sniffer.guis.live_language import register_language_refresh, set_i18n_colon_label
from session_sniffer.guis.secret_line_edit import SecretLineEdit
from session_sniffer.guis.stylesheets import (
    COMPACT_BUTTON_STYLESHEET,
    COMPACT_DANGER_BUTTON_STYLESHEET,
    SVG_ICON_CONTEXT_MENU_STYLESHEET,
    WEBSERVER_HELP_LABEL_STYLESHEET,
)
from session_sniffer.guis.theming import ICONS_DIR_PATH
from session_sniffer.guis.userip_manager_helpers import IPRangeBuilderDialog
from session_sniffer.guis.utils import scale_by_ui
from session_sniffer.i18n import tr
from session_sniffer.settings import SETTING_DEFAULTS, SettingMeta, SettingType
from session_sniffer.settings.settings import Settings

if TYPE_CHECKING:
    from collections.abc import Callable


def format_setting_tooltip(meta: SettingMeta) -> str | None:
    """Return the localized tooltip text for *meta*, consistently including the capture restart note if required."""
    if not meta.tooltip:
        return tr('Requires capture restart') if meta.requires_capture_restart else None
    translated_tooltip = tr(meta.tooltip)
    if meta.requires_capture_restart and '(requires capture restart)' not in meta.tooltip:
        return tr('{tooltip} (requires capture restart)', tooltip=translated_tooltip)
    return translated_tooltip


def create_standard_form_layout(parent: QWidget | None = None) -> QFormLayout:
    """Create and configure a standard `QFormLayout` for settings pages and groups."""
    layout = QFormLayout(parent) if parent else QFormLayout()
    layout.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)
    layout.setLabelAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
    return layout


def create_standard_vbox_layout(parent: QWidget | None = None) -> QVBoxLayout:
    """Create and configure a standard `QVBoxLayout` with uniform group spacing."""
    layout = QVBoxLayout(parent) if parent else QVBoxLayout()
    layout.setSpacing(16)
    return layout


def create_setting_label(meta: SettingMeta) -> QLabel:
    """Create a standard form label for a setting with an optional tooltip."""
    label = QLabel()
    set_i18n_colon_label(label, meta.display_label)
    tooltip = format_setting_tooltip(meta)
    if tooltip is not None and tooltip:
        label.setToolTip(tooltip)
    return label


def create_boolean_widget(meta: SettingMeta) -> QCheckBox:
    """Create a checkbox widget for a boolean setting."""
    checkbox = QCheckBox()
    tooltip = format_setting_tooltip(meta)
    if tooltip is not None and tooltip:
        checkbox.setToolTip(tooltip)
    return checkbox


def create_color_widget(meta: SettingMeta) -> ColorPickerButton:
    """Create a color picker button widget for a color setting."""
    button = ColorPickerButton()
    tooltip = format_setting_tooltip(meta)
    if tooltip is not None and tooltip:
        button.setToolTip(tooltip)
    return button


class HotkeyEditWidget(QWidget):
    """Single-chord keyboard shortcut editor with a clear button."""

    hotkey_changed = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the shortcut editor and clear button."""
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        self._key_edit = QKeySequenceEdit()
        self._key_edit.setMaximumSequenceLength(1)
        self._key_edit.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self._clear_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'x.svg')), f" {tr('Clear')}")
        self._clear_button.setToolTip(tr('Clear shortcut (disable hotkey)'))
        self._clear_button.setStyleSheet(COMPACT_BUTTON_STYLESHEET)
        self._clear_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self._clear_button.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        self._clear_button.setEnabled(False)

        inner_line_edit = self._key_edit.findChild(QLineEdit)

        def _apply_language() -> None:
            if inner_line_edit is not None:
                inner_line_edit.setPlaceholderText(tr('None (click and press shortcut...)'))
            self._clear_button.setText(f" {tr('Clear')}")
            self._clear_button.setToolTip(tr('Clear shortcut (disable hotkey)'))

        _apply_language()
        register_language_refresh(self, _apply_language)

        self._key_edit.keySequenceChanged.connect(self._on_sequence_changed)
        self._clear_button.clicked.connect(self._clear_shortcut)

        layout.addWidget(self._key_edit, 1)
        layout.addWidget(self._clear_button)

    def _on_sequence_changed(self, sequence: QKeySequence) -> None:
        portable = sequence.toString(QKeySequence.SequenceFormat.PortableText).strip()
        if not sequence.isEmpty() and (not portable or portable == 'Esc' or '\ufffd' in portable):
            with QSignalBlocker(self._key_edit):
                self._key_edit.clear()
        self._clear_button.setEnabled(not self._key_edit.keySequence().isEmpty())
        self.hotkey_changed.emit()

    def _clear_shortcut(self) -> None:
        self._key_edit.clear()

    def value(self) -> str | None:
        """Return the current portable key sequence string, or `None` if empty."""
        seq = self._key_edit.keySequence()
        if seq.isEmpty():
            return None
        text = seq.toString(QKeySequence.SequenceFormat.PortableText).strip()
        return text if text and '\ufffd' not in text else None

    def set_value(self, value: str | None) -> None:
        """Set the current shortcut from a portable string or `None`."""
        seq = QKeySequence.fromString(value, QKeySequence.SequenceFormat.PortableText) if value is not None and value else QKeySequence()
        with QSignalBlocker(self._key_edit):
            self._key_edit.setKeySequence(seq)
        self._clear_button.setEnabled(not seq.isEmpty())


def create_hotkey_widget(meta: SettingMeta) -> HotkeyEditWidget:
    """Create a keyboard shortcut editor widget for a hotkey setting."""
    widget = HotkeyEditWidget()
    tooltip = format_setting_tooltip(meta)
    if tooltip is not None and tooltip:
        widget.setToolTip(tooltip)
    return widget


def create_text_widget(meta: SettingMeta) -> QLineEdit:
    """Create a line-edit widget for a string/IPv4/MAC setting.

    For secret fields (`meta.secret=True`) a reveal toggle action is embedded
    as a trailing icon inside the `QLineEdit` itself.
    """
    le = SecretLineEdit() if meta.secret else QLineEdit()
    if meta.setting_type == SettingType.IPV4:
        le.setPlaceholderText(tr('e.g. 192.168.1.100'))
        le.setMaxLength(15)
        le.setValidator(QRegularExpressionValidator(QRegularExpression(r'[0-9.]{0,15}')))
    elif meta.setting_type == SettingType.MAC_ADDRESS:
        le.setPlaceholderText(tr('e.g. AA:BB:CC:DD:EE:FF'))
        le.setMaxLength(17)
        le.setValidator(QRegularExpressionValidator(QRegularExpression(r'[0-9A-Fa-f:]{0,17}')))

        def _auto_format_mac(text: str, widget: QLineEdit = le) -> None:
            cursor = widget.cursorPosition()
            hex_before = sum(1 for char in text[:cursor] if char in '0123456789ABCDEFabcdef')
            hex_only = ''.join(char for char in text.upper() if char in '0123456789ABCDEF')[:12]
            formatted = ':'.join(hex_only[i : i + 2] for i in range(0, len(hex_only), 2))
            if formatted == text:
                return
            with QSignalBlocker(widget):
                widget.setText(formatted)
            new_pos = len(formatted)
            hex_count = 0
            for i, char in enumerate(formatted):
                if hex_count == hex_before:
                    new_pos = i
                    break
                if char != ':':
                    hex_count += 1
            widget.setCursorPosition(new_pos)

        le.textEdited.connect(_auto_format_mac)
    if meta.max_length is not None:
        le.setMaxLength(meta.max_length)
    if meta.validator_pattern is not None:
        _char_rx = re.compile(meta.validator_pattern)

        def _filter_chars(text: str, _le: QLineEdit = le, _rx: re.Pattern[str] = _char_rx) -> None:
            filtered = ''.join(_rx.findall(text))
            if filtered == text:
                return
            with QSignalBlocker(_le):
                _le.setText(filtered)

        le.textEdited.connect(_filter_chars)
    tooltip = format_setting_tooltip(meta)
    if tooltip is not None and tooltip:
        le.setToolTip(tooltip)
    if meta.min_width is not None:
        le.setMinimumWidth(meta.min_width)
    if meta.max_width is not None:
        le.setMaximumWidth(meta.max_width)
    if isinstance(le, SecretLineEdit):
        reveal_action = le.addAction(QIcon(str(ICONS_DIR_PATH / 'eye-off.svg')), QLineEdit.ActionPosition.TrailingPosition)
        if not reveal_action:
            message = 'QLineEdit.addAction returned None'
            raise RuntimeError(message)
        for button in le.findChildren(QToolButton):
            button.setCursor(Qt.CursorShape.PointingHandCursor)
        _act: QAction = reveal_action
        _act.setCheckable(True)
        _act.setToolTip(tr('Show'))

        def _toggle_echo() -> None:
            checked = _act.isChecked()
            le.set_revealed(revealed=checked)
            _act.setIcon(QIcon(str(ICONS_DIR_PATH / ('eye.svg' if checked else 'eye-off.svg'))))
            _act.setToolTip(tr('Hide') if checked else tr('Show'))

        _act.toggled.connect(_toggle_echo)
        le.setProperty('secret_action', _act)
    return le


def _apply_spinbox_suffix(spin: QSpinBox | QDoubleSpinBox, suffix: str) -> None:
    spin.setSuffix(f' {tr(suffix[1:])}' if suffix.startswith(' ') else tr(suffix))


def combo_canonical_value(combo: QComboBox) -> str:
    """Return the canonical enum key stored in `UserRole` for *combo*'s active item, falling back to its text."""
    user_data = combo.currentData(Qt.ItemDataRole.UserRole)
    if isinstance(user_data, str) and user_data:
        return user_data
    return combo.currentText()


def set_combo_by_canonical(combo: QComboBox, canonical: str, *, fallback: str | None = None) -> bool:
    """Select the item matching *canonical* in `UserRole` (or text / case-insensitive text / *fallback*)."""
    index = combo.findData(canonical, Qt.ItemDataRole.UserRole)
    if index < 0:
        for i in range(combo.count()):
            item_data = combo.itemData(i, Qt.ItemDataRole.UserRole)
            if isinstance(item_data, str) and item_data.casefold() == canonical.casefold():
                index = i
                break
    if index < 0:
        index = combo.findText(canonical, Qt.MatchFlag.MatchFixedString)
    if index < 0 and fallback is not None:
        index = combo.findData(fallback, Qt.ItemDataRole.UserRole)
        if index < 0:
            index = combo.findText(fallback, Qt.MatchFlag.MatchFixedString)
    if index >= 0:
        combo.setCurrentIndex(index)
        return True
    return False


def create_float_widget(meta: SettingMeta) -> QDoubleSpinBox:
    """Create a double spin-box widget for a float setting."""
    spin = QDoubleSpinBox()
    spin.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
    spin.setDecimals(1)
    spin.setSingleStep(meta.step if meta.step is not None else 0.5)
    spin.setMinimum(meta.min_value if meta.min_value is not None else 0.0)
    spin.setMaximum(meta.max_value if meta.max_value is not None else 99999.0)
    if meta.suffix is not None:
        _apply_spinbox_suffix(spin, meta.suffix)
    spin.lineEdit().setTextMargins(scale_by_ui(5), 0, 0, 0)
    tooltip = format_setting_tooltip(meta)
    if tooltip is not None and tooltip:
        spin.setToolTip(tooltip)
    return spin


def create_integer_widget(meta: SettingMeta) -> QSpinBox:
    """Create a spin-box widget for an integer setting."""
    spin = QSpinBox()
    spin.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
    spin.setSingleStep(int(meta.step) if meta.step is not None else 1)
    spin.setMinimum(int(meta.min_value) if meta.min_value is not None else 0)
    spin.setMaximum(int(meta.max_value) if meta.max_value is not None else 99999)
    if meta.suffix is not None:
        _apply_spinbox_suffix(spin, meta.suffix)
    spin.lineEdit().setTextMargins(scale_by_ui(5), 0, 0, 0)
    tooltip = format_setting_tooltip(meta)
    if tooltip is not None and tooltip:
        spin.setToolTip(tooltip)
    return spin


def create_integer_or_all_widget(meta: SettingMeta) -> QSpinBox:
    """Create a spin-box widget for an integer-or-all setting (0 displays as special text)."""
    spin = create_integer_widget(meta)
    spin.setMinimum(0)
    spin.setSpecialValueText(tr(meta.special_value_text))
    return spin


def create_enum_widget(meta: SettingMeta) -> QComboBox:
    """Create a combo-box widget for an enum setting storing canonical values in `UserRole`."""
    combo = QComboBox()
    combo.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
    if meta.allowed_values:
        for val in meta.allowed_values:
            # Explicit `display_labels` (e.g. native language names in `SUPPORTED_LANGUAGES`) stay verbatim.
            display_text = meta.display_labels.get(val, val) if meta.display_labels is not None else tr(val)
            combo.addItem(display_text, val)
    elif meta.allowed_columns_attr is not None and meta.allowed_columns_attr:
        if meta.allowed_columns_attr == 'GUI_ALL_CONNECTED_COLUMNS':
            columns = [col for col in Settings.GUI_ALL_CONNECTED_COLUMNS if col in set(Settings.gui_columns_connected_shown) or col in Settings.GUI_FORCED_COLUMNS]
        elif meta.allowed_columns_attr == 'GUI_ALL_DISCONNECTED_COLUMNS':
            columns = [col for col in Settings.GUI_ALL_DISCONNECTED_COLUMNS if col in set(Settings.gui_columns_disconnected_shown) or col in Settings.GUI_FORCED_COLUMNS]
        else:
            columns = list(cast('tuple[str, ...]', getattr(Settings, meta.allowed_columns_attr, ())))
        for col in columns:
            combo.addItem(tr(col), col)
    tooltip = format_setting_tooltip(meta)
    if tooltip is not None and tooltip:
        combo.setToolTip(tooltip)
    return combo


def _create_checklist_button_row(
    *,
    reset_tooltip: str,
    on_select_all: Callable[[], None] | None = None,
    on_deselect_all: Callable[[], None] | None = None,
    on_reset: Callable[[], None] | None = None,
) -> tuple[QHBoxLayout, QPushButton, QPushButton, QPushButton]:
    """Create a compact 'Select All' / 'Unselect All' / 'Reset to Default' button row."""
    button_select_all = QPushButton(QIcon(str(ICONS_DIR_PATH / 'square-check.svg')), f" {tr('Select All')}")
    button_deselect_all = QPushButton(QIcon(str(ICONS_DIR_PATH / 'square.svg')), f" {tr('Unselect All')}")
    button_reset = QPushButton(QIcon(str(ICONS_DIR_PATH / 'undo.svg')), f" {tr('Reset to Default')}")
    button_reset.setToolTip(reset_tooltip)
    for button in (button_select_all, button_deselect_all):
        button.setStyleSheet(COMPACT_BUTTON_STYLESHEET)
        button.setCursor(Qt.CursorShape.PointingHandCursor)
        button.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
    button_reset.setStyleSheet(COMPACT_DANGER_BUTTON_STYLESHEET)
    button_reset.setCursor(Qt.CursorShape.PointingHandCursor)
    button_reset.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
    if on_select_all is not None:
        button_select_all.clicked.connect(on_select_all)
    if on_deselect_all is not None:
        button_deselect_all.clicked.connect(on_deselect_all)
    if on_reset is not None:
        button_reset.clicked.connect(on_reset)

    button_row = QHBoxLayout()
    button_row.setContentsMargins(0, 0, 0, 0)
    button_row.setSpacing(6)
    button_row.addWidget(button_select_all)
    button_row.addWidget(button_deselect_all)
    button_row.addStretch()
    button_row.addWidget(button_reset)
    return button_row, button_select_all, button_deselect_all, button_reset


def create_column_tuple_widget(key: str, meta: SettingMeta) -> QGroupBox:
    """Create a multi-column grid of checkboxes for column visibility."""
    allowed_attr = meta.allowed_columns_attr or ''
    allowed_columns = cast('tuple[str, ...]', getattr(Settings, allowed_attr, ()))
    default_columns = cast('tuple[str, ...]', SETTING_DEFAULTS.get(key, ()))

    group = QGroupBox(tr(meta.display_label).replace('&', '&&'))
    tooltip = format_setting_tooltip(meta)
    if tooltip is not None and tooltip:
        group.setToolTip(tooltip)

    inner = QWidget()
    grid = QGridLayout(inner)
    grid.setContentsMargins(4, 4, 4, 4)
    grid.setSpacing(2)

    column_count = 3
    for i, column_name in enumerate(allowed_columns):
        display_text = meta.display_labels.get(column_name, column_name) if meta.display_labels is not None and meta.display_labels else tr(column_name)
        checkbox = QCheckBox(display_text)
        checkbox.setObjectName(column_name)
        grid.addWidget(checkbox, i // column_count, i % column_count)
    grid.setRowStretch(grid.rowCount(), 1)

    button_row, _, _, _ = _create_checklist_button_row(
        reset_tooltip=tr('Reset to default selected columns'),
        on_select_all=lambda: set_all_checkboxes(inner, checked=True),
        on_deselect_all=lambda: set_all_checkboxes(inner, checked=False),
        on_reset=lambda: set_checkboxes_to(inner, default_columns),
    )

    outer = QVBoxLayout(group)
    outer.setSpacing(4)
    outer.addLayout(button_row)
    outer.addWidget(inner)
    return group


def create_third_party_servers_split_widget(key: str, meta: SettingMeta) -> QWidget:
    """Create a widget with checkable presets and a single list of server checkboxes."""
    allowed_attr = meta.allowed_columns_attr or ''
    allowed_columns = cast('tuple[str, ...]', getattr(Settings, allowed_attr, ()))
    default_columns = cast('tuple[str, ...]', SETTING_DEFAULTS.get(key, ()))
    display_labels = meta.display_labels or {}

    container = QWidget()
    layout = QVBoxLayout(container)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(10)

    # Presets group box
    presets_group = QGroupBox(tr('App & Game Presets').replace('&', '&&'))
    presets_group.setToolTip(tr('Select presets to automatically block their required IP ranges. You can check multiple presets.'))
    presets_grid_container = QWidget()
    presets_grid = QGridLayout(presets_grid_container)
    presets_grid.setContentsMargins(4, 4, 4, 4)
    presets_grid.setSpacing(2)

    preset_names = [
        'Azar',
        'Borderlands 2',
        'Borderlands 3',
        'Borderlands 4',
        'Borderlands: The Pre-Sequel',
        'Call of Duty®: Advanced Warfare',
        'Call of Duty®: Black Ops',
        'Call of Duty®: Black Ops Cold War',
        'Call of Duty®: Black Ops II',
        'Call of Duty®: Black Ops III',
        'Call of Duty®: Ghosts',
        'Call of Duty®: Infinite Warfare',
        'Call of Duty®: Modern Warfare® 2 (2009)',
        'Call of Duty®: Modern Warfare® 3 (2011)',
        'Call of Duty®: Vanguard',
        'Call of Duty®: WWII',
        'Chatspin',
        'Deep Rock Galactic',
        'Discord',
        'Dying Light',
        'Dying Light 2',
        'Grand Theft Auto Online',
        "John Carpenter's Toxic Commando",
        'Minecraft Bedrock Edition',
        'Monopoly Madness',
        'Mortal Kombat 11',
        'Mortal Kombat X',
        'Need for Speed™ Most Wanted',
        'NEW MONOPOLY®',
        'OmeTV',
        'Payday 2',
        'PlayStation Party Chat',
        'Ready or Not',
        'Red Dead Online',
        'Risk of Rain 2',
        'RustDesk',
        'Sniper Elite 3',
        'Steam',
        'The Division 2',
        'theHunter Call of the Wild™',
        'theHunter Classic',
        "Tom Clancy's Ghost Recon® Breakpoint",
        'UNO',
        'Warframe',
        'Watch Dogs® 2',
        'Windows',
        'Xbox',
    ]

    preset_checkboxes: dict[str, QCheckBox] = {}
    presets_num_columns = 3
    for i, preset_name in enumerate(preset_names):
        checkbox = QCheckBox(preset_name)
        checkbox.setObjectName(preset_name)
        preset_checkboxes[preset_name] = checkbox
        presets_grid.addWidget(checkbox, i // presets_num_columns, i % presets_num_columns)
    presets_grid.setRowStretch(presets_grid.rowCount(), 1)

    preset_button_row, preset_button_select_all, preset_button_deselect_all, preset_button_reset = _create_checklist_button_row(
        reset_tooltip=tr('Reset to default presets'),
    )

    presets_layout = QVBoxLayout(presets_group)
    presets_layout.setSpacing(4)
    presets_layout.addLayout(preset_button_row)
    presets_layout.addWidget(presets_grid_container)

    # Checklist container
    checklist_group = QGroupBox(tr(meta.display_label).replace('&', '&&'))
    tooltip = format_setting_tooltip(meta)
    if tooltip is not None and tooltip:
        checklist_group.setToolTip(tooltip)

    grid_container = QWidget()
    grid = QGridLayout(grid_container)
    grid.setContentsMargins(4, 4, 4, 4)
    grid.setSpacing(2)

    checkboxes: dict[str, QCheckBox] = {}
    column_count = 3
    for i, column_name in enumerate(allowed_columns):
        display_text = display_labels.get(column_name, column_name)
        checkbox = QCheckBox(display_text)
        checkbox.setObjectName(column_name)
        checkboxes[column_name] = checkbox
        grid.addWidget(checkbox, i // column_count, i % column_count)
    grid.setRowStretch(grid.rowCount(), 1)

    button_row, _, _, _ = _create_checklist_button_row(
        reset_tooltip=tr('Reset to default selected options'),
        on_select_all=lambda: set_all_checkboxes(grid_container, checked=True),
        on_deselect_all=lambda: set_all_checkboxes(grid_container, checked=False),
        on_reset=lambda: set_checkboxes_to(grid_container, default_columns),
    )

    group_layout = QVBoxLayout(checklist_group)
    group_layout.setSpacing(4)
    group_layout.addLayout(button_row)
    group_layout.addWidget(grid_container)

    layout.addWidget(presets_group)
    layout.addWidget(checklist_group)

    # Preset mappings
    presets_map: dict[str, set[str]] = {
        'Azar': {'CLOUDFLARE', 'GOOGLE_LLC', 'MICROSOFT'},
        'Borderlands 2': {'AMAZON', 'GOOGLE_LLC'},
        'Borderlands 3': {'MICROSOFT', 'UNITY_TECHNOLOGIES_APS'},
        'Borderlands 4': {'AMAZON', 'MICROSOFT', 'UNITY_TECHNOLOGIES_APS'},
        'Borderlands: The Pre-Sequel': {'GOOGLE_LLC'},
        'Call of Duty®: Advanced Warfare': {'COMVIVE_SERVIDORES', 'DEMONWARE', 'DIMENSION_DATA', 'LATITUDE_SH', 'LEVEL_3_PARENT', 'THE_CONSTANT_COMPANY'},
        'Call of Duty®: Black Ops': {'DEMONWARE', 'MICROSOFT', 'THE_CONSTANT_COMPANY', 'UK_MINISTRY_OF_DEFENCE', 'US_DEPARTMENT_OF_DEFENSE'},
        'Call of Duty®: Black Ops Cold War': {'DEMONWARE', 'THE_CONSTANT_COMPANY'},
        'Call of Duty®: Black Ops II': {'DEMONWARE'},
        'Call of Duty®: Black Ops III': {'DEMONWARE', 'DIMENSION_DATA', 'LATITUDE_SH', 'THE_CONSTANT_COMPANY', 'SEFLOW'},
        'Call of Duty®: Ghosts': {'COMVIVE_SERVIDORES', 'DEMONWARE', 'DIMENSION_DATA', 'LATITUDE_SH', 'LEVEL_3_PARENT', 'THE_CONSTANT_COMPANY', 'SEFLOW'},
        'Call of Duty®: Infinite Warfare': {'DEMONWARE', 'THE_CONSTANT_COMPANY', 'SEFLOW'},
        'Call of Duty®: Modern Warfare® 2 (2009)': {'DEMONWARE'},
        'Call of Duty®: Modern Warfare® 3 (2011)': {'DEMONWARE'},
        'Call of Duty®: Vanguard': {'DEMONWARE', 'THE_CONSTANT_COMPANY'},
        'Call of Duty®: WWII': {'DEMONWARE', 'FRIEND_IT', 'LATITUDE_SH', 'MICROSOFT', 'TENCENT', 'THE_CONSTANT_COMPANY', 'SEFLOW', 'US_DEPARTMENT_OF_DEFENSE'},
        'Chatspin': {'GOOGLE_LLC'},
        'Deep Rock Galactic': {'US_DEPARTMENT_OF_DEFENSE'},
        'Discord': {'CLOUDFLARE', 'DISCORD'},
        'Dying Light': {'AMAZON', 'GOOGLE_LLC', 'US_DEPARTMENT_OF_DEFENSE'},
        'Dying Light 2': {'AMAZON'},
        'Grand Theft Auto Online': {'BATTLEYE', 'MICROSOFT', 'TAKETWO_INTERACTIVE', 'TELLAS_GREECE', 'UK_MINISTRY_OF_DEFENCE', 'US_DEPARTMENT_OF_DEFENSE'},
        "John Carpenter's Toxic Commando": {'COMNET_INTERNATIONAL_BV', 'G_CORE_LABS', 'GOOGLE_LLC', 'MICROSOFT', 'SERVERS_COM', 'US_DEPARTMENT_OF_DEFENSE', 'ZENLAYER'},
        'Minecraft Bedrock Edition': {'MICROSOFT'},
        'Monopoly Madness': {'AMAZON'},
        'Mortal Kombat 11': {'US_DEPARTMENT_OF_DEFENSE'},
        'Mortal Kombat X': {'MICROSOFT', 'US_DEPARTMENT_OF_DEFENSE'},
        'Need for Speed™ Most Wanted': {'EA', 'I3D_NET', 'MICROSOFT'},
        'NEW MONOPOLY®': {'AMAZON'},
        'OmeTV': {'GOOGLE_LLC', 'OVH'},
        'Payday 2': {'AMAZON', 'US_DEPARTMENT_OF_DEFENSE'},
        'PlayStation Party Chat': {'PLAYSTATION_SONY'},
        'Ready or Not': {'AMAZON'},
        'Red Dead Online': {'MICROSOFT', 'TAKETWO_INTERACTIVE', 'UK_MINISTRY_OF_DEFENCE', 'US_DEPARTMENT_OF_DEFENSE'},
        'Risk of Rain 2': {'AMAZON', 'US_DEPARTMENT_OF_DEFENSE'},
        'RustDesk': {'RUSTDESK'},
        'Sniper Elite 3': {'LIMESTONE_NETWORKS'},
        'Steam': {'VALVE'},
        'The Division 2': {'CLOUDFLARE', 'MICROSOFT'},
        'theHunter Call of the Wild™': {'AMAZON', 'MICROSOFT', 'US_DEPARTMENT_OF_DEFENSE'},
        'theHunter Classic': {'AMAZON', 'GOOGLE_LLC'},
        "Tom Clancy's Ghost Recon® Breakpoint": {'AMAZON', 'I3D_NET'},
        'UNO': {'AMAZON', 'I3D_NET', 'MICROSOFT', 'US_DEPARTMENT_OF_DEFENSE'},
        'Warframe': {'AKAMAI_CONNECTED_CLOUD'},
        'Watch Dogs® 2': {'I3D_NET', 'UK_MINISTRY_OF_DEFENCE', 'US_DEPARTMENT_OF_DEFENSE'},
        'Windows': {'MICROSOFT'},
        'Xbox': {'MICROSOFT'},
    }

    is_updating = False

    def update_presets_from_ranges() -> None:
        nonlocal is_updating
        if is_updating:
            return
        is_updating = True
        try:
            checked_ranges = {range_name for range_name, checkbox in checkboxes.items() if checkbox.isChecked()}
            for preset_name, preset_set in presets_map.items():
                is_active = preset_set.issubset(checked_ranges)
                with QSignalBlocker(preset_checkboxes[preset_name]):
                    preset_checkboxes[preset_name].setChecked(is_active)
        finally:
            is_updating = False

    def on_preset_clicked(pname: str, *, checked: bool) -> None:
        nonlocal is_updating
        if is_updating:
            return
        is_updating = True
        try:
            preset_set = presets_map[pname]
            for rname in preset_set:
                if rname in checkboxes:
                    checkboxes[rname].setChecked(checked)

            checked_ranges = {range_name for range_name, checkbox in checkboxes.items() if checkbox.isChecked()}
            for other_name, other_set in presets_map.items():
                is_active = other_set.issubset(checked_ranges)
                with QSignalBlocker(preset_checkboxes[other_name]):
                    preset_checkboxes[other_name].setChecked(is_active)
        finally:
            is_updating = False

    def make_handler(name: str) -> Callable[[], None]:
        def handler() -> None:
            on_preset_clicked(name, checked=preset_checkboxes[name].isChecked())

        return handler

    def select_all_presets() -> None:
        nonlocal is_updating
        is_updating = True
        try:
            for checkbox in preset_checkboxes.values():
                with QSignalBlocker(checkbox):
                    checkbox.setChecked(True)
            for preset_set in presets_map.values():
                for rname in preset_set:
                    if rname in checkboxes:
                        checkboxes[rname].setChecked(True)
        finally:
            is_updating = False
        update_presets_from_ranges()

    def deselect_all_presets() -> None:
        nonlocal is_updating
        is_updating = True
        try:
            for checkbox in preset_checkboxes.values():
                with QSignalBlocker(checkbox):
                    checkbox.setChecked(False)
            for preset_set in presets_map.values():
                for rname in preset_set:
                    if rname in checkboxes:
                        checkboxes[rname].setChecked(False)
        finally:
            is_updating = False
        update_presets_from_ranges()

    def reset_presets() -> None:
        set_checkboxes_to(grid_container, default_columns)

    preset_button_select_all.clicked.connect(select_all_presets)
    preset_button_deselect_all.clicked.connect(deselect_all_presets)
    preset_button_reset.clicked.connect(reset_presets)

    for preset_name, preset_checkbox in preset_checkboxes.items():
        preset_checkbox.clicked.connect(make_handler(preset_name))

    for checkbox in checkboxes.values():
        checkbox.toggled.connect(update_presets_from_ranges)

    update_presets_from_ranges()

    return container


class _AutoFitListWidget(QListWidget):
    """List widget that pads its size hint to avoid spurious scrollbars."""

    @override
    def sizeHint(self) -> QSize:
        """Return a slightly padded size hint to prevent spurious scrollbars."""
        hint = super().sizeHint()
        if not self.count():
            return QSize(hint.width(), 44)
        return QSize(hint.width(), hint.height() + 10)


def _create_editable_list_group(meta: SettingMeta, *, add_tooltip: str, prompt_entry: Callable[[], str | None]) -> QGroupBox:
    """Create an add/remove `_AutoFitListWidget` group box for a string-tuple setting."""
    group = QGroupBox(tr(meta.display_label).replace('&', '&&'))
    tooltip = format_setting_tooltip(meta)
    if tooltip is not None and tooltip:
        group.setToolTip(tooltip)

    list_widget = _AutoFitListWidget()
    list_widget.setSizeAdjustPolicy(QListWidget.SizeAdjustPolicy.AdjustToContents)
    list_widget.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
    list_widget.setMaximumHeight(250)
    list_widget.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
    list_widget.setItemDelegate(ElidedTextTooltipDelegate(list_widget))
    list_widget.setWordWrap(False)
    list_widget.setSelectionMode(QListWidget.SelectionMode.ExtendedSelection)
    list_widget.setSortingEnabled(True)
    list_widget.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)

    def _make_btn(icon_name: str, text: str, tip: str, style: str) -> QPushButton:
        btn = QPushButton(QIcon(str(ICONS_DIR_PATH / icon_name)), text)
        btn.setToolTip(tip)
        btn.setStyleSheet(style)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        return btn

    add_button = _make_btn('plus.svg', f" {tr('Add')}", add_tooltip, COMPACT_BUTTON_STYLESHEET)
    remove_button = _make_btn('remove.svg', f" {tr('Remove')}", tr('Remove the selected entries (Delete)'), COMPACT_DANGER_BUTTON_STYLESHEET)
    remove_button.setEnabled(False)

    def _sync_remove_button() -> None:
        sel_count = len(list_widget.selectedItems())
        remove_button.setEnabled(sel_count > 0)
        remove_button.setText(f" {tr('Remove ({count})', count=sel_count)}" if sel_count > 1 else f" {tr('Remove')}")

    register_language_refresh(group, _sync_remove_button)

    def _add_entry() -> None:
        entry = prompt_entry()
        if entry is None or not entry:
            return
        if entry not in {item.text() for i in range(list_widget.count()) if (item := list_widget.item(i))}:
            list_widget.addItem(entry)

    def _remove_entries() -> None:
        for row in sorted({list_widget.row(item) for item in list_widget.selectedItems()}, reverse=True):
            list_widget.takeItem(row)
        _sync_remove_button()

    def _on_context_menu(pos: QPoint) -> None:
        if (clicked := list_widget.itemAt(pos)) is not None and not clicked.isSelected():
            list_widget.clearSelection()
            list_widget.setCurrentItem(clicked)
            clicked.setSelected(True)
        sel_count = len(list_widget.selectedItems())
        menu = QMenu(group)
        menu.setStyleSheet(SVG_ICON_CONTEXT_MENU_STYLESHEET)
        menu.addAction(QIcon(str(ICONS_DIR_PATH / 'plus.svg')), tr('Add\u2026')).triggered.connect(_add_entry)
        rm_act = menu.addAction(
            QIcon(str(ICONS_DIR_PATH / 'remove.svg')),
            tr('Remove ({count})', count=sel_count) if sel_count > 1 else tr('Remove'),
        )
        rm_act.setShortcut('Delete')
        rm_act.setEnabled(sel_count > 0)
        rm_act.triggered.connect(_remove_entries)
        menu.addSeparator()
        sel_all_act = menu.addAction(QIcon(str(ICONS_DIR_PATH / 'square-check.svg')), tr('Select All'))
        sel_all_act.setShortcut('Ctrl+A')
        sel_all_act.setEnabled(list_widget.count() > 0)
        sel_all_act.triggered.connect(list_widget.selectAll)
        if viewport := list_widget.viewport():
            menu.exec(viewport.mapToGlobal(pos))

    list_widget.itemSelectionChanged.connect(_sync_remove_button)
    list_widget.customContextMenuRequested.connect(_on_context_menu)
    QShortcut(QKeySequence('Delete'), list_widget, context=Qt.ShortcutContext.WidgetShortcut).activated.connect(_remove_entries)
    add_button.clicked.connect(_add_entry)
    remove_button.clicked.connect(_remove_entries)

    button_row = QHBoxLayout()
    button_row.setContentsMargins(0, 0, 0, 0)
    button_row.setSpacing(6)
    button_row.addWidget(add_button)
    button_row.addWidget(remove_button)
    button_row.addStretch()

    outer_layout = QVBoxLayout(group)
    outer_layout.setSpacing(4)
    outer_layout.addLayout(button_row)
    outer_layout.addWidget(list_widget, 1)
    return group


def create_ip_range_tuple_widget(meta: SettingMeta, parent: QWidget) -> QGroupBox:
    """Create an add/remove list widget for managing a tuple of IP addresses and ranges."""

    def _prompt_ip_range() -> str | None:
        dialog = IPRangeBuilderDialog(parent)
        return (dialog.result_entry() or None) if dialog.exec() == QDialog.DialogCode.Accepted else None

    return _create_editable_list_group(meta, add_tooltip=tr('Add a new blocked IP address, range, or subnet'), prompt_entry=_prompt_ip_range)


def create_string_tuple_widget(meta: SettingMeta, parent: QWidget) -> QGroupBox:
    """Create an add/remove list widget for managing a tuple of strings."""

    def _prompt_string() -> str | None:
        text, success = QInputDialog.getText(parent, tr('Add Filtered ISP / ASN'), tr('Enter ISP or ASN name (e.g. Take-Two, Amazon, Hetzner, AS15169):'))
        return entry if success and (entry := text.strip()) else None

    return _create_editable_list_group(meta, add_tooltip=tr('Add a new entry to the list'), prompt_entry=_prompt_string)


def set_all_checkboxes(container: QWidget, *, checked: bool) -> None:
    """Set all QCheckBox children of `container` to `checked`."""
    for checkbox in container.findChildren(QCheckBox):
        checkbox.setChecked(checked)


def set_checkboxes_to(container: QWidget, selected: tuple[str, ...]) -> None:
    """Check exactly the QCheckBox children whose objectName is in `selected`."""
    wanted = set(selected)
    for checkbox in container.findChildren(QCheckBox):
        checkbox.setChecked(checkbox.objectName() in wanted)


def build_webserver_help_group() -> QGroupBox:
    """Build an explanatory guide for Web Server host/port behavior and common usage patterns."""
    group_box = QGroupBox(tr('Web Server Usage Guide'))
    layout = QVBoxLayout(group_box)

    help_label = QLabel(
        tr(
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
        ),
    )
    help_label.setWordWrap(True)
    help_label.setTextFormat(Qt.TextFormat.RichText)
    help_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    help_label.setStyleSheet(WEBSERVER_HELP_LABEL_STYLESHEET)
    layout.addWidget(help_label)

    return group_box


def build_shortcuts_help_group() -> QGroupBox:
    """Build an explanatory header for global hotkeys and main window shortcuts."""
    group_box = QGroupBox()
    layout = QVBoxLayout(group_box)

    help_label = QLabel()
    help_label.setWordWrap(True)
    help_label.setTextFormat(Qt.TextFormat.RichText)
    help_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    help_label.setStyleSheet(WEBSERVER_HELP_LABEL_STYLESHEET)
    layout.addWidget(help_label)

    def _refresh_text() -> None:
        group_box.setTitle(tr('Keyboard Shortcuts Guide'))
        help_label.setText(
            tr(
                '<b>Global Hotkeys</b> (<i>Capture &amp; Notifications</i>, <i>Game Process &amp; Session</i>, <i>Looky System</i>): '
                'Registered system-wide so they work at any time, including while playing fullscreen in-game.<br>'
                '<b>Window Shortcuts</b> (<i>Main Window</i>): Active while the main Session Sniffer window is focused.<br><br>'
                'Click any shortcut field and press a key combination to assign it, or click <b>Clear</b> (or press <b>Esc</b>) to disable it.',
            ),
        )

    _refresh_text()
    register_language_refresh(group_box, _refresh_text)
    return group_box
