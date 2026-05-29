"""Widget factory helpers shared by `SettingsDialog`."""

from PyQt6.QtCore import QRegularExpression, Qt
from PyQt6.QtGui import QRegularExpressionValidator
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDoubleSpinBox,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLineEdit,
    QListWidget,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.guis.stylesheets import COMPACT_BUTTON_STYLESHEET
from session_sniffer.guis.userip_manager_helpers import IPRangeBuilderDialog
from session_sniffer.settings import SETTING_DEFAULTS, SettingMeta, SettingType
from session_sniffer.settings.settings import Settings

_RESTART_INDICATOR = ' \u27F3'


def create_boolean_widget(meta: SettingMeta) -> QCheckBox:
    """Create a checkbox widget for a boolean setting."""
    cb = QCheckBox()
    if meta.tooltip:
        cb.setToolTip(meta.tooltip)
    return cb


def create_text_widget(meta: SettingMeta) -> QLineEdit:
    """Create a line-edit widget for a string/IPv4/MAC setting."""
    le = QLineEdit()
    if meta.setting_type == SettingType.IPV4:
        le.setPlaceholderText('e.g. 192.168.1.100')
        le.setMaxLength(15)
        le.setValidator(QRegularExpressionValidator(QRegularExpression(r'[0-9.]{0,15}')))
    elif meta.setting_type == SettingType.MAC_ADDRESS:
        le.setPlaceholderText('e.g. AA:BB:CC:DD:EE:FF')
        le.setMaxLength(17)
        le.setValidator(QRegularExpressionValidator(QRegularExpression(r'[0-9A-Fa-f:]{0,17}')))

        def _auto_format_mac(text: str, widget: QLineEdit = le) -> None:
            cursor = widget.cursorPosition()
            hex_before = sum(1 for c in text[:cursor] if c in '0123456789ABCDEFabcdef')
            hex_only = ''.join(c for c in text.upper() if c in '0123456789ABCDEF')[:12]
            formatted = ':'.join(hex_only[i:i + 2] for i in range(0, len(hex_only), 2))
            if formatted == text:
                return
            widget.blockSignals(True)  # noqa: FBT003
            widget.setText(formatted)
            widget.blockSignals(False)  # noqa: FBT003
            new_pos = len(formatted)
            hex_count = 0
            for i, c in enumerate(formatted):
                if hex_count == hex_before:
                    new_pos = i
                    break
                if c != ':':
                    hex_count += 1
            widget.setCursorPosition(new_pos)

        le.textEdited.connect(_auto_format_mac)
    if meta.tooltip:
        le.setToolTip(meta.tooltip)
    return le


def create_float_widget(meta: SettingMeta) -> QDoubleSpinBox:
    """Create a double spin-box widget for a float setting."""
    spin = QDoubleSpinBox()
    spin.setDecimals(1)
    spin.setSingleStep(0.5)
    spin.setMinimum(meta.min_value if meta.min_value is not None else 0.0)
    spin.setMaximum(meta.max_value if meta.max_value is not None else 99999.0)
    if meta.tooltip:
        spin.setToolTip(meta.tooltip)
    return spin


def create_integer_widget(meta: SettingMeta) -> QSpinBox:
    """Create a spin-box widget for an integer setting."""
    spin = QSpinBox()
    spin.setSingleStep(int(meta.step) if meta.step is not None else 1)
    spin.setMinimum(int(meta.min_value) if meta.min_value is not None else 0)
    spin.setMaximum(int(meta.max_value) if meta.max_value is not None else 99999)
    if meta.tooltip:
        spin.setToolTip(meta.tooltip)
    return spin


def create_integer_or_all_widget(meta: SettingMeta) -> QSpinBox:
    """Create a spin-box widget for an integer-or-all setting (0 displays as special text)."""
    spin = QSpinBox()
    spin.setSingleStep(int(meta.step) if meta.step is not None else 1)
    spin.setMinimum(0)
    spin.setMaximum(int(meta.max_value) if meta.max_value is not None else 99999)
    spin.setSpecialValueText(meta.special_value_text)
    if meta.tooltip:
        spin.setToolTip(meta.tooltip)
    return spin


def create_enum_widget(meta: SettingMeta) -> QComboBox:
    """Create a combo-box widget for an enum setting."""
    combo = QComboBox()
    if meta.allowed_values:
        combo.addItems(meta.allowed_values)
    if meta.tooltip:
        combo.setToolTip(meta.tooltip)
    return combo


def create_bool_or_enum_widget(meta: SettingMeta) -> QComboBox:
    """Create a combo-box widget for a bool-or-enum setting (first item is 'Disabled')."""
    combo = QComboBox()
    items = ['Disabled']
    if meta.allowed_values:
        items.extend(meta.allowed_values)
    combo.addItems(items)
    if meta.tooltip:
        combo.setToolTip(meta.tooltip)
    return combo


def create_column_tuple_widget(key: str, meta: SettingMeta) -> QGroupBox:
    """Create a scrollable multi-column grid of checkboxes for column visibility."""
    allowed_attr = meta.allowed_columns_attr or ''
    allowed_columns: tuple[str, ...] = getattr(Settings, allowed_attr, ())
    default_columns: tuple[str, ...] = tuple(SETTING_DEFAULTS.get(key, ()))

    title = meta.display_label
    if meta.requires_capture_restart:
        title += _RESTART_INDICATOR
    group = QGroupBox(title)
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
    for btn in (btn_select_all, btn_deselect_all, btn_reset):
        btn.setStyleSheet(COMPACT_BUTTON_STYLESHEET)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
    btn_select_all.clicked.connect(lambda: set_all_checkboxes(inner, checked=True))
    btn_deselect_all.clicked.connect(lambda: set_all_checkboxes(inner, checked=False))
    btn_reset.clicked.connect(lambda: set_checkboxes_to(inner, default_columns))

    btn_row = QHBoxLayout()
    btn_row.setContentsMargins(0, 0, 0, 0)
    btn_row.setSpacing(6)
    btn_row.addWidget(btn_select_all)
    btn_row.addWidget(btn_deselect_all)
    btn_row.addWidget(btn_reset)
    btn_row.addStretch()

    outer = QVBoxLayout(group)
    outer.setSpacing(4)
    outer.addLayout(btn_row)
    outer.addWidget(scroll, 1)
    return group


def create_ip_range_tuple_widget(meta: SettingMeta, parent: QWidget) -> QGroupBox:
    """Create an add/remove list widget for managing a tuple of IP addresses and ranges."""
    title = meta.display_label
    if meta.requires_capture_restart:
        title += _RESTART_INDICATOR
    group = QGroupBox(title)
    if meta.tooltip:
        group.setToolTip(meta.tooltip)

    list_widget = QListWidget()
    list_widget.setMaximumHeight(180)
    list_widget.setSelectionMode(QListWidget.SelectionMode.ExtendedSelection)
    list_widget.setSortingEnabled(True)

    add_button = QPushButton('\u2795 Add')
    add_button.setToolTip('Add a new blocked IP address, range, or subnet')
    add_button.setStyleSheet(COMPACT_BUTTON_STYLESHEET)
    add_button.setCursor(Qt.CursorShape.PointingHandCursor)
    add_button.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)

    remove_button = QPushButton('\U0001f5d1 Remove')
    remove_button.setToolTip('Remove the selected entries')
    remove_button.setStyleSheet(COMPACT_BUTTON_STYLESHEET)
    remove_button.setCursor(Qt.CursorShape.PointingHandCursor)
    remove_button.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)

    def _add_entry() -> None:
        dialog = IPRangeBuilderDialog(parent)
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

    add_button.clicked.connect(_add_entry)
    remove_button.clicked.connect(_remove_entries)

    btn_row = QHBoxLayout()
    btn_row.setContentsMargins(0, 0, 0, 0)
    btn_row.setSpacing(6)
    btn_row.addWidget(add_button)
    btn_row.addWidget(remove_button)
    btn_row.addStretch()

    outer_layout = QVBoxLayout(group)
    outer_layout.setSpacing(4)
    outer_layout.addLayout(btn_row)
    outer_layout.addWidget(list_widget, 1)
    return group


def set_all_checkboxes(container: QWidget, *, checked: bool) -> None:
    """Set all QCheckBox children of `container` to `checked`."""
    for cb in container.findChildren(QCheckBox):
        cb.setChecked(checked)


def set_checkboxes_to(container: QWidget, selected: tuple[str, ...]) -> None:
    """Check exactly the QCheckBox children whose objectName is in `selected`."""
    wanted = set(selected)
    for cb in container.findChildren(QCheckBox):
        cb.setChecked(cb.objectName() in wanted)
