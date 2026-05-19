"""Database settings panel mixin for the UserIP Databases Manager dialog."""

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.guis.utils import (
    SUSPEND_TOOLTIP_ADAPTIVE,
    SUSPEND_TOOLTIP_AUTO,
    SUSPEND_TOOLTIP_MANUAL,
)
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings import Settings

_MixinBase = QDialog


_SVG_COLOR_GROUPS: dict[str, list[str]] = {
    'Reds': [
        'red', 'darkred', 'firebrick', 'crimson', 'indianred',
        'lightcoral', 'salmon', 'darksalmon', 'lightsalmon', 'rosybrown',
        'tomato', 'orangered',
    ],
    'Pinks': [
        'pink', 'lightpink', 'hotpink', 'deeppink',
        'palevioletred', 'mediumvioletred',
    ],
    'Oranges': [
        'orange', 'darkorange', 'coral', 'chocolate', 'peru', 'sandybrown',
    ],
    'Browns': [
        'saddlebrown', 'sienna', 'brown', 'maroon', 'burlywood',
        'bisque', 'tan', 'wheat', 'moccasin', 'navajowhite',
        'peachpuff', 'papayawhip', 'blanchedalmond', 'antiquewhite',
    ],
    'Yellows': [
        'yellow', 'gold', 'goldenrod', 'darkgoldenrod', 'palegoldenrod',
        'lemonchiffon', 'lightyellow', 'lightgoldenrodyellow', 'khaki', 'darkkhaki',
    ],
    'Greens': [
        'greenyellow', 'yellowgreen', 'chartreuse', 'lawngreen',
        'lime', 'limegreen', 'palegreen', 'lightgreen',
        'green', 'darkgreen', 'forestgreen', 'springgreen',
        'mediumspringgreen', 'mediumseagreen', 'seagreen', 'darkseagreen',
        'olive', 'olivedrab', 'darkolivegreen', 'mediumaquamarine',
    ],
    'Cyans': [
        'aquamarine', 'turquoise', 'mediumturquoise', 'darkturquoise',
        'lightseagreen', 'darkcyan', 'teal',
        'cyan', 'aqua', 'lightcyan', 'paleturquoise', 'cadetblue',
    ],
    'Blues': [
        'powderblue', 'lightblue', 'lightskyblue', 'skyblue', 'deepskyblue',
        'cornflowerblue', 'steelblue', 'dodgerblue',
        'royalblue', 'blue', 'mediumblue', 'darkblue', 'navy', 'midnightblue',
        'lightsteelblue', 'slateblue', 'darkslateblue', 'mediumslateblue',
    ],
    'Purples & Magentas': [
        'blueviolet', 'indigo', 'darkviolet', 'darkorchid', 'darkmagenta',
        'purple', 'mediumorchid', 'mediumpurple', 'orchid',
        'violet', 'plum', 'thistle', 'lavender', 'magenta', 'fuchsia',
    ],
    'Whites & Light': [
        'white', 'snow', 'honeydew', 'mintcream', 'azure', 'aliceblue',
        'ghostwhite', 'whitesmoke', 'ivory', 'cornsilk', 'beige',
        'floralwhite', 'oldlace', 'linen', 'seashell', 'lavenderblush', 'mistyrose',
    ],
    'Grays & Black': [
        'gainsboro', 'lightgray', 'lightgrey', 'silver',
        'darkgray', 'darkgrey', 'gray', 'grey', 'dimgray', 'dimgrey',
        'lightslategray', 'lightslategrey', 'slategray', 'slategrey',
        'darkslategray', 'darkslategrey', 'black',
    ],
}

_SWATCH_COLS = 8
_SWATCH_W = 110
_SWATCH_H = 30


class _SVGColorPickerDialog(QDialog):
    """Modal dialog showing SVG named colors organized into labeled groups."""

    def __init__(self, initial_color: QColor, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle('Choose Color')
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint)
        self.resize(960, 580)

        self._chosen: QColor = QColor()
        self._chosen_name: str = ''

        outer = QVBoxLayout(self)
        outer.setSpacing(8)
        outer.setContentsMargins(10, 10, 10, 10)

        scroll_content = QWidget()
        content_layout = QVBoxLayout(scroll_content)
        content_layout.setSpacing(4)
        content_layout.setContentsMargins(4, 4, 4, 4)

        initial_hex = initial_color.name().lower() if initial_color.isValid() else ''

        for group_name, color_names in _SVG_COLOR_GROUPS.items():
            header = QLabel(group_name)
            header.setStyleSheet('color: #8ab4d4; font-size: 8pt; font-weight: bold; padding: 4px 0px 1px 2px;')
            content_layout.addWidget(header)

            sep = QFrame()
            sep.setFrameShape(QFrame.Shape.HLine)
            sep.setStyleSheet('color: #3a3a3a;')
            content_layout.addWidget(sep)

            group_widget = QWidget()
            grid = QGridLayout(group_widget)
            grid.setSpacing(2)
            grid.setContentsMargins(0, 0, 0, 2)

            for idx, name in enumerate(color_names):
                row, col = divmod(idx, _SWATCH_COLS)
                color = QColor(name)
                lum = 0.299 * color.red() + 0.587 * color.green() + 0.114 * color.blue()
                text_color = '#111111' if lum > 128 else '#eeeeee'  # noqa: PLR2004
                is_current = color.name().lower() == initial_hex
                border_color = '#ffffff' if is_current else '#555555'
                border_width = 3 if is_current else 1
                btn = QPushButton(name)
                btn.setFixedSize(_SWATCH_W, _SWATCH_H)
                btn.setAutoDefault(False)
                btn.setStyleSheet(
                    f'background-color: {color.name()}; color: {text_color};'
                    f' border: {border_width}px solid {border_color}; border-radius: 2px;'
                    ' font-size: 8pt; font-weight: bold; text-align: center;',
                )
                btn.clicked.connect(lambda _, n=name: self._pick(QColor(n), n))  # pyright: ignore[reportUnknownLambdaType]
                grid.addWidget(btn, row, col)

            content_layout.addWidget(group_widget)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(scroll_content)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        outer.addWidget(scroll)

        bottom = QHBoxLayout()
        no_color_btn = QPushButton('✖ No Color')
        no_color_btn.setAutoDefault(False)
        no_color_btn.setToolTip('Remove the color for this database')
        no_color_btn.clicked.connect(self._clear)
        bottom.addWidget(no_color_btn)
        bottom.addStretch()
        cancel_btn = QPushButton('Cancel')
        cancel_btn.setAutoDefault(False)
        cancel_btn.clicked.connect(self.reject)
        bottom.addWidget(cancel_btn)
        outer.addLayout(bottom)

    def _pick(self, color: QColor, name: str) -> None:
        self._chosen = color
        self._chosen_name = name
        self.accept()

    def _clear(self) -> None:
        self._chosen = QColor()
        self._chosen_name = ''
        self.accept()

    @classmethod
    def get_color(cls, initial: QColor, parent: QWidget | None = None) -> tuple[bool, QColor, str]:
        """Show the SVG color palette.

        Returns `(accepted, color, svg_name)`.
        `accepted=False` means the user cancelled — keep the existing color.
        An invalid *color* with an empty *svg_name* means the user cleared the color.
        """
        dlg = cls(initial, parent)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            return True, dlg._chosen, dlg._chosen_name
        return False, QColor(), ''


_SUSPEND_MODE_ADAPTIVE_INDEX = 2

_SETTINGS_CONTAINER_STYLESHEET = """
#SettingsContainer {
    border: 2px solid #4A90E2;
    border-radius: 8px;
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 rgba(74, 144, 226, 0.08), stop:1 rgba(74, 144, 226, 0.02));
}
"""

_SETTINGS_TOGGLE_STYLESHEET = """
QPushButton {
    background: transparent;
    border: none;
    color: #4A90E2;
    font-size: 11pt;
    font-weight: bold;
    text-align: left;
    padding: 4px 8px;
}
QPushButton:hover {
    color: #6DB3F2;
}
"""

_SETTINGS_BODY_STYLESHEET = """
QLabel {
    color: #b0bec5;
    font-size: 10pt;
    font-weight: normal;
    background: transparent;
}
QComboBox, QLineEdit, QDoubleSpinBox {
    background: #2d2d2d;
    color: #d4d4d4;
    border: 1px solid #555;
    border-radius: 4px;
    padding: 4px 8px;
    font-size: 10pt;
    min-height: 22px;
}
QComboBox:hover, QLineEdit:hover, QDoubleSpinBox:hover {
    border-color: #4A90E2;
}
QComboBox:disabled, QLineEdit:disabled, QDoubleSpinBox:disabled {
    background: #222;
    color: #555;
    border-color: #3a3a3a;
}
QLineEdit:focus {
    border-color: #4A90E2;
    background: #333;
}
QComboBox::drop-down {
    border: none;
    width: 20px;
}
QComboBox::down-arrow {
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-top: 6px solid #888;
    margin-right: 6px;
}
QComboBox QAbstractItemView {
    background: #2d2d2d;
    color: #d4d4d4;
    border: 1px solid #4A90E2;
    selection-background-color: #4A90E2;
    selection-color: white;
}
QPushButton {
    background: #3a3a3a;
    color: #d4d4d4;
    border: 1px solid #555;
    border-radius: 4px;
    font-size: 10pt;
    min-width: 28px;
    min-height: 24px;
    padding: 2px 6px;
}
QPushButton:hover {
    background: #4A90E2;
    color: white;
    border-color: #4A90E2;
}
"""


class SettingsPanelMixin(_MixinBase):  # pylint: disable=too-few-public-methods,too-many-instance-attributes
    """Mixin that builds and manages the database settings panel.

    Expects these attributes on the concrete class:
        _dirty, _settings_loading
    """

    # -- Attribute stubs for type checkers --
    _dirty: bool
    _settings_loading: bool
    _settings_container: QFrame
    _settings_toggle: QPushButton
    _settings_content: QWidget
    _settings_body: QWidget
    _setting_enabled: QCheckBox
    _setting_color: QPushButton
    _current_color: QColor
    _current_color_name: str
    _setting_log: QCheckBox
    _setting_notifications: QCheckBox
    _setting_voice: QComboBox
    _setting_protection: QCheckBox
    _protection_details: QWidget
    _setting_proc_path: QLineEdit
    _setting_suspend_mode: QComboBox
    _setting_suspend_custom: QSpinBox
    _settings_snapshot: dict[str, str]

    def _mark_settings_dirty(self) -> None: ...

    @staticmethod
    def _is_protection_supported() -> bool:
        """Return whether UserIP protection actions are currently supported."""
        return Settings.capture_program_preset == 'GTA5' and not CaptureState.is_neighbour_interface

    def _refresh_protection_visibility(self) -> None:
        """Refresh protection section visibility for current runtime capture mode."""
        self._protection_section.setVisible(self._is_protection_supported())

    def _build_settings_panel(self, parent_layout: QVBoxLayout) -> None:  # pylint: disable=too-many-statements
        """Construct the collapsible database settings panel and add it to the layout."""
        self._settings_container = QFrame()
        self._settings_container.setObjectName('SettingsContainer')
        self._settings_container.setStyleSheet(_SETTINGS_CONTAINER_STYLESHEET)
        self._settings_container.setVisible(False)

        group_outer = QVBoxLayout(self._settings_container)
        group_outer.setContentsMargins(8, 4, 8, 8)
        group_outer.setSpacing(0)

        self._settings_toggle = QPushButton('▼ ⚙ Database Settings')
        self._settings_toggle.setCursor(self._settings_toggle.cursor())
        self._settings_toggle.setStyleSheet(_SETTINGS_TOGGLE_STYLESHEET)
        self._settings_toggle.clicked.connect(self._on_settings_toggle_clicked)
        group_outer.addWidget(self._settings_toggle)

        self._settings_content = QWidget()
        self._settings_content.setStyleSheet(_SETTINGS_BODY_STYLESHEET)
        content = QVBoxLayout(self._settings_content)
        content.setContentsMargins(0, 0, 0, 0)
        content.setSpacing(8)

        # ── Row 1: Enabled only ──
        row1 = QHBoxLayout()
        row1.setSpacing(14)

        self._setting_enabled = QCheckBox('Enabled')
        self._setting_enabled.setToolTip('Whether this database is active for detection')
        self._setting_enabled.toggled.connect(self._on_enabled_changed)
        row1.addWidget(self._setting_enabled)

        row1.addStretch()
        content.addLayout(row1)

        # ── Body: hidden when Enabled is unchecked ──
        self._settings_body = QWidget()
        body_layout = QVBoxLayout(self._settings_body)
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(8)

        # ── Color · Log · Notifications ──
        row_cln = QHBoxLayout()
        row_cln.setSpacing(14)

        color_lbl = QLabel('Color:')
        row_cln.addWidget(color_lbl)

        self._current_color = QColor()
        self._setting_color = QPushButton()
        self._setting_color.setFixedSize(52, 26)
        self._setting_color.setToolTip('Click to choose a display color for entries from this database')
        self._setting_color.setAutoDefault(False)
        self._setting_color.clicked.connect(self._on_color_button_clicked)
        self._update_color_button()
        row_cln.addWidget(self._setting_color)

        self._setting_log = QCheckBox('Log')
        self._setting_log.setToolTip('Log connections from IPs in this database')
        self._setting_log.toggled.connect(self._on_setting_changed)
        row_cln.addWidget(self._setting_log)

        self._setting_notifications = QCheckBox('Notifications')
        self._setting_notifications.setToolTip('Show popup notifications when IPs from this database connect')
        self._setting_notifications.toggled.connect(self._on_setting_changed)
        row_cln.addWidget(self._setting_notifications)

        row_cln.addStretch()
        body_layout.addLayout(row_cln)

        # ── Row 2: Voice ──
        row2 = QHBoxLayout()
        row2.setSpacing(8)

        voice_lbl = QLabel('Voice:')
        row2.addWidget(voice_lbl)

        self._setting_voice = QComboBox()
        self._setting_voice.addItems(['Disabled', 'Male', 'Female'])
        self._setting_voice.setToolTip('Text-to-speech voice for notifications')
        self._setting_voice.setMinimumWidth(120)
        self._setting_voice.currentIndexChanged.connect(self._on_setting_changed)
        row2.addWidget(self._setting_voice)

        row2.addStretch()
        body_layout.addLayout(row2)

        # ── Protection section (hidden for neighbour interface / console scanning) ──
        self._protection_section = QWidget()
        protection_section_layout = QVBoxLayout(self._protection_section)
        protection_section_layout.setContentsMargins(0, 0, 0, 0)
        protection_section_layout.setSpacing(8)

        # ── Separator ──
        separator = QFrame()
        separator.setFrameShape(QFrame.Shape.HLine)
        separator.setFixedHeight(1)
        separator.setStyleSheet('background-color: rgba(74, 144, 226, 0.2); border: none;')
        protection_section_layout.addWidget(separator)

        prot_row = QHBoxLayout()

        self._setting_protection = QCheckBox('Protection')
        self._setting_protection.setToolTip('Suspend the target process when an IP from this database connects')
        self._setting_protection.toggled.connect(self._on_protection_changed)
        prot_row.addWidget(self._setting_protection)

        prot_row.addStretch()
        protection_section_layout.addLayout(prot_row)

        # ── Protection Details (enabled/disabled by Protection combo) ──
        self._protection_details = QWidget()
        prot_form = QFormLayout(self._protection_details)
        prot_form.setContentsMargins(0, 2, 0, 0)
        prot_form.setHorizontalSpacing(12)
        prot_form.setVerticalSpacing(6)

        proc_row = QHBoxLayout()
        self._setting_proc_path = QLineEdit()
        self._setting_proc_path.setPlaceholderText('None')
        self._setting_proc_path.setToolTip('Path to the process to protect')
        self._setting_proc_path.textChanged.connect(self._on_setting_changed)
        proc_row.addWidget(self._setting_proc_path)
        proc_browse = QPushButton('…')
        proc_browse.setFixedWidth(30)
        proc_browse.setToolTip('Browse for process executable')
        proc_browse.clicked.connect(lambda: self._browse_path(self._setting_proc_path))
        proc_row.addWidget(proc_browse)
        prot_form.addRow('Process Path:', proc_row)

        suspend_row = QHBoxLayout()
        self._setting_suspend_mode = QComboBox()
        self._setting_suspend_mode.addItems(['Auto', 'Manual', 'Adaptive'])
        self._setting_suspend_mode.setItemData(0, SUSPEND_TOOLTIP_AUTO, Qt.ItemDataRole.ToolTipRole)
        self._setting_suspend_mode.setItemData(1, SUSPEND_TOOLTIP_MANUAL, Qt.ItemDataRole.ToolTipRole)
        self._setting_suspend_mode.setItemData(2, SUSPEND_TOOLTIP_ADAPTIVE, Qt.ItemDataRole.ToolTipRole)
        self._setting_suspend_mode.currentIndexChanged.connect(self._on_suspend_mode_changed)
        suspend_row.addWidget(self._setting_suspend_mode)
        self._setting_suspend_custom = QSpinBox()
        self._setting_suspend_custom.setSingleStep(1)
        self._setting_suspend_custom.setMinimum(0)
        self._setting_suspend_custom.setMaximum(99999)
        self._setting_suspend_custom.setToolTip('Fixed suspend duration in seconds')
        self._setting_suspend_custom.setVisible(False)
        self._setting_suspend_custom.valueChanged.connect(self._on_setting_changed)
        suspend_row.addWidget(self._setting_suspend_custom)
        prot_form.addRow('Suspend Mode:', suspend_row)

        protection_section_layout.addWidget(self._protection_details)

        body_layout.addWidget(self._protection_section)
        content.addWidget(self._settings_body)

        group_outer.addWidget(self._settings_content)
        parent_layout.addWidget(self._settings_container)

        self._settings_loading = False

    # ------------------------------------------------------------------
    # Populate / read
    # ------------------------------------------------------------------

    def _populate_settings_widgets(self, settings_dict: dict[str, str]) -> None:
        """Populate settings widgets from a parsed settings dictionary, suppressing dirty signals."""
        self._settings_loading = True

        self._setting_enabled.setChecked(settings_dict.get('ENABLED', 'True').strip().lower() == 'true')
        raw_color = settings_dict.get('COLOR', '').strip()
        self._current_color = QColor(raw_color) if raw_color and QColor(raw_color).isValid() else QColor()
        self._current_color_name = raw_color if self._current_color.isValid() else ''
        self._update_color_button()
        self._setting_log.setChecked(settings_dict.get('LOG', 'True').strip().lower() == 'true')
        self._setting_notifications.setChecked(settings_dict.get('NOTIFICATIONS', 'True').strip().lower() == 'true')

        voice_val = settings_dict.get('VOICE_NOTIFICATIONS', 'False').strip()
        voice_map = {'false': 0, 'male': 1, 'female': 2}
        self._setting_voice.setCurrentIndex(voice_map.get(voice_val.lower(), 0))

        prot_val = settings_dict.get('PROTECTION', 'False').strip()
        self._setting_protection.setChecked(prot_val.lower() not in ('false', '0', ''))

        proc_path = settings_dict.get('PROTECTION_PROCESS_PATH', 'None').strip()
        self._setting_proc_path.setText('' if proc_path.lower() == 'none' else proc_path)

        suspend_val = settings_dict.get('PROTECTION_SUSPEND_PROCESS_MODE', 'Auto').strip()
        if suspend_val.lower() == 'auto':
            self._setting_suspend_mode.setCurrentIndex(0)
            self._setting_suspend_custom.setVisible(False)
        elif suspend_val.lower() == 'manual':
            self._setting_suspend_mode.setCurrentIndex(1)
            self._setting_suspend_custom.setVisible(True)
        elif suspend_val.lower() == 'adaptive':
            self._setting_suspend_mode.setCurrentIndex(_SUSPEND_MODE_ADAPTIVE_INDEX)
            self._setting_suspend_custom.setVisible(False)
        else:
            self._setting_suspend_mode.setCurrentIndex(1)
            self._setting_suspend_custom.setVisible(True)
            try:
                if suspend_val.startswith('Manual(') and suspend_val.endswith(')'):
                    self._setting_suspend_custom.setValue(int(suspend_val.removeprefix('Manual(').removesuffix(')')))
                else:
                    self._setting_suspend_custom.setValue(int(suspend_val))
            except ValueError:
                self._setting_suspend_custom.setValue(0)

        self._update_protection_fields_enabled()
        self._update_enabled_body_visible()

        self._refresh_protection_visibility()

        self._settings_loading = False

    def _read_settings_from_widgets(self) -> dict[str, str]:
        """Read current widget values and return a settings dictionary for serialization."""
        settings: dict[str, str] = {}

        settings['ENABLED'] = str(self._setting_enabled.isChecked())
        settings['COLOR'] = self._current_color_name
        settings['LOG'] = str(self._setting_log.isChecked())
        settings['NOTIFICATIONS'] = str(self._setting_notifications.isChecked())

        voice_idx = self._setting_voice.currentIndex()
        settings['VOICE_NOTIFICATIONS'] = ['False', 'Male', 'Female'][voice_idx]

        if not self._is_protection_supported():
            settings['PROTECTION'] = 'False'
        else:
            settings['PROTECTION'] = 'Suspend_Process' if self._setting_protection.isChecked() else 'False'

        proc_text = self._setting_proc_path.text().strip()
        settings['PROTECTION_PROCESS_PATH'] = proc_text or 'None'

        suspend_idx = self._setting_suspend_mode.currentIndex()
        if not suspend_idx:
            settings['PROTECTION_SUSPEND_PROCESS_MODE'] = 'Auto'
        elif suspend_idx == 1:
            settings['PROTECTION_SUSPEND_PROCESS_MODE'] = f'Manual({self._setting_suspend_custom.value()})'
        elif suspend_idx == _SUSPEND_MODE_ADAPTIVE_INDEX:
            settings['PROTECTION_SUSPEND_PROCESS_MODE'] = 'Adaptive'

        return settings

    # ------------------------------------------------------------------
    # Signals
    # ------------------------------------------------------------------

    def _on_setting_changed(self) -> None:
        """Mark database as dirty when any setting widget changes."""
        if not self._settings_loading:
            self._mark_settings_dirty()

    def _on_enabled_changed(self) -> None:
        """Show/hide all settings below Enabled based on the checkbox state."""
        self._update_enabled_body_visible()
        self._on_setting_changed()

    def _on_color_button_clicked(self) -> None:
        """Open the SVG color palette and update the stored color."""
        accepted, chosen, name = _SVGColorPickerDialog.get_color(self._current_color, self)
        if accepted:
            self._current_color = chosen
            self._current_color_name = name
            self._update_color_button()
            self._on_setting_changed()

    def _update_color_button(self) -> None:
        """Refresh the color button's background to reflect the current color."""
        if self._current_color.isValid():
            self._setting_color.setStyleSheet(
                f'background-color: {self._current_color.name()}; border: 1px solid #555; border-radius: 4px;',
            )
        else:
            self._setting_color.setStyleSheet('background-color: transparent; border: 1px solid #555; border-radius: 4px;')

    def _on_protection_changed(self) -> None:
        """Update protection field enabled state and mark dirty."""
        self._update_protection_fields_enabled()
        self._on_setting_changed()

    def _on_suspend_mode_changed(self, index: int) -> None:
        """Show/hide the custom duration spin box based on suspend mode selection."""
        self._setting_suspend_custom.setVisible(index == 1)
        self._on_setting_changed()

    def _update_protection_fields_enabled(self) -> None:
        """Show/hide protection sub-fields based on the protection checkbox."""
        self._protection_details.setVisible(self._setting_protection.isChecked())

    def _update_enabled_body_visible(self) -> None:
        """Show/hide all settings below Enabled based on the checkbox state."""
        self._settings_body.setVisible(self._setting_enabled.isChecked())

    def _on_settings_toggle_clicked(self) -> None:
        """Toggle the settings content visibility and update the arrow indicator."""
        visible = not self._settings_content.isVisible()
        self._settings_content.setVisible(visible)
        arrow = '▼' if visible else '▶'
        self._settings_toggle.setText(f'{arrow} ⚙ Database Settings')

    @staticmethod
    def _browse_path(line_edit: QLineEdit) -> None:
        """Open a file dialog and set the selected path into the given QLineEdit."""
        path, _ = QFileDialog.getOpenFileName(
            None,
            'Select Executable',
            '',
            'Executables (*.exe);;All Files (*)',
        )
        if path:
            line_edit.setText(path)
