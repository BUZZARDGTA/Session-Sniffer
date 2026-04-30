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
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.settings import Settings

_MixinBase = QDialog


_SUSPEND_MODE_ADAPTIVE_INDEX = 2
_SUSPEND_MODE_CUSTOM_INDEX = 3

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
QCheckBox {
    color: #d4d4d4;
    font-size: 10pt;
    spacing: 6px;
}
QCheckBox::indicator {
    width: 16px;
    height: 16px;
    border: 2px solid #555;
    border-radius: 3px;
    background: #2d2d2d;
}
QCheckBox::indicator:checked {
    background: #4A90E2;
    border-color: #4A90E2;
}
QCheckBox::indicator:hover {
    border-color: #4A90E2;
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
    _setting_enabled: QCheckBox
    _setting_color: QLineEdit
    _color_swatch: QLabel
    _setting_log: QCheckBox
    _setting_notifications: QCheckBox
    _setting_voice: QComboBox
    _setting_protection: QCheckBox
    _protection_details: QWidget
    _setting_proc_path: QLineEdit
    _setting_suspend_mode: QComboBox
    _setting_suspend_custom: QSpinBox

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

        # ── Row 1: Enabled · Color · Log · Notifications ──
        row1 = QHBoxLayout()
        row1.setSpacing(14)

        self._setting_enabled = QCheckBox('Enabled')
        self._setting_enabled.setToolTip('Whether this database is active for detection')
        self._setting_enabled.toggled.connect(self._on_setting_changed)
        row1.addWidget(self._setting_enabled)

        color_lbl = QLabel('Color:')
        row1.addWidget(color_lbl)

        self._setting_color = QLineEdit()
        self._setting_color.setPlaceholderText('e.g. RED, #FF00FF')
        self._setting_color.setToolTip('Display color for entries from this database (Qt color name or hex)')
        self._setting_color.setFixedWidth(180)
        self._setting_color.textChanged.connect(self._on_color_text_changed)
        row1.addWidget(self._setting_color)

        self._color_swatch = QLabel()
        self._color_swatch.setFixedSize(26, 26)
        self._color_swatch.setStyleSheet('background-color: transparent; border: 1px solid #555; border-radius: 4px;')
        row1.addWidget(self._color_swatch)

        self._setting_log = QCheckBox('Log')
        self._setting_log.setToolTip('Log connections from IPs in this database')
        self._setting_log.toggled.connect(self._on_setting_changed)
        row1.addWidget(self._setting_log)

        self._setting_notifications = QCheckBox('Notifications')
        self._setting_notifications.setToolTip('Show popup notifications when IPs from this database connect')
        self._setting_notifications.toggled.connect(self._on_setting_changed)
        row1.addWidget(self._setting_notifications)

        row1.addStretch()
        content.addLayout(row1)

        # ── Row 2: Voice · Protection ──
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
        content.addLayout(row2)

        # ── Protection section (hidden for ARP / console scanning) ──
        self._protection_section = QWidget()
        protection_section_layout = QVBoxLayout(self._protection_section)
        protection_section_layout.setContentsMargins(0, 0, 0, 0)
        protection_section_layout.setSpacing(8)

        prot_row = QHBoxLayout()

        self._setting_protection = QCheckBox('Protection')
        self._setting_protection.setToolTip('Suspend the target process when an IP from this database connects')
        self._setting_protection.toggled.connect(self._on_protection_changed)
        prot_row.addWidget(self._setting_protection)

        prot_row.addStretch()
        protection_section_layout.addLayout(prot_row)

        # ── Separator ──
        separator = QFrame()
        separator.setFrameShape(QFrame.Shape.HLine)
        separator.setFixedHeight(1)
        separator.setStyleSheet('background-color: rgba(74, 144, 226, 0.2); border: none;')
        protection_section_layout.addWidget(separator)

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
        self._setting_suspend_mode.addItems(['Auto', 'Manual', 'Adaptive', 'Custom'])
        self._setting_suspend_mode.setItemData(
            0,
            'Resume when the hostile player fully disconnects.\n'
            '\u2022 Robustness: High \u2013 game stays frozen until the threat is gone.\n'
            '\u2022 Freeze time: Moderate \u2013 depends on how long the player stays.',
            Qt.ItemDataRole.ToolTipRole,
        )
        self._setting_suspend_mode.setItemData(
            1,
            'Remain suspended indefinitely (must be resumed manually).\n'
            '\u2022 Robustness: Maximum \u2013 nothing resumes automatically.\n'
            '\u2022 Freeze time: Longest \u2013 game stays frozen until you intervene.',
            Qt.ItemDataRole.ToolTipRole,
        )
        self._setting_suspend_mode.setItemData(
            2,
            'PPS-based smart suspend/resume.\n'
            'Temporarily resumes while the hostile player is idle (0 packets/sec)\n'
            'and re-suspends as soon as activity is detected.\n'
            '\u2022 Robustness: Moderate \u2013 idle players may still be connected.\n'
            '\u2022 Freeze time: Shortest \u2013 game is only frozen during active traffic.',
            Qt.ItemDataRole.ToolTipRole,
        )
        self._setting_suspend_mode.setItemData(
            3,
            'Resume after a fixed number of seconds.\n'
            '\u2022 Robustness: Low \u2013 timer may expire while the threat is still active.\n'
            '\u2022 Freeze time: Fixed \u2013 exactly the duration you specify.',
            Qt.ItemDataRole.ToolTipRole,
        )
        self._setting_suspend_mode.currentIndexChanged.connect(self._on_suspend_mode_changed)
        suspend_row.addWidget(self._setting_suspend_mode)
        self._setting_suspend_custom = QSpinBox()
        self._setting_suspend_custom.setSingleStep(1)
        self._setting_suspend_custom.setMinimum(0)
        self._setting_suspend_custom.setMaximum(99999)
        self._setting_suspend_custom.setToolTip('Custom suspend duration in seconds')
        self._setting_suspend_custom.setVisible(False)
        self._setting_suspend_custom.valueChanged.connect(self._on_setting_changed)
        suspend_row.addWidget(self._setting_suspend_custom)
        prot_form.addRow('Suspend Mode:', suspend_row)

        protection_section_layout.addWidget(self._protection_details)

        content.addWidget(self._protection_section)

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
        self._setting_color.setText(settings_dict.get('COLOR', ''))
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
            self._setting_suspend_custom.setVisible(False)
        elif suspend_val.lower() == 'adaptive':
            self._setting_suspend_mode.setCurrentIndex(_SUSPEND_MODE_ADAPTIVE_INDEX)
            self._setting_suspend_custom.setVisible(False)
        else:
            self._setting_suspend_mode.setCurrentIndex(_SUSPEND_MODE_CUSTOM_INDEX)
            self._setting_suspend_custom.setVisible(True)
            try:
                self._setting_suspend_custom.setValue(int(suspend_val))
            except ValueError:
                self._setting_suspend_custom.setValue(0)

        self._update_protection_fields_enabled()

        if not Settings.is_protection_supported:
            self._protection_section.setVisible(False)

        self._settings_loading = False

    def _read_settings_from_widgets(self) -> dict[str, str]:
        """Read current widget values and return a settings dictionary for serialization."""
        settings: dict[str, str] = {}

        settings['ENABLED'] = str(self._setting_enabled.isChecked())
        settings['COLOR'] = self._setting_color.text().strip()
        settings['LOG'] = str(self._setting_log.isChecked())
        settings['NOTIFICATIONS'] = str(self._setting_notifications.isChecked())

        voice_idx = self._setting_voice.currentIndex()
        settings['VOICE_NOTIFICATIONS'] = ['False', 'Male', 'Female'][voice_idx]

        if not Settings.is_protection_supported:
            settings['PROTECTION'] = 'False'
        else:
            settings['PROTECTION'] = 'Suspend_Process' if self._setting_protection.isChecked() else 'False'

        proc_text = self._setting_proc_path.text().strip()
        settings['PROTECTION_PROCESS_PATH'] = proc_text or 'None'

        suspend_idx = self._setting_suspend_mode.currentIndex()
        if not suspend_idx:
            settings['PROTECTION_SUSPEND_PROCESS_MODE'] = 'Auto'
        elif suspend_idx == 1:
            settings['PROTECTION_SUSPEND_PROCESS_MODE'] = 'Manual'
        elif suspend_idx == _SUSPEND_MODE_ADAPTIVE_INDEX:
            settings['PROTECTION_SUSPEND_PROCESS_MODE'] = 'Adaptive'
        else:
            val = self._setting_suspend_custom.value()
            settings['PROTECTION_SUSPEND_PROCESS_MODE'] = str(val)

        return settings

    # ------------------------------------------------------------------
    # Signals
    # ------------------------------------------------------------------

    def _on_setting_changed(self) -> None:
        """Mark database as dirty when any setting widget changes."""
        if not self._settings_loading:
            self._dirty = True

    def _on_color_text_changed(self, text: str) -> None:
        """Update the color swatch preview and mark dirty."""
        color = QColor(text.strip())
        if color.isValid():
            self._color_swatch.setStyleSheet(f'background-color: {color.name()}; border: 1px solid #555; border-radius: 4px;')
        else:
            self._color_swatch.setStyleSheet('background-color: transparent; border: 1px solid #555; border-radius: 4px;')
        self._on_setting_changed()

    def _on_protection_changed(self) -> None:
        """Update protection field enabled state and mark dirty."""
        self._update_protection_fields_enabled()
        self._on_setting_changed()

    def _on_suspend_mode_changed(self, index: int) -> None:
        """Show/hide the custom duration spin box based on suspend mode selection."""
        self._setting_suspend_custom.setVisible(index == _SUSPEND_MODE_CUSTOM_INDEX)
        self._on_setting_changed()

    def _update_protection_fields_enabled(self) -> None:
        """Enable/disable protection sub-fields based on the protection checkbox."""
        self._protection_details.setEnabled(self._setting_protection.isChecked())

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
