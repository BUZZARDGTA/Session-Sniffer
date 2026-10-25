"""Database settings panel mixin for the UserIP Databases Manager dialog."""

from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.local import RESOURCES_DIR_PATH
from session_sniffer.constants.standalone import MAX_SUSPEND_DURATION_SECONDS
from session_sniffer.guis._combo_rule_editor import (
    read_duration_widgets_helper,
    read_voice_combo_helper,
    set_duration_widgets_helper,
    set_voice_combo_helper,
)
from session_sniffer.guis.color_picker_dialog import ColorPickerButton
from session_sniffer.guis.stylesheets import (
    SETTINGS_SEPARATOR_STYLESHEET,
    USERIP_SETTINGS_BODY_STYLESHEET,
    USERIP_SETTINGS_CONTAINER_STYLESHEET,
    USERIP_SETTINGS_TOGGLE_STYLESHEET,
)
from session_sniffer.guis.utils import (
    SUSPEND_TOOLTIP_AUTO,
    SUSPEND_TOOLTIP_DISABLED,
    SUSPEND_TOOLTIP_MANUAL,
)
from session_sniffer.models.userip_settings_model import UserIPSettingsModel
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings import Settings
from session_sniffer.text_utils import DEFAULT_MANUAL_SUSPEND_DURATION_SECONDS


class SettingsPanelMixin(QDialog):
    """Mixin that builds and manages the database settings panel.

    Expects these attributes on the concrete class:
        _settings_loading
    """

    # -- Attribute stubs for type checkers --
    _settings_loading: bool
    _settings_container: QFrame
    _settings_toggle: QPushButton
    _settings_content: QWidget
    _settings_body: QWidget
    _setting_enabled: QCheckBox
    _setting_color: ColorPickerButton
    _setting_log: QCheckBox
    _setting_notifications: QCheckBox
    _setting_voice: QComboBox
    _setting_suspend_mode: QComboBox
    _setting_suspend_custom: QSpinBox

    def _mark_settings_dirty(self) -> None: ...

    @staticmethod
    def _is_protection_supported() -> bool:
        """Return whether UserIP protection actions are currently supported."""
        return Settings.is_gta5_feature_set() and CaptureState.is_local_capture()

    def _refresh_protection_visibility(self) -> None:
        """Refresh protection section visibility for current runtime capture mode."""
        self._protection_section.setVisible(self._is_protection_supported())

    def build_settings_panel(self, parent_layout: QVBoxLayout) -> None:
        """Construct the collapsible database settings panel and add it to the layout."""
        self._settings_container = QFrame()
        self._settings_container.setObjectName('SettingsContainer')
        self._settings_container.setStyleSheet(USERIP_SETTINGS_CONTAINER_STYLESHEET)
        self._settings_container.setVisible(False)

        group_outer = QVBoxLayout(self._settings_container)
        group_outer.setContentsMargins(8, 4, 8, 8)
        group_outer.setSpacing(0)

        self._icon_arrow_right = QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'chevron-right.svg'))
        self._icon_arrow_down = QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'chevron-down.svg'))
        self._settings_toggle = QPushButton(self._icon_arrow_right, ' Database Settings')
        self._settings_toggle.setAutoDefault(False)
        self._settings_toggle.setCursor(Qt.CursorShape.PointingHandCursor)
        self._settings_toggle.setStyleSheet(USERIP_SETTINGS_TOGGLE_STYLESHEET)
        self._settings_toggle.clicked.connect(self._on_settings_toggle_clicked)
        group_outer.addWidget(self._settings_toggle)

        self._settings_content = QWidget()
        self._settings_content.setStyleSheet(USERIP_SETTINGS_BODY_STYLESHEET)
        self._settings_content.setVisible(False)
        content = QVBoxLayout(self._settings_content)
        content.setContentsMargins(4, 8, 4, 0)
        content.setSpacing(8)

        # ── Row 1: Enabled only ──
        row1 = QHBoxLayout()
        row1.setSpacing(14)
        row1.setAlignment(Qt.AlignmentFlag.AlignVCenter)

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
        row_cln.setAlignment(Qt.AlignmentFlag.AlignVCenter)

        color_lbl = QLabel('Color:')
        row_cln.addWidget(color_lbl)

        self._setting_color = ColorPickerButton(self)
        self._setting_color.setObjectName('DatabaseColorButton')
        self._setting_color.setToolTip('Click to choose a display color for entries from this database')
        self._setting_color.color_changed.connect(self._on_setting_changed)
        row_cln.addWidget(self._setting_color)

        self._setting_log = QCheckBox('Log')
        self._setting_log.setToolTip('Log connections from IPs in this database')
        self._setting_log.toggled.connect(self._on_setting_changed)
        row_cln.addWidget(self._setting_log)

        self._setting_notifications = QCheckBox('Notifications')
        self._setting_notifications.setToolTip('Show popup notifications when IPs from this database connect')
        self._setting_notifications.toggled.connect(self._on_setting_changed)
        row_cln.addWidget(self._setting_notifications)

        voice_lbl = QLabel('Voice:')
        row_cln.addWidget(voice_lbl)

        self._setting_voice = QComboBox()
        self._setting_voice.addItems(['Disabled', 'Male', 'Female'])
        self._setting_voice.setToolTip('Text-to-speech voice for notifications')
        self._setting_voice.setMinimumWidth(120)
        self._setting_voice.currentIndexChanged.connect(self._on_setting_changed)
        row_cln.addWidget(self._setting_voice)

        row_cln.addStretch()
        body_layout.addLayout(row_cln)

        # ── Protection section (hidden for neighbour interface / console scanning) ──
        self._protection_section = QWidget()
        protection_section_layout = QVBoxLayout(self._protection_section)
        protection_section_layout.setContentsMargins(0, 0, 0, 0)
        protection_section_layout.setSpacing(8)

        # ── Separator ──
        separator = QFrame()
        separator.setFrameShape(QFrame.Shape.HLine)
        separator.setFixedHeight(1)
        separator.setStyleSheet(SETTINGS_SEPARATOR_STYLESHEET)
        protection_section_layout.addWidget(separator)

        suspend_row = QHBoxLayout()
        suspend_row.setAlignment(Qt.AlignmentFlag.AlignVCenter)
        suspend_row.addWidget(QLabel('Suspend Mode:'))
        self._setting_suspend_mode = QComboBox()
        self._setting_suspend_mode.addItems(['Disabled', 'Auto', 'Manual'])
        self._setting_suspend_mode.setItemData(0, SUSPEND_TOOLTIP_DISABLED, Qt.ItemDataRole.ToolTipRole)
        self._setting_suspend_mode.setItemData(1, SUSPEND_TOOLTIP_AUTO, Qt.ItemDataRole.ToolTipRole)
        self._setting_suspend_mode.setItemData(2, SUSPEND_TOOLTIP_MANUAL, Qt.ItemDataRole.ToolTipRole)
        self._setting_suspend_mode.currentTextChanged.connect(self._on_suspend_mode_changed)
        suspend_row.addWidget(self._setting_suspend_mode)
        self._setting_suspend_custom = QSpinBox()
        self._setting_suspend_custom.setRange(1, MAX_SUSPEND_DURATION_SECONDS)
        self._setting_suspend_custom.setValue(DEFAULT_MANUAL_SUSPEND_DURATION_SECONDS)
        self._setting_suspend_custom.setSuffix(' seconds')
        self._setting_suspend_custom.setToolTip('Fixed suspend duration in seconds')
        self._setting_suspend_custom.setVisible(False)
        self._setting_suspend_custom.valueChanged.connect(self._on_setting_changed)
        suspend_row.addWidget(self._setting_suspend_custom)
        suspend_row.addStretch()
        protection_section_layout.addLayout(suspend_row)

        body_layout.addWidget(self._protection_section)
        content.addWidget(self._settings_body)

        group_outer.addWidget(self._settings_content)
        parent_layout.addWidget(self._settings_container)

        self._settings_loading = False

    # ------------------------------------------------------------------
    # Populate / read
    # ------------------------------------------------------------------

    def populate_settings_widgets(self, settings: UserIPSettingsModel) -> None:
        """Populate settings widgets from a `UserIPSettingsModel`, suppressing dirty signals."""
        self._settings_loading = True

        self._setting_enabled.setChecked(settings.ENABLED)
        self._setting_color.set_color(settings.COLOR)
        self._setting_log.setChecked(settings.LOG)
        self._setting_notifications.setChecked(settings.NOTIFICATIONS)

        set_voice_combo_helper(self._setting_voice, value=settings.VOICE_NOTIFICATIONS)
        set_duration_widgets_helper(
            self._setting_suspend_mode,
            self._setting_suspend_custom,
            settings.PROTECTION_SUSPEND_PROCESS_MODE if settings.PROTECTION else 'Disabled',
        )

        self._update_enabled_body_visible()

        self._refresh_protection_visibility()

        self._settings_loading = False

    def read_settings_from_widgets(self) -> UserIPSettingsModel:
        """Read current widget values and return a `UserIPSettingsModel` for serialization."""
        voice_notifications = read_voice_combo_helper(self._setting_voice)
        protection_enabled = self._setting_suspend_mode.currentText() != 'Disabled'
        suspend_mode = read_duration_widgets_helper(self._setting_suspend_mode, self._setting_suspend_custom) if protection_enabled else 'Auto'

        return UserIPSettingsModel(
            ENABLED=self._setting_enabled.isChecked(),
            COLOR=self._setting_color.color(),
            LOG=self._setting_log.isChecked(),
            NOTIFICATIONS=self._setting_notifications.isChecked(),
            VOICE_NOTIFICATIONS=voice_notifications,
            PROTECTION=protection_enabled,
            PROTECTION_SUSPEND_PROCESS_MODE=suspend_mode,
        )

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

    def _on_suspend_mode_changed(self, text: str) -> None:
        """Show/hide the custom duration spin box based on suspend mode selection."""
        is_manual = text == 'Manual'
        if is_manual and self._setting_suspend_custom.value() <= 0:
            self._setting_suspend_custom.setValue(DEFAULT_MANUAL_SUSPEND_DURATION_SECONDS)
        self._setting_suspend_custom.setVisible(is_manual)
        self._on_setting_changed()

    def _update_enabled_body_visible(self) -> None:
        """Show/hide all settings below Enabled based on the checkbox state."""
        self._settings_body.setVisible(self._setting_enabled.isChecked())

    def _on_settings_toggle_clicked(self) -> None:
        """Toggle the settings content visibility and update the arrow indicator."""
        visible = not self._settings_content.isVisible()
        self._settings_content.setVisible(visible)
        self._settings_toggle.setIcon(self._icon_arrow_down if visible else self._icon_arrow_right)
