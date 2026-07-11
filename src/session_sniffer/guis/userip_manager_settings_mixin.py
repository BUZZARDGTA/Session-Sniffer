"""Database settings panel mixin for the UserIP Databases Manager dialog."""

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QIcon
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.local import RESOURCES_DIR_PATH
from session_sniffer.guis.stylesheets import (
    COLOR_BUTTON_EMPTY_STYLESHEET,
    COLOR_SWATCH_GROUP_HEADER_STYLESHEET,
    COLOR_SWATCH_SEPARATOR_STYLESHEET,
    SETTINGS_SEPARATOR_STYLESHEET,
    USERIP_SETTINGS_BODY_STYLESHEET,
    USERIP_SETTINGS_CONTAINER_STYLESHEET,
    USERIP_SETTINGS_TOGGLE_STYLESHEET,
    color_button_filled_stylesheet,
    color_swatch_button_stylesheet,
)
from session_sniffer.guis.utils import (
    SUSPEND_TOOLTIP_AUTO,
    SUSPEND_TOOLTIP_DISABLED,
    SUSPEND_TOOLTIP_MANUAL,
)
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings import Settings

_SVG_COLOR_GROUPS: dict[str, list[str]] = {
    'Reds': [
        'red',
        'darkred',
        'firebrick',
        'crimson',
        'indianred',
        'lightcoral',
        'salmon',
        'darksalmon',
        'lightsalmon',
        'rosybrown',
        'tomato',
        'orangered',
    ],
    'Pinks': [
        'pink',
        'lightpink',
        'hotpink',
        'deeppink',
        'palevioletred',
        'mediumvioletred',
    ],
    'Oranges': [
        'orange',
        'darkorange',
        'coral',
        'chocolate',
        'peru',
        'sandybrown',
    ],
    'Browns': [
        'saddlebrown',
        'sienna',
        'brown',
        'maroon',
        'burlywood',
        'bisque',
        'tan',
        'wheat',
        'moccasin',
        'navajowhite',
        'peachpuff',
        'papayawhip',
        'blanchedalmond',
        'antiquewhite',
    ],
    'Yellows': [
        'yellow',
        'gold',
        'goldenrod',
        'darkgoldenrod',
        'palegoldenrod',
        'lemonchiffon',
        'lightyellow',
        'lightgoldenrodyellow',
        'khaki',
        'darkkhaki',
    ],
    'Greens': [
        'greenyellow',
        'yellowgreen',
        'chartreuse',
        'lawngreen',
        'lime',
        'limegreen',
        'palegreen',
        'lightgreen',
        'green',
        'darkgreen',
        'forestgreen',
        'springgreen',
        'mediumspringgreen',
        'mediumseagreen',
        'seagreen',
        'darkseagreen',
        'olive',
        'olivedrab',
        'darkolivegreen',
        'mediumaquamarine',
    ],
    'Cyans': [
        'aquamarine',
        'turquoise',
        'mediumturquoise',
        'darkturquoise',
        'lightseagreen',
        'darkcyan',
        'teal',
        'cyan',
        'aqua',
        'lightcyan',
        'paleturquoise',
        'cadetblue',
    ],
    'Blues': [
        'powderblue',
        'lightblue',
        'lightskyblue',
        'skyblue',
        'deepskyblue',
        'cornflowerblue',
        'steelblue',
        'dodgerblue',
        'royalblue',
        'blue',
        'mediumblue',
        'darkblue',
        'navy',
        'midnightblue',
        'lightsteelblue',
        'slateblue',
        'darkslateblue',
        'mediumslateblue',
    ],
    'Purples & Magentas': [
        'blueviolet',
        'indigo',
        'darkviolet',
        'darkorchid',
        'darkmagenta',
        'purple',
        'mediumorchid',
        'mediumpurple',
        'orchid',
        'violet',
        'plum',
        'thistle',
        'lavender',
        'magenta',
        'fuchsia',
    ],
    'Whites & Light': [
        'white',
        'snow',
        'honeydew',
        'mintcream',
        'azure',
        'aliceblue',
        'ghostwhite',
        'whitesmoke',
        'ivory',
        'cornsilk',
        'beige',
        'floralwhite',
        'oldlace',
        'linen',
        'seashell',
        'lavenderblush',
        'mistyrose',
    ],
    'Grays & Black': [
        'gainsboro',
        'lightgray',
        'lightgrey',
        'silver',
        'darkgray',
        'darkgrey',
        'gray',
        'grey',
        'dimgray',
        'dimgrey',
        'lightslategray',
        'lightslategrey',
        'slategray',
        'slategrey',
        'darkslategray',
        'darkslategrey',
        'black',
    ],
}

_SWATCH_COLUMNS = 8
_SWATCH_WIDTH = 110
_SWATCH_HEIGHT = 30
_LUMINANCE_DARK_THRESHOLD = 128


class _SVGColorPickerDialog(QDialog):
    """Modal dialog showing SVG named colors organized into labeled groups."""

    def __init__(self, initial_color: QColor, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowModality(Qt.WindowModality.WindowModal)
        self.setWindowTitle('Choose Color')
        self.setWindowFlag(Qt.WindowType.WindowContextHelpButtonHint, False)
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
            header.setStyleSheet(COLOR_SWATCH_GROUP_HEADER_STYLESHEET)
            content_layout.addWidget(header)

            sep = QFrame()
            sep.setFrameShape(QFrame.Shape.HLine)
            sep.setStyleSheet(COLOR_SWATCH_SEPARATOR_STYLESHEET)
            content_layout.addWidget(sep)

            group_widget = QWidget()
            grid = QGridLayout(group_widget)
            grid.setSpacing(2)
            grid.setContentsMargins(0, 0, 0, 2)

            for i, color_name in enumerate(color_names):
                row, column = divmod(i, _SWATCH_COLUMNS)
                color = QColor(color_name)
                luminance = 0.299 * color.red() + 0.587 * color.green() + 0.114 * color.blue()
                text_color = '#111111' if luminance > _LUMINANCE_DARK_THRESHOLD else '#eeeeee'
                is_current = color.name().lower() == initial_hex
                border_color = '#ffffff' if is_current else '#555555'
                border_width = 3 if is_current else 1
                swatch_button = QPushButton(color_name)
                swatch_button.setFixedSize(_SWATCH_WIDTH, _SWATCH_HEIGHT)
                swatch_button.setCursor(Qt.CursorShape.PointingHandCursor)
                swatch_button.setAutoDefault(False)
                swatch_button.setStyleSheet(
                    color_swatch_button_stylesheet(color.name(), text_color, border_width, border_color),
                )

                def _on_clicked(*_: object, color_name: str = color_name) -> None:
                    self._pick(QColor(color_name), color_name)

                swatch_button.clicked.connect(_on_clicked)
                grid.addWidget(swatch_button, row, column)

            content_layout.addWidget(group_widget)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(scroll_content)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        outer.addWidget(scroll)

        bottom = QHBoxLayout()
        no_color_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'close.svg')), ' No Color')
        no_color_button.setAutoDefault(False)
        no_color_button.setCursor(Qt.CursorShape.PointingHandCursor)
        no_color_button.setToolTip('Remove the color for this database')
        no_color_button.clicked.connect(self._clear)
        bottom.addWidget(no_color_button)
        bottom.addStretch()
        cancel_button = QPushButton('Cancel')
        cancel_button.setAutoDefault(False)
        cancel_button.setCursor(Qt.CursorShape.PointingHandCursor)
        cancel_button.clicked.connect(self.reject)
        bottom.addWidget(cancel_button)
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


class SettingsPanelMixin(QDialog):
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
    _setting_suspend_mode: QComboBox
    _setting_suspend_custom: QSpinBox
    _settings_snapshot: dict[str, str]

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

        self._icon_arrow_right = QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'arrow_right.svg'))
        self._icon_arrow_down = QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'arrow_down.svg'))
        self._settings_toggle = QPushButton(self._icon_arrow_right, ' Database Settings')
        self._settings_toggle.setAutoDefault(False)
        self._settings_toggle.setCursor(Qt.CursorShape.PointingHandCursor)
        self._settings_toggle.setStyleSheet(USERIP_SETTINGS_TOGGLE_STYLESHEET)
        self._settings_toggle.clicked.connect(self._on_settings_toggle_clicked)
        group_outer.addWidget(self._settings_toggle)

        self._settings_content = QWidget()
        self._settings_content.setStyleSheet(USERIP_SETTINGS_BODY_STYLESHEET)
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
        self._setting_color.setCursor(Qt.CursorShape.PointingHandCursor)
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
        suspend_row.addWidget(QLabel('Suspend Mode:'))
        self._setting_suspend_mode = QComboBox()
        self._setting_suspend_mode.addItems(['Disabled', 'Auto', 'Manual'])
        self._setting_suspend_mode.setItemData(0, SUSPEND_TOOLTIP_DISABLED, Qt.ItemDataRole.ToolTipRole)
        self._setting_suspend_mode.setItemData(1, SUSPEND_TOOLTIP_AUTO, Qt.ItemDataRole.ToolTipRole)
        self._setting_suspend_mode.setItemData(2, SUSPEND_TOOLTIP_MANUAL, Qt.ItemDataRole.ToolTipRole)
        self._setting_suspend_mode.currentTextChanged.connect(self._on_suspend_mode_changed)
        suspend_row.addWidget(self._setting_suspend_mode)
        self._setting_suspend_custom = QSpinBox()
        self._setting_suspend_custom.setSingleStep(1)
        self._setting_suspend_custom.setMinimum(0)
        self._setting_suspend_custom.setMaximum(99999)
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

    def populate_settings_widgets(self, settings_dict: dict[str, str]) -> None:
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
        suspend_val = settings_dict.get('PROTECTION_SUSPEND_PROCESS_MODE', 'Auto').strip()
        if prot_val.lower() in ('false', '0', ''):
            self._setting_suspend_mode.setCurrentIndex(0)  # Disabled
            self._setting_suspend_custom.setVisible(False)
        elif suspend_val.lower() == 'auto':
            self._setting_suspend_mode.setCurrentIndex(1)  # Auto
            self._setting_suspend_custom.setVisible(False)
        else:
            self._setting_suspend_mode.setCurrentIndex(2)  # Manual
            self._setting_suspend_custom.setVisible(True)
            try:
                if suspend_val.startswith('Manual(') and suspend_val.endswith(')'):
                    self._setting_suspend_custom.setValue(int(suspend_val.removeprefix('Manual(').removesuffix(')')))
                else:
                    self._setting_suspend_custom.setValue(int(suspend_val))
            except ValueError:
                self._setting_suspend_custom.setValue(0)

        self._update_enabled_body_visible()

        self._refresh_protection_visibility()

        self._settings_loading = False

    def read_settings_from_widgets(self) -> dict[str, str]:
        """Read current widget values and return a settings dictionary for serialization."""
        settings: dict[str, str] = {}

        settings['ENABLED'] = str(self._setting_enabled.isChecked())
        settings['COLOR'] = self._current_color_name
        settings['LOG'] = str(self._setting_log.isChecked())
        settings['NOTIFICATIONS'] = str(self._setting_notifications.isChecked())

        voice_index = self._setting_voice.currentIndex()
        settings['VOICE_NOTIFICATIONS'] = ['False', 'Male', 'Female'][voice_index]

        if not self._is_protection_supported():
            settings['PROTECTION'] = 'False'
        else:
            settings['PROTECTION'] = 'Suspend_Process' if self._setting_suspend_mode.currentIndex() else 'False'

        suspend_index = self._setting_suspend_mode.currentIndex()
        if suspend_index <= 1:  # Disabled or Auto
            settings['PROTECTION_SUSPEND_PROCESS_MODE'] = 'Auto'
        else:
            settings['PROTECTION_SUSPEND_PROCESS_MODE'] = f'Manual({self._setting_suspend_custom.value()})'

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
                color_button_filled_stylesheet(self._current_color.name()),
            )
        else:
            self._setting_color.setStyleSheet(COLOR_BUTTON_EMPTY_STYLESHEET)

    def _on_suspend_mode_changed(self, text: str) -> None:
        """Show/hide the custom duration spin box based on suspend mode selection."""
        self._setting_suspend_custom.setVisible(text == 'Manual')
        self._on_setting_changed()

    def _update_enabled_body_visible(self) -> None:
        """Show/hide all settings below Enabled based on the checkbox state."""
        self._settings_body.setVisible(self._setting_enabled.isChecked())

    def _on_settings_toggle_clicked(self) -> None:
        """Toggle the settings content visibility and update the arrow indicator."""
        visible = not self._settings_content.isVisible()
        self._settings_content.setVisible(visible)
        self._settings_toggle.setIcon(self._icon_arrow_down if visible else self._icon_arrow_right)
