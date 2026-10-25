"""SVG color picker dialog and swatch button widget."""

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.guis.stylesheets import (
    COLOR_BUTTON_EMPTY_STYLESHEET,
    COLOR_SWATCH_GROUP_HEADER_STYLESHEET,
    COLOR_SWATCH_SEPARATOR_STYLESHEET,
    color_button_filled_stylesheet,
    color_swatch_button_stylesheet,
)

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


class SVGColorPickerDialog(QDialog):
    """Modal dialog showing SVG named colors organized into labeled groups."""

    def __init__(self, initial_color: QColor, parent: QWidget | None = None) -> None:
        """Initialize the SVG color picker dialog."""
        super().__init__(parent)
        self.setWindowModality(Qt.WindowModality.WindowModal)
        self.setWindowTitle('Choose Color')
        self.setWindowFlag(Qt.WindowType.WindowContextHelpButtonHint, on=False)
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

    @classmethod
    def get_color(cls, initial: QColor, parent: QWidget | None = None) -> tuple[bool, QColor, str]:
        """Show the SVG color palette.

        Returns `(accepted, color, svg_name)`.
        `accepted=False` means the user cancelled — keep the existing color.
        """
        dlg = cls(initial, parent)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            return True, dlg._chosen, dlg._chosen_name
        return False, QColor(), ''


class ColorPickerButton(QPushButton):
    """Button showing a color swatch that opens the SVG color picker on click."""

    color_changed = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the color picker button."""
        super().__init__(parent)
        self.setObjectName('ColorPickerButton')
        self._color: QColor = QColor()
        self._color_name: str = ''
        self.setFixedSize(52, 26)
        self.setAutoDefault(False)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.clicked.connect(self._on_clicked)
        self._update_style()

    def color(self) -> str:
        """Return the current color name or hex string."""
        return self._color_name

    def set_color(self, color_name: str) -> None:
        """Set the button's color and update its visual swatch."""
        cleaned = color_name.strip()
        self._color = QColor(cleaned) if cleaned and QColor(cleaned).isValid() else QColor()
        self._color_name = cleaned if self._color.isValid() else ''
        self._update_style()

    def _update_style(self) -> None:
        if self._color.isValid():
            self.setStyleSheet(color_button_filled_stylesheet(self._color.name()))
        else:
            self.setStyleSheet(COLOR_BUTTON_EMPTY_STYLESHEET)

    def _on_clicked(self) -> None:
        accepted, _chosen, name = SVGColorPickerDialog.get_color(self._color, self)
        if accepted:
            self.set_color(name)
            self.color_changed.emit(name)
