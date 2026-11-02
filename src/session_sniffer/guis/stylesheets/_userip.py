"""UserIP manager, settings panel, IP range builder, and color swatch QSS."""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

# =============================================================================
# USERIP MANAGER STYLES
# =============================================================================

USERIP_METADATA_CONTAINER_STYLESHEET = """
QFrame {
    background-color: rgba(16, 20, 26, 0.85);
    border: 1px solid rgba(50, 65, 80, 0.7);
    border-radius: 6px;
}
QLabel {
    background: transparent;
    border: none;
    line-height: 1.4;
}
"""


def userip_dialog_button_stylesheet(scale: Callable[[int], int]) -> str:
    """Return the scaled QSS for standard action buttons in the UserIP manager."""
    font_pt = max(6, scale(9))
    pad_v = scale(4)
    pad_h = scale(5)
    min_h = scale(24)
    radius = scale(6)
    return f"""
QPushButton {{
    font-size: {font_pt}pt;
    font-weight: 600;
    padding: {pad_v}px {pad_h}px;
    min-height: {min_h}px;
    border-radius: {radius}px;
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #2d3e50, stop:0.5 #243342, stop:1 #1c2836);
    color: #d4e4f7;
    border: 1px solid #3d5266;
}}
QPushButton:hover {{
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #3a5168, stop:0.5 #2f4458, stop:1 #253649);
    border: 1px solid #5588cc;
    color: #ffffff;
}}
QPushButton:pressed {{
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #1a252f, stop:0.5 #1f2d3a, stop:1 #263545);
    border: 1px solid #6ba3e8;
    color: #ffffff;
}}
QPushButton:disabled {{
    background: #1a2028;
    color: #556270;
    border: 1px solid #2a3440;
}}
"""


def userip_dialog_danger_button_stylesheet(scale: Callable[[int], int]) -> str:
    """Return the scaled QSS for destructive action buttons in the UserIP manager."""
    font_pt = max(6, scale(9))
    pad_v = scale(4)
    pad_h = scale(5)
    min_h = scale(24)
    radius = scale(6)
    return f"""
QPushButton {{
    font-size: {font_pt}pt;
    font-weight: 600;
    padding: {pad_v}px {pad_h}px;
    min-height: {min_h}px;
    border-radius: {radius}px;
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #b33a3a, stop:0.5 #962d2d, stop:1 #7a2222);
    color: #ffffff;
    border: 1px solid #c94444;
}}
QPushButton:hover {{
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #cc4444, stop:0.5 #b03535, stop:1 #932a2a);
    border: 1px solid #e05555;
    color: #ffffff;
}}
QPushButton:pressed {{
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #6e1e1e, stop:0.5 #7f2424, stop:1 #912c2c);
    border: 1px solid #ff6666;
    color: #ffffff;
}}
QPushButton:disabled {{
    background: #281a1a;
    color: #705555;
    border: 1px solid #402a2a;
}}
"""


SUBNET_DESC_LABEL_STYLESHEET = 'color: #a0a0a0; font-style: italic;'

COLOR_SWATCH_GROUP_HEADER_STYLESHEET = 'color: #8ab4d4; font-size: 8pt; font-weight: bold; padding: 4px 0px 1px 2px;'

COLOR_SWATCH_SEPARATOR_STYLESHEET = 'color: #3a3a3a;'

SETTINGS_SEPARATOR_STYLESHEET = 'background-color: rgba(74, 144, 226, 0.2); border: none;'

COLOR_BUTTON_EMPTY_STYLESHEET = (
    'QPushButton#ColorPickerButton, QPushButton#DatabaseColorButton {'
    ' background-color: transparent;'
    ' border: 1px solid #555;'
    ' border-radius: 4px;'
    ' min-width: 52px;'
    ' max-width: 52px;'
    ' min-height: 26px;'
    ' max-height: 26px;'
    ' padding: 0px;'
    ' margin: 0px;'
    '}'
    ' QPushButton#ColorPickerButton:hover, QPushButton#DatabaseColorButton:hover { border-color: #4a90e2; }'
)


def color_swatch_button_stylesheet(bg_color: str, text_color: str, border_width: int, border_color: str, *, font_pt: int = 8) -> str:
    """Return the QSS for a color swatch button in the SVG color picker."""
    return (
        f'background-color: {bg_color}; color: {text_color};'
        f' border: {border_width}px solid {border_color}; border-radius: 2px;'
        f' font-size: {font_pt}pt; font-weight: bold; text-align: center; padding: 0px;'
    )


def color_button_filled_stylesheet(color_name: str) -> str:
    """Return the QSS for a color preview button showing the given `color_name`."""
    return (
        'QPushButton#ColorPickerButton, QPushButton#DatabaseColorButton {'
        f' background-color: {color_name};'
        ' border: 1px solid #555;'
        ' border-radius: 4px;'
        ' min-width: 52px;'
        ' max-width: 52px;'
        ' min-height: 26px;'
        ' max-height: 26px;'
        ' padding: 0px;'
        ' margin: 0px;'
        '}'
        ' QPushButton#ColorPickerButton:hover, QPushButton#DatabaseColorButton:hover { border-color: #ffffff; }'
    )


# =============================================================================
# USERIP MANAGER SETTINGS PANEL STYLES
# =============================================================================

USERIP_SETTINGS_CONTAINER_STYLESHEET = """
#SettingsContainer {
    border: 2px solid #455364;
    border-radius: 8px;
    background: transparent;
}
"""


def userip_settings_toggle_stylesheet(scale: Callable[[int], int]) -> str:
    """Return the scaled QSS for the collapsible Database Settings header toggle button."""
    font_pt = max(7, scale(11))
    pad_v = scale(4)
    pad_h = scale(8)
    return f"""
QPushButton {{
    background: transparent;
    border: none;
    color: #4a90e2;
    font-size: {font_pt}pt;
    font-weight: bold;
    text-align: left;
    padding: {pad_v}px {pad_h}px;
}}
QPushButton:hover {{
    color: #6db3f2;
}}
"""


def userip_settings_body_stylesheet(scale: Callable[[int], int]) -> str:
    """Return the scaled QSS for the collapsible Database Settings body controls."""
    font_pt = max(6, scale(10))
    pad_v = scale(4)
    pad_h = scale(8)
    min_h = scale(22)
    btn_min_w = scale(28)
    btn_min_h = scale(24)
    btn_pad_v = scale(2)
    btn_pad_h = scale(6)
    return f"""
QLabel {{
    color: #b0bec5;
    font-size: {font_pt}pt;
    font-weight: normal;
    background: transparent;
}}
QComboBox, QLineEdit, QDoubleSpinBox {{
    background: #2d2d2d;
    color: #d4d4d4;
    border: 1px solid #555;
    border-radius: 4px;
    padding: {pad_v}px {pad_h}px;
    font-size: {font_pt}pt;
    min-height: {min_h}px;
}}
QComboBox:hover, QLineEdit:hover, QDoubleSpinBox:hover {{
    border-color: #4a90e2;
}}
QComboBox:disabled, QLineEdit:disabled, QDoubleSpinBox:disabled {{
    background: #222;
    color: #555;
    border-color: #3a3a3a;
}}
QLineEdit:focus {{
    border-color: #4a90e2;
    background: #333;
}}
QPushButton {{
    background: #3a3a3a;
    color: #d4d4d4;
    border: 1px solid #555;
    border-radius: 4px;
    font-size: {font_pt}pt;
    min-width: {btn_min_w}px;
    min-height: {btn_min_h}px;
    padding: {btn_pad_v}px {btn_pad_h}px;
}}
QPushButton:hover {{
    background: #4a90e2;
    color: white;
    border-color: #4a90e2;
}}
"""


# =============================================================================
# IP RANGE BUILDER DIALOG STYLES
# =============================================================================

IP_RANGE_PREVIEW_VALID_STYLESHEET = 'font-family: Menlo, Consolas, "Courier New", monospace; font-size: 10pt; padding: 6px; color: #80c080;'
IP_RANGE_PREVIEW_ERROR_STYLESHEET = 'font-family: Menlo, Consolas, "Courier New", monospace; font-size: 10pt; padding: 6px; color: #e06060;'
IP_RANGE_PREVIEW_EMPTY_STYLESHEET = 'font-family: Menlo, Consolas, "Courier New", monospace; font-size: 10pt; padding: 6px; color: #a0a0a0;'
