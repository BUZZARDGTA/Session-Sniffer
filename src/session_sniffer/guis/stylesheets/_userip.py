"""UserIP manager, settings panel, IP range builder, and color swatch QSS."""

from typing import TYPE_CHECKING

from session_sniffer.guis.theming import themed_color, themed_qss

if TYPE_CHECKING:
    from collections.abc import Callable

# =============================================================================
# USERIP MANAGER STYLES
# =============================================================================

USERIP_METADATA_CONTAINER_STYLESHEET = themed_qss("""
QFrame {
    background-color: @surface;
    border: 1px solid @border;
    border-radius: 6px;
}
QLabel {
    background: transparent;
    border: none;
    line-height: 1.4;
}
""")


def _userip_scaled_button_base(scale: Callable[[int], int]) -> str:
    """Return the shared scaled font/padding/size properties for UserIP manager buttons."""
    return (
        f'    font-size: {max(6, scale(9))}pt;\n'
        '    font-weight: 600;\n'
        f'    padding: {scale(4)}px {scale(5)}px;\n'
        f'    min-height: {scale(24)}px;\n'
        f'    border-radius: {scale(6)}px;'
    )


def userip_dialog_button_stylesheet(scale: Callable[[int], int]) -> str:
    """Return the scaled QSS for standard action buttons in the UserIP manager."""
    base = _userip_scaled_button_base(scale)
    return themed_qss(f"""
QPushButton {{
{base}
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 @control:hover, stop:1 @control);
    color: @text_strong;
    border: 1px solid @border;
}}
QPushButton:hover {{
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 @control~accent/26, stop:1 @control~accent/16);
    border: 1px solid @accent;
    color: @text_strong;
}}
QPushButton:pressed {{
    background: @control:pressed;
    border: 1px solid @accent;
    color: @text_strong;
}}
QPushButton:disabled {{
    background: @control:disabled;
    color: @text_muted:disabled;
    border: 1px solid @border:disabled;
}}
""")


def userip_dialog_danger_button_stylesheet(scale: Callable[[int], int]) -> str:
    """Return the scaled QSS for destructive action buttons in the UserIP manager."""
    base = _userip_scaled_button_base(scale)
    return themed_qss(f"""
QPushButton {{
{base}
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 @danger, stop:1 @danger:pressed);
    color: @text_strong;
    border: 1px solid @danger;
}}
QPushButton:hover {{
    background: @danger:hover;
    border: 1px solid @danger:hover;
    color: @text_strong;
}}
QPushButton:pressed {{
    background: @danger:pressed;
    border: 1px solid @danger:pressed;
    color: @text_strong;
}}
QPushButton:disabled {{
    background: @control:disabled;
    color: @text_muted:disabled;
    border: 1px solid @border:disabled;
}}
""")


SUBNET_DESC_LABEL_STYLESHEET = themed_qss('color: @text_muted; font-style: italic;')

COLOR_SWATCH_GROUP_HEADER_STYLESHEET = themed_qss('color: @accent; font-size: 8pt; font-weight: bold; padding: 4px 0px 1px 2px;')

COLOR_SWATCH_SEPARATOR_STYLESHEET = themed_qss('color: @border;')

SETTINGS_SEPARATOR_STYLESHEET = themed_qss('background-color: @border; border: none;')


def _color_picker_button_stylesheet(background_color: str, hover_border_color: str) -> str:
    """Build the QSS for `ColorPickerButton` and `DatabaseColorButton` (preserving user swatch `background_color`)."""
    border_color = themed_color('@border')
    themed_hover_border = themed_color(hover_border_color)
    return (
        'QPushButton#ColorPickerButton, QPushButton#DatabaseColorButton {'
        f' background-color: {background_color};'
        f' border: 1px solid {border_color};'
        ' border-radius: 4px;'
        ' min-width: 52px;'
        ' max-width: 52px;'
        ' min-height: 26px;'
        ' max-height: 26px;'
        ' padding: 0px;'
        ' margin: 0px;'
        '}'
        f' QPushButton#ColorPickerButton:hover, QPushButton#DatabaseColorButton:hover {{ border-color: {themed_hover_border}; }}'
    )


COLOR_BUTTON_EMPTY_STYLESHEET = _color_picker_button_stylesheet('transparent', '@accent')


def color_swatch_button_stylesheet(bg_color: str, text_color: str, border_width: int, border_color: str, *, font_pt: int = 8) -> str:
    """Return the QSS for a color swatch button in the SVG color picker (preserving user swatch colors)."""
    return (
        f'background-color: {bg_color}; color: {text_color};'
        f' border: {border_width}px solid {themed_color(border_color)}; border-radius: 2px;'
        f' font-size: {font_pt}pt; font-weight: bold; text-align: center; padding: 0px;'
    )


def color_button_filled_stylesheet(color_name: str) -> str:
    """Return the QSS for a color preview button showing the given `color_name`."""
    return _color_picker_button_stylesheet(color_name, '@text_strong')


# =============================================================================
# USERIP MANAGER SETTINGS PANEL STYLES
# =============================================================================

USERIP_SETTINGS_CONTAINER_STYLESHEET = themed_qss("""
#SettingsContainer {
    border: 2px solid @border;
    border-radius: 8px;
    background: @surface;
}
""")


def userip_settings_toggle_stylesheet(scale: Callable[[int], int]) -> str:
    """Return the scaled QSS for the collapsible Database Settings header toggle button."""
    font_pt = max(7, scale(11))
    pad_v = scale(4)
    pad_h = scale(8)
    return themed_qss(f"""
QPushButton {{
    background: transparent;
    border: none;
    color: @accent;
    font-size: {font_pt}pt;
    font-weight: bold;
    text-align: left;
    padding: {pad_v}px {pad_h}px;
}}
QPushButton:hover {{
    color: @accent:hover;
}}
""")


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
    return themed_qss(f"""
QLabel {{
    color: @text_muted;
    font-size: {font_pt}pt;
    font-weight: normal;
    background: transparent;
}}
QComboBox, QLineEdit, QDoubleSpinBox {{
    background: @input;
    color: @text;
    border: 1px solid @border;
    border-radius: 4px;
    padding: {pad_v}px {pad_h}px;
    font-size: {font_pt}pt;
    min-height: {min_h}px;
}}
QComboBox:hover, QLineEdit:hover, QDoubleSpinBox:hover {{
    border-color: @accent;
}}
QComboBox:disabled, QLineEdit:disabled, QDoubleSpinBox:disabled {{
    background: @input:disabled;
    color: @text_muted:disabled;
    border-color: @border:disabled;
}}
QLineEdit:focus {{
    border-color: @accent;
    background: @input;
}}
QPushButton {{
    background: @control;
    color: @text_strong;
    border: 1px solid @border;
    border-radius: 4px;
    font-size: {font_pt}pt;
    min-width: {btn_min_w}px;
    min-height: {btn_min_h}px;
    padding: {btn_pad_v}px {btn_pad_h}px;
}}
QPushButton:hover {{
    background: @accent;
    color: @text_strong;
    border-color: @accent;
}}
""")


# =============================================================================
# IP RANGE BUILDOG STYLES
# =============================================================================


def _ip_range_preview_stylesheet(color: str) -> str:
    """Build the monospace QSS for the IP Range Builder preview label."""
    return themed_qss(f'font-family: Menlo, Consolas, "Courier New", monospace; font-size: 10pt; padding: 6px; color: {color};')


IP_RANGE_PREVIEW_VALID_STYLESHEET = _ip_range_preview_stylesheet('@success')
IP_RANGE_PREVIEW_ERROR_STYLESHEET = _ip_range_preview_stylesheet('@danger')
IP_RANGE_PREVIEW_EMPTY_STYLESHEET = _ip_range_preview_stylesheet('@text_muted')
