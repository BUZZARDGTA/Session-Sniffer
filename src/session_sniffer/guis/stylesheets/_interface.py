"""Interface selection dialog QSS — static containers, table, checkboxes, and scaled buttons."""

from session_sniffer.guis.theming import themed_qss

# =============================================================================
# INTERFACE SELECTION DIALOG STYLES
# =============================================================================

INTERFACE_TABLE_CONTAINER_STYLESHEET = themed_qss('QFrame#tableContainer { border: 1px solid @border; border-radius: 6px; }')

INTERFACE_BOTTOM_CONTAINER_STYLESHEET = themed_qss(
    'QFrame#bottomContainer {'
    ' background-color: @surface;'
    ' border: 1px solid @border;'
    ' border-radius: 6px;'
    '}'
    'QFrame#bottomContainer QCheckBox {'
    ' background-color: transparent;'
    '}'
    'QFrame#bottomContainer QLabel {'
    ' background-color: transparent;'
    '}',
)

INTERFACE_BOTTOM_SEPARATOR_STYLESHEET = themed_qss('QFrame#bottomSeparator { background-color: @border; max-height: 1px; border: none; }')


def _scale(value: int, ui_scale: float) -> int:
    return max(1, round(value * ui_scale))


def interface_table_stylesheet(ui_scale: float) -> str:
    """Return the QSS for the interface selection table widget at the given UI `scale`."""
    return themed_qss(
        'QTableWidget {'
        ' background-color: @table;'
        ' alternate-background-color: @table_alt;'
        ' border: none;'
        ' outline: none;'
        '}'
        'QTableWidget::item {'
        f' font-size: {_scale(9, ui_scale)}pt;'
        ' color: @text;'
        f' padding: 0px {_scale(8, ui_scale)}px;'
        ' border-bottom: 1px solid @border;'
        ' border-right: 1px solid @border;'
        '}'
        'QTableWidget::item:selected {'
        ' background-color: @selection;'
        ' color: @text_strong;'
        f' padding: 0px {_scale(8, ui_scale)}px;'
        ' border-bottom: 1px solid @border;'
        ' border-right: 1px solid @border;'
        '}'
        'QTableWidget::item:hover:!selected {'
        ' background-color: @selection/40;'
        ' border-bottom: 1px solid @border;'
        ' border-right: 1px solid @border;'
        '}'
        'QHeaderView {'
        ' background-color: @table_header;'
        ' border: none;'
        ' border-bottom: 2px solid @accent;'
        '}'
        'QHeaderView::section {'
        ' background-color: @table_header;'
        ' color: @accent;'
        f' min-height: {_scale(36, ui_scale)}px;'
        f' padding: 0px {_scale(8, ui_scale)}px;'
        ' border-bottom: 2px solid @accent;'
        ' border-right: 1px solid @border;'
        ' border-top: none;'
        ' border-left: none;'
        '}',
    )


def interface_checkbox_stylesheet(obj_name: str, ui_scale: float) -> str:
    """Return the QSS for an interface selection dialog checkbox at the given UI `scale`."""
    return themed_qss(
        f'QCheckBox#{obj_name} {{ font-size: {_scale(13, ui_scale)}pt; }} '
        f'QCheckBox#{obj_name}::indicator {{ width: {_scale(19, ui_scale)}px; height: {_scale(19, ui_scale)}px; }}',
    )


def interface_instruction_label_stylesheet(scale: float) -> str:
    """Return the QSS for the interface selection dialog instruction label at the given UI `scale`."""
    return themed_qss(f'font-size: {_scale(13, scale)}pt;')


# =============================================================================
# INTERFACE SELECTION DIALOG BUTTON STYLES (SCALED)
# =============================================================================


def interface_select_button_disabled_style(scale: float) -> str:
    """Return the QSS for the interface selection dialog Select button in its disabled state at *scale*."""
    return themed_qss(
        f'QPushButton {{ font-size: {_scale(20, scale)}pt; background-color: @control:disabled;'
        ' color: @text_muted:disabled; border: 2px solid @border:disabled; border-radius: 10px; }',
    )


def interface_select_button_enabled_style(scale: float) -> str:
    """Return the QSS for the interface selection dialog Select button in its enabled state at *scale*."""
    return themed_qss(
        'QPushButton {'
        f' font-size: {_scale(22, scale)}pt;'
        ' background-color: @accent;'
        ' color: @text_strong;'
        ' border: 2px solid @accent;'
        ' border-radius: 10px;'
        '}'
        'QPushButton:hover {'
        ' background-color: @accent:hover;'
        ' border: 2px solid @accent:hover;'
        ' color: @text_strong;'
        '}',
    )


def interface_secondary_button_enabled_style(scale: float) -> str:
    """Return the QSS for an enabled secondary action button in the interface selection dialog at *scale*."""
    return themed_qss(
        'QPushButton {'
        f' font-size: {_scale(14, scale)}pt;'
        ' background-color: @control;'
        ' color: @text_strong;'
        ' border: 2px solid @border;'
        ' border-radius: 8px;'
        f' padding: {_scale(4, scale)}px {_scale(10, scale)}px;'
        '}'
        'QPushButton:hover {'
        ' background-color: @control:hover;'
        ' border: 2px solid @accent;'
        ' color: @text_strong;'
        '}',
    )


def interface_secondary_button_disabled_style(scale: float) -> str:
    """Return the QSS for a disabled secondary action button in the interface selection dialog at *scale*."""
    return themed_qss(
        'QPushButton {'
        f' font-size: {_scale(14, scale)}pt;'
        ' background-color: @control:disabled;'
        ' color: @text_muted:disabled;'
        ' border: 2px solid @border:disabled;'
        ' border-radius: 8px;'
        f' padding: {_scale(4, scale)}px {_scale(10, scale)}px;'
        '}',
    )


def format_interface_refresh_arp_progress_style(ui_scale: float, fraction: float, *, dimmed: bool = False) -> str:
    """Build a QSS that renders a horizontal gradient progress fill inside the Refresh ARP button."""
    if dimmed:
        fill_left = '@control:disabled'
        fill_mid = '@control'
        fill_right = '@control:hover'
        track_dark = '@input:disabled'
        track_light = '@input'
        border_color = '@border'
    else:
        fill_left = '@accent:pressed'
        fill_mid = '@accent'
        fill_right = '@accent:hover'
        track_dark = '@input'
        track_light = '@control'
        border_color = '@accent'
    clamped = max(0.0, min(1.0, fraction))
    next_stop = min(1.0, clamped + 0.0001)
    return themed_qss(
        'QPushButton {'
        f' font-size: {_scale(12, ui_scale)}pt;'
        ' background: qlineargradient(x1:0, y1:0, x2:1, y2:0,'
        f' stop:0 {fill_left},'
        f' stop:{clamped * 0.5:.4f} {fill_mid},'
        f' stop:{clamped:.4f} {fill_right},'
        f' stop:{next_stop:.4f} {track_dark},'
        f' stop:1 {track_light});'
        ' color: @text_strong;'
        ' font-weight: 700;'
        ' letter-spacing: 1px;'
        f' border: 2px solid {border_color};'
        ' border-radius: 8px;'
        f' padding: {_scale(4, ui_scale)}px {_scale(10, ui_scale)}px;'
        ' }',
    )


def interface_tab_container_stylesheet(ui_scale: float) -> str:
    """Return the QSS for the segmented navigation tab bar container at the given UI `scale`."""
    return themed_qss(
        f'QFrame#interfaceTabContainer {{ background-color: @menubar; border: 1px solid @border;'
        f' border-radius: {_scale(8, ui_scale)}px; padding: {_scale(4, ui_scale)}px; }}',
    )


def interface_tab_button_stylesheet(ui_scale: float) -> str:
    """Return the QSS for segmented navigation tab buttons at the given UI `scale`."""
    return themed_qss(
        'QPushButton#tabInterfacesButton, QPushButton#tabHotspotButton {'
        f' font-size: {_scale(10, ui_scale)}pt;'
        ' font-weight: 600;'
        ' color: @text_muted;'
        ' background-color: transparent;'
        ' border: 1px solid transparent;'
        f' border-radius: {_scale(6, ui_scale)}px;'
        f' padding: {_scale(8, ui_scale)}px {_scale(20, ui_scale)}px;'
        f' min-height: {_scale(34, ui_scale)}px;'
        ' text-align: center;'
        '}'
        'QPushButton#tabInterfacesButton:hover:!checked, QPushButton#tabHotspotButton:hover:!checked {'
        ' background-color: @control/45;'
        ' color: @text_strong;'
        '}'
        'QPushButton#tabInterfacesButton:checked, QPushButton#tabHotspotButton:checked {'
        ' background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 @menubar~accent/26, stop:1 @menubar~accent/10);'
        ' border: 1px solid @accent;'
        ' color: @text_strong;'
        ' font-weight: 700;'
        '}'
        'QPushButton#tabInterfacesButton:checked:hover, QPushButton#tabHotspotButton:checked:hover {'
        ' background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 @menubar~accent/34, stop:1 @menubar~accent/16);'
        ' border: 1px solid @accent:hover;'
        ' color: @text_strong;'
        '}',
    )
