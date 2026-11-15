"""Interface selection dialog QSS — static containers, table, checkboxes, and scaled buttons."""

from session_sniffer.guis.theming import themed_qss

# =============================================================================
# INTERFACE SELECTION DIALOG STYLES
# =============================================================================

INTERFACE_TABLE_CONTAINER_STYLESHEET = themed_qss('QFrame#tableContainer { border: 1px solid @accent[#3a6aaa]; border-radius: 6px;}')

INTERFACE_BOTTOM_CONTAINER_STYLESHEET = themed_qss(
    'QFrame#bottomContainer {'
    ' background-color: @surface[#1a2535];'
    ' border: 1px solid @accent[#3a6aaa];'
    ' border-radius: 6px;'
    '}'
    'QFrame#bottomContainer QCheckBox {'
    ' background-color: transparent;'
    '}'
    'QFrame#bottomContainer QLabel {'
    ' background-color: transparent;'
    '}',
)

INTERFACE_BOTTOM_SEPARATOR_STYLESHEET = themed_qss('QFrame#bottomSeparator { background-color: @border[#2f4356]; max-height: 1px; border: none;}')


def _scale(value: int, ui_scale: float) -> int:
    return max(1, round(value * ui_scale))


def interface_table_stylesheet(ui_scale: float) -> str:
    """Return the QSS for the interface selection table widget at the given UI `scale`."""
    return themed_qss(
        'QTableWidget {'
        ' background-color: @table[#131e2c];'
        ' alternate-background-color: @table_alt[#182536];'
        ' border: none;'
        ' outline: none;'
        '}'
        'QTableWidget::item {'
        f' font-size: {_scale(9, ui_scale)}pt;'
        ' color: @text[#c8ddf0];'
        f' padding: 0px {_scale(8, ui_scale)}px;'
        ' border-bottom: 1px solid @border[#1e3048];'
        ' border-right: 1px solid @border[#1e3048];'
        '}'
        'QTableWidget::item:selected {'
        ' background-color: @selection[#1a4a8a];'
        ' color: @text_strong[#ffffff];'
        f' padding: 0px {_scale(8, ui_scale)}px;'
        ' border-bottom: 1px solid @border[#1e3048];'
        ' border-right: 1px solid @border[#1e3048];'
        '}'
        'QTableWidget::item:hover:!selected {'
        ' background-color: @selection[#1c3050];'
        ' border-bottom: 1px solid @border[#1e3048];'
        ' border-right: 1px solid @border[#1e3048];'
        '}'
        'QHeaderView {'
        ' background-color: @table_header[#0e1824];'
        ' border: none;'
        ' border-bottom: 2px solid @accent[#2a5080];'
        '}'
        'QHeaderView::section {'
        ' background-color: @table_header[#0e1824];'
        ' color: @accent[#7bafd4];'
        f' min-height: {_scale(36, ui_scale)}px;'
        f' padding: 0px {_scale(8, ui_scale)}px;'
        ' border-bottom: 2px solid @accent[#2a5080];'
        ' border-right: 1px solid @border[#1e3048];'
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
        f'QPushButton {{ font-size: {_scale(20, scale)}pt; background-color: @control[#555555];'
        ' color: @text_muted[#aaaaaa]; border: 2px solid @border[#3a3a3a]; border-radius: 10px;}',
    )


def interface_select_button_enabled_style(scale: float) -> str:
    """Return the QSS for the interface selection dialog Select button in its enabled state at *scale*."""
    return themed_qss(
        'QPushButton {'
        f' font-size: {_scale(22, scale)}pt;'
        ' background-color: @accent[#175bb0];'
        ' color: @text_strong[#ffffff];'
        ' border: 2px solid @accent[#2a6aaa];'
        ' border-radius: 10px;'
        '}'
        'QPushButton:hover {'
        ' background-color: @accent[#1e6ec7];'
        ' border: 2px solid @accent[#4a8fd4];'
        '}',
    )


def interface_secondary_button_enabled_style(scale: float) -> str:
    """Return the QSS for an enabled secondary action button in the interface selection dialog at *scale*."""
    return themed_qss(
        'QPushButton {'
        f' font-size: {_scale(14, scale)}pt;'
        ' background-color: @control[#21334c];'
        ' color: @text_strong[#e8f0f8];'
        ' border: 2px solid @border[#1e3f60];'
        ' border-radius: 8px;'
        f' padding: {_scale(4, scale)}px {_scale(10, scale)}px;'
        '}'
        'QPushButton:hover {'
        ' background-color: @control[#2c4463];'
        ' border: 2px solid @accent[#2a5888];'
        '}',
    )


def interface_secondary_button_disabled_style(scale: float) -> str:
    """Return the QSS for a disabled secondary action button in the interface selection dialog at *scale*."""
    return themed_qss(
        'QPushButton {'
        f' font-size: {_scale(14, scale)}pt;'
        ' background-color: @control[#555555];'
        ' color: @text_muted[#aaaaaa];'
        ' border: 2px solid @border[#3a3a3a];'
        ' border-radius: 8px;'
        f' padding: {_scale(4, scale)}px {_scale(10, scale)}px;'
        '}',
    )


def format_interface_refresh_arp_progress_style(ui_scale: float, fraction: float, *, dimmed: bool = False) -> str:
    """Build a QSS that renders a horizontal gradient progress fill inside the Refresh ARP button."""
    if dimmed:
        fill_left = '@control[#4a4a4a]'
        fill_mid = '@control[#666666]'
        fill_right = '@control[#7a7a7a]'
        track_dark = '@input[#1e1e1e]'
        track_light = '@input[#2e2e2e]'
    else:
        fill_left = '@accent[#1e5a9c]'
        fill_mid = '@accent[#3d7fc4]'
        fill_right = '@accent[#5599dd]'
        track_dark = '@input[#0f1a28]'
        track_light = '@control[#1a2738]'
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
        ' color: @text_strong[#ffffff];'
        ' font-weight: 700;'
        ' letter-spacing: 1px;'
        ' border: 2px solid @accent[#2a5888];'
        ' border-radius: 8px;'
        f' padding: {_scale(4, ui_scale)}px {_scale(10, ui_scale)}px;'
        ' }',
    )


def interface_tab_container_stylesheet(ui_scale: float) -> str:
    """Return the QSS for the segmented navigation tab bar container at the given UI `scale`."""
    return themed_qss(
        f'QFrame#interfaceTabContainer {{ background-color: @menubar[#0b1420]; border: 1px solid @border[#1a2c42];'
        f' border-radius: {_scale(8, ui_scale)}px; padding: {_scale(4, ui_scale)}px;}}',
    )


def interface_tab_button_stylesheet(ui_scale: float) -> str:
    """Return the QSS for segmented navigation tab buttons at the given UI `scale`."""
    return themed_qss(
        'QPushButton#tabInterfacesButton, QPushButton#tabHotspotButton {'
        f' font-size: {_scale(10, ui_scale)}pt;'
        ' font-weight: 600;'
        ' color: @text_muted[#7e95ab];'
        ' background-color: transparent;'
        ' border: 1px solid transparent;'
        f' border-radius: {_scale(6, ui_scale)}px;'
        f' padding: {_scale(8, ui_scale)}px {_scale(20, ui_scale)}px;'
        f' min-height: {_scale(34, ui_scale)}px;'
        ' text-align: center;'
        '}'
        'QPushButton#tabInterfacesButton:hover:!checked, QPushButton#tabHotspotButton:hover:!checked {'
        ' background-color: @control[rgba(255, 255, 255, 0.04)];'
        ' color: @text[#cbe0f5];'
        '}'
        'QPushButton#tabInterfacesButton:checked, QPushButton#tabHotspotButton:checked {'
        ' background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 @accent[rgba(0, 180, 216, 0.22)], stop:1 @accent[rgba(0, 180, 216, 0.06)]);'
        ' border: 1px solid @accent[#00b4d8];'
        ' color: @text_strong[#ffffff];'
        ' font-weight: 700;'
        '}'
        'QPushButton#tabInterfacesButton:checked:hover, QPushButton#tabHotspotButton:checked:hover {'
        ' background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 @accent[rgba(56, 189, 248, 0.28)], stop:1 @accent[rgba(56, 189, 248, 0.10)]);'
        ' border: 1px solid @accent[#38bdf8];'
        ' color: @text_strong[#ffffff];'
        '}',
    )
