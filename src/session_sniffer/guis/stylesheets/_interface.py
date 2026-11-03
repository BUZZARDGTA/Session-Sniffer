"""Interface selection dialog QSS — static containers, table, checkboxes, and scaled buttons."""

# =============================================================================
# INTERFACE SELECTION DIALOG STYLES
# =============================================================================

INTERFACE_TABLE_CONTAINER_STYLESHEET = 'QFrame#tableContainer { border: 1px solid #3a6aaa; border-radius: 6px;}'

INTERFACE_BOTTOM_CONTAINER_STYLESHEET = (
    'QFrame#bottomContainer {'
    ' background-color: #1a2535;'
    ' border: 1px solid #3a6aaa;'
    ' border-radius: 6px;'
    '}'
    'QFrame#bottomContainer QCheckBox {'
    ' background-color: transparent;'
    '}'
    'QFrame#bottomContainer QLabel {'
    ' background-color: transparent;'
    '}'
)

INTERFACE_BOTTOM_SEPARATOR_STYLESHEET = 'QFrame#bottomSeparator { background-color: #2f4356; max-height: 1px; border: none;}'


def _scale(value: int, ui_scale: float) -> int:
    return max(1, round(value * ui_scale))


def interface_table_stylesheet(ui_scale: float) -> str:
    """Return the QSS for the interface selection table widget at the given UI `scale`."""
    return (
        'QTableWidget {'
        ' background-color: #131e2c;'
        ' alternate-background-color: #182536;'
        ' border: none;'
        ' outline: none;'
        '}'
        'QTableWidget::item {'
        f' font-size: {_scale(9, ui_scale)}pt;'
        ' color: #c8ddf0;'
        f' padding: 0px {_scale(8, ui_scale)}px;'
        ' border-bottom: 1px solid #1e3048;'
        ' border-right: 1px solid #1e3048;'
        '}'
        'QTableWidget::item:selected {'
        ' background-color: #1a4a8a;'
        ' color: #ffffff;'
        f' padding: 0px {_scale(8, ui_scale)}px;'
        ' border-bottom: 1px solid #1e3048;'
        ' border-right: 1px solid #1e3048;'
        '}'
        'QTableWidget::item:hover:!selected {'
        ' background-color: #1c3050;'
        ' border-bottom: 1px solid #1e3048;'
        ' border-right: 1px solid #1e3048;'
        '}'
        'QHeaderView {'
        ' background-color: #0e1824;'
        ' border: none;'
        ' border-bottom: 2px solid #2a5080;'
        '}'
        'QHeaderView::section {'
        ' background-color: #0e1824;'
        ' color: #7bafd4;'
        f' min-height: {_scale(36, ui_scale)}px;'
        f' padding: 0px {_scale(8, ui_scale)}px;'
        ' border-bottom: 2px solid #2a5080;'
        ' border-right: 1px solid #1e3048;'
        ' border-top: none;'
        ' border-left: none;'
        '}'
    )


def interface_checkbox_stylesheet(obj_name: str, ui_scale: float) -> str:
    """Return the QSS for an interface selection dialog checkbox at the given UI `scale`."""
    return (
        f'QCheckBox#{obj_name} {{ font-size: {_scale(13, ui_scale)}pt; }} '
        f'QCheckBox#{obj_name}::indicator {{ width: {_scale(19, ui_scale)}px; height: {_scale(19, ui_scale)}px; }}'
    )


def interface_instruction_label_stylesheet(scale: float) -> str:
    """Return the QSS for the interface selection dialog instruction label at the given UI `scale`."""
    return f'font-size: {_scale(13, scale)}pt;'


# =============================================================================
# INTERFACE SELECTION DIALOG BUTTON STYLES (SCALED)
# =============================================================================


def interface_select_button_disabled_style(scale: float) -> str:
    """Return the QSS for the interface selection dialog Select button in its disabled/greyed state at the given UI `scale`."""
    return f'QPushButton {{ font-size: {_scale(20, scale)}pt; background-color: #555555; color: #aaaaaa; border: 2px solid #3a3a3a; border-radius: 10px;}}'


def interface_select_button_enabled_style(scale: float) -> str:
    """Return the QSS for the interface selection dialog Select button in its enabled state at the given UI `scale`."""
    return (
        'QPushButton {'
        f' font-size: {_scale(22, scale)}pt;'
        ' background-color: #175bb0;'
        ' color: #ffffff;'
        ' border: 2px solid #2a6aaa;'
        ' border-radius: 10px;'
        '}'
        'QPushButton:hover {'
        ' background-color: #1e6ec7;'
        ' border: 2px solid #4a8fd4;'
        '}'
    )


def interface_secondary_button_enabled_style(scale: float) -> str:
    """Return the QSS for a secondary action button in the interface selection dialog in its enabled state at the given UI `scale`."""
    return (
        'QPushButton {'
        f' font-size: {_scale(14, scale)}pt;'
        ' background-color: #21334c;'
        ' color: #e8f0f8;'
        ' border: 2px solid #1e3f60;'
        ' border-radius: 8px;'
        f' padding: {_scale(4, scale)}px {_scale(10, scale)}px;'
        '}'
        'QPushButton:hover {'
        ' background-color: #2c4463;'
        ' border: 2px solid #2a5888;'
        '}'
    )


def interface_secondary_button_disabled_style(scale: float) -> str:
    """Return the QSS for a secondary action button in the interface selection dialog in its disabled (greyed-out) state at the given UI `scale`."""
    return (
        'QPushButton {'
        f' font-size: {_scale(14, scale)}pt;'
        ' background-color: #555555;'
        ' color: #aaaaaa;'
        ' border: 2px solid #3a3a3a;'
        ' border-radius: 8px;'
        f' padding: {_scale(4, scale)}px {_scale(10, scale)}px;'
        '}'
    )


def format_interface_refresh_arp_progress_style(ui_scale: float, fraction: float, *, dimmed: bool = False) -> str:
    """Build a QSS that renders a horizontal gradient progress fill inside the Refresh ARP button.

    Designed to match the dialog's deep-blue palette (Start button `#175bb0`,
    button base `#21334c`). The fill animates a bright accent gradient over a
    darker track to read clearly against the dialog's bottom container.
    When `dimmed` is True, grey colors are used to signal the button will be disabled on completion.
    """
    if dimmed:
        _fill_left = '#4a4a4a'
        _fill_mid = '#666666'
        _fill_right = '#7a7a7a'
        _track_dark = '#1e1e1e'
        _track_light = '#2e2e2e'
    else:
        _fill_left = '#1e5a9c'
        _fill_mid = '#3d7fc4'
        _fill_right = '#5599dd'
        _track_dark = '#0f1a28'
        _track_light = '#1a2738'
    clamped = max(0.0, min(1.0, fraction))
    next_stop = min(1.0, clamped + 0.0001)
    return (
        'QPushButton {'
        f' font-size: {_scale(12, ui_scale)}pt;'
        ' background: qlineargradient(x1:0, y1:0, x2:1, y2:0,'
        f' stop:0 {_fill_left},'
        f' stop:{clamped * 0.5:.4f} {_fill_mid},'
        f' stop:{clamped:.4f} {_fill_right},'
        f' stop:{next_stop:.4f} {_track_dark},'
        f' stop:1 {_track_light});'
        ' color: #ffffff;'
        ' font-weight: 700;'
        ' letter-spacing: 1px;'
        ' border: 2px solid #2a5888;'
        ' border-radius: 8px;'
        f' padding: {_scale(4, ui_scale)}px {_scale(10, ui_scale)}px;'
        ' }'
    )


def interface_tab_container_stylesheet(ui_scale: float) -> str:
    """Return the QSS for the segmented navigation tab bar container at the given UI `scale`."""
    return f'QFrame#interfaceTabContainer {{ background-color: #0b1420; border: 1px solid #1a2c42; border-radius: {_scale(8, ui_scale)}px; padding: {_scale(4, ui_scale)}px;}}'


def interface_tab_button_stylesheet(ui_scale: float) -> str:
    """Return the QSS for segmented navigation tab buttons at the given UI `scale`."""
    return (
        'QPushButton#tabInterfacesButton, QPushButton#tabHotspotButton {'
        f' font-size: {_scale(10, ui_scale)}pt;'
        ' font-weight: 600;'
        ' color: #7e95ab;'
        ' background-color: transparent;'
        ' border: 1px solid transparent;'
        f' border-radius: {_scale(6, ui_scale)}px;'
        f' padding: {_scale(8, ui_scale)}px {_scale(20, ui_scale)}px;'
        f' min-height: {_scale(34, ui_scale)}px;'
        ' text-align: center;'
        '}'
        'QPushButton#tabInterfacesButton:hover:!checked, QPushButton#tabHotspotButton:hover:!checked {'
        ' background-color: rgba(255, 255, 255, 0.04);'
        ' color: #cbe0f5;'
        '}'
        'QPushButton#tabInterfacesButton:checked, QPushButton#tabHotspotButton:checked {'
        ' background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 rgba(0, 180, 216, 0.22), stop:1 rgba(0, 180, 216, 0.06));'
        ' border: 1px solid #00b4d8;'
        ' color: #ffffff;'
        ' font-weight: 700;'
        '}'
        'QPushButton#tabInterfacesButton:checked:hover, QPushButton#tabHotspotButton:checked:hover {'
        ' background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 rgba(56, 189, 248, 0.28), stop:1 rgba(56, 189, 248, 0.10));'
        ' border: 1px solid #38bdf8;'
        ' color: #ffffff;'
        '}'
    )
