"""Interface selection dialog QSS — static containers, table, checkboxes, and scaled buttons."""

# =============================================================================
# INTERFACE SELECTION DIALOG STYLES
# =============================================================================

INTERFACE_TABLE_CONTAINER_STYLESHEET = (
    'QFrame#tableContainer {'
    ' border: 1px solid #3a6aaa;'
    ' border-radius: 6px;'
    '}'
)

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

INTERFACE_BOTTOM_SEPARATOR_STYLESHEET = (
    'QFrame#bottomSeparator {'
    ' background-color: #2f4356;'
    ' max-height: 1px;'
    ' border: none;'
    '}'
)


def interface_header_label_stylesheet(scale: float) -> str:
    """Return the QSS for the interface selection dialog title label at the given UI `scale`."""
    def _s(n: int) -> int:
        return max(1, round(n * scale))
    return (
        'QLabel#dialogTitleLabel {'
        ' color: #f4f7fb;'
        f' font-size: {_s(23)}px;'
        ' font-weight: 700;'
        f' padding-top: {_s(6)}px;'
        f' padding-bottom: {_s(6)}px;'
        '}'
    )


def interface_table_stylesheet(scale: float) -> str:
    """Return the QSS for the interface selection table widget at the given UI `scale`."""
    def _s(n: int) -> int:
        return max(1, round(n * scale))
    return (
        'QTableWidget {'
        ' background-color: #131e2c;'
        ' alternate-background-color: #182536;'
        ' border: none;'
        ' outline: none;'
        '}'
        'QTableWidget::item {'
        f' font-size: {_s(12)}px;'
        ' color: #c8ddf0;'
        f' padding: 0px {_s(16)}px;'
        ' border-bottom: 1px solid #1e3048;'
        ' border-right: 1px solid #1e3048;'
        '}'
        'QTableWidget::item:selected {'
        ' background-color: #1a4a8a;'
        ' color: #ffffff;'
        f' padding: 0px {_s(16)}px;'
        ' border-bottom: 1px solid #1e3048;'
        ' border-right: 1px solid #1e3048;'
        '}'
        'QTableWidget::item:hover:!selected {'
        ' background-color: #1c3050;'
        ' border-bottom: 1px solid #1e3048;'
        ' border-right: 1px solid #1e3048;'
        '}'
        'QHeaderView::section {'
        ' background-color: #0e1824;'
        ' color: #7bafd4;'
        f' min-height: {_s(36)}px;'
        f' padding: 0px {_s(16)}px;'
        ' border-bottom: 2px solid #2a5080;'
        ' border-right: 1px solid #1e3048;'
        ' border-top: none;'
        ' border-left: none;'
        '}'
    )


def interface_checkbox_stylesheet(obj_name: str, scale: float) -> str:
    """Return the QSS for an interface selection dialog checkbox at the given UI `scale`."""
    def _s(n: int) -> int:
        return max(1, round(n * scale))
    return (
        f'QCheckBox#{obj_name} {{ font-size: {_s(14)}pt; }}'
        f' QCheckBox#{obj_name}::indicator {{ width: {_s(20)}px; height: {_s(20)}px; }}'
    )


def interface_instruction_label_stylesheet(scale: float) -> str:
    """Return the QSS for the interface selection dialog instruction label at the given UI `scale`."""
    return f'font-size: {max(1, round(17 * scale))}px;'


# =============================================================================
# INTERFACE SELECTION DIALOG BUTTON STYLES (SCALED)
# =============================================================================


def interface_select_button_disabled_style(scale: float) -> str:
    """Return the QSS for the interface selection dialog Select button in its disabled/greyed state at the given UI `scale`."""
    font_size = max(1, round(20 * scale))
    return (
        'QPushButton {'
        f' font-size: {font_size}pt;'
        ' background-color: #555555;'
        ' color: #aaaaaa;'
        ' border: 2px solid #3a3a3a;'
        ' border-radius: 10px;'
        '}'
    )


def interface_select_button_enabled_style(scale: float) -> str:
    """Return the QSS for the interface selection dialog Select button in its enabled state at the given UI `scale`."""
    font_size = max(1, round(22 * scale))
    return (
        'QPushButton {'
        f' font-size: {font_size}pt;'
        ' background-color: #175BB0;'
        ' color: #ffffff;'
        ' border: 2px solid #2a6aaa;'
        ' border-radius: 10px;'
        '}'
        'QPushButton:hover {'
        ' background-color: #1e6ec7;'
        ' border: 2px solid #4a8fd4;'
        '}'
    )


def interface_refresh_arp_button_enabled_style(scale: float) -> str:
    """Return the QSS for the Refresh ARP button in its enabled state at the given UI `scale`."""
    font_size = max(1, round(16 * scale))
    padding_v = max(1, round(6 * scale))
    padding_h = max(1, round(14 * scale))
    return (
        'QPushButton {'
        f' font-size: {font_size}pt;'
        ' background-color: #21334C;'
        ' color: #e8f0f8;'
        ' border: 2px solid #1e3f60;'
        ' border-radius: 10px;'
        f' padding: {padding_v}px {padding_h}px;'
        '}'
        'QPushButton:hover {'
        ' background-color: #2c4463;'
        ' border: 2px solid #2a5888;'
        '}'
    )


def format_interface_refresh_arp_progress_style(ui_scale: float, fraction: float) -> str:
    """Build a QSS that renders a horizontal grey gradient progress fill inside the Refresh ARP button."""
    _fill_light = '#e6e6e6'
    _fill_dark = '#9a9a9a'
    _track_light = '#4a4a4a'
    _track_dark = '#2e2e2e'
    _dark_text_threshold = 0.45
    clamped = max(0.0, min(1.0, fraction))
    next_stop = min(1.0, clamped + 0.0001)
    text_color = '#1a1a1a' if clamped >= _dark_text_threshold else '#f0f0f0'
    font_size = round(12 * ui_scale)
    return (
        'QPushButton {'
        f' font-size: {font_size}pt;'
        ' background: qlineargradient(x1:0, y1:0, x2:1, y2:0,'
        f' stop:0 {_fill_light},'
        f' stop:{clamped:.4f} {_fill_dark},'
        f' stop:{next_stop:.4f} {_track_light},'
        f' stop:1 {_track_dark});'
        f' color: {text_color};'
        ' font-weight: bold;'
        ' border: 1px solid #1a1a1a;'
        ' border-radius: 10px;'
        ' padding: 4px 12px;'
        ' }'
    )
