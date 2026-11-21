"""Section header bar and expand-button QSS."""

from session_sniffer.guis.theming import themed_qss

# =============================================================================
# SECTION HEADER BAR STYLES
# =============================================================================

_ROLE_CANONICAL_ACCENTS: dict[str, tuple[str, str, str]] = {
    'success': ('#22c55e', '34, 197, 94', '#4ade80'),
    'danger': ('#ef4444', '239, 68, 68', '#f87171'),
}


def section_bar_qss(role_token: str) -> str:
    """Return the QSS for a session table section header bar bound to `@table_header` and `@<role_token>`."""
    accent_hex = _ROLE_CANONICAL_ACCENTS.get(role_token, ('#22c55e', '34, 197, 94', '#4ade80'))[0]
    red, green, blue = int(accent_hex[1:3], 16), int(accent_hex[3:5], 16), int(accent_hex[5:7], 16)
    bg_top = f'#{int(red * 0.12) + 14:02x}{int(green * 0.12) + 16:02x}{int(blue * 0.12) + 18:02x}'
    bg_bottom = f'#{int(red * 0.06) + 10:02x}{int(green * 0.06) + 11:02x}{int(blue * 0.06) + 13:02x}'
    border_color = f'#{int(red * 0.3) + 18:02x}{int(green * 0.3) + 20:02x}{int(blue * 0.3) + 22:02x}'
    return themed_qss(
        f"""
    QFrame#sectionBar {{
        background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                    stop:0 @table_header~{role_token}[{bg_top}],
                                    stop:1 @table_header~{role_token}[{bg_bottom}]);
        border: 1px solid @border~{role_token}[{border_color}];
        border-top: 2px solid @{role_token}[{accent_hex}];
        border-bottom: 1px solid @border~{role_token}[{border_color}];
        border-top-left-radius: 8px;
        border-top-right-radius: 8px;
    }}
    QLabel {{
        color: @text_muted[#94a3b8];
        background: transparent;
        font-size: 8.5pt;
    }}
    QLabel#sectionTitle {{
        font-size: 11pt;
        font-weight: 600;
        color: @text_strong[#ffffff];
        letter-spacing: 0.2px;
    }}
    QPushButton {{
        min-height: 26px;
        max-height: 26px;
        padding: 0 12px;
        color: @text[#cbd5e1];
        background: @control[rgba(255, 255, 255, 0.05)];
        border: 1px solid @border[rgba(255, 255, 255, 0.12)];
        border-radius: 6px;
        font-weight: 700;
        font-size: 8.5pt;
    }}
    QPushButton:hover {{
        background: @control[rgba(255, 255, 255, 0.10)];
        border-color: @border[rgba(255, 255, 255, 0.25)];
        color: @text_strong[#ffffff];
    }}
    QPushButton:disabled {{
        background: @control[rgba(255, 255, 255, 0.02)];
        border-color: @border[rgba(255, 255, 255, 0.05)];
        color: @text_muted[#4b5563];
    }}
    QPushButton:pressed {{
        background: @control[rgba(255, 255, 255, 0.03)];
    }}
    QPushButton#sectionClearButton:hover {{
        background: @danger[rgba(239, 68, 68, 0.15)];
        border-color: @danger[rgba(239, 68, 68, 0.45)];
        color: @danger[#fca5a5];
    }}
    QPushButton#sectionMergeButton:hover {{
        background: @accent[rgba(59, 130, 246, 0.15)];
        border-color: @accent[rgba(59, 130, 246, 0.45)];
        color: @accent[#93c5fd];
    }}
    QToolButton#sectionCollapseButton {{
        min-width: 26px;
        max-width: 26px;
        min-height: 26px;
        max-height: 26px;
        padding: 0;
        color: @text[#cbd5e1];
        background: @control[rgba(255, 255, 255, 0.05)];
        border: 1px solid @border[rgba(255, 255, 255, 0.12)];
        border-radius: 6px;
    }}
    QToolButton#sectionCollapseButton:hover {{
        background: @control[rgba(255, 255, 255, 0.10)];
        border-color: @border[rgba(255, 255, 255, 0.25)];
        color: @text_strong[#ffffff];
    }}
    QToolButton#sectionCollapseButton:pressed {{
        background: @control[rgba(255, 255, 255, 0.03)];
    }}
    QComboBox {{
        min-height: 26px;
        max-height: 26px;
        padding: 0 20px 0 8px;
        color: @text[#f1f5f9];
        background: @input[rgba(0, 0, 0, 0.35)];
        border: 1px solid @border[rgba(255, 255, 255, 0.12)];
        border-radius: 6px;
        min-width: 55px;
        font-size: 8.5pt;
    }}
    QComboBox:hover {{
        background: @input[rgba(0, 0, 0, 0.50)];
        border-color: @border[rgba(255, 255, 255, 0.25)];
    }}
    QComboBox:focus, QComboBox:on {{
        border-color: @{role_token}[{accent_hex}];
    }}
    QComboBox:disabled {{
        color: @text_muted[rgba(255, 255, 255, 0.35)];
        background: @input[rgba(0, 0, 0, 0.20)];
        border-color: @border[rgba(255, 255, 255, 0.05)];
    }}
    QComboBox::drop-down {{
        subcontrol-origin: padding;
        subcontrol-position: top right;
        width: 18px;
        border: none;
        border-left: 1px solid @border[rgba(255, 255, 255, 0.10)];
    }}
    QSpinBox {{
        min-height: 26px;
        max-height: 26px;
        padding: 0 18px 0 6px;
        color: @text[#f1f5f9];
        background: @input[rgba(0, 0, 0, 0.35)];
        border: 1px solid @border[rgba(255, 255, 255, 0.12)];
        border-radius: 6px;
        font-size: 8.5pt;
    }}
    QSpinBox#sectionRowsSpinBox {{
        min-width: 48px;
        max-width: 60px;
    }}
    QSpinBox#sectionPageSpinBox {{
        min-width: 34px;
        max-width: 46px;
    }}
    QSpinBox:hover {{
        background: @input[rgba(0, 0, 0, 0.50)];
        border-color: @border[rgba(255, 255, 255, 0.25)];
    }}
    QSpinBox:focus {{
        border-color: @{role_token}[{accent_hex}];
    }}
    QSpinBox:disabled {{
        color: @text_muted[rgba(241, 245, 249, 0.65)];
        background: @input[rgba(0, 0, 0, 0.28)];
        border-color: @border[rgba(255, 255, 255, 0.08)];
    }}
    QSpinBox::up-button {{
        subcontrol-origin: border;
        subcontrol-position: top right;
        width: 16px;
        border: none;
        border-left: 1px solid @border[rgba(255, 255, 255, 0.10)];
        border-bottom: 1px solid @border[rgba(255, 255, 255, 0.06)];
    }}
    QSpinBox::down-button {{
        subcontrol-origin: border;
        subcontrol-position: bottom right;
        width: 16px;
        border: none;
        border-left: 1px solid @border[rgba(255, 255, 255, 0.10)];
    }}
    QSpinBox::up-button:hover, QSpinBox::down-button:hover {{
        background: @control[rgba(255, 255, 255, 0.08)];
    }}
    QSpinBox::up-arrow {{
        right: 1px;
        top: 1px;
    }}
    QSpinBox::down-arrow {{
        right: 1px;
        bottom: 1px;
    }}
    QLineEdit {{
        min-height: 26px;
        max-height: 26px;
        padding: 0 30px 0 8px;
        color: @text[#f1f5f9];
        background: @input[rgba(0, 0, 0, 0.35)];
        border: 1px solid @border[rgba(255, 255, 255, 0.12)];
        border-radius: 6px;
        font-size: 8.5pt;
    }}
    QLineEdit:hover {{
        background: @input[rgba(0, 0, 0, 0.50)];
        border-color: @border[rgba(255, 255, 255, 0.25)];
    }}
    QLineEdit:focus {{
        border-color: @{role_token}[{accent_hex}];
    }}
    QLineEdit QToolButton {{
        min-height: 0;
        padding: 0 2px;
        border: none;
        background: transparent;
    }}
    QComboBox QAbstractItemView {{
        background-color: @popup[#1e1e24];
        color: @text[#e0e0e0];
        border: 1px solid @border[#333642];
        border-radius: 6px;
        padding: 2px;
        selection-background-color: @selection[#2b2e3a];
        outline: 0;
    }}
    QComboBox QAbstractItemView::item {{
        min-height: 20px;
        padding: 2px 6px;
        border-radius: 4px;
        border: none;
    }}
    QComboBox QAbstractItemView::item:selected, QComboBox QAbstractItemView::item:hover {{
        background-color: @selection[#2b2e3a];
        color: @text_strong[#ffffff];
    }}
    QComboBox QAbstractItemView::item:disabled {{
        color: @text_muted[rgba(255, 255, 255, 0.35)];
        background: transparent;
    }}
    """.strip(),
    )


def get_expand_button_stylesheet(role_token: str) -> str:
    """Generate a stylesheet for a collapsed section expand button bound to `@control` and `@<role_token>`."""
    _, accent_rgba, text_color = _ROLE_CANONICAL_ACCENTS.get(role_token, ('#22c55e', '34, 197, 94', '#4ade80'))
    return themed_qss(
        f"""
QPushButton {{
    background-color: @{role_token}[rgba({accent_rgba}, 0.12)];
    color: @{role_token}[{text_color}];
    border: 1px solid @{role_token}[rgba({accent_rgba}, 0.35)];
    border-radius: 6px;
    padding: 6px 16px;
    font-size: 8.5pt;
    font-weight: 600;
    margin: 5px;
}}

QPushButton:hover {{
    background-color: @{role_token}[rgba({accent_rgba}, 0.22)];
    border-color: @{role_token}[rgba({accent_rgba}, 0.55)];
    color: @text_strong[#ffffff];
}}

QPushButton:pressed {{
    background-color: @{role_token}[rgba({accent_rgba}, 0.08)];
}}
""".strip(),
    )


CONNECTED_EXPAND_BUTTON_STYLESHEET = get_expand_button_stylesheet('success')

DISCONNECTED_EXPAND_BUTTON_STYLESHEET = get_expand_button_stylesheet('danger')
