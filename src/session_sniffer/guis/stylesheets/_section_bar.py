"""Section header bar and expand-button QSS."""

# =============================================================================
# SECTION HEADER BAR STYLES
# =============================================================================


def section_bar_qss(accent: str) -> str:
    """Return the QSS for a session table section header bar with the given `accent` color."""
    red, green, blue = int(accent[1:3], 16), int(accent[3:5], 16), int(accent[5:7], 16)
    bg_top = f'#{int(red * 0.12) + 14:02x}{int(green * 0.12) + 16:02x}{int(blue * 0.12) + 18:02x}'
    bg_bottom = f'#{int(red * 0.06) + 10:02x}{int(green * 0.06) + 11:02x}{int(blue * 0.06) + 13:02x}'
    border_color = f'#{int(red * 0.3) + 18:02x}{int(green * 0.3) + 20:02x}{int(blue * 0.3) + 22:02x}'
    return f"""
    QFrame#sectionBar {{
        background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                    stop:0 {bg_top},
                                    stop:1 {bg_bottom});
        border: 1px solid {border_color};
        border-top: 2px solid {accent};
        border-bottom: 1px solid {border_color};
        border-top-left-radius: 8px;
        border-top-right-radius: 8px;
    }}
    QLabel {{
        color: #94a3b8;
        background: transparent;
        font-size: 8.5pt;
    }}
    QLabel#sectionTitle {{
        font-size: 11pt;
        font-weight: 600;
        color: #ffffff;
        letter-spacing: 0.2px;
    }}
    QPushButton, QToolButton {{
        min-height: 28px;
        padding: 0 10px;
        color: #cbd5e1;
        background: rgba(255, 255, 255, 0.05);
        border: 1px solid rgba(255, 255, 255, 0.12);
        border-radius: 6px;
        font-size: 8.5pt;
    }}
    QPushButton:hover, QToolButton:hover {{
        background: rgba(255, 255, 255, 0.10);
        border-color: rgba(255, 255, 255, 0.25);
        color: #ffffff;
    }}
    QPushButton:pressed, QToolButton:pressed {{
        background: rgba(255, 255, 255, 0.03);
    }}
    QPushButton#sectionClearButton:hover {{
        background: rgba(239, 68, 68, 0.15);
        border-color: rgba(239, 68, 68, 0.45);
        color: #fca5a5;
    }}
    QPushButton#sectionMergeButton:hover {{
        background: rgba(59, 130, 246, 0.15);
        border-color: rgba(59, 130, 246, 0.45);
        color: #93c5fd;
    }}
    QComboBox {{
        min-height: 28px;
        padding: 0 16px 0 6px;
        color: #f1f5f9;
        background: rgba(0, 0, 0, 0.35);
        border: 1px solid rgba(255, 255, 255, 0.12);
        border-radius: 6px;
        min-width: 55px;
        max-width: 90px;
        font-size: 8.5pt;
    }}
    QComboBox:hover {{
        background: rgba(0, 0, 0, 0.50);
        border-color: rgba(255, 255, 255, 0.25);
    }}
    QComboBox:focus, QComboBox:on {{
        border-color: {accent};
    }}
    QComboBox:disabled {{
        color: rgba(255, 255, 255, 0.35);
        background: rgba(0, 0, 0, 0.20);
        border-color: rgba(255, 255, 255, 0.05);
    }}
    QComboBox::drop-down {{
        subcontrol-origin: padding;
        subcontrol-position: top right;
        width: 16px;
        border: none;
        border-left: 1px solid rgba(255, 255, 255, 0.10);
    }}
    QSpinBox {{
        min-height: 28px;
        padding: 0 16px 0 6px;
        color: #f1f5f9;
        background: rgba(0, 0, 0, 0.35);
        border: 1px solid rgba(255, 255, 255, 0.12);
        border-radius: 6px;
        min-width: 55px;
        max-width: 72px;
        font-size: 8.5pt;
    }}
    QSpinBox:hover {{
        background: rgba(0, 0, 0, 0.50);
        border-color: rgba(255, 255, 255, 0.25);
    }}
    QSpinBox:focus {{
        border-color: {accent};
    }}
    QSpinBox::up-button {{
        subcontrol-origin: border;
        subcontrol-position: top right;
        width: 16px;
        border: none;
        border-left: 1px solid rgba(255, 255, 255, 0.10);
        border-bottom: 1px solid rgba(255, 255, 255, 0.06);
    }}
    QSpinBox::down-button {{
        subcontrol-origin: border;
        subcontrol-position: bottom right;
        width: 16px;
        border: none;
        border-left: 1px solid rgba(255, 255, 255, 0.10);
    }}
    QSpinBox::up-button:hover, QSpinBox::down-button:hover {{
        background: rgba(255, 255, 255, 0.08);
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
        min-height: 28px;
        padding: 0 30px 0 8px;
        color: #f1f5f9;
        background: rgba(0, 0, 0, 0.35);
        border: 1px solid rgba(255, 255, 255, 0.12);
        border-radius: 6px;
        font-size: 8.5pt;
    }}
    QLineEdit:hover {{
        background: rgba(0, 0, 0, 0.50);
        border-color: rgba(255, 255, 255, 0.25);
    }}
    QLineEdit:focus {{
        border-color: {accent};
    }}
    QLineEdit QToolButton {{
        min-height: 0;
        padding: 0 2px;
        border: none;
        background: transparent;
    }}
    QComboBox QAbstractItemView {{
        background-color: #1e1e24;
        color: #e0e0e0;
        border: 1px solid #333642;
        border-radius: 6px;
        padding: 2px;
        selection-background-color: #2b2e3a;
        outline: 0;
    }}
    QComboBox QAbstractItemView::item {{
        min-height: 20px;
        padding: 2px 6px;
        border-radius: 4px;
        border: none;
    }}
    QComboBox QAbstractItemView::item:selected, QComboBox QAbstractItemView::item:hover {{
        background-color: #2b2e3a;
        color: #ffffff;
    }}
    QComboBox QAbstractItemView::item:disabled {{
        color: rgba(255, 255, 255, 0.35);
        background: transparent;
    }}
    """.strip()


def get_expand_button_stylesheet(accent_rgba: str, text_color: str) -> str:
    """Generate a stylesheet for an expand button with the given accent and text color."""
    return f"""
QPushButton {{
    background-color: rgba({accent_rgba}, 0.12);
    color: {text_color};
    border: 1px solid rgba({accent_rgba}, 0.35);
    border-radius: 6px;
    padding: 6px 16px;
    font-size: 8.5pt;
    font-weight: 600;
    margin: 5px;
}}

QPushButton:hover {{
    background-color: rgba({accent_rgba}, 0.22);
    border-color: rgba({accent_rgba}, 0.55);
    color: #ffffff;
}}

QPushButton:pressed {{
    background-color: rgba({accent_rgba}, 0.08);
}}
""".strip()


CONNECTED_EXPAND_BUTTON_STYLESHEET = get_expand_button_stylesheet('34, 197, 94', '#4ade80')

DISCONNECTED_EXPAND_BUTTON_STYLESHEET = get_expand_button_stylesheet('239, 68, 68', '#f87171')
