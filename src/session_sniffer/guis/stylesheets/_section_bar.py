"""Section header bar and expand-button QSS."""

# =============================================================================
# SECTION HEADER BAR STYLES
# =============================================================================


def section_bar_qss(accent: str) -> str:
    """Return the QSS for a session table section header bar with the given `accent` color."""
    red, green, blue = int(accent[1:3], 16), int(accent[3:5], 16), int(accent[5:7], 16)
    dark = f'#{int(red * 0.6):02x}{int(green * 0.6):02x}{int(blue * 0.6):02x}'
    return f"""
    QFrame#sectionBar {{
        background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                    stop:0 {accent},
                                    stop:1 {dark});
        border: 2px solid {accent};
        border-bottom: none;
        border-top-left-radius: 8px;
        border-top-right-radius: 8px;
    }}
    QLabel {{
        color: white;
        background: transparent;
    }}
    QLabel#sectionTitle {{
        font-size: 11pt;
        font-weight: 600;
    }}
    QComboBox, QPushButton, QToolButton {{
        min-height: 28px;
        padding: 0 8px;
        color: white;
        background: rgba(0, 0, 0, 0.18);
        border: 1px solid rgba(255, 255, 255, 0.55);
        border-radius: 6px;
    }}
    QSpinBox {{
        min-height: 28px;
        padding: 0 14px 0 2px;
        color: white;
        background: rgba(0, 0, 0, 0.18);
        border: 1px solid rgba(255, 255, 255, 0.55);
        border-radius: 6px;
        min-width: 55px;
        max-width: 68px;
    }}
    QLineEdit {{
        min-height: 28px;
        padding: 0 30px 0 8px;
        color: white;
        background: rgba(0, 0, 0, 0.18);
        border: 1px solid rgba(255, 255, 255, 0.55);
        border-radius: 6px;
    }}
    QLineEdit QToolButton {{
        min-height: 0;
        padding: 0 2px;
        border: none;
        background: transparent;
    }}
    QPushButton:hover, QToolButton:hover, QComboBox:hover, QLineEdit:hover, QSpinBox:hover {{
        border-color: rgba(255, 255, 255, 0.85);
        background: rgba(0, 0, 0, 0.28);
    }}
    QPushButton:pressed, QToolButton:pressed {{
        background: rgba(0, 0, 0, 0.40);
    }}
    QComboBox::drop-down {{
        subcontrol-origin: padding;
        subcontrol-position: top right;
        width: 20px;
        border: none;
        border-left: 1px solid rgba(255, 255, 255, 0.55);
    }}
    QSpinBox::up-button {{
        subcontrol-origin: border;
        subcontrol-position: top right;
        width: 18px;
        border: none;
        border-left: 1px solid rgba(255, 255, 255, 0.55);
        border-bottom: 1px solid rgba(255, 255, 255, 0.25);
    }}
    QSpinBox::down-button {{
        subcontrol-origin: border;
        subcontrol-position: bottom right;
        width: 18px;
        border: none;
        border-left: 1px solid rgba(255, 255, 255, 0.55);
    }}
    QComboBox QAbstractItemView {{
        background-color: #2a2a2a; color: #e0e0e0;
        border: 1px solid rgba(128, 128, 128, 0.5);
        selection-background-color: #404040; outline: 0;
    }}
    """.strip()


def get_expand_button_stylesheet(
    background_color: str,
    border_color: str,
    hover_background_color: str,
    hover_border_color: str,
    pressed_background_color: str,
) -> str:
    """Generate a stylesheet for an expand button with the given colors."""
    return f"""
QPushButton {{
    background-color: {background_color};
    color: #e0e0e0;
    border: 1px solid {border_color};
    border-radius: 4px;
    padding: 6px 16px;
    font-size: 9pt;
    font-weight: bold;
    margin: 5px;
}}

QPushButton:hover {{
    background-color: {hover_background_color};
    border-color: {hover_border_color};
}}

QPushButton:pressed {{
    background-color: {pressed_background_color};
}}
""".strip()


CONNECTED_EXPAND_BUTTON_STYLESHEET = get_expand_button_stylesheet(
    background_color='#2b663d',
    border_color='#1d4d2b',
    hover_background_color='#327546',
    hover_border_color='#235932',
    pressed_background_color='#1f4f2e',
)

DISCONNECTED_EXPAND_BUTTON_STYLESHEET = get_expand_button_stylesheet(
    background_color='#823232',
    border_color='#5c2323',
    hover_background_color='#943b3b',
    hover_border_color='#732a2a',
    pressed_background_color='#632525',
)
