"""Section header bar and expand-button QSS."""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

# =============================================================================
# SECTION HEADER BAR STYLES
# =============================================================================


def section_bar_qss(accent: str, resources_dir: Path) -> str:
    """Return the QSS for a session table section header bar with the given `accent` color."""
    r, g, b = int(accent[1:3], 16), int(accent[3:5], 16), int(accent[5:7], 16)
    dark = f'#{int(r * 0.6):02x}{int(g * 0.6):02x}{int(b * 0.6):02x}'
    arrow_down_path = (resources_dir / 'icons' / 'arrow_down.svg').as_posix()
    arrow_up_path = (resources_dir / 'icons' / 'arrow_up.svg').as_posix()
    return f"""
    QFrame#sectionBar {{
        background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                    stop:0 {accent},
                                    stop:1 {dark});
        border: 2px solid {accent};
        border-radius: 8px;
    }}
    QLabel {{
        color: white;
        background: transparent;
    }}
    QLabel#sectionTitle {{
        font-size: 15px;
        font-weight: 600;
    }}
    QComboBox, QPushButton, QToolButton, QSpinBox {{
        min-height: 28px;
        padding: 0 8px;
        color: white;
        background: rgba(0, 0, 0, 0.18);
        border: 1px solid rgba(255, 255, 255, 0.55);
        border-radius: 6px;
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
    QComboBox::down-arrow {{
        image: url("{arrow_down_path}");
        width: 8px;
        height: 5px;
    }}
    QSpinBox::up-button {{
        subcontrol-origin: border;
        subcontrol-position: top right;
        width: 18px;
        border: none;
        border-left: 1px solid rgba(255, 255, 255, 0.55);
        border-bottom: 1px solid rgba(255, 255, 255, 0.25);
    }}
    QSpinBox::up-arrow {{
        image: url("{arrow_up_path}");
        width: 7px;
        height: 4px;
    }}
    QSpinBox::down-button {{
        subcontrol-origin: border;
        subcontrol-position: bottom right;
        width: 18px;
        border: none;
        border-left: 1px solid rgba(255, 255, 255, 0.55);
    }}
    QSpinBox::down-arrow {{
        image: url("{arrow_down_path}");
        width: 7px;
        height: 4px;
    }}
    QComboBox QAbstractItemView {{
        background-color: #2a2a2a; color: #e0e0e0;
        border: 1px solid rgba(128, 128, 128, 0.5);
        selection-background-color: #404040; outline: 0;
    }}
    """.strip()


CONNECTED_EXPAND_BUTTON_STYLESHEET = """
QPushButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #2e7d32, stop:1 #1b5e20);
    color: white;
    border: 2px solid #444;
    border-radius: 8px;
    padding: 8px 16px;
    font-size: 12px;
    font-weight: bold;
    margin: 5px;
}

QPushButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #388e3c, stop:1 #2e7d32);
    border-color: #666;
}

QPushButton:pressed {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #1b5e20, stop:1 #0d47a1);
    border-color: #333;
}
""".strip()

DISCONNECTED_EXPAND_BUTTON_STYLESHEET = """
QPushButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #8B0000, stop:1 #660000);
    color: white;
    border: 2px solid #444;
    border-radius: 8px;
    padding: 8px 16px;
    font-size: 12px;
    font-weight: bold;
    margin: 5px;
}

QPushButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #A52A2A, stop:1 #8B0000);
    border-color: #666;
}

QPushButton:pressed {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #660000, stop:1 #4A0000);
    border-color: #333;
}
""".strip()
