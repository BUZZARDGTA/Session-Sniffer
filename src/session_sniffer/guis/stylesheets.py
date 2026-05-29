"""GUI Stylesheets Module.

This module contains all the QSS (Qt Style Sheets) used throughout the application.
Centralizing stylesheets here makes them easier to maintain and modify.
"""

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


# =============================================================================
# DIALOG BUTTON STYLES
# =============================================================================

DIALOG_BUTTON_STYLESHEET = """
QPushButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 rgba(236, 240, 241, 0.12), stop:1 rgba(189, 195, 199, 0.18));
    color: #ecf0f1;
    border: 1px solid rgba(52, 73, 94, 0.6);
    border-radius: 6px;
    padding: 6px 18px;
    font-size: 12px;
    font-weight: bold;
    min-height: 28px;
}

QPushButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 rgba(52, 152, 219, 0.25), stop:1 rgba(41, 128, 185, 0.35));
    border: 1px solid rgba(52, 152, 219, 0.8);
    color: #ffffff;
}

QPushButton:pressed {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 rgba(41, 128, 185, 0.45), stop:1 rgba(52, 152, 219, 0.55));
    border: 1px solid rgba(41, 128, 185, 1.0);
}

QPushButton:disabled {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 rgba(80, 80, 80, 0.15), stop:1 rgba(60, 60, 60, 0.20));
    color: #666672;
    border: 1px solid rgba(80, 80, 80, 0.3);
}
""".strip()

DIALOG_PRIMARY_BUTTON_STYLESHEET = """
QPushButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #3d8ec9, stop:1 #2a6fa0);
    color: #ffffff;
    border: 1px solid rgba(52, 152, 219, 0.7);
    border-radius: 6px;
    padding: 6px 24px;
    font-size: 12px;
    font-weight: bold;
    min-height: 28px;
}

QPushButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #4da3de, stop:1 #3d8ec9);
    border: 1px solid rgba(77, 163, 222, 0.9);
}

QPushButton:pressed {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #2a6fa0, stop:1 #1e5a85);
    border: 1px solid rgba(42, 111, 160, 1.0);
}

QPushButton:disabled {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 rgba(80, 80, 80, 0.15), stop:1 rgba(60, 60, 60, 0.20));
    color: #666672;
    border: 1px solid rgba(80, 80, 80, 0.3);
}
""".strip()

DIALOG_DANGER_BUTTON_STYLESHEET = """
QPushButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 rgba(192, 57, 43, 0.7), stop:1 rgba(146, 43, 33, 0.8));
    color: #ffffff;
    border: 1px solid rgba(192, 57, 43, 0.6);
    border-radius: 6px;
    padding: 6px 18px;
    font-size: 12px;
    font-weight: bold;
    min-height: 28px;
}

QPushButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 rgba(231, 76, 60, 0.8), stop:1 rgba(192, 57, 43, 0.9));
    border: 1px solid rgba(231, 76, 60, 0.9);
}

QPushButton:pressed {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 rgba(146, 43, 33, 0.9), stop:1 rgba(120, 35, 27, 1.0));
    border: 1px solid rgba(146, 43, 33, 1.0);
}

QPushButton:disabled {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 rgba(80, 80, 80, 0.15), stop:1 rgba(60, 60, 60, 0.20));
    color: #666672;
    border: 1px solid rgba(80, 80, 80, 0.3);
}
""".strip()


# =============================================================================
# CONTEXT MENU STYLES
# =============================================================================

# TODO(BUZZARDGTA): Implement a better way to retrieve the default background color for table cells.
# Currently hardcoded to Gray.B10, which should be the same color for everyone.
CUSTOM_CONTEXT_MENU_STYLESHEET = """
QMenu {
    background-color: #1e1e1e;     /* Dark background */
    border: 1px solid #2d2d2d;     /* Subtle border */
    border-radius: 8px;            /* Rounded corners */
    padding: 4px;                  /* Space inside the menu */
}

QMenu::item {
    color: #d4d4d4;                /* Light gray text color */
    padding: 6px 20px;             /* Padding for each item */
    background-color: transparent; /* Default background */
}

QMenu::item:selected {
    background: qlineargradient(
        x1: 0, y1: 0, x2: 1, y2: 1,
        stop: 0 #4a90e2,           /* Soft blue gradient start */
        stop: 1 #3c5a9a            /* Muted navy blue gradient end */
    );
    color: #ffffff;                /* White text for better contrast */
    border: 1px solid #5a5a5a;     /* Subtle border for selection */
    border-radius: 6px;            /* Rounded corners for selection */
    margin: 2px;                   /* Spacing around the item */
}

QMenu::item:disabled {
    color: #7F7F91;                /* Greyed-out text for disabled items */
    background-color: transparent; /* No background for disabled items */
}

QMenu::item:disabled:hover,
QMenu::item:disabled:selected {
    background-color: transparent; /* Prevent hover or selection color */
    color: #7F7F91;                /* Ensure text remains greyed-out */
    border: none;                  /* Remove any border effect */
}

QMenu::item:pressed {
    background-color: #36547c;     /* Slightly darker blue when pressed */
    color: #e0e0e0;                /* Slightly muted text color */
}

QMenu::separator {
    height: 1px;
    background: #2d2d2d;           /* Separator color */
    margin: 4px 0;
}
""".strip()


# =============================================================================
# DISCORD DIALOG STYLES
# =============================================================================

DISCORD_POPUP_MAIN_STYLESHEET = """
background-color: #222244;  /* Dark blueish background */
border-radius: 15px;        /* Rounded corners */
color: white;
""".strip()

DISCORD_POPUP_EXIT_BUTTON_STYLESHEET = """
font-size: 10px;
color: white;
background-color: #FF4C4C;  /* Light red background */
border-radius: 15px;        /* Make it circular */
""".strip()

DISCORD_POPUP_JOIN_BUTTON_STYLESHEET = """
font-size: 14px;
padding: 7px;
background-color: #5865F2;  /* Discord blue */
color: white;
border-radius: 10px;
border: none;
""".strip()


# =============================================================================
# STATUS BAR STYLES
# =============================================================================

MENU_BAR_STYLESHEET = """
QMenuBar {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 #2e3440, stop:1 #3b4252);
    color: #d8dee9;
    border-bottom: 2px solid #88c0d0;
    font-family: 'Segoe UI', 'Roboto', sans-serif;
    font-size: 10pt;
    font-weight: 600;
    padding: 2px 4px;
    spacing: 2px;
}

QMenuBar::item {
    background: transparent;
    color: #d8dee9;
    padding: 5px 14px;
    border-radius: 4px;
}

QMenuBar::item:selected {
    background: rgba(136, 192, 208, 0.22);
    color: #88c0d0;
}

QMenuBar::item:pressed {
    background: rgba(136, 192, 208, 0.35);
    color: #eceff4;
}

QMenu {
    background: #2e3440;
    color: #d8dee9;
    border: 1px solid #4c566a;
    border-radius: 4px;
    padding: 4px 0px;
}

QMenu::item {
    background: transparent;
    color: #d8dee9;
    padding: 6px 28px 6px 16px;
    font-size: 10pt;
}

QMenu::item:selected {
    background: rgba(136, 192, 208, 0.25);
    color: #eceff4;
    border-radius: 3px;
}

QMenu::item:disabled {
    color: #4c566a;
}

QMenu::separator {
    height: 1px;
    background: #4c566a;
    margin: 4px 10px;
}

QMenu::right-arrow {
    width: 12px;
    height: 12px;
    margin-right: 4px;
}
""".strip()


# =============================================================================
# STATUS BAR STYLES
# =============================================================================

STATUS_BAR_STYLESHEET = """
QStatusBar {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 #2e3440, stop:1 #3b4252);
    color: #d8dee9;
    border-top: 2px solid #88c0d0;
    font-family: 'Segoe UI', 'Roboto', sans-serif;
    font-size: 10pt;
    font-weight: 500;
    padding: 4px 8px;
    min-height: 24px;
}
QStatusBar::item {
    border: none;
}
""".strip()


STATUS_BAR_CAPTURE_LABEL_STYLESHEET = """
QLabel {
    background: transparent;
    color: #d8dee9;
    border: none;
    padding: 4px 8px 4px 8px;
}
""".strip()


STATUS_BAR_CONFIG_LABEL_STYLESHEET = """
QLabel {
    background: transparent;
    color: #d8dee9;
    border: none;
    padding: 4px 8px;
}
""".strip()


STATUS_BAR_ISSUES_LABEL_STYLESHEET = """
QLabel {
    background: transparent;
    color: #d8dee9;
    border: none;
    padding: 4px 8px;
}
""".strip()


STATUS_BAR_PERFORMANCE_LABEL_STYLESHEET = """
QLabel {
    background: transparent;
    color: #d8dee9;
    border: none;
    padding: 4px 8px 4px 4px;
}
""".strip()


# =============================================================================
# GTA5 MANUAL SUSPEND BUTTON STYLES
# =============================================================================

GTA5_MANUAL_SUSPEND_IDLE_STYLESHEET = """
QPushButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 rgba(230, 126, 34, 0.18), stop:1 rgba(211, 84, 0, 0.28));
    color: #f0a030;
    border: 1px solid rgba(230, 126, 34, 0.65);
    border-radius: 4px;
    padding: 3px 8px;
    font-weight: bold;
}
QPushButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 rgba(230, 126, 34, 0.45), stop:1 rgba(211, 84, 0, 0.55));
    border: 1px solid rgba(230, 126, 34, 1.0);
    color: #ffd080;
}
QPushButton:pressed {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 rgba(211, 84, 0, 0.65), stop:1 rgba(230, 126, 34, 0.75));
    padding-top: 4px;
    padding-left: 9px;
}
QPushButton:disabled {
    color: rgba(150, 100, 50, 0.45);
    border: 1px solid rgba(150, 100, 50, 0.28);
    background: transparent;
}
""".strip()

GTA5_SOLO_SESSION_ACTIVE_STYLESHEET = """
QPushButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #1565c0, stop:1 #0d47a1);
    color: #e3f2fd;
    border: 1px solid #42a5f5;
    border-radius: 4px;
    padding: 3px 8px;
    font-weight: bold;
}
QPushButton:disabled {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #0d47a1, stop:1 #1565c0);
    color: #90caf9;
    border: 1px solid #1976d2;
}
""".strip()

GTA5_MANUAL_SUSPEND_ACTIVE_STYLESHEET = """
QPushButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #c0392b, stop:1 #96281b);
    color: #ffffff;
    border: 1px solid #e74c3c;
    border-radius: 4px;
    padding: 3px 8px;
    font-weight: bold;
}
QPushButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #e74c3c, stop:1 #c0392b);
    border: 1px solid #ff6b5b;
    color: #fff8f8;
}
QPushButton:pressed {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #96281b, stop:1 #c0392b);
    padding-top: 4px;
    padding-left: 9px;
}
""".strip()


# =============================================================================
# COMBO RULE / DETECTIONS MANAGER STYLES
# =============================================================================

GROUPBOX_STYLE = """
    QGroupBox {
        font-size: 12pt;
        font-weight: bold;
        border: 2px solid #4A90E2;
        border-radius: 8px;
        margin-top: 12px;
        padding-top: 15px;
        background: rgba(74, 144, 226, 0.05);
    }
    QGroupBox::title {
        subcontrol-origin: margin;
        subcontrol-position: top left;
        left: 15px;
        padding: 0 5px;
        color: #4A90E2;
    }
"""

LIST_WIDGET_STYLE = """
    QListWidget {
        background: #2d2d2d;
        border: 2px solid #4A90E2;
        border-radius: 4px;
        padding: 5px;
        font-family: 'Consolas', 'Courier New', monospace;
    }
    QListWidget::item {
        padding: 5px;
        border-radius: 3px;
    }
    QListWidget::item:selected {
        background: #4A90E2;
        color: white;
    }
"""

SECTION_SEPARATOR_LABEL_STYLESHEET = 'color: #666; font-size: 9pt; padding: 5px 0;'

DESC_LABEL_STYLESHEET = 'color: #a0a0a0; font-style: italic; font-size: 10pt; padding: 5px;'

HINT_LABEL_STYLESHEET = 'color: #a0a0a0; font-style: italic; padding-bottom: 4px;'

BOLD_LABEL_STYLESHEET = 'font-weight: bold;'

RELAY_FILTER_WARNING_STYLESHEET = (
    'QWidget { background-color: #3a2400; border: 1px solid #c87800; border-radius: 6px; padding: 2px; }'
    'QLabel { border: none; }'
    'QPushButton { border: 1px solid #c87800; border-radius: 4px; background-color: #5a3a00;'
    ' color: #ffcc66; padding: 4px 10px; font-weight: bold; }'
    'QPushButton:hover { background-color: #7a5200; }'
)

WARNING_ICON_LABEL_STYLESHEET = 'font-size: 18pt; border: none;'

WARNING_TEXT_LABEL_STYLESHEET = 'color: #ffcc66; border: none;'

DETECTIONS_MANAGER_HEADER_STYLESHEET = (
    'font-size: 16pt; font-weight: bold; color: #4A90E2; padding: 10px;'
    'background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #1e1e2e, stop:1 #2d2d4e);'
    'border-radius: 6px;'
)


# =============================================================================
# SECTION TABLE HEADER STYLES
# =============================================================================

SECTION_CLEAR_BUTTON_STYLESHEET = 'font-weight: 700; font-size: 12px;'

SECTION_HEADER_SEPARATOR_STYLESHEET = (
    'background-color: rgba(255,255,255,0.55); max-width: 1px; min-width: 1px; margin: 6px 6px;'
)


# =============================================================================
# MAIN WINDOW STYLES
# =============================================================================

GTA5_STATUS_LABEL_STYLESHEET = (
    'QLabel { background-color: #2e3440; color: #d8dee9; padding: 6px 28px 6px 16px; font-size: 10pt; }'
)


# =============================================================================
# PLAYER IDENTIFIER STYLES
# =============================================================================

PROGRESS_BAR_IDLE_STYLESHEET = ''

PROGRESS_BAR_CHUNK_GREEN_STYLESHEET = 'QProgressBar::chunk { background-color: #27ae60; }'

PROGRESS_BAR_CHUNK_RED_STYLESHEET = 'QProgressBar::chunk { background-color: #e74c3c; }'


# =============================================================================
# PLAYER INFO DIALOG STYLES
# =============================================================================

PLAYER_INFO_FORM_LABEL_STYLESHEET = 'color: #cbd5e0; font-weight: 600; background: transparent;'

PLAYER_INFO_VALUE_LABEL_STYLESHEET = (
    'color: #ffffff; font-weight: bold; padding: 3px 6px; border-radius: 3px; background: rgba(255, 255, 255, 12);'
)

DETECTION_WARN_LABEL_STYLESHEET = (
    'color: #f6e05e; font-weight: bold; padding: 4px 8px;'
    'background: rgba(214, 158, 46, 20); border: 1px solid rgba(214, 158, 46, 80);'
    'border-radius: 4px;'
)


def player_info_group_stylesheet(accent: str) -> str:
    """Return the QSS for a player info group box with the given `accent` color."""
    return (
        'QGroupBox {'
        f' border: 1px solid {accent};'
        ' border-radius: 6px;'
        ' margin-top: 14px;'
        ' padding-top: 10px;'
        ' background: rgba(255, 255, 255, 8);'
        ' font-weight: bold;'
        '}'
        'QGroupBox::title {'
        ' subcontrol-origin: margin;'
        ' subcontrol-position: top left;'
        ' left: 10px; padding: 2px 8px;'
        f' background: {accent};'
        ' color: #ffffff;'
        ' border-radius: 4px;'
        '}'
    )


def player_info_header_stylesheet(grad_stop0: str, grad_stop1: str) -> str:
    """Return the QSS for a player info dialog header label with the given gradient stops."""
    return (
        'font-size: 14pt; font-weight: bold; padding: 8px 6px;'
        'color: #ffffff; background: qlineargradient(x1:0, y1:0, x2:1, y2:0,'
        f' stop:0 {grad_stop0}, stop:1 {grad_stop1}); border-radius: 6px;'
    )


# =============================================================================
# SETTINGS DIALOG STYLES
# =============================================================================

DISCORD_INFO_LABEL_STYLESHEET = (
    'QLabel {'
    'background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #262b36, stop:1 #1f2430);'
    'border: 1px solid #3b4455;'
    'border-left: 4px solid #5865f2;'
    'border-radius: 10px;'
    'padding: 12px 14px;'
    'color: #dbe4f0;'
    'line-height: 1.35;'
    '}'
)

WEBSERVER_HELP_LABEL_STYLESHEET = (
    'QLabel {'
    'background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #262b36, stop:1 #1f2430);'
    'border: 1px solid #3b4455;'
    'border-left: 4px solid #61afef;'
    'border-radius: 10px;'
    'padding: 12px 14px;'
    'color: #dbe4f0;'
    'line-height: 1.35;'
    '}'
)

WEBHOOK_NOTE_LABEL_STYLESHEET = 'color: #888; font-size: 11px;'


# =============================================================================
# SPLASH SCREEN STYLES
# =============================================================================

SPLASH_SCREEN_STYLESHEET = 'background-color: #19232d;'

SPLASH_TITLE_LABEL_STYLESHEET = 'color: #e0e6ee; background: transparent;'

SPLASH_SUBTITLE_LABEL_STYLESHEET = 'color: #667788; background: transparent;'

SPLASH_SUBTITLE_READY_STYLESHEET = 'color: #44cc66; background: transparent;'

SPLASH_LOG_AREA_STYLESHEET = (
    'QTextEdit {'
    '  background-color: #141922;'
    '  color: #8899aa;'
    '  border: 1px solid #2a3544;'
    '  border-radius: 6px;'
    '  padding: 8px;'
    '}'
)


# =============================================================================
# USERIP MANAGER STYLES
# =============================================================================

SUBNET_DESC_LABEL_STYLESHEET = 'color: #a0a0a0; font-style: italic;'

COLOR_SWATCH_GROUP_HEADER_STYLESHEET = (
    'color: #8ab4d4; font-size: 8pt; font-weight: bold; padding: 4px 0px 1px 2px;'
)

COLOR_SWATCH_SEPARATOR_STYLESHEET = 'color: #3a3a3a;'

SETTINGS_SEPARATOR_STYLESHEET = 'background-color: rgba(74, 144, 226, 0.2); border: none;'

COLOR_BUTTON_EMPTY_STYLESHEET = (
    'background-color: transparent; border: 1px solid #555; border-radius: 4px;'
)


def color_swatch_btn_stylesheet(bg_color: str, text_color: str, border_width: int, border_color: str) -> str:
    """Return the QSS for a color swatch button in the SVG color picker."""
    return (
        f'background-color: {bg_color}; color: {text_color};'
        f' border: {border_width}px solid {border_color}; border-radius: 2px;'
        ' font-size: 8pt; font-weight: bold; text-align: center;'
    )


def color_button_filled_stylesheet(color_name: str) -> str:
    """Return the QSS for a color preview button showing the given `color_name`."""
    return f'background-color: {color_name}; border: 1px solid #555; border-radius: 4px;'


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
# COMPACT BUTTON STYLE (shared across settings widgets)
# =============================================================================

COMPACT_BUTTON_STYLESHEET = (
    'QPushButton { background: qlineargradient(x1:0,y1:0,x2:0,y2:1,'
    ' stop:0 rgba(236,240,241,0.12), stop:1 rgba(189,195,199,0.18));'
    ' color: #ecf0f1; border: 1px solid rgba(52,73,94,0.6);'
    ' border-radius: 4px; padding: 2px 10px; font-size: 11px; font-weight: bold; }'
    ' QPushButton:hover { background: qlineargradient(x1:0,y1:0,x2:0,y2:1,'
    ' stop:0 rgba(52,152,219,0.25), stop:1 rgba(41,128,185,0.35));'
    ' border: 1px solid rgba(52,152,219,0.8); color: #ffffff; }'
    ' QPushButton:pressed { background: qlineargradient(x1:0,y1:0,x2:0,y2:1,'
    ' stop:0 rgba(41,128,185,0.45), stop:1 rgba(52,152,219,0.55));'
    ' border: 1px solid rgba(41,128,185,1.0); }'
)
