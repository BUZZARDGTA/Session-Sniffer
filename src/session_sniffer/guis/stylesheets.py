"""GUI Stylesheets Module.

This module contains all the QSS (Qt Style Sheets) used throughout the application.
Centralizing stylesheets here makes them easier to maintain and modify.
"""

# =============================================================================
# CONTAINER HEADER STYLES
# =============================================================================

CONNECTED_HEADER_CONTAINER_STYLESHEET = 'background-color: green;'

DISCONNECTED_HEADER_CONTAINER_STYLESHEET = 'background-color: red;'


# =============================================================================
# SEARCH BAR STYLES
# =============================================================================

SEARCH_BAR_STYLESHEET = """
QLineEdit {
    background-color: rgba(0, 0, 0, 0.18);
    color: rgba(255, 255, 255, 0.9);
    border: 1px solid rgba(255, 255, 255, 0.25);
    border-radius: 3px;
    padding: 1px 6px;
    font-size: 11px;
    max-height: 22px;
    min-width: 200px;
    max-width: 350px;
}
QLineEdit:focus {
    background-color: rgba(0, 0, 0, 0.35);
    border: 1px solid rgba(255, 255, 255, 0.55);
}
""".strip()

SEARCH_COMBO_STYLESHEET = """
QComboBox {
    background-color: rgba(0, 0, 0, 0.18);
    color: rgba(255, 255, 255, 0.9);
    border: 1px solid rgba(255, 255, 255, 0.25);
    border-radius: 3px;
    padding: 1px 4px;
    font-size: 11px;
    max-height: 22px;
    max-width: 120px;
}
QComboBox:focus, QComboBox:on {
    background-color: rgba(0, 0, 0, 0.35);
    border: 1px solid rgba(255, 255, 255, 0.55);
}
QComboBox::drop-down {
    border: none;
    width: 16px;
}
QComboBox::down-arrow {
    image: none;
    border-left: 3px solid transparent;
    border-right: 3px solid transparent;
    border-top: 4px solid rgba(255, 255, 255, 0.75);
    width: 0;
    height: 0;
    margin-right: 4px;
    margin-top: 1px;
}
QComboBox QAbstractItemView {
    background-color: #2a2a2a;
    color: #e0e0e0;
    border: 1px solid rgba(128, 128, 128, 0.5);
    selection-background-color: #404040;
    outline: 0;
}
""".strip()


# =============================================================================
# HEADER STYLES
# =============================================================================

CONNECTED_HEADER_TEXT_STYLESHEET = """
background-color: green;
color: white;
font-size: 16px;
font-weight: bold;
padding: 5px;
background: transparent;
""".strip()


DISCONNECTED_HEADER_TEXT_STYLESHEET = """
background-color: red;
color: white;
font-size: 16px;
font-weight: bold;
padding: 5px;
background: transparent;
""".strip()


# =============================================================================
# COMMON BUTTON STYLES
# =============================================================================

CONNECTED_CLEAR_BUTTON_STYLESHEET = """
QPushButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
    stop:0 rgba(236, 240, 241, 0.1), stop:1 rgba(189, 195, 199, 0.2));
    color: #ecf0f1;
    border: 1px solid rgba(52, 73, 94, 0.6);
    border-radius: 6px;
    padding: 3px;
    font-size: 11px;
    font-weight: bold;
    min-width: 40px;
    max-width: 45px;
    min-height: 28px;
    max-height: 30px;
    margin-left: 6px;
    margin-right: 2px;
}

QPushButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
    stop:0 rgba(52, 152, 219, 0.3), stop:1 rgba(41, 128, 185, 0.4));
    border: 1px solid rgba(52, 152, 219, 0.8);
    color: white;
}

QPushButton:pressed {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
    stop:0 rgba(41, 128, 185, 0.5), stop:1 rgba(52, 152, 219, 0.6));
    border: 1px solid rgba(41, 128, 185, 1.0);
    padding-top: 4px;
    padding-left: 4px;
}
""".strip()

DISCONNECTED_CLEAR_BUTTON_STYLESHEET = """
QPushButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
    stop:0 rgba(236, 240, 241, 0.1), stop:1 rgba(189, 195, 199, 0.2));
    color: #ecf0f1;
    border: 1px solid rgba(52, 73, 94, 0.6);
    border-radius: 6px;
    padding: 3px;
    font-size: 11px;
    font-weight: bold;
    min-width: 40px;
    max-width: 45px;
    min-height: 28px;
    max-height: 30px;
    margin-left: 6px;
    margin-right: 2px;
}

QPushButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
    stop:0 rgba(52, 152, 219, 0.3), stop:1 rgba(41, 128, 185, 0.4));
    border: 1px solid rgba(52, 152, 219, 0.8);
    color: white;
}

QPushButton:pressed {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
    stop:0 rgba(41, 128, 185, 0.5), stop:1 rgba(52, 152, 219, 0.6));
    border: 1px solid rgba(41, 128, 185, 1.0);
    padding-top: 4px;
    padding-left: 4px;
}
""".strip()

COMMON_COLLAPSE_BUTTON_STYLESHEET = """
QPushButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
    stop:0 rgba(236, 240, 241, 0.1), stop:1 rgba(189, 195, 199, 0.2));
    color: #ecf0f1;
    border: 1px solid rgba(52, 73, 94, 0.6);
    border-radius: 6px;
    padding: 3px;
    font-size: 11px;
    font-weight: bold;
    min-width: 24px;
    max-width: 24px;
    min-height: 24px;
    max-height: 24px;
    margin-left: 5px;
    margin-right: 2px;
}

QPushButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
    stop:0 rgba(52, 152, 219, 0.3), stop:1 rgba(41, 128, 185, 0.4));
    border: 1px solid rgba(52, 152, 219, 0.8);
    color: white;
}

QPushButton:pressed {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
    stop:0 rgba(41, 128, 185, 0.5), stop:1 rgba(52, 152, 219, 0.6));
    border: 1px solid rgba(41, 128, 185, 1.0);
    padding-top: 4px;
    padding-left: 4px;
}
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
