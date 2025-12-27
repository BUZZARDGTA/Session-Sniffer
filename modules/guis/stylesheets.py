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
