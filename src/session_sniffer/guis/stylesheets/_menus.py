"""Context menu, menu bar, and status bar QSS."""

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
