"""Context menu, menu bar, and status bar QSS."""

from session_sniffer.constants.local import RESOURCES_DIR_PATH

_CHEVRON_RIGHT_PATH = (RESOURCES_DIR_PATH / 'icons' / 'chevron_right.svg').as_posix()

# =============================================================================
# CONTEXT MENU STYLES
# =============================================================================

# TODO(BUZZARDGTA): Implement a better way to retrieve the default background color for table cells.
# Currently hardcoded to Gray.B10, which should be the same color for everyone.
SHARED_QMENU_RIGHT_ARROW_STYLESHEET = """
QMenu::right-arrow {
    image: url("{chevron_right_path}");
    width: 14px;
    height: 14px;
    padding-right: 6px;
}
"""

SVG_ICON_CONTEXT_MENU_STYLESHEET = ("""
QMenu {
    background-color: #1e1e1e;     /* Dark background */
    border: 1px solid #2d2d2d;     /* Subtle border */
    border-radius: 8px;            /* Rounded corners */
    padding: 4px;                  /* Space inside the menu */
}

QMenu::item {
    color: #d4d4d4;                /* Light gray text color */
    padding: 5px 20px 5px 8px;    /* top right bottom left — left leaves room for icon column */
    background-color: transparent; /* Default background */
}

QMenu::icon {
    width: 16px;                   /* Fix SVG icon width */
    height: 16px;                  /* Fix SVG icon height */
    padding-left: 6px;             /* Indent icon from the left edge */
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
""" + SHARED_QMENU_RIGHT_ARROW_STYLESHEET).strip().replace('{chevron_right_path}', _CHEVRON_RIGHT_PATH)


# =============================================================================
# STATUS BAR STYLES
# =============================================================================

MENU_BAR_STYLESHEET = ''


# =============================================================================
# STATUS BAR STYLES
# =============================================================================

STATUS_BAR_STYLESHEET = ''


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
