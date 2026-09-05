"""Context menu, menu bar, and status bar QSS."""

from session_sniffer.constants.local import RESOURCES_DIR_PATH

_CHEVRON_RIGHT_PATH = (RESOURCES_DIR_PATH / 'icons' / 'chevron_right.svg').as_posix()
_CHEVRON_RIGHT_DISABLED_PATH = (RESOURCES_DIR_PATH / 'icons' / 'chevron_right_disabled.svg').as_posix()
_CHECKBOX_CHECKED_PATH = (RESOURCES_DIR_PATH / 'icons' / 'select_all.svg').as_posix()
_CHECKBOX_UNCHECKED_PATH = (RESOURCES_DIR_PATH / 'icons' / 'unselect_all.svg').as_posix()

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
QMenu::right-arrow:disabled {
    image: url("{chevron_right_disabled_path}");
}
"""

SVG_ICON_CONTEXT_MENU_STYLESHEET = (
    (
        """
QMenu {
    padding: 4px;
    background-color: #2b2b2b;
    border: 1px solid #3a3a3a;
}

QMenu::item {
    /* left padding reserves the fixed slot for the icon/indicator */
    padding: 6px 24px 6px 16px;
    background-color: transparent;
    /* no border here — hover must not change the box geometry */
}

QMenu::item:selected {
    /* ONLY the background changes on hover, so nothing shifts */
    background-color: #3a3a3a;
}

QMenu::item:disabled {
    color: #666666;
    background-color: transparent;
}

QMenu::item:disabled:selected {
    color: #666666;
    background-color: transparent;
}

QMenu::icon {
    /* pin the icon with padding (absolute), not a relative 'left' offset */
    padding-left: 20px;
}

QMenu::indicator {
    width: 14px;
    height: 14px;
    margin-left: 4px;
}

QMenu::indicator:unchecked {
    image: url("{checkbox_unchecked_path}");
}

QMenu::indicator:checked {
    image: url("{checkbox_checked_path}");
}

QMenu::separator {
    height: 1px;
    background-color: #3a3a3a;
    margin: 4px 8px;
}
"""
        + SHARED_QMENU_RIGHT_ARROW_STYLESHEET
    )
    .strip()
    .replace('{chevron_right_path}', _CHEVRON_RIGHT_PATH)
    .replace('{chevron_right_disabled_path}', _CHEVRON_RIGHT_DISABLED_PATH)
    .replace('{checkbox_checked_path}', _CHECKBOX_CHECKED_PATH)
    .replace('{checkbox_unchecked_path}', _CHECKBOX_UNCHECKED_PATH)
)


CATEGORY_SUBMENU_CHECKBOX_STYLESHEET = (
    (
        """
QMenu {
    padding: 4px;
    background-color: #2b2b2b;
    border: 1px solid #3a3a3a;
}

QMenu::item {
    padding: 6px 24px 6px 4px;
    background-color: transparent;
}

QMenu::item:selected {
    background-color: #3a3a3a;
}

QMenu::item:disabled {
    color: #666666;
    background-color: transparent;
}

QMenu::item:disabled:selected {
    color: #666666;
    background-color: transparent;
}

QMenu::icon {
    margin-left: 4px;
}

QMenu::indicator {
    width: 14px;
    height: 14px;
    margin-left: 4px;
    margin-right: 6px;
}

QMenu::indicator:unchecked {
    image: url("{checkbox_unchecked_path}");
}

QMenu::indicator:checked {
    image: url("{checkbox_checked_path}");
}

QMenu::separator {
    height: 1px;
    background-color: #3a3a3a;
    margin: 4px 8px;
}
"""
        + SHARED_QMENU_RIGHT_ARROW_STYLESHEET
    )
    .strip()
    .replace('{chevron_right_path}', _CHEVRON_RIGHT_PATH)
    .replace('{chevron_right_disabled_path}', _CHEVRON_RIGHT_DISABLED_PATH)
    .replace('{checkbox_checked_path}', _CHECKBOX_CHECKED_PATH)
    .replace('{checkbox_unchecked_path}', _CHECKBOX_UNCHECKED_PATH)
)


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
