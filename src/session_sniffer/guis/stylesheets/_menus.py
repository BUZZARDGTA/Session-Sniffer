"""Context menu, menu bar, and status bar QSS."""

from session_sniffer.guis.theming import ICONS_DIR_PATH, themed_qss

_CHEVRON_RIGHT_PATH = (ICONS_DIR_PATH / 'chevron-right.svg').as_posix()
_CHEVRON_RIGHT_DISABLED_PATH = (ICONS_DIR_PATH / 'chevron-right-disabled.svg').as_posix()
_CHECKBOX_CHECKED_PATH = (ICONS_DIR_PATH / 'square-check.svg').as_posix()
_CHECKBOX_UNCHECKED_PATH = (ICONS_DIR_PATH / 'square.svg').as_posix()

# =============================================================================
# CONTEXT MENU STYLES
# =============================================================================

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

SVG_ICON_CONTEXT_MENU_STYLESHEET = themed_qss(
    (
        """
QMenu {
    padding: 4px;
    background-color: @popup[#2b2b2b];
    border: 1px solid @border[#3a3a3a];
}

QMenu::item {
    /* left padding reserves the fixed slot for the icon/indicator */
    padding: 6px 24px 6px 16px;
    background-color: transparent;
    /* no border here — hover must not change the box geometry */
}

QMenu::item:selected {
    /* ONLY the background changes on hover, so nothing shifts */
    background-color: @selection[#3a3a3a];
}

QMenu::item:disabled {
    color: @text_muted[#666666];
    background-color: transparent;
}

QMenu::item:disabled:selected {
    color: @text_muted[#666666];
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
    background-color: @border[#3a3a3a];
    margin: 4px 8px;
}
"""
        + SHARED_QMENU_RIGHT_ARROW_STYLESHEET
    )
    .strip()
    .replace('{chevron_right_path}', _CHEVRON_RIGHT_PATH)
    .replace('{chevron_right_disabled_path}', _CHEVRON_RIGHT_DISABLED_PATH)
    .replace('{checkbox_checked_path}', _CHECKBOX_CHECKED_PATH)
    .replace('{checkbox_unchecked_path}', _CHECKBOX_UNCHECKED_PATH),
)


CATEGORY_SUBMENU_CHECKBOX_STYLESHEET = themed_qss(
    (
        """
QMenu {
    padding: 4px;
    background-color: @popup[#2b2b2b];
    border: 1px solid @border[#3a3a3a];
}

QMenu::item {
    padding: 6px 24px 6px 4px;
    background-color: transparent;
}

QMenu::item:selected {
    background-color: @selection[#3a3a3a];
}

QMenu::item:disabled {
    color: @text_muted[#666666];
    background-color: transparent;
}

QMenu::item:disabled:selected {
    color: @text_muted[#666666];
    background-color: transparent;
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
    background-color: @border[#3a3a3a];
    margin: 4px 8px;
}
"""
        + SHARED_QMENU_RIGHT_ARROW_STYLESHEET
    )
    .strip()
    .replace('{chevron_right_path}', _CHEVRON_RIGHT_PATH)
    .replace('{chevron_right_disabled_path}', _CHEVRON_RIGHT_DISABLED_PATH)
    .replace('{checkbox_checked_path}', _CHECKBOX_CHECKED_PATH)
    .replace('{checkbox_unchecked_path}', _CHECKBOX_UNCHECKED_PATH),
)


# =============================================================================
# STATUS BAR STYLES
# =============================================================================

STATUS_BAR_LABEL_STYLESHEET = themed_qss(
    """
QLabel {
    background: transparent;
    color: @text[#d8dee9];
    border: none;
    padding: 4px 8px;
}
""".strip(),
)


STATUS_BAR_PERFORMANCE_LABEL_STYLESHEET = themed_qss(
    """
QLabel {
    background: transparent;
    color: @text[#d8dee9];
    border: none;
    padding: 4px 8px 4px 4px;
}
""".strip(),
)
