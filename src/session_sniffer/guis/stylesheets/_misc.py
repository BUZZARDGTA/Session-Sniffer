"""Miscellaneous QSS: Discord popups, section headers, main window, settings labels, splash screen."""

from session_sniffer.guis.theming import CHECKBOX_CHECK_ICON_PATH, ICONS_DIR_PATH, themed_qss

_CHEVRON_RIGHT_PATH = (ICONS_DIR_PATH / 'branch_chevron_right.svg').as_posix()
_CHEVRON_DOWN_PATH = (ICONS_DIR_PATH / 'branch_chevron_down.svg').as_posix()
_CHECK_PATH = CHECKBOX_CHECK_ICON_PATH.as_posix()

# =============================================================================
# DISCORD DIALOG STYLES
# =============================================================================

DISCORD_POPUP_MAIN_STYLESHEET = themed_qss(
    """
background-color: @popup~secondary/18;
border: 1px solid @border;
border-radius: 15px;
color: @text_strong;
""".strip(),
)

DISCORD_POPUP_EXIT_BUTTON_STYLESHEET = themed_qss(
    """
font-size: 8pt;
color: @text_strong;
background-color: @danger;
border-radius: 15px;
""".strip(),
)

DISCORD_POPUP_JOIN_BUTTON_STYLESHEET = themed_qss(
    """
font-size: 10pt;
padding: 7px;
background-color: @secondary;
color: @text_strong;
border-radius: 10px;
border: none;
""".strip(),
)

# =============================================================================
# SECTION TABLE HEADER STYLES
# =============================================================================

SECTION_HEADER_SEPARATOR_STYLESHEET = themed_qss('background-color: @border/55; border: none; max-width: 1px; min-width: 1px; margin: 4px 4px;')

# =============================================================================
# MAIN WINDOW STYLES
# =============================================================================

GTA5_STATUS_LABEL_STYLESHEET = themed_qss('QLabel { background: transparent; padding: 6px 28px 6px 16px; font-size: 10pt; }')

# =============================================================================
# SETTINGS DIALOG STYLES
# =============================================================================


def _settings_info_label_stylesheet(role_token: str) -> str:
    """Build the shared settings card info-banner QLabel QSS with *role_token* left border."""
    return themed_qss(
        'QLabel {'
        f'background-color: @surface~{role_token}/8;'
        'border: 1px solid @border;'
        f'border-left: 4px solid @{role_token};'
        'border-radius: 10px;'
        'padding: 12px 14px;'
        'color: @text;'
        'line-height: 1.35;'
        '}',
    )


DISCORD_INFO_LABEL_STYLESHEET = _settings_info_label_stylesheet('secondary')

WEBSERVER_HELP_LABEL_STYLESHEET = _settings_info_label_stylesheet('accent')

WEBHOOK_NOTE_LABEL_STYLESHEET = themed_qss('color: @text_muted; font-size: 8pt;')

LOOKY_INFO_LABEL_STYLESHEET = _settings_info_label_stylesheet('secondary')

LOOKY_ACCOUNT_CARD_STYLESHEET = themed_qss(
    'QFrame#lookyAccountCard {background-color: @surface~secondary/12; border: 1px solid @border~secondary/35; border-radius: 8px; padding: 4px;}',
)

INTERFACE_INFO_CARD_STYLESHEET = themed_qss(
    'QGroupBox {'
    'background-color: @surface;'
    'border: 1px solid @border;'
    'border-left: 4px solid @accent;'
    'border-radius: 8px;'
    'margin-top: 14px;'
    'padding-top: 12px;'
    '}'
    'QGroupBox::title {'
    'subcontrol-origin: margin;'
    'subcontrol-position: top left;'
    'left: 10px; padding: 2px 8px;'
    'background-color: @accent;'
    'color: @text_strong;'
    'border-radius: 4px;'
    'font-weight: bold;'
    '}',
)

INTERFACE_INFO_VALUE_LABEL_STYLESHEET = themed_qss('color: @accent; font-weight: bold; padding: 2px 6px; background-color: @accent/12; border-radius: 3px;')

SETTINGS_RESTART_BANNER_STYLESHEET = themed_qss(
    'QFrame#restartNoticeBanner {'
    'background-color: @surface~warning/8;'
    'border: 1px solid @border;'
    'border-left: 4px solid @warning;'
    'border-radius: 6px;'
    '}',
)

# =============================================================================
# SPLASH SCREEN STYLES
# =============================================================================

SPLASH_SCREEN_STYLESHEET = themed_qss('background-color: @background;')

SPLASH_TITLE_LABEL_STYLESHEET = themed_qss('color: @text_strong; background: transparent; font-size: 20pt; font-weight: bold;')

SPLASH_SUBTITLE_LABEL_STYLESHEET = themed_qss('color: @text_muted; background: transparent; font-size: 11pt;')

SPLASH_SUBTITLE_READY_STYLESHEET = themed_qss('color: @success; background: transparent; font-size: 11pt;')

SPLASH_LOG_AREA_STYLESHEET = themed_qss('QTextEdit { background-color: @input; color: @text_muted; border: 1px solid @border; border-radius: 6px; padding: 8px; }')

# =============================================================================
# CRASH DIALOG STYLES
# =============================================================================

CRASH_DIALOG_FRAME_STYLESHEET = themed_qss(
    'QFrame#crashDialogFrame {'
    '    background-color: @surface~danger/6;'
    '    border: 1px solid @border~danger/40;'
    '    border-radius: 14px;'
    '}',
)

CRASH_DIALOG_ICON_CONTAINER_STYLESHEET = themed_qss(
    'QFrame#crashDialogIconContainer {'
    '    background-color: @danger/18;'
    '    border: 1px solid @danger/42;'
    '    border-radius: 10px;'
    '}',
)

CRASH_DIALOG_KICKER_LABEL_STYLESHEET = themed_qss('color: @danger; background: transparent; font-size: 8pt; font-weight: 700; letter-spacing: 1px;')

CRASH_DIALOG_SUBTITLE_LABEL_STYLESHEET = themed_qss('color: @text_muted; background: transparent; font-size: 8.5pt;')

CRASH_DIALOG_INFO_CARD_STYLESHEET = themed_qss(
    'QFrame#crashDialogInfoCard { background-color: @surface; border: 1px solid @border; border-left: 3px solid @danger; border-radius: 10px; }',
)

CRASH_DIALOG_SECTION_LABEL_STYLESHEET = themed_qss('color: @text_muted; background: transparent; font-size: 8pt; font-weight: 700; letter-spacing: 0.8px;')

CRASH_DIALOG_BADGE_STYLESHEET = themed_qss(
    'color: @danger; background-color: @danger/14; border: 1px solid @danger/32; border-radius: 8px; padding: 2px 10px; font-size: 8pt; font-weight: 700;',
)

CRASH_DIALOG_TRACEBACK_EDIT_STYLESHEET = themed_qss(
    'QPlainTextEdit#crashDialogTracebackEdit {'
    '    background-color: @input;'
    '    color: @text;'
    '    border: 1px solid @border;'
    '    border-radius: 8px;'
    '    padding: 8px 10px;'
    '    selection-background-color: @selection;'
    '    selection-color: @text_strong;'
    '}',
)

CRASH_DIALOG_PRIMARY_BUTTON_STYLESHEET = themed_qss(
    'QPushButton {'
    '    background-color: @accent;'
    '    color: @text_strong;'
    '    border: 1px solid @accent:hover;'
    '    border-radius: 7px;'
    '    padding: 5px 14px;'
    '    font-weight: 700;'
    '    font-size: 9pt;'
    '}'
    'QPushButton:hover {'
    '    background-color: @accent:hover;'
    '    border: 1px solid @accent:hover;'
    '    color: @text_strong;'
    '}'
    'QPushButton:pressed {'
    '    background-color: @accent:pressed;'
    '    border: 1px solid @accent;'
    '}',
)

CRASH_DIALOG_SECONDARY_BUTTON_STYLESHEET = themed_qss(
    'QPushButton {'
    '    background-color: @control;'
    '    color: @text;'
    '    border: 1px solid @border;'
    '    border-radius: 7px;'
    '    padding: 5px 12px;'
    '    font-weight: 700;'
    '    font-size: 9pt;'
    '}'
    'QPushButton:hover {'
    '    background-color: @control:hover;'
    '    border: 1px solid @accent;'
    '    color: @text_strong;'
    '}'
    'QPushButton:pressed {'
    '    background-color: @control:pressed;'
    '    border: 1px solid @accent;'
    '}',
)

CRASH_DIALOG_EXIT_BUTTON_STYLESHEET = themed_qss(
    'QPushButton {'
    '    background-color: @danger;'
    '    color: @text_strong;'
    '    border: 1px solid @danger:hover;'
    '    border-radius: 7px;'
    '    padding: 5px 18px;'
    '    font-weight: 700;'
    '    font-size: 9pt;'
    '}'
    'QPushButton:hover {'
    '    background-color: @danger:hover;'
    '    border: 1px solid @danger:hover;'
    '    color: @text_strong;'
    '}'
    'QPushButton:pressed {'
    '    background-color: @danger:pressed;'
    '    border: 1px solid @danger;'
    '}',
)

# =============================================================================
# DEPENDENCY PROMPT DIALOG STYLES
# =============================================================================

DEPENDENCY_PROMPT_DIALOG_STYLESHEET = themed_qss('QDialog { background-color: transparent; }')

DEPENDENCY_PROMPT_FRAME_STYLESHEET = themed_qss(
    'QFrame#dependencyPromptFrame {'
    '    background-color: @surface;'
    '    border: 1px solid @border;'
    '    border-radius: 14px;'
    '}',
)

DEPENDENCY_PROMPT_ICON_CONTAINER_STYLESHEET = themed_qss(
    'QFrame#dependencyPromptIconContainer {'
    '    background-color: @accent/16;'
    '    border: 1px solid @accent/35;'
    '    border-radius: 10px;'
    '}',
)

DEPENDENCY_PROMPT_KICKER_LABEL_STYLESHEET = themed_qss('color: @accent; background: transparent; font-size: 8pt; font-weight: 700; letter-spacing: 1px;')

DEPENDENCY_PROMPT_TITLE_LABEL_STYLESHEET = themed_qss('color: @text_strong; background: transparent; font-size: 15pt; font-weight: 700; letter-spacing: 0.3px;')

DEPENDENCY_PROMPT_CLOSE_BUTTON_STYLESHEET = themed_qss(
    'QPushButton#dependencyPromptCloseButton {'
    '    background: transparent;'
    '    color: @text_muted;'
    '    border: none;'
    '    border-radius: 6px;'
    '    font-size: 11pt;'
    '    font-weight: 700;'
    '    min-width: 26px;'
    '    max-width: 26px;'
    '    min-height: 26px;'
    '    max-height: 26px;'
    '}'
    'QPushButton#dependencyPromptCloseButton:hover {'
    '    background-color: @danger/22;'
    '    color: @text_strong;'
    '}'
    'QPushButton#dependencyPromptCloseButton:pressed {'
    '    background-color: @danger/38;'
    '}',
)

DEPENDENCY_PROMPT_INFO_CARD_STYLESHEET = themed_qss(
    'QFrame#dependencyPromptInfoCard { background-color: @input; border: 1px solid @border; border-radius: 10px; }',
)

DEPENDENCY_PROMPT_MESSAGE_LABEL_STYLESHEET = themed_qss('color: @text; background: transparent; font-size: 9.5pt;')

DEPENDENCY_PROMPT_ACTION_BUTTON_STYLESHEET = themed_qss(
    'QPushButton {'
    '    background-color: @accent;'
    '    color: @text_strong;'
    '    border: 1px solid @accent:hover;'
    '    border-radius: 8px;'
    '    padding: 7px 26px;'
    '    font-weight: 700;'
    '    font-size: 9.5pt;'
    '    letter-spacing: 0.3px;'
    '}'
    'QPushButton:hover {'
    '    background-color: @accent:hover;'
    '    border: 1px solid @accent:hover;'
    '    color: @text_strong;'
    '}'
    'QPushButton:pressed {'
    '    background-color: @accent:pressed;'
    '    border: 1px solid @accent;'
    '}',
)

DEPENDENCY_PROMPT_STATUS_CARD_STYLESHEET = themed_qss(
    'QFrame#dependencyPromptStatusCard {'
    '    background-color: @input;'
    '    border: 1px solid @accent/30;'
    '    border-radius: 9px;'
    '}',
)

DEPENDENCY_PROMPT_STATUS_TITLE_STYLESHEET = themed_qss('color: @text_strong; background: transparent; font-size: 9pt; font-weight: 700;')

DEPENDENCY_PROMPT_STATUS_SUBTITLE_STYLESHEET = themed_qss('color: @text_muted; background: transparent; font-size: 8pt;')

DEPENDENCY_PROMPT_STATUS_BADGE_STYLESHEET = themed_qss(
    'color: @success;'
    'background-color: @success/14;'
    'border: 1px solid @success/35;'
    'border-radius: 4px;'
    'padding: 2px 7px;'
    'font-size: 7.5pt;'
    'letter-spacing: 0.5px;'
    'font-weight: 800;',
)

DEPENDENCY_PROMPT_FOOTER_HINT_STYLESHEET = themed_qss('color: @text_muted; background: transparent; font-size: 8pt;')

DEPENDENCY_PROMPT_EXIT_BUTTON_STYLESHEET = themed_qss(
    'QPushButton {'
    '    background-color: @control;'
    '    color: @text;'
    '    border: 1px solid @border;'
    '    border-radius: 7px;'
    '    padding: 6px 18px;'
    '    font-weight: 700;'
    '    font-size: 9pt;'
    '}'
    'QPushButton:hover {'
    '    background-color: @control:hover;'
    '    border: 1px solid @accent;'
    '    color: @text_strong;'
    '}'
    'QPushButton:pressed {'
    '    background-color: @control:pressed;'
    '    border: 1px solid @accent;'
    '}',
)

# =============================================================================
# UPDATE DOWNLOAD DIALOG STYLES
# =============================================================================

UPDATE_DOWNLOAD_DIALOG_STYLESHEET = themed_qss('QDialog { background-color: transparent; }')

UPDATE_DOWNLOAD_FRAME_STYLESHEET = themed_qss(
    'QFrame#updateDownloadFrame {'
    '  background-color: @surface;'
    '  border: 1px solid @border;'
    '  border-radius: 14px;'
    '}',
)

UPDATE_DOWNLOAD_TITLE_LABEL_STYLESHEET = themed_qss('color: @text_strong; background: transparent; letter-spacing: 0.5px;')

UPDATE_DOWNLOAD_DIVIDER_STYLESHEET = themed_qss('background-color: @border/45; min-height: 1px; max-height: 1px; border: none;')

UPDATE_DOWNLOAD_VERSION_CARD_CURRENT_STYLESHEET = themed_qss(
    'QFrame#updateDownloadVersionCardCurrent { background-color: @input; border: 1px solid @border; border-radius: 10px; }',
)

UPDATE_DOWNLOAD_VERSION_CARD_NEW_STYLESHEET = themed_qss(
    'QFrame#updateDownloadVersionCardNew {'
    '  background-color: @surface~accent/14;'
    '  border: 1px solid @accent;'
    '  border-radius: 10px;'
    '}',
)

UPDATE_DOWNLOAD_VERSION_CARD_LABEL_MUTED_STYLESHEET = themed_qss('color: @text_muted; background: transparent; font-size: 12px; letter-spacing: 0.6px; font-weight: 700;')

UPDATE_DOWNLOAD_VERSION_CARD_LABEL_ACCENT_STYLESHEET = themed_qss('color: @accent; background: transparent; font-size: 12px; letter-spacing: 0.6px; font-weight: 700;')


def _version_card_badge_stylesheet(role_token: str) -> str:
    """Build the QSS for a release-channel badge on the update download dialog."""
    return themed_qss(
        f'color: @{role_token}; background-color: @{role_token}/14; border: 1px solid @{role_token}/35;'
        'border-radius: 4px; padding: 1px 5px; font-size: 9.5px; letter-spacing: 0.4px; font-weight: 700;',
    )


UPDATE_DOWNLOAD_VERSION_CARD_BADGE_STABLE_STYLESHEET = _version_card_badge_stylesheet('success')

UPDATE_DOWNLOAD_VERSION_CARD_BADGE_PRERELEASE_STYLESHEET = _version_card_badge_stylesheet('warning')

UPDATE_DOWNLOAD_VERSION_CARD_VALUE_MUTED_STYLESHEET = themed_qss('color: @text; background: transparent; font-size: 17px; font-weight: 700;')

UPDATE_DOWNLOAD_VERSION_CARD_VALUE_ACCENT_STYLESHEET = themed_qss('color: @text_strong; background: transparent; font-size: 17px; font-weight: 700;')

UPDATE_DOWNLOAD_VERSION_CARD_DATE_STYLESHEET = themed_qss('color: @text_muted; background: transparent; font-family: Menlo, Consolas, "Courier New", monospace;')

UPDATE_DOWNLOAD_VERSION_CARD_SHA_STYLESHEET = themed_qss(
    'color: @text_muted; background: transparent; font-family: Menlo, Consolas, "Courier New", monospace; font-size: 11.5px;',
)

UPDATE_DOWNLOAD_VERSION_ARROW_STYLESHEET = themed_qss('color: @accent; background: transparent; font-weight: 800;')

UPDATE_DOWNLOAD_STATUS_LABEL_STYLESHEET = themed_qss('color: @text; background: transparent;')

UPDATE_DOWNLOAD_SIZE_PILL_STYLESHEET = themed_qss('QFrame#updateDownloadSizePill { background-color: @input; border: 1px solid @border; border-radius: 12px; }')

UPDATE_DOWNLOAD_SIZE_LABEL_STYLESHEET = themed_qss('color: @text; background: transparent; font-family: Menlo, Consolas, "Courier New", monospace; font-weight: 600;')

UPDATE_DOWNLOAD_PROGRESS_BAR_STYLESHEET = themed_qss(
    'QProgressBar {'
    '  background-color: @input;'
    '  border: 1px solid @border;'
    '  border-radius: 10px;'
    '  text-align: center;'
    '  color: @text_strong;'
    '  font-weight: 700;'
    '  font-size: 11pt;'
    '  min-height: 26px;'
    '}'
    'QProgressBar::chunk {'
    '  background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 @accent, stop:1 @accent:hover);'
    '  border-radius: 8px;'
    '  margin: 2px;'
    '}',
)

UPDATE_DOWNLOAD_CANCEL_BUTTON_STYLESHEET = themed_qss(
    'QPushButton {'
    '  background-color: @control~danger/24;'
    '  color: @text_strong;'
    '  border: 1px solid @danger/65;'
    '  border-radius: 8px;'
    '  padding: 7px 22px;'
    '  font-weight: 700;'
    '  font-size: 10pt;'
    '  letter-spacing: 0.5px;'
    '  min-width: 80px;'
    '}'
    'QPushButton:hover {'
    '  background-color: @control~danger/36:hover;'
    '  border: 1px solid @danger;'
    '  color: @text_strong;'
    '}'
    'QPushButton:pressed {'
    '  background-color: @control~danger/45:pressed;'
    '  border: 1px solid @danger;'
    '  padding-top: 8px;'
    '  padding-bottom: 6px;'
    '}',
)

UPDATE_DOWNLOAD_SKIP_BUTTON_STYLESHEET = themed_qss(
    'QPushButton {'
    '  background-color: @control;'
    '  color: @text;'
    '  border: 1px solid @border;'
    '  border-radius: 8px;'
    '  padding: 7px 22px;'
    '  font-weight: 700;'
    '  font-size: 10pt;'
    '  letter-spacing: 0.5px;'
    '  min-width: 80px;'
    '}'
    'QPushButton:hover {'
    '  background-color: @control:hover;'
    '  border: 1px solid @accent;'
    '  color: @text_strong;'
    '}'
    'QPushButton:pressed {'
    '  background-color: @control:pressed;'
    '  border: 1px solid @accent;'
    '  padding-top: 8px;'
    '  padding-bottom: 6px;'
    '}',
)

UPDATE_DOWNLOAD_UPDATE_BUTTON_STYLESHEET = themed_qss(
    'QPushButton {'
    '  background-color: @accent;'
    '  color: @text_strong;'
    '  border: 1px solid @accent:hover;'
    '  border-radius: 8px;'
    '  padding: 7px 24px;'
    '  font-weight: 700;'
    '  font-size: 10pt;'
    '  letter-spacing: 0.5px;'
    '  min-width: 90px;'
    '}'
    'QPushButton:hover {'
    '  background-color: @accent:hover;'
    '  border: 1px solid @accent:hover;'
    '  color: @text_strong;'
    '}'
    'QPushButton:pressed {'
    '  background-color: @accent:pressed;'
    '  border: 1px solid @accent;'
    '  padding-top: 8px;'
    '  padding-bottom: 6px;'
    '}',
)

# =============================================================================
# LOOKY SYSTEM ACCOUNT CARD STYLES
# =============================================================================

LOOKY_CARD_LABEL_STYLESHEET = themed_qss('color: @secondary; font-size: 10.5pt;')

LOOKY_CARD_VALUE_STYLESHEET = themed_qss('color: @text; font-size: 10.5pt;')

# =============================================================================
# LOOKY SYSTEM CRAWLER DIALOG STYLES
# =============================================================================

LOOKY_CRAWLER_HEADER_STYLESHEET = themed_qss(
    'font-size: 11pt;'
    'font-weight: 700;'
    'padding: 10px 14px;'
    'color: @secondary;'
    'background-color: @table_header~secondary/22;'
    'border: 1px solid @border~secondary/45;'
    'border-radius: 8px;',
)

LOOKY_CRAWLER_LOG_STYLESHEET = themed_qss(
    'QPlainTextEdit {'
    '    background-color: @input;'
    '    color: @text;'
    '    border: 1px solid @border~secondary/35;'
    '    border-radius: 6px;'
    '    font-family: Menlo, Consolas, "Courier New", monospace;'
    '    font-size: 10pt;'
    '    padding: 6px;'
    '    selection-background-color: @selection~secondary/35;'
    '    selection-color: @text_strong;'
    '}',
)

LOOKY_PROGRESS_BAR_STYLESHEET = themed_qss(
    'QProgressBar {'
    '    background-color: @input;'
    '    border: 1px solid @border~secondary/35;'
    '    border-radius: 7px;'
    '}'
    'QProgressBar::chunk {'
    '    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 @secondary, stop:1 @secondary:hover);'
    '    border-radius: 7px;'
    '}',
)

LOOKY_STATUS_LABEL_STYLESHEET = themed_qss('font-size: 10pt; padding: 4px;')


def _looky_outline_button_stylesheet(padding: str, extra_props: str = '') -> str:
    """Build the secondary-accent outline QPushButton QSS for Looky System dialogs."""
    return themed_qss(
        'QPushButton {'
        '    background-color: @control~secondary/18;'
        '    color: @secondary;'
        '    border: 1px solid @border~secondary/50;'
        '    border-radius: 6px;'
        f'    padding: {padding};'
        f'    font-weight: 600;{extra_props}'
        '}'
        'QPushButton:hover {'
        '    background-color: @control~secondary/28:hover;'
        '    border-color: @secondary;'
        '}'
        'QPushButton:pressed {'
        '    background-color: @control~secondary/38:pressed;'
        '}',
    )


LOOKY_ACTION_BUTTON_STYLESHEET = _looky_outline_button_stylesheet('5px 16px')

LOOKY_PRIMARY_ACTION_BUTTON_STYLESHEET = themed_qss(
    'QPushButton {'
    '    background-color: @secondary;'
    '    color: @text_strong;'
    '    border: 1px solid @secondary:hover;'
    '    border-radius: 7px;'
    '    padding: 10px 22px;'
    '    font-size: 10pt;'
    '    font-weight: 700;'
    '}'
    'QPushButton:hover {'
    '    background-color: @secondary:hover;'
    '}'
    'QPushButton:pressed {'
    '    background-color: @secondary:pressed;'
    '}',
)

LOOKY_LIST_WIDGET_STYLESHEET = themed_qss(
    'QListWidget {'
    '    background-color: @table;'
    '    color: @text;'
    '    border: 1px solid @border~secondary/35;'
    '    border-radius: 6px;'
    '    padding: 4px;'
    '    font-family: Menlo, Consolas, "Courier New", monospace;'
    '    font-size: 9pt;'
    '    outline: 0;'
    '}'
    'QListWidget::item {'
    '    padding: 6px 8px;'
    '    border-radius: 4px;'
    '}'
    'QListWidget::item:hover {'
    '    background-color: @table_alt~secondary/16;'
    '}'
    'QListWidget::item:selected {'
    '    background-color: @selection~secondary/35;'
    '    color: @text_strong;'
    '}',
)

LOOKY_BODY_LABEL_STYLESHEET = themed_qss('color: @text; font-size: 12pt; padding: 2px;')

# =============================================================================
# LOOKY SYSTEM REFRESH REVIEW DIALOG STYLES
# =============================================================================

LOOKY_REVIEW_DIALOG_STYLESHEET = themed_qss('QDialog { background-color: @background~secondary/8; }')

LOOKY_REVIEW_TABLE_STYLESHEET = themed_qss(
    'QTreeWidget {'
    '    background-color: @table;'
    '    color: @text;'
    '    border: 1px solid @border~secondary/35;'
    '    border-radius: 8px;'
    '    font-family: Menlo, Consolas, "Courier New", monospace;'
    '    font-size: 9pt;'
    '    padding: 4px;'
    '    outline: 0;'
    '    alternate-background-color: @table_alt;'
    '}'
    'QTreeWidget::item {'
    '    padding: 5px 6px;'
    '    border-bottom: 1px solid @border/40;'
    '}'
    'QTreeWidget::item:hover {'
    '    background-color: @table_alt~secondary/16;'
    '}'
    'QTreeWidget::item:selected {'
    '    background-color: @selection~secondary/35;'
    '    color: @text_strong;'
    '}'
    'QTreeWidget::item:selected:hover {'
    '    background-color: @selection~secondary/45:hover;'
    '    color: @text_strong;'
    '}'
    'QTreeWidget::branch {'
    '    background: transparent;'
    '    border: none;'
    '    border-image: none;'
    '    image: none;'
    '}'
    'QTreeWidget::branch:hover {'
    '    background-color: @table_alt~secondary/16;'
    '}'
    'QTreeWidget::branch:selected {'
    '    background-color: @selection~secondary/35;'
    '}'
    'QTreeWidget::branch:selected:hover {'
    '    background-color: @selection~secondary/45:hover;'
    '}'
    'QTreeWidget::branch:has-siblings:!adjoins-item,'
    'QTreeWidget::branch:has-siblings:adjoins-item,'
    'QTreeWidget::branch:!has-children:!has-siblings:adjoins-item,'
    'QTreeWidget::branch:!has-children:!has-siblings:!adjoins-item {'
    '    border-image: none;'
    '    image: none;'
    '}'
    'QTreeWidget::branch:has-children:!has-siblings:closed,'
    'QTreeWidget::branch:closed:has-children:has-siblings {'
    '    border-image: none;'
    f'    image: url("{_CHEVRON_RIGHT_PATH}");'
    '}'
    'QTreeWidget::branch:has-children:!has-siblings:open,'
    'QTreeWidget::branch:open:has-children:has-siblings {'
    '    border-image: none;'
    f'    image: url("{_CHEVRON_DOWN_PATH}");'
    '}'
    'QTreeWidget::indicator {'
    '    width: 16px;'
    '    height: 16px;'
    '}'
    'QTreeWidget::indicator:unchecked {'
    '    border: 1px solid @border~secondary/50;'
    '    border-radius: 4px;'
    '    background-color: @input;'
    '}'
    'QTreeWidget::indicator:unchecked:hover {'
    '    border: 1px solid @secondary;'
    '    background-color: @input:hover;'
    '}'
    'QTreeWidget::indicator:checked {'
    '    border: 1px solid @secondary;'
    '    border-radius: 4px;'
    '    background-color: @secondary;'
    f'    image: url("{_CHECK_PATH}");'
    '}'
    'QTreeWidget::indicator:checked:hover {'
    '    border: 1px solid @secondary:hover;'
    '    background-color: @secondary:hover;'
    '}'
    'QHeaderView::section {'
    '    background-color: @table_header~secondary/22;'
    '    color: @secondary;'
    '    border: 1px solid @border~secondary/45;'
    '    padding: 6px 10px;'
    '    font-weight: 700;'
    '    font-size: 8pt;'
    '}',
)

LOOKY_REVIEW_SUMMARY_STYLESHEET = themed_qss(
    'QFrame {'
    '    background-color: @surface~secondary/12;'
    '    border: 1px solid @border~secondary/35;'
    '    border-radius: 10px;'
    '    padding: 10px 14px;'
    '}',
)

LOOKY_REVIEW_SELECT_BUTTON_STYLESHEET = _looky_outline_button_stylesheet('4px 14px', '    font-size: 8pt;')

LOOKY_REVIEW_MATCHES_TOGGLE_STYLESHEET = themed_qss(
    'QPushButton {'
    '    background-color: @control;'
    '    color: @text_muted;'
    '    border: 1px dashed @border~secondary/45;'
    '    border-radius: 6px;'
    '    padding: 4px 16px;'
    '    font-weight: 700;'
    '    font-size: 8pt;'
    '}'
    'QPushButton:hover {'
    '    background-color: @control:hover;'
    '    color: @secondary;'
    '    border: 1px solid @secondary;'
    '}'
    'QPushButton:checked {'
    '    background-color: @secondary;'
    '    color: @text_strong;'
    '    border: 1px solid @accent;'
    '}'
    'QPushButton:checked:hover {'
    '    background-color: @secondary:hover;'
    '    border: 1px solid @accent:hover;'
    '    color: @text_strong;'
    '}',
)
