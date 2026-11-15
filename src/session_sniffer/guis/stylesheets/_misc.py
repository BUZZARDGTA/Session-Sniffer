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
background-color: @popup[#222244];  /* Dark blueish background */
border-radius: 15px;        /* Rounded corners */
color: @text_strong[#ffffff];
""".strip(),
)

DISCORD_POPUP_EXIT_BUTTON_STYLESHEET = themed_qss(
    """
font-size: 8pt;
color: @text_strong[#ffffff];
background-color: @danger[#ff4c4c];  /* Light red background */
border-radius: 15px;        /* Make it circular */
""".strip(),
)

DISCORD_POPUP_JOIN_BUTTON_STYLESHEET = themed_qss(
    """
font-size: 10pt;
padding: 7px;
background-color: @lock[#5865f2];  /* Discord blue */
color: @lock[#ffffff];
border-radius: 10px;
border: none;
""".strip(),
)

# =============================================================================
# SECTION TABLE HEADER STYLES
# =============================================================================

SECTION_HEADER_SEPARATOR_STYLESHEET = themed_qss(
    'background-color: @border[rgba(255, 255, 255, 0.12)]; border: none; max-width: 1px; min-width: 1px; margin: 4px 4px;',
)

# =============================================================================
# MAIN WINDOW STYLES
# =============================================================================

GTA5_STATUS_LABEL_STYLESHEET = themed_qss('QLabel { background: transparent; padding: 6px 28px 6px 16px; font-size: 10pt; }')

# =============================================================================
# SETTINGS DIALOG STYLES
# =============================================================================


def _settings_info_label_stylesheet(accent_color: str) -> str:
    """Build the shared settings card info-banner QLabel QSS with *accent_color* left border."""
    return themed_qss(
        'QLabel {'
        'background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 @surface[#262b36], stop:1 @surface[#1f2430]);'
        'border: 1px solid @border[#3b4455];'
        f'border-left: 4px solid {accent_color};'
        'border-radius: 10px;'
        'padding: 12px 14px;'
        'color: @text[#dbe4f0];'
        'line-height: 1.35;'
        '}',
    )


DISCORD_INFO_LABEL_STYLESHEET = _settings_info_label_stylesheet('@lock[#5865f2]')

WEBSERVER_HELP_LABEL_STYLESHEET = _settings_info_label_stylesheet('@accent[#61afef]')

WEBHOOK_NOTE_LABEL_STYLESHEET = themed_qss('color: @text_muted[#888888]; font-size: 8pt;')

LOOKY_INFO_LABEL_STYLESHEET = _settings_info_label_stylesheet('@lock[#7c3aed]')

LOOKY_ACCOUNT_CARD_STYLESHEET = themed_qss(
    'QFrame#lookyAccountCard {background: @lock[rgba(76, 29, 149, 0.12)];border: 1px solid @lock[#3d2d6e];border-radius: 8px;padding: 4px;}',
)

INTERFACE_INFO_CARD_STYLESHEET = themed_qss(
    'QGroupBox {'
    'background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 @surface[#262b36], stop:1 @surface[#1f2430]);'
    'border: 1px solid @border[#3b4455];'
    'border-left: 4px solid @accent[#3d8ec9];'
    'border-radius: 8px;'
    'margin-top: 14px;'
    'padding-top: 12px;'
    '}'
    'QGroupBox::title {'
    'subcontrol-origin: margin;'
    'subcontrol-position: top left;'
    'left: 10px; padding: 2px 8px;'
    'background: @accent[#3d8ec9];'
    'color: @text_strong[#ffffff];'
    'border-radius: 4px;'
    'font-weight: bold;'
    '}',
)

INTERFACE_INFO_VALUE_LABEL_STYLESHEET = themed_qss(
    'color: @accent[#61afef]; font-weight: bold; padding: 2px 6px;background: @accent[rgba(61, 142, 201, 0.10)]; border-radius: 3px;',
)

SETTINGS_RESTART_BANNER_STYLESHEET = themed_qss(
    'QFrame#restartNoticeBanner {'
    'background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 @surface[#262b36], stop:1 @surface[#1f2430]);'
    'border: 1px solid @border[#3b4455];'
    'border-left: 4px solid @warning[#f59e0b];'
    'border-radius: 6px;'
    '}',
)

# =============================================================================
# SPLASH SCREEN STYLES
# =============================================================================

SPLASH_SCREEN_STYLESHEET = themed_qss('background-color: @background[#19232d];')

SPLASH_TITLE_LABEL_STYLESHEET = themed_qss('color: @text_strong[#e0e6ee]; background: transparent; font-size: 20pt; font-weight: bold;')

SPLASH_SUBTITLE_LABEL_STYLESHEET = themed_qss('color: @text_muted[#667788]; background: transparent; font-size: 11pt;')

SPLASH_SUBTITLE_READY_STYLESHEET = themed_qss('color: @success[#44cc66]; background: transparent; font-size: 11pt;')

SPLASH_LOG_AREA_STYLESHEET = themed_qss(
    'QTextEdit {  background-color: @input[#141922];  color: @text_muted[#8899aa];  border: 1px solid @border[#2a3544];  border-radius: 6px;  padding: 8px;}',
)

# =============================================================================
# CRASH DIALOG STYLES
# =============================================================================

CRASH_DIALOG_FRAME_STYLESHEET = themed_qss(
    'QFrame#crashDialogFrame {'
    '    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 @surface~danger[#26202a], stop:0.25 @surface[#1f2531], stop:1 @background[#161d26]);'
    '    border: 1px solid @border~danger[#5a3540];'
    '    border-radius: 14px;'
    '}',
)

CRASH_DIALOG_ICON_CONTAINER_STYLESHEET = themed_qss(
    'QFrame#crashDialogIconContainer {'
    '    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 @danger[rgba(239, 68, 68, 0.24)], stop:1 @danger[rgba(185, 28, 28, 0.12)]);'
    '    border: 1px solid @danger[rgba(248, 113, 113, 0.42)];'
    '    border-radius: 10px;'
    '}',
)

CRASH_DIALOG_KICKER_LABEL_STYLESHEET = themed_qss('color: @danger[#f87171]; background: transparent; font-size: 8pt; font-weight: 700; letter-spacing: 1px;')

CRASH_DIALOG_SUBTITLE_LABEL_STYLESHEET = themed_qss('color: @text_muted[#8b9bb0]; background: transparent; font-size: 8.5pt;')

CRASH_DIALOG_INFO_CARD_STYLESHEET = themed_qss(
    'QFrame#crashDialogInfoCard {'
    '    background: @surface[rgba(16, 23, 33, 0.82)];'
    '    border: 1px solid @border[#2c3a4d];'
    '    border-left: 3px solid @danger[#ef4444];'
    '    border-radius: 10px;'
    '}',
)

CRASH_DIALOG_SECTION_LABEL_STYLESHEET = themed_qss('color: @text_muted[#94a3b8]; background: transparent; font-size: 8pt; font-weight: 700; letter-spacing: 0.8px;')

CRASH_DIALOG_BADGE_STYLESHEET = themed_qss(
    'color: @danger[#fca5a5];background: @danger[rgba(239, 68, 68, 0.12)];border: 1px solid @danger[rgba(248, 113, 113, 0.28)];'
    'border-radius: 8px;padding: 2px 10px;font-size: 8pt;font-weight: 700;',
)

CRASH_DIALOG_TRACEBACK_EDIT_STYLESHEET = themed_qss(
    'QPlainTextEdit#crashDialogTracebackEdit {'
    '    background-color: @input[#0d131c];'
    '    color: @text[#e2e8f0];'
    '    border: 1px solid @border[#2b384b];'
    '    border-radius: 8px;'
    '    padding: 8px 10px;'
    '    selection-background-color: @selection[#2b4c7e];'
    '    selection-color: @text_strong[#ffffff];'
    '}',
)

CRASH_DIALOG_PRIMARY_BUTTON_STYLESHEET = themed_qss(
    'QPushButton {'
    '    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 @accent[#388ecc], stop:1 @accent[#1c62a4]);'
    '    color: @text_strong[#ffffff];'
    '    border: 1px solid @accent[#4da2e4];'
    '    border-radius: 7px;'
    '    padding: 5px 14px;'
    '    font-weight: 700;'
    '    font-size: 9pt;'
    '}'
    'QPushButton:hover {'
    '    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 @accent[#479de0], stop:1 @accent[#2472bc]);'
    '    border: 1px solid @accent[#7ec2fc];'
    '    color: @text_strong[#ffffff];'
    '}'
    'QPushButton:pressed {'
    '    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 @accent[#17548f], stop:1 @accent[#2974b8]);'
    '    border: 1px solid @accent[#3d8ec9];'
    '    color: @text_strong[#ffffff];'
    '}',
)

CRASH_DIALOG_SECONDARY_BUTTON_STYLESHEET = themed_qss(
    'QPushButton {'
    '    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 @control[#253140], stop:1 @control[#1a222d]);'
    '    color: @text[#c8d6e5];'
    '    border: 1px solid @border[#38485c];'
    '    border-radius: 7px;'
    '    padding: 5px 12px;'
    '    font-weight: 700;'
    '    font-size: 9pt;'
    '}'
    'QPushButton:hover {'
    '    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 @control[#334358], stop:1 @control[#222d3c]);'
    '    border: 1px solid @border[#526780];'
    '    color: @text_strong[#ffffff];'
    '}'
    'QPushButton:pressed {'
    '    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 @control[#1a222d], stop:1 @control[#253140]);'
    '    border: 1px solid @border[#28374a];'
    '    color: @text_strong[#ffffff];'
    '}',
)

CRASH_DIALOG_EXIT_BUTTON_STYLESHEET = themed_qss(
    'QPushButton {'
    '    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 @danger[rgba(192, 57, 43, 0.75)], stop:1 @danger[rgba(146, 43, 33, 0.85)]);'
    '    color: @text_strong[#ffffff];'
    '    border: 1px solid @danger[rgba(231, 76, 60, 0.65)];'
    '    border-radius: 7px;'
    '    padding: 5px 18px;'
    '    font-weight: 700;'
    '    font-size: 9pt;'
    '}'
    'QPushButton:hover {'
    '    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 @danger[rgba(231, 76, 60, 0.85)], stop:1 @danger[rgba(192, 57, 43, 0.95)]);'
    '    border: 1px solid @danger[rgba(248, 113, 113, 0.95)];'
    '    color: @text_strong[#ffffff];'
    '}'
    'QPushButton:pressed {'
    '    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 @danger[rgba(146, 43, 33, 0.95)], stop:1 @danger[rgba(120, 35, 27, 1.0)]);'
    '    border: 1px solid @danger[rgba(192, 57, 43, 1.0)];'
    '    color: @text_strong[#ffffff];'
    '}',
)

# =============================================================================
# DEPENDENCY PROMPT DIALOG STYLES
# =============================================================================

DEPENDENCY_PROMPT_DIALOG_STYLESHEET = themed_qss('QDialog { background-color: transparent; }')

DEPENDENCY_PROMPT_FRAME_STYLESHEET = themed_qss(
    'QFrame#dependencyPromptFrame {'
    '    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 @surface[#232f3e], stop:1 @background[#18212c]);'
    '    border: 1px solid @border[#3a4a5c];'
    '    border-radius: 14px;'
    '}',
)

DEPENDENCY_PROMPT_ICON_CONTAINER_STYLESHEET = themed_qss(
    'QFrame#dependencyPromptIconContainer {'
    '    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 @accent[rgba(95, 180, 245, 0.20)], stop:1 @accent[rgba(31, 108, 200, 0.10)]);'
    '    border: 1px solid @accent[rgba(95, 180, 245, 0.35)];'
    '    border-radius: 10px;'
    '}',
)

DEPENDENCY_PROMPT_KICKER_LABEL_STYLESHEET = themed_qss('color: @accent[#5fb4f5];background: transparent;font-size: 8pt;font-weight: 700;letter-spacing: 1px;')

DEPENDENCY_PROMPT_TITLE_LABEL_STYLESHEET = themed_qss('color: @text_strong[#f0f4fa];background: transparent;font-size: 15pt;font-weight: 700;letter-spacing: 0.3px;')

DEPENDENCY_PROMPT_CLOSE_BUTTON_STYLESHEET = themed_qss(
    'QPushButton#dependencyPromptCloseButton {'
    '    background: transparent;'
    '    color: @text_muted[#6f7e91];'
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
    '    background: @danger[rgba(231, 76, 60, 0.22)];'
    '    color: @text_strong[#ffffff];'
    '}'
    'QPushButton#dependencyPromptCloseButton:pressed {'
    '    background: @danger[rgba(231, 76, 60, 0.38)];'
    '    color: @text_strong[#ffffff];'
    '}',
)

DEPENDENCY_PROMPT_INFO_CARD_STYLESHEET = themed_qss(
    'QFrame#dependencyPromptInfoCard {    background: @surface[rgba(18, 26, 38, 0.75)];    border: 1px solid @border[#2c3a4d];    border-radius: 10px;}',
)

DEPENDENCY_PROMPT_MESSAGE_LABEL_STYLESHEET = themed_qss('color: @text[#c8d4e2]; background: transparent; font-size: 9.5pt;')

DEPENDENCY_PROMPT_ACTION_BUTTON_STYLESHEET = themed_qss(
    'QPushButton {'
    '    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 @accent[#388ecc], stop:1 @accent[#1c62a4]);'
    '    color: @text_strong[#ffffff];'
    '    border: 1px solid @accent[#4da2e4];'
    '    border-radius: 8px;'
    '    padding: 7px 26px;'
    '    font-weight: 700;'
    '    font-size: 9.5pt;'
    '    letter-spacing: 0.3px;'
    '}'
    'QPushButton:hover {'
    '    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 @accent[#479de0], stop:1 @accent[#2472bc]);'
    '    border: 1px solid @accent[#7ec2fc];'
    '    color: @text_strong[#ffffff];'
    '}'
    'QPushButton:pressed {'
    '    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 @accent[#17548f], stop:1 @accent[#2974b8]);'
    '    border: 1px solid @accent[#3d8ec9];'
    '    color: @text_strong[#ffffff];'
    '}',
)

DEPENDENCY_PROMPT_STATUS_CARD_STYLESHEET = themed_qss(
    'QFrame#dependencyPromptStatusCard {'
    '    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 @surface[rgba(14, 21, 32, 0.95)], stop:1 @surface[rgba(19, 30, 45, 0.85)]);'
    '    border: 1px solid @accent[rgba(95, 180, 245, 0.28)];'
    '    border-radius: 9px;'
    '}',
)

DEPENDENCY_PROMPT_STATUS_TITLE_STYLESHEET = themed_qss('color: @text_strong[#e2eaf4]; background: transparent; font-size: 9pt; font-weight: 700;')

DEPENDENCY_PROMPT_STATUS_SUBTITLE_STYLESHEET = themed_qss('color: @text_muted[#728498]; background: transparent; font-size: 8pt;')

DEPENDENCY_PROMPT_STATUS_BADGE_STYLESHEET = themed_qss(
    'color: @success[#3dd68c];'
    'background: @success[rgba(61, 214, 140, 0.12)];'
    'border: 1px solid @success[rgba(61, 214, 140, 0.35)];'
    'border-radius: 4px;'
    'padding: 2px 7px;'
    'font-size: 7.5pt;'
    'letter-spacing: 0.5px;'
    'font-weight: 800;',
)

DEPENDENCY_PROMPT_FOOTER_HINT_STYLESHEET = themed_qss('color: @text_muted[#5c6d80]; background: transparent; font-size: 8pt;')

DEPENDENCY_PROMPT_EXIT_BUTTON_STYLESHEET = themed_qss(
    'QPushButton {'
    '    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 @control[#253140], stop:1 @control[#1a222d]);'
    '    color: @text[#b0c0d0];'
    '    border: 1px solid @border[#38485c];'
    '    border-radius: 7px;'
    '    padding: 6px 18px;'
    '    font-weight: 700;'
    '    font-size: 9pt;'
    '}'
    'QPushButton:hover {'
    '    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 @control[#334358], stop:1 @control[#222d3c]);'
    '    border: 1px solid @border[#526780];'
    '    color: @text_strong[#ffffff];'
    '}'
    'QPushButton:pressed {'
    '    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 @control[#1a222d], stop:1 @control[#253140]);'
    '    border: 1px solid @border[#28374a];'
    '    color: @text_strong[#ffffff];'
    '}',
)

# =============================================================================
# UPDATE DOWNLOAD DIALOG STYLES
# =============================================================================

UPDATE_DOWNLOAD_DIALOG_STYLESHEET = themed_qss('QDialog {  background-color: transparent;}')

UPDATE_DOWNLOAD_FRAME_STYLESHEET = themed_qss(
    'QFrame#updateDownloadFrame {'
    '  background: qlineargradient(x1:0, y1:0, x2:0, y2:1,      stop:0 @surface[#232f3e], stop:1 @background[#18212c]);'
    '  border: 1px solid @border[#3a4a5c];'
    '  border-radius: 14px;'
    '}',
)

UPDATE_DOWNLOAD_TITLE_LABEL_STYLESHEET = themed_qss('color: @text_strong[#f0f4fa];background: transparent;letter-spacing: 0.5px;')

UPDATE_DOWNLOAD_DIVIDER_STYLESHEET = themed_qss('background: @border[rgba(255, 255, 255, 0.07)];min-height: 1px;max-height: 1px;border: none;')

UPDATE_DOWNLOAD_VERSION_CARD_CURRENT_STYLESHEET = themed_qss(
    'QFrame#updateDownloadVersionCardCurrent {  background: @surface[rgba(20, 28, 40, 0.55)];  border: 1px solid @border[#2f3e52];  border-radius: 10px;}',
)

UPDATE_DOWNLOAD_VERSION_CARD_NEW_STYLESHEET = themed_qss(
    'QFrame#updateDownloadVersionCardNew {'
    '  background: qlineargradient(x1:0, y1:0, x2:0, y2:1,'
    '      stop:0 @accent[rgba(95, 180, 245, 0.18)], stop:1 @accent[rgba(31, 108, 200, 0.08)]);'
    '  border: 1px solid @accent[#4aa3ee];'
    '  border-radius: 10px;'
    '}',
)

UPDATE_DOWNLOAD_VERSION_CARD_LABEL_MUTED_STYLESHEET = themed_qss(
    'color: @text_muted[#7a8a9c];background: transparent;font-size: 12px;letter-spacing: 0.6px;font-weight: 700;',
)

UPDATE_DOWNLOAD_VERSION_CARD_LABEL_ACCENT_STYLESHEET = themed_qss(
    'color: @accent[#5fb4f5];background: transparent;font-size: 12px;letter-spacing: 0.6px;font-weight: 700;',
)


def _version_card_badge_stylesheet(token: str, fg_color: str, rgb: str) -> str:
    """Build the QSS for a release-channel badge on the update download dialog."""
    return themed_qss(
        f'color: @{token}[{fg_color}];background: @{token}[rgba({rgb}, 0.12)];border: 1px solid @{token}[rgba({rgb}, 0.35)];'
        'border-radius: 4px;padding: 1px 5px;font-size: 9.5px;letter-spacing: 0.4px;font-weight: 700;',
    )


UPDATE_DOWNLOAD_VERSION_CARD_BADGE_STABLE_STYLESHEET = _version_card_badge_stylesheet('success', '#3dd68c', '61, 214, 140')

UPDATE_DOWNLOAD_VERSION_CARD_BADGE_PRERELEASE_STYLESHEET = _version_card_badge_stylesheet('warning', '#f5a76c', '245, 167, 108')

UPDATE_DOWNLOAD_VERSION_CARD_VALUE_MUTED_STYLESHEET = themed_qss('color: @text[#c4ced9];background: transparent;font-size: 17px;font-weight: 700;')

UPDATE_DOWNLOAD_VERSION_CARD_VALUE_ACCENT_STYLESHEET = themed_qss('color: @text_strong[#f0f4fa];background: transparent;font-size: 17px;font-weight: 700;')

UPDATE_DOWNLOAD_VERSION_CARD_DATE_STYLESHEET = themed_qss(
    'color: @text_muted[#6f7e91];background: transparent;font-family: Menlo, Consolas, "Courier New", monospace;',
)

UPDATE_DOWNLOAD_VERSION_CARD_SHA_STYLESHEET = themed_qss(
    'color: @text_muted[#6f7e91];background: transparent;font-family: Menlo, Consolas, "Courier New", monospace;font-size: 11.5px;',
)

UPDATE_DOWNLOAD_VERSION_ARROW_STYLESHEET = themed_qss('color: @accent[#4aa3ee];background: transparent;font-weight: 800;')

UPDATE_DOWNLOAD_STATUS_LABEL_STYLESHEET = themed_qss('color: @text_muted[#a0b0c4];background: transparent;')

UPDATE_DOWNLOAD_SIZE_PILL_STYLESHEET = themed_qss(
    'QFrame#updateDownloadSizePill {  background: @surface[rgba(20, 28, 40, 0.65)];  border: 1px solid @border[#2f3e52];  border-radius: 12px;}',
)

UPDATE_DOWNLOAD_SIZE_LABEL_STYLESHEET = themed_qss(
    'color: @text[#c8d4e4];background: transparent;font-family: Menlo, Consolas, "Courier New", monospace;font-weight: 600;',
)

UPDATE_DOWNLOAD_PROGRESS_BAR_STYLESHEET = themed_qss(
    'QProgressBar {'
    '  background-color: @input[#0f1620];'
    '  border: 1px solid @border[#2a3544];'
    '  border-radius: 10px;'
    '  text-align: center;'
    '  color: @text_strong[#f0f4fa];'
    '  font-weight: 700;'
    '  font-size: 11pt;'
    '  min-height: 26px;'
    '}'
    'QProgressBar::chunk {'
    '  background: qlineargradient(x1:0, y1:0, x2:1, y2:0,'
    '      stop:0 @accent[#1f6cc8], stop:0.5 @accent[#4aa3ee], stop:1 @accent[#7fc8ff]);'
    '  border-radius: 8px;'
    '  margin: 2px;'
    '}',
)

UPDATE_DOWNLOAD_CANCEL_BUTTON_STYLESHEET = themed_qss(
    'QPushButton {'
    '  background: qlineargradient(x1:0, y1:0, x2:0, y2:1,'
    '      stop:0 @control~danger[#4a2030], stop:1 @control~danger[#2a1018]);'
    '  color: @text_strong[#f0d8dd];'
    '  border: 1px solid @danger[#7a3040];'
    '  border-radius: 8px;'
    '  padding: 7px 22px;'
    '  font-weight: 700;'
    '  font-size: 10pt;'
    '  letter-spacing: 0.5px;'
    '  min-width: 80px;'
    '}'
    'QPushButton:hover {'
    '  background: qlineargradient(x1:0, y1:0, x2:0, y2:1,'
    '      stop:0 @control~danger[#6a2838], stop:1 @control~danger[#3a1820]);'
    '  border: 1px solid @danger[#b04050];'
    '  color: @text_strong[#ffffff];'
    '}'
    'QPushButton:pressed {'
    '  background: qlineargradient(x1:0, y1:0, x2:0, y2:1,'
    '      stop:0 @control~danger[#2a1018], stop:1 @control~danger[#4a2030]);'
    '  border: 1px solid @danger[#5a2030];'
    '  color: @text_strong[#ffffff];'
    '  padding-top: 8px;'
    '  padding-bottom: 6px;'
    '}',
)

UPDATE_DOWNLOAD_SKIP_BUTTON_STYLESHEET = themed_qss(
    'QPushButton {'
    '  background: qlineargradient(x1:0, y1:0, x2:0, y2:1,'
    '      stop:0 @control[#253140], stop:1 @control[#1a222d]);'
    '  color: @text[#c0d0e0];'
    '  border: 1px solid @border[#3d4f65];'
    '  border-radius: 8px;'
    '  padding: 7px 22px;'
    '  font-weight: 700;'
    '  font-size: 10pt;'
    '  letter-spacing: 0.5px;'
    '  min-width: 80px;'
    '}'
    'QPushButton:hover {'
    '  background: qlineargradient(x1:0, y1:0, x2:0, y2:1,'
    '      stop:0 @control[#334358], stop:1 @control[#222d3c]);'
    '  border: 1px solid @border[#5a708d];'
    '  color: @text_strong[#ffffff];'
    '}'
    'QPushButton:pressed {'
    '  background: qlineargradient(x1:0, y1:0, x2:0, y2:1,'
    '      stop:0 @control[#1a222d], stop:1 @control[#253140]);'
    '  border: 1px solid @border[#2f3e52];'
    '  color: @text_strong[#ffffff];'
    '  padding-top: 8px;'
    '  padding-bottom: 6px;'
    '}',
)

UPDATE_DOWNLOAD_UPDATE_BUTTON_STYLESHEET = themed_qss(
    'QPushButton {'
    '  background: qlineargradient(x1:0, y1:0, x2:1, y2:0,'
    '      stop:0 @accent[#1f6cc8], stop:0.5 @accent[#3d8ec9], stop:1 @accent[#5fb4f5]);'
    '  color: @text_strong[#ffffff];'
    '  border: 1px solid @accent[#4aa3ee];'
    '  border-radius: 8px;'
    '  padding: 7px 24px;'
    '  font-weight: 700;'
    '  font-size: 10pt;'
    '  letter-spacing: 0.5px;'
    '  min-width: 90px;'
    '}'
    'QPushButton:hover {'
    '  background: qlineargradient(x1:0, y1:0, x2:1, y2:0,'
    '      stop:0 @accent[#2b7ee0], stop:0.5 @accent[#4aa3ee], stop:1 @accent[#7fc8ff]);'
    '  border: 1px solid @accent[#7fc8ff];'
    '  color: @text_strong[#ffffff];'
    '}'
    'QPushButton:pressed {'
    '  background: qlineargradient(x1:0, y1:0, x2:1, y2:0,'
    '      stop:0 @accent[#185299], stop:0.5 @accent[#2b7ee0], stop:1 @accent[#4aa3ee]);'
    '  border: 1px solid @accent[#3d8ec9];'
    '  color: @text_strong[#ffffff];'
    '  padding-top: 8px;'
    '  padding-bottom: 6px;'
    '}',
)

# =============================================================================
# LOOKY SYSTEM PROPRIETARY BRAND STYLES (non-editable, fixed Looky purple)
# =============================================================================

LOOKY_CARD_LABEL_STYLESHEET = themed_qss('color: @lock[#c4b5fd]; font-size: 10.5pt;')

LOOKY_CARD_VALUE_STYLESHEET = themed_qss('color: @lock[#d4c8f0]; font-size: 10.5pt;')

LOOKY_CRAWLER_HEADER_STYLESHEET = (
    'font-size: 11pt;'
    'font-weight: 700;'
    'padding: 10px 14px;'
    'color: #d8b4fe;'
    'background: qlineargradient(x1:0, y1:0, x2:1, y2:0,'
    '    stop:0 #1c0a38, stop:0.5 #2e1065, stop:1 #1c0a38);'
    'border: 1px solid #4c1d95;'
    'border-radius: 8px;'
)

LOOKY_CRAWLER_LOG_STYLESHEET = (
    'QPlainTextEdit {'
    '    background-color: #0e0a1c;'
    '    color: #c4b5fd;'
    '    border: 1px solid #2d1b6e;'
    '    border-radius: 6px;'
    '    font-family: Menlo, Consolas, "Courier New", monospace;'
    '    font-size: 10pt;'
    '    padding: 6px;'
    '    selection-background-color: #4c1d95;'
    '    selection-color: #ffffff;'
    '}'
)

LOOKY_PROGRESS_BAR_STYLESHEET = (
    'QProgressBar {'
    '    background-color: #1a1325;'
    '    border: 1px solid #3b2060;'
    '    border-radius: 7px;'
    '}'
    'QProgressBar::chunk {'
    '    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,'
    '        stop:0 #6d28d9, stop:0.5 #a855f7, stop:1 #ec4899);'
    '    border-radius: 7px;'
    '}'
)

LOOKY_STATUS_LABEL_STYLESHEET = 'font-size: 10pt; padding: 4px;'


def _looky_outline_button_stylesheet(padding: str, extra_props: str = '') -> str:
    """Build the proprietary dark-purple outline QPushButton QSS for Looky System dialogs."""
    return (
        'QPushButton {'
        '    background-color: #1e1030;'
        '    color: #c084fc;'
        '    border: 1px solid #5b21b6;'
        '    border-radius: 6px;'
        f'    padding: {padding};'
        f'    font-weight: 600;{extra_props}'
        '}'
        'QPushButton:hover {'
        '    background-color: #2d1858;'
        '    color: #e9d5ff;'
        '    border-color: #7c3aed;'
        '}'
        'QPushButton:pressed {'
        '    background-color: #4c1d95;'
        '    color: #ffffff;'
        '}'
    )


LOOKY_ACTION_BUTTON_STYLESHEET = _looky_outline_button_stylesheet('5px 16px')

LOOKY_PRIMARY_ACTION_BUTTON_STYLESHEET = (
    'QPushButton {'
    '    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,'
    '        stop:0 #6d28d9, stop:0.5 #a855f7, stop:1 #ec4899);'
    '    color: #ffffff;'
    '    border: 1px solid #7c3aed;'
    '    border-radius: 7px;'
    '    padding: 10px 22px;'
    '    font-size: 10pt;'
    '    font-weight: 700;'
    '}'
    'QPushButton:hover {'
    '    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,'
    '        stop:0 #7c3aed, stop:0.5 #c084fc, stop:1 #f472b6);'
    '    color: #ffffff;'
    '}'
    'QPushButton:pressed {'
    '    background: #4c1d95;'
    '    color: #ffffff;'
    '}'
)

LOOKY_LIST_WIDGET_STYLESHEET = (
    'QListWidget {'
    '    background-color: #0e0a1c;'
    '    color: #c4b5fd;'
    '    border: 1px solid #2d1b6e;'
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
    '    background-color: #1e1030;'
    '}'
    'QListWidget::item:selected {'
    '    background-color: #4c1d95;'
    '    color: #ffffff;'
    '}'
)

LOOKY_BODY_LABEL_STYLESHEET = themed_qss('color: @lock[#d4c8f0]; font-size: 12pt; padding: 2px;')

# =============================================================================
# LOOKY SYSTEM REFRESH REVIEW DIALOG STYLES (proprietary self-contained palette)
# =============================================================================

LOOKY_REVIEW_DIALOG_STYLESHEET = 'QDialog {    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,        stop:0 #1a0e2e, stop:1 #0f0a1c);}'

LOOKY_REVIEW_TABLE_STYLESHEET = (
    'QTreeWidget {'
    '    background-color: #0e0a1c;'
    '    color: #d4c8f0;'
    '    border: 1px solid #2d1b6e;'
    '    border-radius: 8px;'
    '    font-family: Menlo, Consolas, "Courier New", monospace;'
    '    font-size: 9pt;'
    '    padding: 4px;'
    '    outline: 0;'
    '    alternate-background-color: #140f24;'
    '}'
    'QTreeWidget::item {'
    '    padding: 5px 6px;'
    '    border-bottom: 1px solid rgba(45, 27, 110, 0.3);'
    '}'
    'QTreeWidget::item:hover {'
    '    background-color: #1e1030;'
    '}'
    'QTreeWidget::item:selected {'
    '    background-color: #4c1d95;'
    '    color: #ffffff;'
    '}'
    'QTreeWidget::item:selected:hover {'
    '    background-color: #5b21b6;'
    '    color: #ffffff;'
    '}'
    'QTreeWidget::branch {'
    '    background: transparent;'
    '    border: none;'
    '    border-image: none;'
    '    image: none;'
    '}'
    'QTreeWidget::branch:hover {'
    '    background-color: #1e1030;'
    '}'
    'QTreeWidget::branch:selected {'
    '    background-color: #4c1d95;'
    '}'
    'QTreeWidget::branch:selected:hover {'
    '    background-color: #5b21b6;'
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
    '    border: 1px solid #5b21b6;'
    '    border-radius: 4px;'
    '    background-color: #1a1325;'
    '}'
    'QTreeWidget::indicator:unchecked:hover {'
    '    border: 1px solid #a855f7;'
    '    background-color: #241a3c;'
    '}'
    'QTreeWidget::indicator:checked {'
    '    border: 1px solid #a855f7;'
    '    border-radius: 4px;'
    '    background-color: #7c3aed;'
    f'    image: url("{_CHECK_PATH}");'
    '}'
    'QTreeWidget::indicator:checked:hover {'
    '    border: 1px solid #c084fc;'
    '    background-color: #8b45f0;'
    '}'
    'QHeaderView::section {'
    '    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,'
    '        stop:0 #2e1065, stop:1 #1c0a38);'
    '    color: #d8b4fe;'
    '    border: 1px solid #4c1d95;'
    '    padding: 6px 10px;'
    '    font-weight: 700;'
    '    font-size: 8pt;'
    '}'
)

LOOKY_REVIEW_SUMMARY_STYLESHEET = (
    'QFrame {'
    '    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,'
    '        stop:0 rgba(76, 29, 149, 0.15), stop:1 rgba(30, 16, 48, 0.25));'
    '    border: 1px solid #3d2d6e;'
    '    border-radius: 10px;'
    '    padding: 10px 14px;'
    '}'
)

LOOKY_REVIEW_SELECT_BUTTON_STYLESHEET = _looky_outline_button_stylesheet('4px 14px', '    font-size: 8pt;')

LOOKY_REVIEW_MATCHES_TOGGLE_STYLESHEET = (
    'QPushButton {'
    '    background-color: #161024;'
    '    color: #9ca3af;'
    '    border: 1px dashed #4c3575;'
    '    border-radius: 6px;'
    '    padding: 4px 16px;'
    '    font-weight: 700;'
    '    font-size: 8pt;'
    '}'
    'QPushButton:hover {'
    '    background-color: #22163a;'
    '    color: #d8b4fe;'
    '    border: 1px solid #7c3aed;'
    '}'
    'QPushButton:checked {'
    '    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,'
    '        stop:0 #0284c7, stop:0.5 #6d28d9, stop:1 #a855f7);'
    '    color: #ffffff;'
    '    border: 1px solid #38bdf8;'
    '}'
    'QPushButton:checked:hover {'
    '    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,'
    '        stop:0 #0ea5e9, stop:0.5 #7c3aed, stop:1 #c084fc);'
    '    border: 1px solid #7dd3fc;'
    '    color: #ffffff;'
    '}'
)
