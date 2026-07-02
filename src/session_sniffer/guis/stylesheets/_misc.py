"""Miscellaneous QSS: Discord popups, section headers, main window, settings labels, splash screen."""

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
# SECTION TABLE HEADER STYLES
# =============================================================================

SECTION_CLEAR_BUTTON_STYLESHEET = 'font-weight: 700; font-size: 12px;'

SECTION_HEADER_SEPARATOR_STYLESHEET = 'background-color: rgba(255,255,255,0.55); max-width: 1px; min-width: 1px; margin: 6px 6px;'

# =============================================================================
# MAIN WINDOW STYLES
# =============================================================================

GTA5_STATUS_LABEL_STYLESHEET = 'QLabel { background-color: #2e3440; color: #d8dee9; padding: 6px 28px 6px 16px; font-size: 10pt; }'

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

LOOKY_INFO_LABEL_STYLESHEET = (
    'QLabel {'
    'background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #262b36, stop:1 #1f2430);'
    'border: 1px solid #3b4455;'
    'border-left: 4px solid #7c3aed;'
    'border-radius: 10px;'
    'padding: 12px 14px;'
    'color: #dbe4f0;'
    'line-height: 1.35;'
    '}'
)

LOOKY_ACCOUNT_CARD_STYLESHEET = 'QFrame {background: rgba(76, 29, 149, 0.12);border: 1px solid #3d2d6e;border-radius: 8px;padding: 4px;}'

# =============================================================================
# SPLASH SCREEN STYLES
# =============================================================================

SPLASH_SCREEN_STYLESHEET = 'background-color: #19232d;'

SPLASH_TITLE_LABEL_STYLESHEET = 'color: #e0e6ee; background: transparent;'

SPLASH_SUBTITLE_LABEL_STYLESHEET = 'color: #667788; background: transparent;'

SPLASH_SUBTITLE_READY_STYLESHEET = 'color: #44cc66; background: transparent;'

SPLASH_LOG_AREA_STYLESHEET = 'QTextEdit {  background-color: #141922;  color: #8899aa;  border: 1px solid #2a3544;  border-radius: 6px;  padding: 8px;}'

# =============================================================================
# UPDATE DOWNLOAD DIALOG STYLES
# =============================================================================

UPDATE_DOWNLOAD_DIALOG_STYLESHEET = 'QDialog {  background-color: transparent;}'

UPDATE_DOWNLOAD_FRAME_STYLESHEET = (
    'QFrame#updateDownloadFrame {  background: qlineargradient(x1:0, y1:0, x2:0, y2:1,      stop:0 #232f3e, stop:1 #18212c);  border: 1px solid #3a4a5c;  border-radius: 14px;}'
)

UPDATE_DOWNLOAD_APP_TITLE_STYLESHEET = 'color: #8aa0b8;background: transparent;letter-spacing: 3px;font-weight: 600;'

UPDATE_DOWNLOAD_TITLE_LABEL_STYLESHEET = 'color: #f0f4fa;background: transparent;letter-spacing: 0.5px;'

UPDATE_DOWNLOAD_VERSION_LABEL_STYLESHEET = 'color: #5fb4f5;background: transparent;font-weight: 600;'

UPDATE_DOWNLOAD_DIVIDER_STYLESHEET = 'background: rgba(255, 255, 255, 0.07);min-height: 1px;max-height: 1px;border: none;'

UPDATE_DOWNLOAD_VERSION_CARD_CURRENT_STYLESHEET = (
    'QFrame#updateDownloadVersionCardCurrent {  background: rgba(20, 28, 40, 0.55);  border: 1px solid #2f3e52;  border-radius: 10px;}'
)

UPDATE_DOWNLOAD_VERSION_CARD_NEW_STYLESHEET = (
    'QFrame#updateDownloadVersionCardNew {'
    '  background: qlineargradient(x1:0, y1:0, x2:0, y2:1,'
    '      stop:0 rgba(95, 180, 245, 0.18), stop:1 rgba(31, 108, 200, 0.08));'
    '  border: 1px solid #4aa3ee;'
    '  border-radius: 10px;'
    '}'
)

UPDATE_DOWNLOAD_VERSION_CARD_LABEL_MUTED_STYLESHEET = 'color: #7a8a9c;background: transparent;letter-spacing: 1.5px;font-weight: 700;'

UPDATE_DOWNLOAD_VERSION_CARD_LABEL_ACCENT_STYLESHEET = 'color: #5fb4f5;background: transparent;letter-spacing: 1.5px;font-weight: 700;'

UPDATE_DOWNLOAD_VERSION_CARD_VALUE_MUTED_STYLESHEET = 'color: #c4ced9;background: transparent;font-weight: 700;'

UPDATE_DOWNLOAD_VERSION_CARD_VALUE_ACCENT_STYLESHEET = 'color: #f0f4fa;background: transparent;font-weight: 700;'

UPDATE_DOWNLOAD_VERSION_CARD_DATE_STYLESHEET = 'color: #6f7e91;background: transparent;font-family: Consolas, "Courier New", monospace;'

UPDATE_DOWNLOAD_VERSION_ARROW_STYLESHEET = 'color: #4aa3ee;background: transparent;font-weight: 800;'

UPDATE_DOWNLOAD_STATUS_LABEL_STYLESHEET = 'color: #a0b0c4;background: transparent;'

UPDATE_DOWNLOAD_SIZE_PILL_STYLESHEET = 'QFrame#updateDownloadSizePill {  background: rgba(20, 28, 40, 0.65);  border: 1px solid #2f3e52;  border-radius: 12px;}'

UPDATE_DOWNLOAD_SIZE_LABEL_STYLESHEET = 'color: #c8d4e4;background: transparent;font-family: Consolas, "Courier New", monospace;font-weight: 600;'

UPDATE_DOWNLOAD_PROGRESS_BAR_STYLESHEET = (
    'QProgressBar {'
    '  background-color: #0f1620;'
    '  border: 1px solid #2a3544;'
    '  border-radius: 10px;'
    '  text-align: center;'
    '  color: #f0f4fa;'
    '  font-weight: 700;'
    '  font-size: 11pt;'
    '  min-height: 26px;'
    '}'
    'QProgressBar::chunk {'
    '  background: qlineargradient(x1:0, y1:0, x2:1, y2:0,'
    '      stop:0 #1f6cc8, stop:0.5 #4aa3ee, stop:1 #7fc8ff);'
    '  border-radius: 8px;'
    '  margin: 2px;'
    '}'
)

UPDATE_DOWNLOAD_CANCEL_BUTTON_STYLESHEET = (
    'QPushButton {'
    '  background: qlineargradient(x1:0, y1:0, x2:0, y2:1,'
    '      stop:0 #4a2030, stop:1 #2a1018);'
    '  color: #f0d8dd;'
    '  border: 1px solid #7a3040;'
    '  border-radius: 8px;'
    '  padding: 7px 22px;'
    '  font-weight: 700;'
    '  font-size: 10pt;'
    '  letter-spacing: 0.5px;'
    '  min-width: 80px;'
    '}'
    'QPushButton:hover {'
    '  background: qlineargradient(x1:0, y1:0, x2:0, y2:1,'
    '      stop:0 #6a2838, stop:1 #3a1820);'
    '  border: 1px solid #b04050;'
    '  color: #ffffff;'
    '}'
    'QPushButton:pressed {'
    '  background: qlineargradient(x1:0, y1:0, x2:0, y2:1,'
    '      stop:0 #2a1018, stop:1 #4a2030);'
    '  border: 1px solid #5a2030;'
    '  padding-top: 8px;'
    '  padding-bottom: 6px;'
    '}'
)

# =============================================================================
# LOOKY SYSTEM ACCOUNT CARD STYLES
# =============================================================================

LOOKY_CARD_LABEL_STYLESHEET = 'color: #9ca3af; font-size: 10pt;'

LOOKY_CARD_VALUE_STYLESHEET = 'color: #d4c8f0; font-size: 10pt;'

# =============================================================================
# LOOKY SYSTEM CRAWLER DIALOG STYLES
# =============================================================================

LOOKY_CRAWLER_HEADER_STYLESHEET = (
    'font-size: 15px;'
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
    '    font-family: Consolas, "Courier New", monospace;'
    '    font-size: 14px;'
    '    padding: 6px;'
    '    selection-background-color: #4c1d95;'
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

LOOKY_STATUS_LABEL_STYLESHEET = 'font-size: 13px; padding: 4px;'

LOOKY_ACTION_BUTTON_STYLESHEET = (
    'QPushButton {'
    '    background-color: #1e1030;'
    '    color: #c084fc;'
    '    border: 1px solid #5b21b6;'
    '    border-radius: 6px;'
    '    padding: 5px 16px;'
    '    font-weight: 600;'
    '}'
    'QPushButton:hover {'
    '    background-color: #2d1858;'
    '    border-color: #7c3aed;'
    '}'
    'QPushButton:pressed {'
    '    background-color: #4c1d95;'
    '}'
)

LOOKY_PRIMARY_ACTION_BUTTON_STYLESHEET = (
    'QPushButton {'
    '    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,'
    '        stop:0 #6d28d9, stop:0.5 #a855f7, stop:1 #ec4899);'
    '    color: #ffffff;'
    '    border: 1px solid #7c3aed;'
    '    border-radius: 7px;'
    '    padding: 10px 22px;'
    '    font-size: 13px;'
    '    font-weight: 700;'
    '}'
    'QPushButton:hover {'
    '    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,'
    '        stop:0 #7c3aed, stop:0.5 #c084fc, stop:1 #f472b6);'
    '}'
    'QPushButton:pressed {'
    '    background: #4c1d95;'
    '}'
)

LOOKY_LIST_WIDGET_STYLESHEET = (
    'QListWidget {'
    '    background-color: #0e0a1c;'
    '    color: #c4b5fd;'
    '    border: 1px solid #2d1b6e;'
    '    border-radius: 6px;'
    '    padding: 4px;'
    '    font-family: Consolas, "Courier New", monospace;'
    '    font-size: 12px;'
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

LOOKY_BODY_LABEL_STYLESHEET = 'color: #d4c8f0; font-size: 12pt; padding: 2px;'

# =============================================================================
# LOOKY SYSTEM REFRESH REVIEW DIALOG STYLES
# =============================================================================

LOOKY_REVIEW_DIALOG_STYLESHEET = (
    'QDialog {'
    '    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,'
    '        stop:0 #1a0e2e, stop:1 #0f0a1c);'
    '}'
)

LOOKY_REVIEW_TABLE_STYLESHEET = (
    'QTreeWidget {'
    '    background-color: #0e0a1c;'
    '    color: #d4c8f0;'
    '    border: 1px solid #2d1b6e;'
    '    border-radius: 8px;'
    '    font-family: Consolas, "Courier New", monospace;'
    '    font-size: 12px;'
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
    '    image: none;'
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
    '    font-size: 11px;'
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

LOOKY_REVIEW_SELECT_BUTTON_STYLESHEET = (
    'QPushButton {'
    '    background-color: #1e1030;'
    '    color: #c084fc;'
    '    border: 1px solid #5b21b6;'
    '    border-radius: 6px;'
    '    padding: 4px 14px;'
    '    font-weight: 600;'
    '    font-size: 11px;'
    '}'
    'QPushButton:hover {'
    '    background-color: #2d1858;'
    '    border-color: #7c3aed;'
    '}'
    'QPushButton:pressed {'
    '    background-color: #4c1d95;'
    '}'
)
