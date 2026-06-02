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

LOOKY_ACCOUNT_CARD_STYLESHEET = (
    'QFrame {'
    'background: rgba(76, 29, 149, 0.12);'
    'border: 1px solid #3d2d6e;'
    'border-radius: 8px;'
    'padding: 4px;'
    '}'
)

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
    '    font-size: 12px;'
    '    padding: 4px;'
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
