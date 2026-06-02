"""GTA5 suspend button and Looky System crawler progress dialog QSS."""

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

# =============================================================================
# CRAWLER PROGRESS DIALOG STYLES
# =============================================================================

CRAWLER_TARGET_INFO_LABEL_STYLESHEET = (
    'background-color: #1e1b2e;'
    'color: #c4b5fd;'
    'border: 1px solid #7c3aed;'
    'border-radius: 4px;'
    'padding: 6px 8px;'
)
