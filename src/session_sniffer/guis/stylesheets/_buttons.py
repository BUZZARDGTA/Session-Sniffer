"""Dialog and compact button QSS."""

from session_sniffer.guis.theming import themed_qss

# =============================================================================
# DIALOG BUTTON STYLES
# =============================================================================

DIALOG_BUTTON_STYLESHEET = themed_qss(
    """
QPushButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 @control:hover, stop:1 @control);
    color: @text_strong;
    border: 1px solid @border;
    border-radius: 6px;
    padding: 6px 12px;
    font-size: 9pt;
    font-weight: bold;
    min-height: 28px;
}

QPushButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 @control~accent/28, stop:1 @control~accent/18);
    border: 1px solid @accent;
    color: @text_strong;
}

QPushButton:pressed {
    background: @control:pressed;
    border: 1px solid @accent;
    color: @text_strong;
}

QPushButton:disabled {
    background: @control:disabled;
    color: @text_muted:disabled;
    border: 1px solid @border:disabled;
}
""".strip(),
)

DIALOG_PRIMARY_BUTTON_STYLESHEET = themed_qss(
    """
QPushButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 @accent:hover, stop:1 @accent);
    color: @text_strong;
    border: 1px solid @accent;
    border-radius: 6px;
    padding: 6px 12px;
    font-size: 9pt;
    font-weight: bold;
    min-height: 28px;
}

QPushButton:hover {
    background: @accent:hover;
    border: 1px solid @accent:hover;
    color: @text_strong;
}

QPushButton:pressed {
    background: @accent:pressed;
    border: 1px solid @accent:pressed;
    color: @text_strong;
}

QPushButton:disabled {
    background: @control:disabled;
    color: @text_muted:disabled;
    border: 1px solid @border:disabled;
}
""".strip(),
)

DIALOG_DANGER_BUTTON_STYLESHEET = themed_qss(
    """
QPushButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 @danger, stop:1 @danger:pressed);
    color: @text_strong;
    border: 1px solid @danger;
    border-radius: 6px;
    padding: 6px 12px;
    font-size: 9pt;
    font-weight: bold;
    min-height: 28px;
}

QPushButton:hover {
    background: @danger:hover;
    border: 1px solid @danger:hover;
    color: @text_strong;
}

QPushButton:pressed {
    background: @danger:pressed;
    border: 1px solid @danger:pressed;
    color: @text_strong;
}

QPushButton:disabled {
    background: @control:disabled;
    color: @text_muted:disabled;
    border: 1px solid @border:disabled;
}
""".strip(),
)

# =============================================================================
# COMPACT BUTTON STYLE (shared across settings and manager widgets)
# =============================================================================

COMPACT_BUTTON_STYLESHEET = themed_qss(
    'QPushButton { background-color: @control; color: @text_strong; border: 1px solid @border;'
    ' border-radius: 6px; padding: 6px 16px; font-size: 8pt; font-weight: bold; }'
    ' QPushButton:hover { background-color: @control:hover; color: @text_strong; border: 1px solid @accent; }'
    ' QPushButton:pressed { background-color: @control:pressed; color: @text_strong; border: 1px solid @accent; }'
    ' QPushButton:disabled { background-color: @control:disabled; color: @text_muted:disabled; border: 1px solid @border:disabled; }',
)

COMPACT_DANGER_BUTTON_STYLESHEET = themed_qss(
    'QPushButton { background-color: @control~danger/22; color: @danger; border: 1px solid @danger/55;'
    ' border-radius: 6px; padding: 6px 16px; font-size: 8pt; font-weight: bold; }'
    ' QPushButton:hover { background-color: @control~danger/38; color: @text_strong; border: 1px solid @danger; }'
    ' QPushButton:pressed { background-color: @control~danger/26:pressed; color: @text_strong; border: 1px solid @danger; }'
    ' QPushButton:disabled { background-color: @control:disabled; color: @text_muted:disabled; border: 1px solid @border:disabled; }',
)

# =============================================================================
# GRAPH POPOUT BUTTON STYLES
# =============================================================================

GRAPH_BPS_POPOUT_BUTTON_STYLESHEET = themed_qss(
    """
QPushButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 @control~accent/18,
        stop:1 @control~accent/28);
    color: @accent;
    border: 1px solid @accent/50;
    border-radius: 6px;
    padding: 2px 10px;
    font-size: 8pt;
    font-weight: 600;
}
QPushButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 @control~accent/35,
        stop:1 @control~accent/48);
    border: 1px solid @accent;
    color: @text_strong;
}
QPushButton:pressed {
    background: @control~accent/55:pressed;
    border: 1px solid @accent;
    color: @text_strong;
}
""".strip(),
)

GRAPH_PPS_POPOUT_BUTTON_STYLESHEET = themed_qss(
    """
QPushButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 @control~success/18,
        stop:1 @control~success/28);
    color: @success;
    border: 1px solid @success/50;
    border-radius: 6px;
    padding: 2px 10px;
    font-size: 8pt;
    font-weight: 600;
}
QPushButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 @control~success/35,
        stop:1 @control~success/48);
    border: 1px solid @success;
    color: @text_strong;
}
QPushButton:pressed {
    background: @control~success/55:pressed;
    border: 1px solid @success;
    color: @text_strong;
}
""".strip(),
)

GRAPH_LATENCY_POPOUT_BUTTON_STYLESHEET = themed_qss(
    """
QPushButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 @control~warning/18,
        stop:1 @control~warning/28);
    color: @warning;
    border: 1px solid @warning/50;
    border-radius: 6px;
    padding: 2px 10px;
    font-size: 8pt;
    font-weight: 600;
}
QPushButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 @control~warning/35,
        stop:1 @control~warning/48);
    border: 1px solid @warning;
    color: @text_strong;
}
QPushButton:pressed {
    background: @control~warning/55:pressed;
    border: 1px solid @warning;
    color: @text_strong;
}
""".strip(),
)
