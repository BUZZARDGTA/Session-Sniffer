"""Dialog and compact button QSS."""

from session_sniffer.guis.theming import themed_qss

# =============================================================================
# DIALOG BUTTON STYLES
# =============================================================================

DIALOG_BUTTON_STYLESHEET = themed_qss(
    """
QPushButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 @control[rgba(236, 240, 241, 0.12)], stop:1 @control[rgba(189, 195, 199, 0.18)]);
    color: @text_strong[#ecf0f1];
    border: 1px solid @border[rgba(52, 73, 94, 0.6)];
    border-radius: 6px;
    padding: 6px 12px;
    font-size: 9pt;
    font-weight: bold;
    min-height: 28px;
}

QPushButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 @accent[rgba(52, 152, 219, 0.25)], stop:1 @accent[rgba(41, 128, 185, 0.35)]);
    border: 1px solid @accent[rgba(52, 152, 219, 0.8)];
    color: @text_strong[#ffffff];
}

QPushButton:pressed {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 @accent[rgba(41, 128, 185, 0.45)], stop:1 @accent[rgba(52, 152, 219, 0.55)]);
    border: 1px solid @accent[rgba(41, 128, 185, 1.0)];
    color: @text_strong[#ffffff];
}

QPushButton:disabled {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 @control[rgba(80, 80, 80, 0.15)], stop:1 @control[rgba(60, 60, 60, 0.20)]);
    color: @text_muted[#666672];
    border: 1px solid @border[rgba(80, 80, 80, 0.3)];
}
""".strip(),
)

DIALOG_PRIMARY_BUTTON_STYLESHEET = themed_qss(
    """
QPushButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 @accent[#3d8ec9], stop:1 @accent[#2a6fa0]);
    color: @text_strong[#ffffff];
    border: 1px solid @accent[rgba(52, 152, 219, 0.7)];
    border-radius: 6px;
    padding: 6px 12px;
    font-size: 9pt;
    font-weight: bold;
    min-height: 28px;
}

QPushButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 @accent[#4da3de], stop:1 @accent[#3d8ec9]);
    border: 1px solid @accent[rgba(77, 163, 222, 0.9)];
    color: @text_strong[#ffffff];
}

QPushButton:pressed {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 @accent[#2a6fa0], stop:1 @accent[#1e5a85]);
    border: 1px solid @accent[rgba(42, 111, 160, 1.0)];
    color: @text_strong[#ffffff];
}

QPushButton:disabled {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 @control[rgba(80, 80, 80, 0.15)], stop:1 @control[rgba(60, 60, 60, 0.20)]);
    color: @text_muted[#666672];
    border: 1px solid @border[rgba(80, 80, 80, 0.3)];
}
""".strip(),
)

DIALOG_DANGER_BUTTON_STYLESHEET = themed_qss(
    """
QPushButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 @danger[rgba(192, 57, 43, 0.7)], stop:1 @danger[rgba(146, 43, 33, 0.8)]);
    color: @text_strong[#ffffff];
    border: 1px solid @danger[rgba(192, 57, 43, 0.6)];
    border-radius: 6px;
    padding: 6px 12px;
    font-size: 9pt;
    font-weight: bold;
    min-height: 28px;
}

QPushButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 @danger[rgba(231, 76, 60, 0.8)], stop:1 @danger[rgba(192, 57, 43, 0.9)]);
    border: 1px solid @danger[rgba(231, 76, 60, 0.9)];
    color: @text_strong[#ffffff];
}

QPushButton:pressed {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 @danger[rgba(146, 43, 33, 0.9)], stop:1 @danger[rgba(120, 35, 27, 1.0)]);
    border: 1px solid @danger[rgba(146, 43, 33, 1.0)];
    color: @text_strong[#ffffff];
}

QPushButton:disabled {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 @control[rgba(80, 80, 80, 0.15)], stop:1 @control[rgba(60, 60, 60, 0.20)]);
    color: @text_muted[#666672];
    border: 1px solid @border[rgba(80, 80, 80, 0.3)];
}
""".strip(),
)

# =============================================================================
# COMPACT BUTTON STYLE (shared across settings and manager widgets)
# =============================================================================

COMPACT_BUTTON_STYLESHEET = themed_qss(
    'QPushButton { background-color: @control[#1a1e24]; color: @text[#a5b4c4]; border: 1px solid @border[#2d3640];'
    ' border-radius: 6px; padding: 6px 16px; font-size: 8pt; font-weight: bold; }'
    ' QPushButton:hover { background-color: @control[#212830]; color: @text_strong[#ffffff]; border: 1px solid @border[#4a5968]; }'
    ' QPushButton:pressed { background-color: @control[#14181d]; color: @text_strong[#ffffff]; border: 1px solid @accent[#3d8ec9]; }'
    ' QPushButton:disabled { background-color: @control[#111317]; color: @text_muted[#40464f]; border: 1px solid @border[#1a1e24]; }',
)

COMPACT_DANGER_BUTTON_STYLESHEET = themed_qss(
    'QPushButton { background-color: @control~danger[#2a1618]; color: @danger[#d67a83]; border: 1px solid @border~danger[#422528];'
    ' border-radius: 6px; padding: 6px 16px; font-size: 8pt; font-weight: bold; }'
    ' QPushButton:hover { background-color: @control~danger[#3b1f22]; color: @text_strong[#ffffff]; border: 1px solid @danger[#5c3237]; }'
    ' QPushButton:pressed { background-color: @control~danger[#1c0e10]; color: @text_strong[#ffffff]; border: 1px solid @danger[#e74c3c]; }'
    ' QPushButton:disabled { background-color: @control[#161111]; color: @text_muted[#4d3839]; border: 1px solid @border[#21191a]; }',
)

# =============================================================================
# GRAPH POPOUT BUTTON STYLES
# =============================================================================

GRAPH_BPS_POPOUT_BUTTON_STYLESHEET = themed_qss(
    """
QPushButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 @accent[rgba(0, 188, 212, 0.15)],
        stop:1 @accent[rgba(0, 151, 167, 0.25)]);
    color: @accent[#80deea];
    border: 1px solid @accent[rgba(0, 188, 212, 0.45)];
    border-radius: 6px;
    padding: 2px 10px;
    font-size: 8pt;
    font-weight: 600;
}
QPushButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 @accent[rgba(0, 229, 255, 0.35)],
        stop:1 @accent[rgba(0, 188, 212, 0.50)]);
    border: 1px solid @accent[#00e5ff];
    color: @text_strong[#ffffff];
}
QPushButton:pressed {
    background: @accent[rgba(0, 151, 167, 0.65)];
    border: 1px solid @accent[#0097a7];
    color: @text_strong[#ffffff];
}
""".strip(),
)

GRAPH_PPS_POPOUT_BUTTON_STYLESHEET = themed_qss(
    """
QPushButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 @success[rgba(76, 175, 80, 0.15)],
        stop:1 @success[rgba(56, 142, 60, 0.25)]);
    color: @success[#a5d6a7];
    border: 1px solid @success[rgba(76, 175, 80, 0.45)];
    border-radius: 6px;
    padding: 2px 10px;
    font-size: 8pt;
    font-weight: 600;
}
QPushButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 @success[rgba(105, 240, 174, 0.35)],
        stop:1 @success[rgba(76, 175, 80, 0.50)]);
    border: 1px solid @success[#69f0ae];
    color: @text_strong[#ffffff];
}
QPushButton:pressed {
    background: @success[rgba(56, 142, 60, 0.65)];
    border: 1px solid @success[#388e3c];
    color: @text_strong[#ffffff];
}
""".strip(),
)

GRAPH_LATENCY_POPOUT_BUTTON_STYLESHEET = themed_qss(
    """
QPushButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 @warning[rgba(255, 152, 0, 0.15)],
        stop:1 @warning[rgba(230, 81, 0, 0.25)]);
    color: @warning[#ffcc80];
    border: 1px solid @warning[rgba(255, 152, 0, 0.45)];
    border-radius: 6px;
    padding: 2px 10px;
    font-size: 8pt;
    font-weight: 600;
}
QPushButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 @warning[rgba(255, 171, 64, 0.35)],
        stop:1 @warning[rgba(255, 152, 0, 0.50)]);
    border: 1px solid @warning[#ffab40];
    color: @text_strong[#ffffff];
}
QPushButton:pressed {
    background: @warning[rgba(230, 81, 0, 0.65)];
    border: 1px solid @warning[#e65100];
    color: @text_strong[#ffffff];
}
""".strip(),
)
