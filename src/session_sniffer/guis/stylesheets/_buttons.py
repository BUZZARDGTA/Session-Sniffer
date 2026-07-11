"""Dialog and compact button QSS."""

# =============================================================================
# DIALOG BUTTON STYLES
# =============================================================================

DIALOG_BUTTON_STYLESHEET = """
QPushButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 rgba(236, 240, 241, 0.12), stop:1 rgba(189, 195, 199, 0.18));
    color: #ecf0f1;
    border: 1px solid rgba(52, 73, 94, 0.6);
    border-radius: 6px;
    padding: 6px 18px;
    font-size: 12px;
    font-weight: bold;
    min-height: 28px;
}

QPushButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 rgba(52, 152, 219, 0.25), stop:1 rgba(41, 128, 185, 0.35));
    border: 1px solid rgba(52, 152, 219, 0.8);
    color: #ffffff;
}

QPushButton:pressed {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 rgba(41, 128, 185, 0.45), stop:1 rgba(52, 152, 219, 0.55));
    border: 1px solid rgba(41, 128, 185, 1.0);
}

QPushButton:disabled {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 rgba(80, 80, 80, 0.15), stop:1 rgba(60, 60, 60, 0.20));
    color: #666672;
    border: 1px solid rgba(80, 80, 80, 0.3);
}
""".strip()

DIALOG_PRIMARY_BUTTON_STYLESHEET = """
QPushButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #3d8ec9, stop:1 #2a6fa0);
    color: #ffffff;
    border: 1px solid rgba(52, 152, 219, 0.7);
    border-radius: 6px;
    padding: 6px 24px;
    font-size: 12px;
    font-weight: bold;
    min-height: 28px;
}

QPushButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #4da3de, stop:1 #3d8ec9);
    border: 1px solid rgba(77, 163, 222, 0.9);
}

QPushButton:pressed {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #2a6fa0, stop:1 #1e5a85);
    border: 1px solid rgba(42, 111, 160, 1.0);
}

QPushButton:disabled {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 rgba(80, 80, 80, 0.15), stop:1 rgba(60, 60, 60, 0.20));
    color: #666672;
    border: 1px solid rgba(80, 80, 80, 0.3);
}
""".strip()

DIALOG_DANGER_BUTTON_STYLESHEET = """
QPushButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 rgba(192, 57, 43, 0.7), stop:1 rgba(146, 43, 33, 0.8));
    color: #ffffff;
    border: 1px solid rgba(192, 57, 43, 0.6);
    border-radius: 6px;
    padding: 6px 18px;
    font-size: 12px;
    font-weight: bold;
    min-height: 28px;
}

QPushButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 rgba(231, 76, 60, 0.8), stop:1 rgba(192, 57, 43, 0.9));
    border: 1px solid rgba(231, 76, 60, 0.9);
}

QPushButton:pressed {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 rgba(146, 43, 33, 0.9), stop:1 rgba(120, 35, 27, 1.0));
    border: 1px solid rgba(146, 43, 33, 1.0);
}

QPushButton:disabled {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 rgba(80, 80, 80, 0.15), stop:1 rgba(60, 60, 60, 0.20));
    color: #666672;
    border: 1px solid rgba(80, 80, 80, 0.3);
}
""".strip()

# =============================================================================
# COMPACT BUTTON STYLE (shared across settings widgets)
# =============================================================================

COMPACT_BUTTON_STYLESHEET = (
    'QPushButton { background-color: #1a1e24; color: #a5b4c4; border: 1px solid #2d3640;'
    ' border-radius: 6px; padding: 6px 16px; font-size: 11px; font-weight: bold; }'
    ' QPushButton:hover { background-color: #212830; color: #ffffff; border: 1px solid #4a5968; }'
    ' QPushButton:pressed { background-color: #14181d; color: #ffffff; border: 1px solid #3d8ec9; }'
    ' QPushButton:disabled { background-color: #111317; color: #40464f; border: 1px solid #1a1e24; }'
)

COMPACT_DANGER_BUTTON_STYLESHEET = (
    'QPushButton { background-color: #2a1618; color: #d67a83; border: 1px solid #422528;'
    ' border-radius: 6px; padding: 6px 16px; font-size: 11px; font-weight: bold; }'
    ' QPushButton:hover { background-color: #3b1f22; color: #ffffff; border: 1px solid #5c3237; }'
    ' QPushButton:pressed { background-color: #1c0e10; color: #ffffff; border: 1px solid #e74c3c; }'
    ' QPushButton:disabled { background-color: #161111; color: #4d3839; border: 1px solid #21191a; }'
)
