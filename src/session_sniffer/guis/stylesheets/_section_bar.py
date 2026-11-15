"""Section header bar and expand-button QSS."""

from session_sniffer.guis.theming import themed_qss

# =============================================================================
# SECTION HEADER BAR STYLES
# =============================================================================


def section_bar_qss(role_token: str) -> str:
    """Return the QSS for a session table section header bar bound to `@table_header` and `@<role_token>`."""
    return themed_qss(
        f"""
    QFrame#sectionBar {{
        background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                    stop:0 @table_header~{role_token}/16,
                                    stop:1 @table_header~{role_token}/8);
        border: 1px solid @border~{role_token}/40;
        border-top: 2px solid @{role_token};
        border-bottom: 1px solid @border~{role_token}/40;
        border-top-left-radius: 8px;
        border-top-right-radius: 8px;
    }}
    QLabel {{
        color: @text_muted;
        background: transparent;
        font-size: 8.5pt;
    }}
    QLabel#sectionTitle {{
        font-size: 11pt;
        font-weight: 600;
        color: @text_strong;
        letter-spacing: 0.2px;
    }}
    QPushButton {{
        min-height: 26px;
        max-height: 26px;
        padding: 0 12px;
        color: @text_strong;
        background: @control;
        border: 1px solid @border;
        border-radius: 6px;
        font-weight: 700;
        font-size: 8.5pt;
    }}
    QPushButton:hover {{
        background: @control:hover;
        border-color: @accent;
        color: @text_strong;
    }}
    QPushButton:disabled {{
        background: @control:disabled;
        border-color: @border:disabled;
        color: @text_muted:disabled;
    }}
    QPushButton:pressed {{
        background: @control:pressed;
        color: @text_strong;
    }}
    QPushButton#sectionClearButton:hover {{
        background: @control~danger/26;
        border-color: @danger;
        color: @text_strong;
    }}
    QPushButton#sectionMergeButton:hover {{
        background: @control~accent/26;
        border-color: @accent;
        color: @text_strong;
    }}
    QToolButton#sectionCollapseButton {{
        min-width: 26px;
        max-width: 26px;
        min-height: 26px;
        max-height: 26px;
        padding: 0;
        color: @text_strong;
        background: @control;
        border: 1px solid @border;
        border-radius: 6px;
    }}
    QToolButton#sectionCollapseButton:hover {{
        background: @control:hover;
        border-color: @accent;
        color: @text_strong;
    }}
    QToolButton#sectionCollapseButton:pressed {{
        background: @control:pressed;
        color: @text_strong;
    }}
    QComboBox {{
        min-height: 26px;
        max-height: 26px;
        padding: 0 20px 0 8px;
        color: @text;
        background: @input;
        border: 1px solid @border;
        border-radius: 6px;
        min-width: 55px;
        font-size: 8.5pt;
    }}
    QComboBox:hover {{
        background: @input:hover;
        border-color: @border:hover;
    }}
    QComboBox:focus, QComboBox:on {{
        border-color: @{role_token};
    }}
    QComboBox:disabled {{
        color: @text_muted:disabled;
        background: @input:disabled;
        border-color: @border:disabled;
    }}
    QComboBox::drop-down {{
        subcontrol-origin: padding;
        subcontrol-position: top right;
        width: 18px;
        border: none;
        border-left: 1px solid @border;
    }}
    QSpinBox {{
        min-height: 26px;
        max-height: 26px;
        padding: 0 18px 0 6px;
        color: @text;
        background: @input;
        border: 1px solid @border;
        border-radius: 6px;
        font-size: 8.5pt;
    }}
    QSpinBox#sectionRowsSpinBox {{
        min-width: 55px;
        max-width: 72px;
    }}
    QSpinBox#sectionPageSpinBox {{
        min-width: 42px;
        max-width: 52px;
    }}
    QSpinBox:hover {{
        background: @input:hover;
        border-color: @border:hover;
    }}
    QSpinBox:focus {{
        border-color: @{role_token};
    }}
    QSpinBox::up-button {{
        subcontrol-origin: border;
        subcontrol-position: top right;
        width: 16px;
        border: none;
        border-left: 1px solid @border;
        border-bottom: 1px solid @border;
    }}
    QSpinBox::down-button {{
        subcontrol-origin: border;
        subcontrol-position: bottom right;
        width: 16px;
        border: none;
        border-left: 1px solid @border;
    }}
    QSpinBox::up-button:hover, QSpinBox::down-button:hover {{
        background: @control/35;
    }}
    QSpinBox::up-arrow {{
        right: 1px;
        top: 1px;
    }}
    QSpinBox::down-arrow {{
        right: 1px;
        bottom: 1px;
    }}
    QLineEdit {{
        min-height: 26px;
        max-height: 26px;
        padding: 0 30px 0 8px;
        color: @text;
        background: @input;
        border: 1px solid @border;
        border-radius: 6px;
        font-size: 8.5pt;
    }}
    QLineEdit:hover {{
        background: @input:hover;
        border-color: @border:hover;
    }}
    QLineEdit:focus {{
        border-color: @{role_token};
    }}
    QLineEdit QToolButton {{
        min-height: 0;
        padding: 0 2px;
        border: none;
        background: transparent;
    }}
    QComboBox QAbstractItemView {{
        background-color: @popup;
        color: @text;
        border: 1px solid @border;
        border-radius: 6px;
        padding: 2px;
        selection-background-color: @selection;
        selection-color: @text_strong;
        outline: 0;
    }}
    QComboBox QAbstractItemView::item {{
        min-height: 20px;
        padding: 2px 6px;
        border-radius: 4px;
        border: none;
        color: @text;
    }}
    QComboBox QAbstractItemView::item:selected, QComboBox QAbstractItemView::item:hover {{
        background-color: @selection;
        color: @text_strong;
    }}
    QComboBox QAbstractItemView::item:disabled {{
        color: @text_muted:disabled;
        background: transparent;
    }}
    """.strip(),
    )


def get_expand_button_stylesheet(role_token: str) -> str:
    """Generate a stylesheet for a collapsed section expand button bound to `@control` and `@<role_token>`."""
    return themed_qss(
        f"""
QPushButton {{
    background-color: @control~{role_token}/16;
    color: @{role_token};
    border: 1px solid @{role_token}/45;
    border-radius: 6px;
    padding: 6px 16px;
    font-size: 8.5pt;
    font-weight: 600;
    margin: 5px;
}}

QPushButton:hover {{
    background-color: @control~{role_token}/28;
    border-color: @{role_token}/70;
    color: @text_strong;
}}

QPushButton:pressed {{
    background-color: @control~{role_token}/20:pressed;
    color: @text_strong;
}}
""".strip(),
    )


CONNECTED_EXPAND_BUTTON_STYLESHEET = get_expand_button_stylesheet('success')

DISCONNECTED_EXPAND_BUTTON_STYLESHEET = get_expand_button_stylesheet('danger')
