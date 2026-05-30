"""Combo rule editor, detections manager, and country selector QSS."""

# =============================================================================
# COMBO RULE / DETECTIONS MANAGER STYLES
# =============================================================================

GROUPBOX_STYLE = """
    QGroupBox {
        font-size: 12pt;
        font-weight: bold;
        border: 2px solid #4A90E2;
        border-radius: 8px;
        margin-top: 12px;
        padding-top: 15px;
        background: rgba(74, 144, 226, 0.05);
    }
    QGroupBox::title {
        subcontrol-origin: margin;
        subcontrol-position: top left;
        left: 15px;
        padding: 0 5px;
        color: #4A90E2;
    }
"""

LIST_WIDGET_STYLE = """
    QListWidget {
        background: #2d2d2d;
        border: 2px solid #4A90E2;
        border-radius: 4px;
        padding: 5px;
        font-family: 'Consolas', 'Courier New', monospace;
    }
    QListWidget::item {
        padding: 5px;
        border-radius: 3px;
    }
    QListWidget::item:selected {
        background: #4A90E2;
        color: white;
    }
"""

SECTION_SEPARATOR_LABEL_STYLESHEET = 'color: #666; font-size: 9pt; padding: 5px 0;'

DESC_LABEL_STYLESHEET = 'color: #a0a0a0; font-style: italic; font-size: 10pt; padding: 5px;'

HINT_LABEL_STYLESHEET = 'color: #a0a0a0; font-style: italic; padding-bottom: 4px;'

BOLD_LABEL_STYLESHEET = 'font-weight: bold;'

RELAY_FILTER_WARNING_STYLESHEET = (
    'QWidget { background-color: #3a2400; border: 1px solid #c87800; border-radius: 6px; padding: 2px; }'
    'QLabel { border: none; }'
    'QPushButton { border: 1px solid #c87800; border-radius: 4px; background-color: #5a3a00;'
    ' color: #ffcc66; padding: 4px 10px; font-weight: bold; }'
    'QPushButton:hover { background-color: #7a5200; }'
)

WARNING_ICON_LABEL_STYLESHEET = 'font-size: 18pt; border: none;'

WARNING_TEXT_LABEL_STYLESHEET = 'color: #ffcc66; border: none;'

DETECTIONS_MANAGER_HEADER_STYLESHEET = (
    'font-size: 16pt; font-weight: bold; color: #4A90E2; padding: 10px;'
    'background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #1e1e2e, stop:1 #2d2d4e);'
    'border-radius: 6px;'
)

# =============================================================================
# COUNTRY SELECTOR COMBO STYLES
# =============================================================================

COUNTRY_SELECTOR_COMBO_STYLESHEET = """
    QComboBox {
        font-size: 11pt;
        padding: 6px 10px;
        min-height: 28px;
    }
    QComboBox QAbstractItemView {
        font-size: 10pt;
    }
"""
