"""Combo rule editor, detections manager, and country selector QSS."""

# =============================================================================
# COMBO RULE / DETECTIONS MANAGER STYLES
# =============================================================================

GROUPBOX_STYLE = """
    QGroupBox {
        font-size: 12pt;
        font-weight: bold;
        border: 1px solid #2a3f4a;
        border-radius: 8px;
        margin-top: 12px;
        padding-top: 15px;
        background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
            stop:0 #1a2530, stop:1 #161e26);
    }
    QGroupBox::title {
        subcontrol-origin: margin;
        subcontrol-position: top left;
        left: 15px;
        padding: 0 8px;
        color: #88c0d0;
        background-color: #1a2530;
        border-radius: 3px;
    }

    /* Make inner container widgets transparent so the group box gradient shows through */
    QGroupBox QWidget {
        background-color: transparent;
    }

    /* Re-specify backgrounds for form controls that need them */
    QGroupBox QComboBox,
    QGroupBox QSpinBox,
    QGroupBox QDoubleSpinBox,
    QGroupBox QLineEdit,
    QGroupBox QTextEdit,
    QGroupBox QPlainTextEdit {
        background-color: #1E1E1E;
        border: 1px solid #3E3E42;
        border-radius: 4px;
        color: #E0E0E0;
        padding: 4px 8px;
    }
    QGroupBox QComboBox:focus,
    QGroupBox QSpinBox:focus,
    QGroupBox QDoubleSpinBox:focus,
    QGroupBox QLineEdit:focus {
        border: 1px solid #007ACC;
    }
    QGroupBox QCheckBox::indicator {
        width: 14px;
        height: 14px;
        background-color: #1E1E1E;
        border: 1px solid #3E3E42;
        border-radius: 3px;
    }
    QGroupBox QCheckBox::indicator:hover {
        border-color: #007ACC;
    }
    QGroupBox QCheckBox::indicator:checked {
        background-color: #007ACC;
        border-color: #007ACC;
    }
"""

LIST_WIDGET_STYLE = """
    QListWidget {
        background: #1a1f26;
        border: 1px solid #2a3f4a;
        border-radius: 4px;
        padding: 5px;
        font-family: 'Consolas', 'Courier New', monospace;
    }
    QListWidget::item {
        padding: 5px;
        border-radius: 3px;
    }
    QListWidget::item:hover {
        background: #243040;
    }
    QListWidget::item:selected {
        background: #007ACC;
        color: white;
    }
"""

SECTION_SEPARATOR_LABEL_STYLESHEET = 'color: #88c0d0; font-size: 9pt; padding: 5px 0;'

DESC_LABEL_STYLESHEET = 'color: #a0b8c0; font-style: italic; font-size: 10pt; padding: 5px;'

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
    'font-size: 16pt; font-weight: bold; color: #88c0d0; padding: 10px;'
    'background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0f1923, stop:0.5 #1a2d3d, stop:1 #0f1923);'
    'border-radius: 6px; border: 1px solid #2a3f4a;'
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
