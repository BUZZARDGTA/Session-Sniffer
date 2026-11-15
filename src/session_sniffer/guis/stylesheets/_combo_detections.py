"""Combo rule editor, detections manager, and country selector QSS."""

from session_sniffer.guis.theming import themed_qss

# =============================================================================
# COMBO RULE / DETECTIONS MANAGER STYLES
# =============================================================================

GROUPBOX_STYLE = themed_qss("""
    QGroupBox {
        font-weight: bold;
        border: 1px solid @border;
        border-radius: 8px;
        margin-top: 14px;
        padding-top: 25px;
        background: @surface;
    }
    QGroupBox::title {
        subcontrol-origin: margin;
        subcontrol-position: top left;
        left: 15px;
        top: 0px;
        padding: 4px 14px;
        color: @accent;
        background-color: @table_header;
        border: 1px solid @border;
        border-radius: 6px;
    }

    QGroupBox .QWidget {
        background-color: transparent;
    }

    QGroupBox QComboBox,
    QGroupBox QLineEdit,
    QGroupBox QTextEdit,
    QGroupBox QPlainTextEdit {
        background-color: @input;
        border: 1px solid @border;
        border-radius: 4px;
        color: @text;
        padding: 4px 8px;
        min-height: 24px;
        font-size: 9pt;
    }
    QGroupBox QSpinBox,
    QGroupBox QDoubleSpinBox {
        background-color: @input;
        border: 1px solid @border;
        border-radius: 4px;
        color: @text;
        padding: 2px 4px;
        min-height: 24px;
        min-width: 100px;
        font-size: 9pt;
    }
    QGroupBox QPushButton {
        min-height: 26px;
        background-color: @control;
        border: 1px solid @border;
        border-radius: 4px;
        color: @text_strong;
        font-size: 9pt;
    }
    QGroupBox QPushButton:hover {
        background-color: @control:hover;
        border-color: @accent;
    }
    QGroupBox QPushButton:pressed {
        background-color: @control:pressed;
    }
    QGroupBox QComboBox:focus,
    QGroupBox QSpinBox:focus,
    QGroupBox QDoubleSpinBox:focus,
    QGroupBox QLineEdit:focus {
        border: 1px solid @accent;
    }
    QGroupBox QComboBox QAbstractItemView {
        background-color: @popup;
        color: @text;
        border: 1px solid @border;
        border-radius: 4px;
        padding: 2px 1px;
        selection-background-color: @selection;
        selection-color: @text_strong;
        outline: none;
    }
    QGroupBox QComboBox QAbstractItemView::item {
        min-height: 20px;
        padding: 2px 6px;
        margin: 1px 0px;
        border-radius: 3px;
        border: none;
        color: @text;
    }
    QGroupBox QComboBox QAbstractItemView::item:hover {
        background-color: @selection/65;
        color: @text_strong;
        border-radius: 3px;
        padding: 2px 6px;
    }
    QGroupBox QComboBox QAbstractItemView::item:selected {
        background-color: @selection;
        color: @text_strong;
        border-radius: 3px;
        padding: 2px 6px;
    }
    QGroupBox QCheckBox::indicator {
        width: 14px;
        height: 14px;
        background-color: @input;
        border: 1px solid @border;
        border-radius: 3px;
    }
    QGroupBox QCheckBox::indicator:hover {
        border-color: @accent;
    }
    QGroupBox QCheckBox::indicator:checked {
        background-color: @accent;
        border-color: @accent;
    }
""")

LIST_WIDGET_STYLE = themed_qss("""
    QListWidget {
        background: @table;
        color: @text;
        border: 1px solid @border;
        border-radius: 4px;
        padding: 5px;
        font-family: 'Menlo', 'Consolas', 'Courier New', monospace;
    }
    QListWidget::item {
        padding: 5px;
        border-radius: 3px;
    }
    QListWidget::item:hover {
        background: @selection/45;
    }
    QListWidget::item:selected {
        background: @selection;
        color: @text_strong;
    }
""")

COMBO_RULES_LIST_STYLE = themed_qss("""
    QListWidget {
        background: @table;
        border: 1px solid @border;
        border-radius: 6px;
        padding: 4px;
        outline: none;
    }
    QListWidget::item {
        background: transparent;
        border: none;
        padding: 0px;
    }
    QListWidget::item:hover {
        background: transparent;
    }
    QListWidget::item:selected {
        background: transparent;
    }
""")

DESC_LABEL_STYLESHEET = themed_qss('color: @text_muted; font-style: italic; font-size: 10pt; padding: 5px;')

HINT_LABEL_STYLESHEET = themed_qss('color: @text_muted; font-style: italic; padding-bottom: 4px;')

RELAY_FILTER_WARNING_STYLESHEET = themed_qss(
    'QWidget { background-color: @surface~warning/20; border: 1px solid @warning; border-radius: 6px; padding: 2px; }'
    'QLabel { border: none; background: transparent; }'
    'QPushButton { border: 1px solid @warning; border-radius: 4px; background-color: @control~warning/28;'
    ' color: @warning; padding: 4px 10px; font-weight: bold; }'
    'QPushButton:hover { background-color: @control~warning/42; color: @text_strong; }',
)

WARNING_ICON_LABEL_STYLESHEET = themed_qss('font-size: 18pt; border: none;')

WARNING_TEXT_LABEL_STYLESHEET = themed_qss('color: @warning; border: none;')

DETECTIONS_MANAGER_HEADER_STYLESHEET = themed_qss(
    'font-size: 16pt; font-weight: bold; color: @accent; padding: 10px;'
    'background: @table_header;'
    'border-radius: 6px; border: 1px solid @border;',
)
