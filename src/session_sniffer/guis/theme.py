"""Global application stylesheet and palette, mapped onto the active theme."""

import sys

from PySide6.QtGui import QPalette

from session_sniffer.guis.stylesheets._menus import SHARED_QMENU_RIGHT_ARROW_STYLESHEET
from session_sniffer.guis.theming import CHECKBOX_CHECK_ICON_PATH, ICONS_DIR_PATH, themed_qcolor, themed_qss, themed_text_qcolor

_SCALE_THRESHOLD_XLARGE = 1.10
_SCALE_THRESHOLD_LARGE = 0.85
_SCALE_THRESHOLD_MEDIUM = 0.75
_CANONICAL_STYLESHEET_CACHE: dict[float, str] = {}


def get_palette() -> QPalette:
    """Return the unified QPalette of the active theme for Qt widgets and window decorations."""
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, themed_qcolor('@background'))
    palette.setColor(QPalette.ColorRole.WindowText, themed_qcolor('@text'))
    palette.setColor(QPalette.ColorRole.Base, themed_qcolor('@table'))
    palette.setColor(QPalette.ColorRole.AlternateBase, themed_qcolor('@table_alt'))
    palette.setColor(QPalette.ColorRole.ToolTipBase, themed_qcolor('@popup'))
    palette.setColor(QPalette.ColorRole.ToolTipText, themed_text_qcolor('@text', '@popup'))
    palette.setColor(QPalette.ColorRole.Text, themed_qcolor('@text'))
    palette.setColor(QPalette.ColorRole.Button, themed_qcolor('@control'))
    palette.setColor(QPalette.ColorRole.ButtonText, themed_text_qcolor('@text_strong', '@control'))
    palette.setColor(QPalette.ColorRole.BrightText, themed_qcolor('@text_strong'))
    palette.setColor(QPalette.ColorRole.Link, themed_qcolor('@accent'))
    palette.setColor(QPalette.ColorRole.Highlight, themed_qcolor('@selection'))
    palette.setColor(QPalette.ColorRole.HighlightedText, themed_text_qcolor('@text_strong', '@selection'))
    return palette


def build_canonical_stylesheet(ui_scale: float = 1.0) -> str:
    """Return the canonical application QSS template bound to `@token` roles for *ui_scale* (thread-safe)."""
    cached = _CANONICAL_STYLESHEET_CACHE.get(ui_scale)
    if cached is not None:
        return cached
    branch_vline_path = (ICONS_DIR_PATH / 'branch_vline.svg').as_posix()
    branch_more_path = (ICONS_DIR_PATH / 'branch_more.svg').as_posix()
    branch_end_path = (ICONS_DIR_PATH / 'branch_end.svg').as_posix()
    chevron_right_path = (ICONS_DIR_PATH / 'chevron-right.svg').as_posix()
    chevron_right_disabled_path = (ICONS_DIR_PATH / 'chevron-right-disabled.svg').as_posix()
    chevron_right_more_path = (ICONS_DIR_PATH / 'chevron_right_more.svg').as_posix()
    chevron_right_end_path = (ICONS_DIR_PATH / 'chevron_right_end.svg').as_posix()
    chevron_down_more_path = (ICONS_DIR_PATH / 'chevron_down_more.svg').as_posix()
    chevron_down_end_path = (ICONS_DIR_PATH / 'chevron_down_end.svg').as_posix()
    arrow_up_path = (ICONS_DIR_PATH / 'chevron-up.svg').as_posix()
    arrow_down_path = (ICONS_DIR_PATH / 'chevron-down.svg').as_posix()
    check_path = CHECKBOX_CHECK_ICON_PATH.as_posix()
    close_path = (ICONS_DIR_PATH / 'x.svg').as_posix()

    if ui_scale >= _SCALE_THRESHOLD_XLARGE:
        base_font_pt = 11
    elif ui_scale >= _SCALE_THRESHOLD_LARGE:
        base_font_pt = 10
    elif ui_scale >= _SCALE_THRESHOLD_MEDIUM:
        base_font_pt = 9
    else:
        base_font_pt = 8

    if sys.platform == 'darwin':
        ui_font_family = "'Helvetica Neue', Arial, sans-serif"
        mono_font_family = "Menlo, 'Courier New', monospace"
    elif sys.platform == 'win32':
        ui_font_family = "'Segoe UI', Arial, sans-serif"
        mono_font_family = "Consolas, 'Courier New', 'Lucida Console', monospace"
    else:
        ui_font_family = "'Ubuntu', 'DejaVu Sans', Arial, sans-serif"
        mono_font_family = "'DejaVu Sans Mono', 'Courier New', monospace"

    css = (
        """
    /* Main Background */
    QMainWindow, QDialog, QWidget {
        background-color: @background;
        color: @text;
        font-family: {ui_font_family};
        font-size: {base_font_pt}pt;
    }

    QScrollArea {
        background-color: transparent;
    }
    QGroupBox .QWidget,
    QTabWidget .QWidget,
    QFrame .QWidget,
    QScrollArea .QWidget,
    QStatusBar .QWidget,
    QToolBar .QWidget {
        background-color: transparent;
    }

    QDialog#InterfaceSelectionDialog {
        background-color: @background~accent/6;
    }
    QDialog#InterfaceSelectionDialog QStackedWidget,
    QDialog#InterfaceSelectionDialog QStackedWidget > QWidget,
    QDialog#InterfaceSelectionDialog QWidget#HotspotManagerWidget {
        background: transparent;
        background-color: transparent;
    }

    /* Tooltips */
    QToolTip {
        background-color: @popup;
        color: @text;
        border: 1px solid @border;
        padding: 4px;
        border-radius: 4px;
    }

    /* Buttons */
    QPushButton {
        background-color: @control;
        color: @text_strong;
        border: 1px solid @border;
        border-radius: 4px;
        padding: 6px 16px;
    }
    QPushButton:default {
        background-color: @control;
        color: @text_strong;
        border: 1px solid @accent;
    }
    QPushButton:default:hover, QPushButton:hover {
        background-color: @control:hover;
        color: @text_strong;
        border-color: @accent;
    }
    QPushButton:default:pressed, QPushButton:pressed {
        background-color: @control:pressed;
        color: @text_strong;
        border-color: @accent;
    }
    QPushButton:disabled {
        background-color: @control:disabled;
        color: @text_muted:disabled;
        border-color: @border:disabled;
    }

    QPushButton[danger="true"] {
        background-color: @control~danger/14;
        border: 1px solid @danger/60;
        color: @danger;
    }
    QPushButton[danger="true"]:hover {
        background-color: @control~danger/28;
        border-color: @danger;
        color: @text_strong;
    }
    QPushButton[danger="true"]:pressed {
        background-color: @control~danger/18:pressed;
        border-color: @danger;
        color: @text_strong;
    }

    /* Input Fields */
    QLineEdit, QSpinBox, QDoubleSpinBox, QComboBox, QTextEdit, QPlainTextEdit {
        background-color: @input;
        color: @text;
        border: 1px solid @border;
        border-radius: 4px;
        padding: 4px 8px;
    }

    QPlainTextEdit {
        font-family: {mono_font_family};
    }

    QAbstractItemView QLineEdit, QAbstractItemView QSpinBox, QAbstractItemView QDoubleSpinBox, QAbstractItemView QComboBox {
        padding: 0px 4px;
        margin: 0px;
        border-radius: 0px;
    }

    /* Checkboxes */
    QCheckBox {
        background-color: transparent;
        spacing: 8px;
        color: @text;
    }
    QCheckBox::indicator {
        width: 14px;
        height: 14px;
        border: 1px solid @border;
        border-radius: 3px;
        background-color: @input;
    }
    QCheckBox::indicator:hover {
        border: 1px solid @accent;
    }
    QCheckBox::indicator:checked {
        background-color: @accent;
        border: 1px solid @accent;
        image: url("{check_path}");
    }
    QCheckBox::indicator:disabled {
        background-color: @input:disabled;
        border: 1px solid @border:disabled;
    }

    /* Radio Buttons */
    QRadioButton {
        background-color: transparent;
        spacing: 8px;
        color: @text;
    }
    QRadioButton::indicator {
        width: 14px;
        height: 14px;
        border: 1px solid @border;
        border-radius: 8px;
        background-color: @input;
    }
    QRadioButton::indicator:hover {
        border: 1px solid @accent;
    }
    QRadioButton::indicator:checked {
        border: 1px solid @accent;
        background-color: qradialgradient(cx:0.5, cy:0.5, radius:0.5, fx:0.5, fy:0.5, stop:0 @accent, stop:0.45 @accent, stop:0.52 @input, stop:1 @input);
    }
    QRadioButton::indicator:checked:hover {
        border: 1px solid @accent:hover;
        background-color: qradialgradient(cx:0.5, cy:0.5, radius:0.5, fx:0.5, fy:0.5, stop:0 @accent:hover, stop:0.45 @accent:hover, stop:0.52 @input, stop:1 @input);
    }
    QRadioButton::indicator:disabled {
        background-color: @input:disabled;
        border: 1px solid @border:disabled;
    }

    QLineEdit, QSpinBox, QDoubleSpinBox, QTextEdit, QPlainTextEdit {
        selection-background-color: @selection;
        selection-color: @text_strong;
    }
    QComboBox {
        selection-background-color: @selection;
        selection-color: @text_strong;
    }
    QLineEdit:focus, QSpinBox:focus, QDoubleSpinBox:focus, QComboBox:focus, QTextEdit:focus, QPlainTextEdit:focus {
        border: 1px solid @accent;
    }
    QLineEdit:disabled, QSpinBox:disabled, QDoubleSpinBox:disabled, QComboBox:disabled, QTextEdit:disabled, QPlainTextEdit:disabled {
        background-color: @input:disabled;
        color: @text_muted:disabled;
        border-color: @border:disabled;
    }

    /* SpinBox Buttons */
    QSpinBox::up-button, QDoubleSpinBox::up-button {
        subcontrol-origin: padding;
        subcontrol-position: top right;
        width: 16px;
        background-color: transparent;
        border-left: 1px solid @border;
        border-bottom: 1px solid @border;
        border-top-right-radius: 3px;
    }
    QSpinBox::up-button:hover, QDoubleSpinBox::up-button:hover,
    QSpinBox::down-button:hover, QDoubleSpinBox::down-button:hover {
        background-color: @control/35;
    }
    QSpinBox::up-button:pressed, QDoubleSpinBox::up-button:pressed,
    QSpinBox::down-button:pressed, QDoubleSpinBox::down-button:pressed {
        background-color: @control/55;
    }

    QSpinBox::down-button, QDoubleSpinBox::down-button {
        subcontrol-origin: padding;
        subcontrol-position: bottom right;
        width: 16px;
        background-color: transparent;
        border-left: 1px solid @border;
        border-bottom-right-radius: 3px;
    }

    QSpinBox::up-arrow, QDoubleSpinBox::up-arrow {
        image: url("{arrow_up_path}");
        width: 7px;
        height: 7px;
    }

    QSpinBox::down-arrow, QDoubleSpinBox::down-arrow {
        image: url("{arrow_down_path}");
        width: 7px;
        height: 7px;
    }

    /* ComboBox Dropdown */
    QComboBox {
        padding: 3px 6px;
    }
    QComboBox:hover, QComboBox:on {
        border-color: @border:hover;
    }
    QComboBox::drop-down {
        subcontrol-origin: padding;
        subcontrol-position: top right;
        width: 20px;
        background-color: transparent;
        border-left: 1px solid @border;
        border-top-right-radius: 3px;
        border-bottom-right-radius: 3px;
    }
    QComboBox::drop-down:hover {
        background-color: @control/35;
    }
    QComboBox::down-arrow {
        image: url("{arrow_down_path}");
        width: 7px;
        height: 7px;
    }
    QComboBox QAbstractItemView, QListView#CompleterPopup {
        background-color: @popup;
        border: 1px solid @border;
        border-radius: 4px;
        padding: 2px 1px;
        outline: none;
        color: @text;
        selection-background-color: @selection;
        selection-color: @text_strong;
    }
    QComboBox QAbstractItemView::item, QListView#CompleterPopup::item {
        min-height: 20px;
        padding: 2px 6px;
        margin: 1px 0px;
        border-radius: 3px;
        border: none;
        border-bottom: none;
        background-color: transparent;
        color: @text;
    }
    QComboBox QAbstractItemView::item:hover, QListView#CompleterPopup::item:hover {
        background-color: @selection/65;
        color: @text_strong;
        border-radius: 3px;
        padding: 2px 6px;
        border: none;
    }
    QComboBox QAbstractItemView::item:selected, QListView#CompleterPopup::item:selected {
        background-color: @selection;
        color: @text_strong;
        border-radius: 3px;
        padding: 2px 6px;
        border: none;
    }
    QComboBox QAbstractItemView::item:selected:hover, QListView#CompleterPopup::item:selected:hover {
        background-color: @selection:hover;
        color: @text_strong;
        border-radius: 3px;
        padding: 2px 6px;
        border: none;
    }
    QComboBox QAbstractItemView::item:focus, QListView#CompleterPopup::item:focus {
        background-color: @selection;
        color: @text_strong;
        border-radius: 3px;
        padding: 2px 6px;
        border: none;
        outline: none;
    }

    /* Tables */
    QTableView, QTreeView, QListView {
        background-color: @table;
        alternate-background-color: @table_alt;
        color: @text;
        gridline-color: @border;
        border: 1px solid @border;
        selection-background-color: @selection;
        selection-color: @text_strong;
        outline: none;
        show-decoration-selected: 0;
    }
    QHeaderView::section {
        background-color: @table_header;
        color: @text_strong;
        padding: 4px;
        border: 1px solid @border;
        font-weight: bold;
    }
    QHeaderView::up-arrow {
        image: url("{arrow_up_path}");
        width: 9px;
        height: 9px;
        margin-left: -7px;
        margin-right: 6px;
    }
    QHeaderView::down-arrow {
        image: url("{arrow_down_path}");
        width: 9px;
        height: 9px;
        margin-left: -7px;
        margin-right: 6px;
    }
    QTableView::item, QTreeView::item, QListView::item {
        border-bottom: 1px solid @border;
        background-color: transparent;
        padding-left: 0px;
        padding-right: 0px;
        margin-left: 0px;
        margin-right: 0px;
        text-indent: 0px;
    }
    QTableView::item:hover, QListView::item:hover {
        background-color: @selection/35;
        padding-left: 0px;
        margin-left: 0px;
    }
    QTableView::item:selected, QTreeView::item:selected, QListView::item:selected {
        background-color: @selection;
        color: @text_strong;
        padding-left: 0px;
        padding-right: 0px;
        margin-left: 0px;
        margin-right: 0px;
        text-indent: 0px;
    }
    QTableView::item:selected:hover, QListView::item:selected:hover {
        background-color: @selection:hover;
        color: @text_strong;
        padding-left: 0px;
        margin-left: 0px;
    }
    QTableView::item:focus, QTreeView::item:focus, QListView::item:focus {
        background-color: @selection:hover;
        border: none;
        outline: none;
        color: @text_strong;
        padding-left: 0px;
        padding-right: 0px;
        margin-left: 0px;
        margin-right: 0px;
        text-indent: 0px;
    }

    QTreeView {
        gridline-color: transparent;
    }

    QTreeView::item {
        border: none;
        border-left: none;
        outline: none;
    }
    QTreeView::item:hover {
        background-color: @selection/35;
    }
    QTreeView::item:selected:hover {
        background-color: @selection:hover;
    }

    QTreeView::branch {
        background: transparent;
        border: none;
        border-image: none;
        image: none;
    }
    QTreeView::branch:hover {
        background-color: @selection/35;
    }
    QTreeView::branch:selected {
        background-color: @selection;
    }
    QTreeView::branch:selected:hover {
        background-color: @selection:hover;
    }

    QTreeView::branch:has-siblings:!adjoins-item {
        border-image: none;
        image: url("{branch_vline_path}");
    }

    QTreeView::branch:has-siblings:adjoins-item {
        border-image: none;
        image: url("{branch_more_path}");
    }

    QTreeView::branch:!has-children:!has-siblings:adjoins-item {
        border-image: none;
        image: url("{branch_end_path}");
    }

    QTreeView::branch:!has-children:!has-siblings:!adjoins-item {
        border-image: none;
        image: none;
    }

    QTreeView::branch:has-children:!has-siblings:closed {
        border-image: none;
        image: url("{chevron_right_end_path}");
    }

    QTreeView::branch:closed:has-children:has-siblings {
        border-image: none;
        image: url("{chevron_right_more_path}");
    }

    QTreeView::branch:has-children:!has-siblings:open {
        border-image: none;
        image: url("{chevron_down_end_path}");
    }

    QTreeView::branch:open:has-children:has-siblings {
        border-image: none;
        image: url("{chevron_down_more_path}");
    }

    /* Scrollbars */
    QScrollBar:vertical {
        border: none;
        background-color: @surface;
        width: 12px;
        margin: 0px;
    }
    QScrollBar::handle:vertical {
        background-color: @scrollbar;
        min-height: 20px;
        border-radius: 4px;
        margin: 2px;
    }
    QScrollBar::handle:vertical:hover {
        background-color: @scrollbar:hover;
    }
    QScrollBar::handle:vertical:pressed {
        background-color: @scrollbar:pressed;
    }
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
        border: none;
        background: none;
        height: 0px;
    }
    QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
        background: none;
    }

    QScrollBar:horizontal {
        border: none;
        background-color: @surface;
        height: 12px;
        margin: 0px;
    }
    QScrollBar::handle:horizontal {
        background-color: @scrollbar;
        min-width: 20px;
        border-radius: 4px;
        margin: 2px;
    }
    QScrollBar::handle:horizontal:hover {
        background-color: @scrollbar:hover;
    }
    QScrollBar::handle:horizontal:pressed {
        background-color: @scrollbar:pressed;
    }
    QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
        border: none;
        background: none;
        width: 0px;
    }
    QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {
        background: none;
    }

    /* Sliders */
    QSlider {
        background-color: transparent;
        min-height: 22px;
    }
    QSlider::groove:horizontal {
        border: 1px solid @border;
        height: 4px;
        background-color: @input;
        margin: 0px;
        border-radius: 2px;
    }
    QSlider::sub-page:horizontal {
        background-color: @accent;
        border: 1px solid @accent;
        height: 4px;
        border-radius: 2px;
    }
    QSlider::sub-page:horizontal:disabled {
        background-color: @input:disabled;
        border-color: @border:disabled;
    }
    QSlider::add-page:horizontal {
        background-color: @input;
        border: 1px solid @border;
        height: 4px;
        border-radius: 2px;
    }
    QSlider::add-page:horizontal:disabled {
        background-color: @input:disabled;
        border-color: @border:disabled;
    }
    QSlider::handle:horizontal {
        background-color: @scrollbar;
        border: 1px solid @border;
        width: 14px;
        margin-top: -5px;
        margin-bottom: -5px;
        border-radius: 7px;
    }
    QSlider::handle:horizontal:hover {
        background-color: @accent;
        border-color: @accent:hover;
    }
    QSlider::handle:horizontal:pressed {
        background-color: @accent:hover;
        border-color: @accent:hover;
    }
    QSlider::handle:horizontal:disabled {
        background-color: @scrollbar:disabled;
        border-color: @border:disabled;
    }

    QSlider::groove:vertical {
        border: 1px solid @border;
        width: 4px;
        background-color: @input;
        margin: 0px;
        border-radius: 2px;
    }
    QSlider::sub-page:vertical {
        background-color: @input;
        border: 1px solid @border;
        width: 4px;
        border-radius: 2px;
    }
    QSlider::sub-page:vertical:disabled {
        background-color: @input:disabled;
        border-color: @border:disabled;
    }
    QSlider::add-page:vertical {
        background-color: @accent;
        border: 1px solid @accent;
        width: 4px;
        border-radius: 2px;
    }
    QSlider::add-page:vertical:disabled {
        background-color: @input:disabled;
        border-color: @border:disabled;
    }
    QSlider::handle:vertical {
        background-color: @scrollbar;
        border: 1px solid @border;
        height: 14px;
        margin-left: -5px;
        margin-right: -5px;
        border-radius: 7px;
    }
    QSlider::handle:vertical:hover {
        background-color: @accent;
        border-color: @accent:hover;
    }
    QSlider::handle:vertical:pressed {
        background-color: @accent:hover;
        border-color: @accent:hover;
    }
    QSlider::handle:vertical:disabled {
        background-color: @scrollbar:disabled;
        border-color: @border:disabled;
    }

    /* Tab Widget */
    QTabWidget::pane {
        border: 1px solid @border;
        background-color: @surface;
    }
    QTabBar::tab {
        background-color: @control;
        color: @text_muted;
        padding: 8px 16px;
        border: 1px solid @border;
        border-bottom: none;
        border-top-left-radius: 4px;
        border-top-right-radius: 4px;
        margin-right: 2px;
    }
    QTabBar::tab:selected {
        background-color: @surface;
        color: @text_strong;
        border-top: 2px solid @accent;
        font-weight: bold;
    }
    QTabBar::tab:hover:!selected {
        background-color: @control:hover;
        color: @text_strong;
    }
    QTabBar::close-button {
        image: url("{close_path}");
        subcontrol-position: right;
        subcontrol-origin: padding;
        width: 14px;
        height: 14px;
        margin-right: 4px;
        border-radius: 3px;
    }
    QTabBar::close-button:hover {
        background-color: @control:hover;
    }
    QTabBar::close-button:pressed {
        background-color: @danger/45;
    }

    /* Group Box */
    QGroupBox {
        background-color: @surface;
        border: 1px solid @border;
        border-radius: 4px;
        border-top-left-radius: 0px;
        margin-top: {group_margin_top}px;
        padding-top: {group_padding_top}px;
    }
    QGroupBox::title {
        subcontrol-origin: margin;
        subcontrol-position: top left;
        left: -1px;
        top: 0px;
        padding: {group_title_pad_v}px {group_title_pad_h}px;
        background-color: @table_header;
        color: @accent;
        border: 1px solid @border;
        border-bottom: none;
        border-top-left-radius: 4px;
        border-top-right-radius: 4px;
        font-size: {group_title_font_pt}pt;
        font-weight: bold;
    }

    /* Menu Bar */
    QMenuBar {
        background-color: @menubar;
        color: @text;
        border-bottom: 1px solid @accent;
        padding: 2px 4px;
        spacing: 2px;
    }
    QMenuBar::item {
        padding: 5px 14px;
        border-radius: 4px;
        background: transparent;
    }
    QMenuBar::item:selected {
        background-color: @selection;
        color: @text_strong;
    }
    QMenuBar::item:pressed {
        background-color: @selection:hover;
        color: @text_strong;
    }
    QMenuBar::item:disabled {
        color: @text_muted:disabled;
        background: transparent;
    }
    QMenu {
        background-color: @popup;
        color: @text;
        border: 1px solid @border;
        border-radius: 4px;
        padding: 4px 6px;
    }
    QMenu::item {
        padding: 6px 24px 6px 8px;
    }
    QMenu::item:selected {
        background-color: @selection;
        color: @text_strong;
        border-radius: 3px;
    }
    QMenu::icon {
        padding-left: 8px;
    }
    QMenu::item:disabled, QMenu::item:disabled:selected {
        color: @text_muted:disabled;
        background-color: transparent;
    }
    QMenu::separator {
        height: 1px;
        background: @border;
        margin: 4px 10px;
    }
    """
        + SHARED_QMENU_RIGHT_ARROW_STYLESHEET
        + """

    /* Toolbar */
    QToolBar {
        background-color: @menubar;
        border-bottom: 1px solid @accent;
        padding: 4px;
    }
    QToolButton {
        background-color: transparent;
        color: @text;
        padding: 4px;
        border-radius: 4px;
    }
    QToolButton:hover {
        background-color: @control:hover;
        color: @text_strong;
    }

    /* Status Bar */
    QStatusBar {
        background-color: @statusbar;
        color: @text;
        border-top: 1px solid @accent;
        padding: 4px 8px;
        min-height: 24px;
        font-size: {base_font_pt}pt;
    }
    QStatusBar::item {
        border: none;
    }

    /* Splitter */
    QSplitter {
        background-color: transparent;
    }
    QSplitter::handle {
        background-color: @scrollbar;
        border-radius: 2px;
    }
    QSplitter::handle:hover {
        background-color: @accent;
    }
    QSplitter::handle:pressed {
        background-color: @accent:hover;
    }
    QSplitter::handle:horizontal {
        margin: 0px 1px;
    }
    QSplitter::handle:vertical {
        margin: 1px 0px;
    }

    /* Labels */
    QLabel {
        background-color: transparent;
        color: @text;
        font-size: {base_font_pt}pt;
    }
    """
    )
    css = css.replace('{branch_vline_path}', branch_vline_path)
    css = css.replace('{branch_more_path}', branch_more_path)
    css = css.replace('{branch_end_path}', branch_end_path)
    css = css.replace('{chevron_right_more_path}', chevron_right_more_path)
    css = css.replace('{chevron_right_path}', chevron_right_path)
    css = css.replace('{chevron_right_disabled_path}', chevron_right_disabled_path)
    css = css.replace('{chevron_right_end_path}', chevron_right_end_path)
    css = css.replace('{chevron_down_more_path}', chevron_down_more_path)
    css = css.replace('{chevron_down_end_path}', chevron_down_end_path)
    css = css.replace('{arrow_up_path}', arrow_up_path)
    css = css.replace('{arrow_down_path}', arrow_down_path)
    css = css.replace('{check_path}', check_path)
    css = css.replace('{close_path}', close_path)
    css = css.replace('{ui_font_family}', ui_font_family)
    css = css.replace('{mono_font_family}', mono_font_family)
    css = css.replace('{group_margin_top}', str(max(16, round(26 * ui_scale))))
    css = css.replace('{group_padding_top}', str(max(6, round(12 * ui_scale))))
    css = css.replace('{group_title_pad_v}', str(max(2, round(4 * ui_scale))))
    css = css.replace('{group_title_pad_h}', str(max(6, round(12 * ui_scale))))
    css = css.replace('{group_title_font_pt}', str(base_font_pt + 1))
    canonical_css = css.replace('{base_font_pt}', str(base_font_pt))
    _CANONICAL_STYLESHEET_CACHE[ui_scale] = canonical_css
    return canonical_css


def get_stylesheet(ui_scale: float = 1.0) -> str:
    """Return the custom PySide6 stylesheet mapped onto the active theme."""
    return themed_qss(build_canonical_stylesheet(ui_scale))
