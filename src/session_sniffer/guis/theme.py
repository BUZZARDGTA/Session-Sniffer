"""Custom sleek dark theme for Session Sniffer."""

from session_sniffer.constants.local import RESOURCES_DIR_PATH
from session_sniffer.guis.stylesheets._menus import SHARED_QMENU_RIGHT_ARROW_STYLESHEET

_SCALE_THRESHOLD_LARGE = 0.85
_SCALE_THRESHOLD_MEDIUM = 0.75


def get_stylesheet(ui_scale: float = 1.0) -> str:
    """Return the custom PySide6 stylesheet.

    Args:
        ui_scale: The UI scale factor from `compute_ui_scale`. Controls font
            sizes throughout the stylesheet so the UI reads clearly at every
            supported screen resolution.

    Returns:
        The QSS stylesheet as a string.
    """
    branch_vline_path = (RESOURCES_DIR_PATH / 'icons' / 'branch_vline.svg').as_posix()
    branch_more_path = (RESOURCES_DIR_PATH / 'icons' / 'branch_more.svg').as_posix()
    branch_end_path = (RESOURCES_DIR_PATH / 'icons' / 'branch_end.svg').as_posix()
    chevron_right_path = (RESOURCES_DIR_PATH / 'icons' / 'chevron_right.svg').as_posix()
    chevron_right_more_path = (RESOURCES_DIR_PATH / 'icons' / 'chevron_right_more.svg').as_posix()
    chevron_right_end_path = (RESOURCES_DIR_PATH / 'icons' / 'chevron_right_end.svg').as_posix()
    chevron_down_more_path = (RESOURCES_DIR_PATH / 'icons' / 'chevron_down_more.svg').as_posix()
    chevron_down_end_path = (RESOURCES_DIR_PATH / 'icons' / 'chevron_down_end.svg').as_posix()
    arrow_up_path = (RESOURCES_DIR_PATH / 'icons' / 'arrow_up.svg').as_posix()
    arrow_down_path = (RESOURCES_DIR_PATH / 'icons' / 'arrow_down.svg').as_posix()
    check_path = (RESOURCES_DIR_PATH / 'icons' / 'check.svg').as_posix()

    # Scale the base font size proportionally to the screen resolution.
    # 10pt is the design baseline (2K / 1.0 scale).  Smaller screens get
    # proportionally smaller text so nothing overflows or clips.
    if ui_scale >= _SCALE_THRESHOLD_LARGE:
        base_font_pt = 10
    elif ui_scale >= _SCALE_THRESHOLD_MEDIUM:
        base_font_pt = 9
    else:
        base_font_pt = 8

    css = (
        """
    /* Main Background */
    QMainWindow, QDialog, QWidget {
        background-color: #121212;
        color: #e0e0e0;
        font-family: 'Segoe UI', Arial, sans-serif;
        font-size: {base_font_pt}pt;
    }

    QDialog#InterfaceSelectionDialog {
        background-color: #0b141f;
    }

    /* Tooltips */
    QToolTip {
        background-color: #1e1e1e;
        color: #e0e0e0;
        border: 1px solid #333333;
        padding: 4px;
        border-radius: 4px;
    }

    /* Buttons */
    QPushButton {
        background-color: #2d2d30;
        color: #ffffff;
        border: 1px solid #3e3e42;
        border-radius: 4px;
        padding: 6px 16px;
    }
    QPushButton:hover {
        background-color: #3e3e42;
        border-color: #007acc;
    }
    QPushButton:pressed {
        background-color: #1e1e1e;
        border-color: #007acc;
    }
    QPushButton:disabled {
        background-color: #1a1a1a;
        color: #666666;
        border-color: #2a2a2a;
    }

    QPushButton[danger="true"] {
        border: 1px solid #7a3b3b;
        color: #e07070;
    }
    QPushButton[danger="true"]:hover {
        background-color: #3d2222;
        border-color: #e55353;
        color: #ff8888;
    }
    QPushButton[danger="true"]:pressed {
        background-color: #2b1515;
        border-color: #e55353;
    }

    /* Input Fields */
    QLineEdit, QSpinBox, QDoubleSpinBox, QComboBox, QTextEdit, QPlainTextEdit {
        background-color: #1e1e1e;
        color: #e0e0e0;
        border: 1px solid #3e3e42;
        border-radius: 4px;
        padding: 4px 8px;
    }

    QAbstractItemView QLineEdit, QAbstractItemView QSpinBox, QAbstractItemView QDoubleSpinBox, QAbstractItemView QComboBox {
        padding: 0px 4px;
        margin: 0px;
        border-radius: 0px;
    }

    /* QSpinBox, QDoubleSpinBox {
        max-width removed to allow auto-sizing for prefixes/suffixes
    } */

    /* Checkboxes */
    QCheckBox {
        spacing: 8px;
        color: #e0e0e0;
    }
    QCheckBox::indicator {
        width: 14px;
        height: 14px;
        border: 1px solid #3e3e42;
        border-radius: 3px;
        background-color: #1e1e1e;
    }
    QCheckBox::indicator:hover {
        border: 1px solid #007acc;
    }
    QCheckBox::indicator:checked {
        background-color: #007acc;
        border: 1px solid #007acc;
        image: url("{check_path}");
    }
    QCheckBox::indicator:disabled {
        background-color: #2d2d30;
        border: 1px solid #3e3e42;
    }

    QLineEdit, QSpinBox, QDoubleSpinBox, QComboBox, QTextEdit, QPlainTextEdit {
        selection-background-color: #007acc;
    }
    QLineEdit:focus, QSpinBox:focus, QDoubleSpinBox:focus, QComboBox:focus, QTextEdit:focus, QPlainTextEdit:focus {
        border: 1px solid #007acc;
    }
    QLineEdit:disabled, QSpinBox:disabled, QDoubleSpinBox:disabled, QComboBox:disabled, QTextEdit:disabled, QPlainTextEdit:disabled {
        background-color: #121212;
        color: #666666;
    }

    /* SpinBox Buttons */
    QSpinBox::up-button, QDoubleSpinBox::up-button {
        subcontrol-origin: padding;
        subcontrol-position: top right;
        width: 16px;
        background-color: transparent;
        border-left: 1px solid #333333;
        border-bottom: 1px solid #333333;
        border-top-right-radius: 3px;
    }
    QSpinBox::up-button:hover, QDoubleSpinBox::up-button:hover {
        background-color: rgba(255, 255, 255, 0.05);
    }
    QSpinBox::up-button:pressed, QDoubleSpinBox::up-button:pressed {
        background-color: rgba(255, 255, 255, 0.1);
    }

    QSpinBox::down-button, QDoubleSpinBox::down-button {
        subcontrol-origin: padding;
        subcontrol-position: bottom right;
        width: 16px;
        background-color: transparent;
        border-left: 1px solid #333333;
        border-bottom-right-radius: 3px;
    }
    QSpinBox::down-button:hover, QDoubleSpinBox::down-button:hover {
        background-color: rgba(255, 255, 255, 0.05);
    }
    QSpinBox::down-button:pressed, QDoubleSpinBox::down-button:pressed {
        background-color: rgba(255, 255, 255, 0.1);
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
    QComboBox::drop-down {
        subcontrol-origin: padding;
        subcontrol-position: top right;
        width: 20px;
        background-color: transparent;
        border-left: 1px solid #333333;
        border-top-right-radius: 3px;
        border-bottom-right-radius: 3px;
    }
    QComboBox::drop-down:hover {
        background-color: rgba(255, 255, 255, 0.05);
    }
    QComboBox::down-arrow {
        image: url("{arrow_down_path}");
        width: 7px;
        height: 7px;
    }
    QComboBox QAbstractItemView {
        background-color: #1e1e1e;
        border: 1px solid #333333;
        selection-background-color: #007acc;
        color: #e0e0e0;
    }
    QComboBox QAbstractItemView::item {
        min-height: 22px;
        padding: 3px 8px;
    }

    /* Tables */
    QTableView, QTreeView, QListView {
        background-color: #1E1E1E;
        alternate-background-color: #252526;
        color: #E0E0E0;
        gridline-color: #333333;
        border: 1px solid #333333;
        selection-background-color: #007ACC;
        selection-color: #FFFFFF;
        outline: none;
        show-decoration-selected: 1;
    }
    QHeaderView::section {
        background-color: #2D2D30;
        color: #88c0d0;
        padding: 4px;
        border: 1px solid #333333;
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
    QTableView::item {
        border-bottom: 1px solid #333333;
        background-color: transparent;
    }
    QTableView::item:hover {
        background-color: #2D2D30;
    }
    QTableView::item:selected, QTreeView::item:selected, QListView::item:selected {
        background-color: #284457;
        color: #ffffff;
    }
    QTableView::item:selected:hover {
        background-color: #2F4F64;
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
        background-color: #2d2d30;
    }
    QTreeView::item:selected:hover {
        background-color: #2f4f64;
    }

    QTreeView::branch {
        background: transparent;
        border: none;
        border-image: none;
        image: none;
    }
    QTreeView::branch:hover {
        background-color: #2d2d30;
    }
    QTreeView::branch:selected {
        background-color: #284457;
    }
    QTreeView::branch:selected:hover {
        background-color: #2f4f64;
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
        background-color: #1e1e1e;
        width: 12px;
        margin: 0px;
    }
    QScrollBar::handle:vertical {
        background-color: #424242;
        min-height: 20px;
        border-radius: 4px;
        margin: 2px;
    }
    QScrollBar::handle:vertical:hover {
        background-color: #686868;
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
        background-color: #1e1e1e;
        height: 12px;
        margin: 0px;
    }
    QScrollBar::handle:horizontal {
        background-color: #424242;
        min-width: 20px;
        border-radius: 4px;
        margin: 2px;
    }
    QScrollBar::handle:horizontal:hover {
        background-color: #686868;
    }
    QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
        border: none;
        background: none;
        width: 0px;
    }
    QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {
        background: none;
    }

    /* Tab Widget */
    QTabWidget::pane {
        border: 1px solid #333333;
        background-color: #1e1e1e;
    }
    QTabBar::tab {
        background-color: #2d2d30;
        color: #c0c0c0;
        padding: 8px 16px;
        border: 1px solid #3e3e42;
        border-bottom: none;
        border-top-left-radius: 4px;
        border-top-right-radius: 4px;
        margin-right: 2px;
    }
    QTabBar::tab:selected {
        background-color: #1e1e1e;
        color: #ffffff;
        border-top: 2px solid #007acc;
        font-weight: bold;
    }
    QTabBar::tab:hover:!selected {
        background-color: #3e3e42;
        color: #ffffff;
    }

    /* Group Box */
    QGroupBox {
        border: 1px solid #333333;
        border-radius: 4px;
        border-top-left-radius: 0px;
        margin-top: 26px;
        padding-top: 12px;
    }
    QGroupBox::title {
        subcontrol-origin: margin;
        subcontrol-position: top left;
        left: -1px;
        top: 0px;
        padding: 4px 12px;
        background-color: #252526;
        color: #88c0d0;
        border: 1px solid #333333;
        border-bottom: none;
        border-top-left-radius: 4px;
        border-top-right-radius: 4px;
        font-size: 11pt;
        font-weight: bold;
    }

    /* Menu Bar */
    QMenuBar {
        background-color: #252526;
        color: #e0e0e0;
        border-bottom: 1px solid #88c0d0;
        padding: 2px 4px;
        spacing: 2px;
    }
    QMenuBar::item {
        padding: 5px 14px;
        border-radius: 4px;
        background: transparent;
    }
    QMenuBar::item:selected {
        background-color: #3e3e42;
    }
    QMenuBar::item:pressed {
        background-color: #55555a;
    }
    QMenu {
        background-color: #252526;
        color: #e0e0e0;
        border: 1px solid #3e3e42;
        border-radius: 4px;
        padding: 4px 6px;
    }
    QMenu::item {
        padding: 6px 24px 6px 8px;
    }
    QMenu::item:selected {
        background-color: #3e3e42;
        border-radius: 3px;
    }
    QMenu::separator {
        height: 1px;
        background: #333333;
        margin: 4px 10px;
    }
    """
        + SHARED_QMENU_RIGHT_ARROW_STYLESHEET
        + """

    /* Toolbar */
    QToolBar {
        background-color: #252526;
        border-bottom: 1px solid #88c0d0;
        padding: 4px;
    }
    QToolButton {
        padding: 4px;
        border-radius: 4px;
    }
    QToolButton:hover {
        background-color: #3e3e42;
    }

    /* Status Bar */
    QStatusBar {
        background-color: #252526;
        color: #e0e0e0;
        border-top: 1px solid #88c0d0;
        padding: 4px 8px;
        min-height: 24px;
        font-size: {base_font_pt}pt;
    }
    QStatusBar::item {
        border: none;
    }

    /* Labels */
    QLabel {
        background-color: transparent;
        color: #e0e0e0;
        font-size: {base_font_pt}pt;
    }
    """
    )
    css = css.replace('{branch_vline_path}', branch_vline_path)
    css = css.replace('{branch_more_path}', branch_more_path)
    css = css.replace('{branch_end_path}', branch_end_path)
    css = css.replace('{chevron_right_more_path}', chevron_right_more_path)
    css = css.replace('{chevron_right_path}', chevron_right_path)
    css = css.replace('{chevron_right_end_path}', chevron_right_end_path)
    css = css.replace('{chevron_down_more_path}', chevron_down_more_path)
    css = css.replace('{chevron_down_end_path}', chevron_down_end_path)
    css = css.replace('{arrow_up_path}', arrow_up_path)
    css = css.replace('{arrow_down_path}', arrow_down_path)
    css = css.replace('{check_path}', check_path)
    return css.replace('{base_font_pt}', str(base_font_pt))
