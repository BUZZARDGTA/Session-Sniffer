"""Shared Looky System pre-flight validation for player action dialogs."""

from dataclasses import dataclass

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QLabel,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.guis.looky_text import (
    LOOKY_TITLE,
    LOOKY_WARNING_API_ACCESS_MISSING,
    LOOKY_WARNING_API_KEY_MISSING,
    LOOKY_WARNING_DISABLED,
)
from session_sniffer.guis.stylesheets import (
    LOOKY_ACTION_BUTTON_STYLESHEET,
    LOOKY_PRIMARY_ACTION_BUTTON_STYLESHEET,
    LOOKY_PROGRESS_BAR_STYLESHEET,
    LOOKY_STATUS_LABEL_STYLESHEET,
)
from session_sniffer.settings.settings import Settings


@dataclass
class LookyProgressWidgets:
    """The three mutable widgets built by `build_looky_progress_widgets`."""

    progress_bar: QProgressBar
    status_label: QLabel
    try_again_btn: QPushButton


def build_looky_progress_widgets(layout: QVBoxLayout, dialog: QDialog) -> LookyProgressWidgets:
    """Add a shared progress / status / try-again / close block to `layout`.

    Appends an indeterminate `QProgressBar`, a hidden `QLabel` for status text,
    a hidden `QPushButton` for retries, and a Close `QDialogButtonBox` wired to
    `dialog.reject`. Returns the three mutable widgets so callers can hide,
    show, and update them from signal handlers.
    """
    progress_bar = QProgressBar()
    progress_bar.setRange(0, 0)
    progress_bar.setTextVisible(False)
    progress_bar.setFixedHeight(14)
    progress_bar.setStyleSheet(LOOKY_PROGRESS_BAR_STYLESHEET)
    layout.addWidget(progress_bar)

    status_label = QLabel()
    status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
    status_label.setTextFormat(Qt.TextFormat.RichText)
    status_label.setWordWrap(True)
    status_label.setStyleSheet(LOOKY_STATUS_LABEL_STYLESHEET)
    status_label.hide()
    layout.addWidget(status_label)

    try_again_btn = QPushButton('Try Again')
    try_again_btn.setStyleSheet(LOOKY_PRIMARY_ACTION_BUTTON_STYLESHEET)
    try_again_btn.hide()
    layout.addWidget(try_again_btn)

    button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
    button_box.rejected.connect(dialog.reject)
    close_btn = button_box.button(QDialogButtonBox.StandardButton.Close)
    if close_btn is not None:
        close_btn.setStyleSheet(LOOKY_ACTION_BUTTON_STYLESHEET)
    layout.addWidget(button_box)

    return LookyProgressWidgets(progress_bar, status_label, try_again_btn)


def check_looky_prerequisites(parent: QWidget) -> str | None:
    """Validate Looky System prerequisites and return the API key on success.

    Checks (in order):
    - API key is set
    - Looky System is enabled
    - API access is granted

    Returns the API key string when all prerequisites are met, or None after
    displaying a warning for the first unmet prerequisite.
    """
    if not Settings.looky_api_key:
        QMessageBox.warning(parent, LOOKY_TITLE, LOOKY_WARNING_API_KEY_MISSING)
        return None

    if not Settings.looky_enabled:
        QMessageBox.warning(parent, LOOKY_TITLE, LOOKY_WARNING_DISABLED)
        return None

    if not Settings.looky_api_access:
        QMessageBox.warning(parent, LOOKY_TITLE, LOOKY_WARNING_API_ACCESS_MISSING)
        return None

    return Settings.looky_api_key
