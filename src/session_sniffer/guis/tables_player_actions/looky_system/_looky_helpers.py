"""Shared Looky System pre-flight validation for player action dialogs."""

import html
from dataclasses import dataclass

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
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
    LOOKY_WARNING_RESTRICTED_GTA5_NOT_RUNNING,
    LOOKY_WARNING_RESTRICTED_NOT_LOCAL,
    is_looky_gta5_restricted,
)
from session_sniffer.guis.stylesheets import (
    LOOKY_ACTION_BUTTON_STYLESHEET,
    LOOKY_CRAWLER_HEADER_STYLESHEET,
    LOOKY_PRIMARY_ACTION_BUTTON_STYLESHEET,
    LOOKY_PROGRESS_BAR_STYLESHEET,
    LOOKY_STATUS_LABEL_STYLESHEET,
)
from session_sniffer.networking.looky_system import LookyState
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings.settings import Settings


@dataclass(frozen=True, slots=True)
class LookyProgressWidgets:
    """The three mutable widgets built by `build_looky_progress_widgets`."""

    progress_bar: QProgressBar
    status_label: QLabel
    try_again_button: QPushButton
    button_box: QDialogButtonBox


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

    try_again_button = QPushButton('Try Again')
    try_again_button.setStyleSheet(LOOKY_PRIMARY_ACTION_BUTTON_STYLESHEET)
    try_again_button.setCursor(Qt.CursorShape.PointingHandCursor)
    try_again_button.hide()
    layout.addWidget(try_again_button)

    button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
    button_box.rejected.connect(dialog.reject)
    close_button = button_box.button(QDialogButtonBox.StandardButton.Close)
    if close_button:
        close_button.setCursor(Qt.CursorShape.PointingHandCursor)
        close_button.setStyleSheet(LOOKY_ACTION_BUTTON_STYLESHEET)
    layout.addWidget(button_box)

    return LookyProgressWidgets(progress_bar, status_label, try_again_button, button_box)


class LookyRefreshLoadingDialog(QDialog):
    """Modal dialog shown while batch-lookup is running in the background."""

    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent)
        self.setWindowTitle(LOOKY_TITLE)
        self.setWindowModality(Qt.WindowModality.WindowModal)
        self.setWindowFlag(Qt.WindowType.WindowContextHelpButtonHint, on=False)
        self.setMinimumSize(360, 160)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)
        header = QLabel('\U0001f441  Looky \u2014 Fetching...')
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.setStyleSheet(LOOKY_CRAWLER_HEADER_STYLESHEET)
        layout.addWidget(header)
        self._widgets = build_looky_progress_widgets(layout, self)
        self._widgets.status_label.setText('<span style="color: #d8b4fe;">Preparing Looky System lookup...</span>')
        self._widgets.status_label.show()

    def update_progress(self, status_text: str, current: int, total: int) -> None:
        """Update the progress bar and status label with the active lookup phase and completion count."""
        self._widgets.progress_bar.setRange(0, max(1, total))
        self._widgets.progress_bar.setValue(current)
        pct = round(current * 100 / total) if total > 0 else 0
        self._widgets.status_label.setText(f'<span style="color: #d8b4fe;">{html.escape(status_text)}: <b>{current} / {total}</b> ({pct}%)</span>')
        self._widgets.status_label.show()

    def show_error(self, message: str) -> None:
        """Hide the progress bar and show the error message."""
        self._widgets.progress_bar.hide()
        self._widgets.status_label.setText(f'<span style="color: #f87171; font-weight: 600;">\u2717 Failed: {html.escape(message)}</span>')
        self._widgets.status_label.show()


def check_looky_prerequisites(parent: QWidget, *, check_gta5_restriction: bool = False) -> str | None:
    """Validate Looky System prerequisites and return the API key on success.

    Checks (in order):
    - GTA V feature set is active
    - API key is set
    - Looky System is enabled
    - API access is granted
    - Local capture is active
    - GTA V process scanning restriction (if `check_gta5_restriction` is True)

    Returns the API key string when all prerequisites are met, or None after
    displaying a warning for the first unmet prerequisite.
    """
    warning_message: str | None = None
    if not Settings.is_gta5_feature_set():
        warning_message = LOOKY_WARNING_RESTRICTED_GTA5_NOT_RUNNING
    elif not bool(Settings.looky_api_key):
        warning_message = LOOKY_WARNING_API_KEY_MISSING
    elif not Settings.looky_enabled:
        warning_message = LOOKY_WARNING_DISABLED
    elif not LookyState.api_access:
        warning_message = LOOKY_WARNING_API_ACCESS_MISSING
    elif not CaptureState.is_local_capture():
        warning_message = LOOKY_WARNING_RESTRICTED_NOT_LOCAL
    elif check_gta5_restriction and is_looky_gta5_restricted():
        warning_message = LOOKY_WARNING_RESTRICTED_GTA5_NOT_RUNNING

    if warning_message is not None:
        QMessageBox.warning(parent, LOOKY_TITLE, warning_message)
        return None

    return Settings.looky_api_key
